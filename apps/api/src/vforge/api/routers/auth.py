"""Authentication, OIDC Authorization Code + PKCE, session, and CSRF endpoints."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.api.deps import Principal, get_client_ip, get_current_principal, get_db
from vforge.auth.oidc import (
    compute_pkce_challenge,
    generate_pkce_verifier,
    hash_oidc_value,
    oidc_client,
)
from vforge.auth.rbac import get_permissions_for_role
from vforge.auth.sessions import create_auth_session, rotate_auth_session
from vforge.config import Settings, get_settings
from vforge.db import set_db_context
from vforge.errors import ForbiddenError, UnauthorizedError, ValidationError
from vforge.logging import correlation_id_var
from vforge.models import (
    AuditOutcome,
    MembershipStatus,
    OidcAuthState,
    Role,
)
from vforge.schemas import (
    AuthMeResponse,
    OrganizationMembershipSummary,
    SwitchOrganizationRequest,
    UserOut,
)
from vforge.security.rate_limit import rate_limiter
from vforge.services.audit import record_audit_event
from vforge.services.organizations import list_user_memberships
from vforge.services.users import upsert_oidc_user

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


def _sanitize_redirect_path(redirect_path: str) -> str:
    cleaned = redirect_path.strip() or "/"
    if not cleaned.startswith("/") or cleaned.startswith("//") or "\\" in cleaned:
        raise ValidationError("redirect_path must be a relative path starting with '/'")
    return cleaned[:512]


def _resolve_post_logout_redirect_uri(request: Request, settings: Settings) -> str:
    """Resolve safe post-logout `/login` URI restricted to configured frontend origins."""
    forwarded_host = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
    host = forwarded_host or (request.headers.get("host") or "").strip()
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    scheme = forwarded_proto or request.url.scheme or "http"
    candidate_origin = f"{scheme}://{host}".rstrip("/") if host else ""
    allowed_origins = {origin.rstrip("/") for origin in settings.cors_allowed_origins if origin}
    if candidate_origin and candidate_origin in allowed_origins:
        return f"{candidate_origin}/login"
    fallback_parsed = urlsplit(settings.frontend_base_url.rstrip("/"))
    base_origin = f"{fallback_parsed.scheme}://{fallback_parsed.netloc}".rstrip("/")
    return f"{base_origin}/login" if base_origin else "/login"


@router.get("/oidc/login")
async def oidc_login(
    request: Request,
    redirect_path: str = Query(default="/organizations"),
    mode: str = Query(default="redirect", pattern="^(redirect|json)$"),
    prompt: str | None = Query(default=None, pattern="^(login|select_account|consent|none)$"),
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> Response:
    """Initiate OIDC Authorization Code Flow with PKCE (S256)."""
    await rate_limiter.check_limit(
        settings=settings,
        bucket="oidc_login",
        key=get_client_ip(request),
        limit=settings.auth_rate_limit_per_minute,
        window_seconds=60,
    )
    if not settings.oidc_enabled or not settings.oidc_issuer:
        raise UnauthorizedError("OIDC authentication is not enabled")

    safe_redirect = _sanitize_redirect_path(redirect_path)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = generate_pkce_verifier()
    code_challenge = compute_pkce_challenge(code_verifier)

    now = datetime.now(UTC)
    await db.execute(delete(OidcAuthState).where(OidcAuthState.expires_at <= now))

    auth_state = OidcAuthState(
        state_hash=hash_oidc_value(state),
        nonce_hash=nonce,  # Bound to single-use state row; verified via hmac.compare_digest
        code_verifier=code_verifier,
        redirect_path=safe_redirect,
        expires_at=now + timedelta(minutes=5),
    )
    db.add(auth_state)
    await db.flush()

    auth_url = await oidc_client.build_authorization_url(
        settings=settings,
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        prompt=prompt,
    )
    if mode == "json":
        return JSONResponse({"authorization_url": auth_url})
    return RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> Response:
    """Handle OIDC authorization callback, verify PKCE + ID token, and issue session cookie."""
    await rate_limiter.check_limit(
        settings=settings,
        bucket="oidc_callback",
        key=get_client_ip(request),
        limit=settings.auth_rate_limit_per_minute,
        window_seconds=60,
    )
    corr_id = correlation_id_var.get()

    if error or not code or not state:
        await record_audit_event(
            db,
            organization_id=None,
            actor_id=None,
            correlation_id=corr_id,
            action="auth.oidc_login",
            resource_type="auth_session",
            outcome=AuditOutcome.FAILURE,
            metadata={"reason": "provider_error_or_missing_code"},
        )
        raise UnauthorizedError("OIDC authentication failed or was cancelled")

    state_hash = hash_oidc_value(state)
    consumed_res = await db.execute(
        delete(OidcAuthState).where(OidcAuthState.state_hash == state_hash).returning(OidcAuthState)
    )
    auth_state = consumed_res.scalar_one_or_none()
    now = datetime.now(UTC)
    if auth_state is None or auth_state.expires_at <= now:
        await record_audit_event(
            db,
            organization_id=None,
            actor_id=None,
            correlation_id=corr_id,
            action="auth.oidc_login",
            resource_type="auth_session",
            outcome=AuditOutcome.DENIED,
            metadata={"reason": "invalid_or_expired_state"},
        )
        raise UnauthorizedError("Invalid or expired OIDC state")

    tokens = await oidc_client.exchange_code_for_tokens(
        settings=settings,
        code=code,
        code_verifier=auth_state.code_verifier,
    )
    raw_id_token = str(tokens["id_token"])
    identity = await oidc_client.verify_jwt(
        token=raw_id_token,
        settings=settings,
        expected_nonce=auth_state.nonce_hash,
    )
    user = await upsert_oidc_user(db, identity=identity, record_login=True)

    memberships = await list_user_memberships(db, user_id=user.id)
    default_org_id = memberships[0][1].id if memberships else None

    raw_session_token, auth_session = await create_auth_session(
        db,
        settings=settings,
        user_id=user.id,
        active_organization_id=default_org_id,
        oidc_id_token=raw_id_token,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    await set_db_context(db, org_id=None, user_id=user.id)
    await record_audit_event(
        db,
        organization_id=None,
        actor_id=user.id,
        correlation_id=corr_id,
        action="auth.oidc_login",
        resource_type="auth_session",
        resource_id=auth_session.id,
        outcome=AuditOutcome.SUCCESS,
        metadata={"issuer": identity.issuer},
    )

    target_url = f"{settings.frontend_base_url.rstrip('/')}{auth_state.redirect_path}"
    response = RedirectResponse(url=target_url, status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_session_token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.effective_cookie_secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key=settings.session_csrf_cookie_name,
        value=auth_session.csrf_token,
        max_age=settings.session_ttl_seconds,
        httponly=False,
        secure=settings.effective_cookie_secure,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/me", response_model=AuthMeResponse)
async def get_me(
    principal: Principal = Depends(get_current_principal),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AuthMeResponse:
    """Return authenticated user profile, CSRF token, and verified organization memberships."""
    pairs = await list_user_memberships(db, user_id=principal.user.id)
    summaries = [
        OrganizationMembershipSummary(
            organization_id=org.id,
            organization_name=org.name,
            organization_slug=org.slug,
            organization_status=org.status,
            role=Role(membership.role),
            membership_status=MembershipStatus(membership.status),
            permissions=get_permissions_for_role(Role(membership.role)),
        )
        for membership, org in pairs
    ]

    active_org = principal.auth_session.active_organization_id if principal.auth_session else None
    if active_org is not None and all(item.organization_id != active_org for item in summaries):
        active_org = None

    return AuthMeResponse(
        user=UserOut.model_validate(principal.user),
        active_organization_id=active_org,
        csrf_token=principal.auth_session.csrf_token if principal.auth_session else None,
        memberships=summaries,
    )


@router.post("/switch-organization", status_code=status.HTTP_200_OK)
async def switch_organization(
    payload: SwitchOrganizationRequest,
    request: Request,
    principal: Principal = Depends(get_current_principal),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> Response:
    """Switch active organization and rotate session/CSRF cookies after verifying DB membership."""
    if principal.auth_session is None:
        raise ValidationError("Organization switching applies only to browser sessions")

    pairs = await list_user_memberships(db, user_id=principal.user.id)
    if all(org.id != payload.organization_id for _m, org in pairs):
        raise ForbiddenError("User does not hold an active membership in this organization")

    raw_session_token, rotated = await rotate_auth_session(
        db,
        current_session=principal.auth_session,
        active_organization_id=payload.organization_id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    await set_db_context(db, org_id=payload.organization_id, user_id=principal.user.id)
    await record_audit_event(
        db,
        organization_id=payload.organization_id,
        actor_id=principal.user.id,
        correlation_id=principal.correlation_id,
        action="auth.organization_switched",
        resource_type="organization",
        resource_id=payload.organization_id,
        metadata={"session_rotated": True},
    )
    response = JSONResponse(
        {
            "active_organization_id": str(payload.organization_id),
            "csrf_token": rotated.csrf_token,
        }
    )
    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_session_token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.effective_cookie_secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key=settings.session_csrf_cookie_name,
        value=rotated.csrf_token,
        max_age=settings.session_ttl_seconds,
        httponly=False,
        secure=settings.effective_cookie_secure,
        samesite="lax",
        path="/",
    )
    return response


@router.post("/session/rotate", status_code=status.HTTP_200_OK)
async def rotate_session(
    request: Request,
    principal: Principal = Depends(get_current_principal),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> Response:
    """Explicitly rotate the active browser session token and CSRF token."""
    if principal.auth_session is None:
        raise ValidationError("Session rotation applies only to browser sessions")

    raw_session_token, rotated = await rotate_auth_session(
        db,
        current_session=principal.auth_session,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    await set_db_context(db, org_id=None, user_id=principal.user.id)
    await record_audit_event(
        db,
        organization_id=None,
        actor_id=principal.user.id,
        correlation_id=principal.correlation_id,
        action="auth.session_rotated",
        resource_type="auth_session",
        resource_id=rotated.id,
    )
    response = JSONResponse({"rotated": True, "csrf_token": rotated.csrf_token})
    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_session_token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.effective_cookie_secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key=settings.session_csrf_cookie_name,
        value=rotated.csrf_token,
        max_age=settings.session_ttl_seconds,
        httponly=False,
        secure=settings.effective_cookie_secure,
        samesite="lax",
        path="/",
    )
    return response


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    request: Request,
    principal: Principal = Depends(get_current_principal),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> Response:
    """Revoke current server-side session, clear cookies, and build IdP end-session URL."""
    id_token_hint: str | None = None
    if principal.auth_session is not None:
        id_token_hint = principal.auth_session.oidc_id_token
        await set_db_context(
            db,
            user_id=principal.user.id,
            session_token_hash=principal.auth_session.token_hash,
        )
        principal.auth_session.revoked_at = datetime.now(UTC)
        principal.auth_session.oidc_id_token = None
        await db.flush()
        await set_db_context(db, org_id=None, user_id=principal.user.id)
        await record_audit_event(
            db,
            organization_id=None,
            actor_id=principal.user.id,
            correlation_id=principal.correlation_id,
            action="auth.logout",
            resource_type="auth_session",
            resource_id=principal.auth_session.id,
        )

    logout_url: str | None = None
    if settings.oidc_enabled and settings.oidc_issuer:
        try:
            logout_url = await oidc_client.build_logout_url(
                settings=settings,
                post_logout_redirect_uri=_resolve_post_logout_redirect_uri(request, settings),
                id_token_hint=id_token_hint,
            )
        except UnauthorizedError:
            logout_url = None

    response = JSONResponse({"status": "logged_out", "logout_url": logout_url})
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(settings.session_csrf_cookie_name, path="/")
    return response
