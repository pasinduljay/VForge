"""FastAPI dependencies for DB sessions, OIDC/cookie auth, CSRF, and tenant RLS."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.auth.oidc import oidc_client
from vforge.auth.sessions import resolve_auth_session, verify_csrf_token
from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory, set_db_context
from vforge.errors import ForbiddenError, UnauthorizedError
from vforge.logging import correlation_id_var
from vforge.models import AppUser, AuthSession, Membership, MembershipStatus, Role, UserStatus
from vforge.security.rate_limit import rate_limiter
from vforge.services.users import upsert_oidc_user

_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class Principal:
    """Authenticated user principal resolved from session cookie or Bearer JWT."""

    user: AppUser
    auth_method: str  # "cookie" | "bearer"
    auth_session: AuthSession | None
    correlation_id: str | None


@dataclass(frozen=True)
class TenantContext:
    """Verified tenant membership and role bound to PostgreSQL RLS context."""

    user: AppUser
    org_id: uuid.UUID
    role: Role
    correlation_id: str | None


def get_client_ip(request: Request) -> str:
    """Extract client IP safely for rate limiting and session metadata."""
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


async def get_db(
    request: Request,
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> AsyncIterator[AsyncSession]:
    """Yield a transaction-scoped AsyncSession using the dedicated non-owner runtime DB login."""
    session_factory = getattr(request.app.state, "session_factory", None)
    temp_engine = None
    if session_factory is None:
        db_url = settings.effective_database_url
        if not db_url:
            raise RuntimeError("Runtime PostgreSQL credentials are not configured")
        temp_engine = build_engine(db_url)
        session_factory = build_session_factory(temp_engine)

    try:
        async with session_factory() as session:
            async with session.begin():
                yield session
    finally:
        if temp_engine is not None:
            await temp_engine.dispose()


async def get_current_principal(
    request: Request,
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> Principal:
    """Authenticate caller via Bearer JWT or HTTP-only session cookie (+ CSRF)."""
    corr_id = correlation_id_var.get()
    auth_header = request.headers.get("authorization", "")

    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        if not token:
            raise UnauthorizedError("Empty bearer token")
        identity = await oidc_client.verify_jwt(token=token, settings=settings)
        user = await upsert_oidc_user(db, identity=identity, record_login=False)
        await set_db_context(db, user_id=user.id)
        return Principal(
            user=user,
            auth_method="bearer",
            auth_session=None,
            correlation_id=corr_id,
        )

    raw_cookie = request.cookies.get(settings.session_cookie_name)
    if raw_cookie:
        auth_session = await resolve_auth_session(db, settings=settings, raw_token=raw_cookie)
        if auth_session is None:
            raise UnauthorizedError("Session expired or invalid")

        if request.method.upper() in _STATE_CHANGING_METHODS:
            verify_csrf_token(auth_session, request.headers.get("x-csrf-token"))

        await set_db_context(db, user_id=auth_session.user_id)
        user_res = await db.execute(select(AppUser).where(AppUser.id == auth_session.user_id))
        cookie_user = user_res.scalar_one_or_none()
        if cookie_user is None or cookie_user.status != UserStatus.ACTIVE.value:
            raise UnauthorizedError("User account is inactive")

        return Principal(
            user=cookie_user,
            auth_method="cookie",
            auth_session=auth_session,
            correlation_id=corr_id,
        )

    raise UnauthorizedError("Authentication required")


async def get_tenant_context(
    org_id: uuid.UUID,
    principal: Principal = Depends(get_current_principal),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> TenantContext:
    """Verify active org membership in DB and bind PostgreSQL RLS tenant context."""
    await set_db_context(db, org_id=org_id, user_id=principal.user.id)
    res = await db.execute(
        select(Membership).where(
            Membership.organization_id == org_id,
            Membership.user_id == principal.user.id,
            Membership.status == MembershipStatus.ACTIVE.value,
        )
    )
    membership = res.scalar_one_or_none()
    if membership is None:
        raise ForbiddenError("Access to this organization is denied")

    return TenantContext(
        user=principal.user,
        org_id=org_id,
        role=Role(membership.role),
        correlation_id=principal.correlation_id,
    )


async def enforce_sensitive_rate_limit(
    request: Request,
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> None:
    """Apply rate limiting to sensitive control-plane mutations."""
    await rate_limiter.check_limit(
        settings=settings,
        bucket="sensitive",
        key=get_client_ip(request),
        limit=settings.sensitive_rate_limit_per_minute,
        window_seconds=60,
    )
