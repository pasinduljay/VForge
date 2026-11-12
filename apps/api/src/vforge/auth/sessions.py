"""Server-side short-lived session and CSRF management."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.config import Settings
from vforge.db import set_db_context
from vforge.errors import ForbiddenError
from vforge.models import AuthSession


def hash_session_token(raw_token: str) -> str:
    """Compute SHA-256 hex digest of an opaque session token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


async def create_auth_session(
    db: AsyncSession,
    *,
    settings: Settings,
    user_id: uuid.UUID,
    active_organization_id: uuid.UUID | None = None,
    oidc_id_token: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, AuthSession]:
    """Create a short-lived server-side session and return `(raw_cookie_token, row)`."""
    now = datetime.now(UTC)
    raw_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    token_hash = hash_session_token(raw_token)

    await set_db_context(
        db,
        user_id=user_id,
        session_token_hash=token_hash,
    )

    session_row = AuthSession(
        user_id=user_id,
        active_organization_id=active_organization_id,
        token_hash=token_hash,
        csrf_token=csrf_token,
        oidc_id_token=oidc_id_token,
        ip_address=ip_address[:64] if ip_address else None,
        user_agent=user_agent[:512] if user_agent else None,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(seconds=settings.session_ttl_seconds),
    )
    db.add(session_row)
    await db.flush()
    return raw_token, session_row


async def resolve_auth_session(
    db: AsyncSession,
    *,
    settings: Settings,
    raw_token: str,
) -> AuthSession | None:
    """Look up an active, non-expired, non-idle session by opaque cookie token."""
    if not raw_token:
        return None
    token_hash = hash_session_token(raw_token)
    await set_db_context(db, session_token_hash=token_hash)

    result = await db.execute(select(AuthSession).where(AuthSession.token_hash == token_hash))
    session_row = result.scalar_one_or_none()
    if session_row is None:
        return None

    now = datetime.now(UTC)
    if session_row.revoked_at is not None or session_row.expires_at <= now:
        return None

    idle_deadline = session_row.last_seen_at + timedelta(
        seconds=settings.session_idle_timeout_seconds
    )
    if idle_deadline <= now:
        session_row.revoked_at = now
        session_row.oidc_id_token = None
        await db.flush()
        return None

    session_row.last_seen_at = now
    await db.flush()
    return session_row


async def rotate_auth_session(
    db: AsyncSession,
    *,
    current_session: AuthSession,
    active_organization_id: uuid.UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, AuthSession]:
    """Revoke `current_session` and issue a replacement session with fresh tokens.

    Preserves the original absolute `expires_at` deadline so rotation cannot be
    used to extend session lifetime indefinitely.
    """
    now = datetime.now(UTC)
    raw_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    token_hash = hash_session_token(raw_token)
    preserved_id_token = current_session.oidc_id_token

    await set_db_context(
        db,
        user_id=current_session.user_id,
        session_token_hash=current_session.token_hash,
    )
    current_session.revoked_at = now
    current_session.oidc_id_token = None
    await db.flush()

    await set_db_context(
        db,
        user_id=current_session.user_id,
        session_token_hash=token_hash,
    )
    target_org = (
        active_organization_id
        if active_organization_id is not None
        else current_session.active_organization_id
    )
    new_session = AuthSession(
        user_id=current_session.user_id,
        active_organization_id=target_org,
        token_hash=token_hash,
        csrf_token=csrf_token,
        oidc_id_token=preserved_id_token,
        ip_address=(ip_address[:64] if ip_address else current_session.ip_address),
        user_agent=(user_agent[:512] if user_agent else current_session.user_agent),
        created_at=now,
        last_seen_at=now,
        expires_at=current_session.expires_at,
    )
    db.add(new_session)
    await db.flush()
    return raw_token, new_session


def verify_csrf_token(auth_session: AuthSession, header_token: str | None) -> None:
    """Validate X-CSRF-Token header against session CSRF secret."""
    if not header_token or not hmac.compare_digest(auth_session.csrf_token, header_token):
        raise ForbiddenError("CSRF validation failed")
