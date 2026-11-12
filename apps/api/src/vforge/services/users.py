"""User identity mapping anchored to OIDC (issuer, subject)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.auth.oidc import OidcIdentity
from vforge.db import set_db_context
from vforge.errors import ForbiddenError
from vforge.models import AppUser, UserStatus


async def upsert_oidc_user(
    db: AsyncSession,
    *,
    identity: OidcIdentity,
    record_login: bool = True,
) -> AppUser:
    """Resolve or provision an application user by (oidc_issuer, oidc_subject)."""
    await set_db_context(db, auth_lookup=(identity.issuer, identity.subject))
    result = await db.execute(
        select(AppUser).where(
            AppUser.oidc_issuer == identity.issuer,
            AppUser.oidc_subject == identity.subject,
        )
    )
    user = result.scalar_one_or_none()
    now = datetime.now(UTC)

    if user is None:
        user = AppUser(
            oidc_issuer=identity.issuer,
            oidc_subject=identity.subject,
            email=identity.email,
            display_name=identity.display_name,
            status=UserStatus.ACTIVE.value,
            last_login_at=now if record_login else None,
        )
        db.add(user)
        await db.flush()
        return user

    if user.status != UserStatus.ACTIVE.value:
        raise ForbiddenError("User account is disabled or locked")

    user.email = identity.email
    user.display_name = identity.display_name
    if record_login:
        user.last_login_at = now
    await db.flush()
    await db.refresh(user)
    return user
