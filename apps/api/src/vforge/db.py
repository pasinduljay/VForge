"""Database engine, session factory, declarative base, and RLS context helpers."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(AsyncAttrs, DeclarativeBase):
    """Base class for SQLAlchemy ORM models."""


def build_engine(database_url: str) -> AsyncEngine:
    """Create an async SQLAlchemy engine for PostgreSQL using psycopg3."""
    return create_async_engine(
        database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        pool_reset_on_return="rollback",
    )


def build_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Build an async session factory safe for pooled RLS transactions."""
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


async def verify_runtime_db_identity(engine: AsyncEngine) -> dict[str, Any]:
    """Verify the connected PostgreSQL runtime role is strictly least-privilege.

    Fails closed if the API connects as a superuser, BYPASSRLS role, role with
    CREATEROLE/CREATEDB, or owner of any table in the `public` schema.
    """
    async with engine.connect() as conn:
        res = await conn.execute(
            text(
                "SELECT "
                "current_user, "
                "r.rolsuper, "
                "r.rolbypassrls, "
                "r.rolcreaterole, "
                "r.rolcreatedb, "
                "r.rolinherit, "
                "EXISTS ("
                "    SELECT 1 FROM pg_tables t "
                "    WHERE t.schemaname = 'public' AND t.tableowner = current_user"
                ") AS owns_tables "
                "FROM pg_roles r "
                "WHERE r.rolname = current_user"
            )
        )
        row = res.one()

    role_name = str(row[0])
    rolsuper = bool(row[1])
    rolbypassrls = bool(row[2])
    rolcreaterole = bool(row[3])
    rolcreatedb = bool(row[4])
    rolinherit = bool(row[5])
    owns_tables = bool(row[6])

    violations: list[str] = []
    if rolsuper:
        violations.append("SUPERUSER")
    if rolbypassrls:
        violations.append("BYPASSRLS")
    if rolcreaterole:
        violations.append("CREATEROLE")
    if rolcreatedb:
        violations.append("CREATEDB")
    if owns_tables:
        violations.append("TABLE_OWNER")

    if violations:
        joined = ", ".join(violations)
        raise RuntimeError(
            f"Unsafe PostgreSQL runtime identity '{role_name}' detected ({joined}); "
            "refusing to start with privileged database role"
        )

    return {
        "role": role_name,
        "rolsuper": rolsuper,
        "rolbypassrls": rolbypassrls,
        "rolcreaterole": rolcreaterole,
        "rolcreatedb": rolcreatedb,
        "rolinherit": rolinherit,
        "owns_tables": owns_tables,
    }


async def set_db_context(
    session: AsyncSession,
    *,
    org_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    auth_lookup: tuple[str, str] | None = None,
    session_token_hash: str | None = None,
) -> None:
    """Set transaction-scoped PostgreSQL GUCs for Row-Level Security.

    Uses ``set_config(..., true)`` so every setting is strictly local to the
    current transaction and cleared automatically on commit/rollback before
    returning the connection to the SQLAlchemy pool.
    """
    issuer, subject = auth_lookup if auth_lookup is not None else ("", "")
    await session.execute(
        text(
            "SELECT "
            "set_config('app.current_org_id', :org_id, true), "
            "set_config('app.current_user_id', :user_id, true), "
            "set_config('app.auth_lookup_issuer', :issuer, true), "
            "set_config('app.auth_lookup_subject', :subject, true), "
            "set_config('app.session_token_hash', :token_hash, true)"
        ),
        {
            "org_id": str(org_id) if org_id is not None else "",
            "user_id": str(user_id) if user_id is not None else "",
            "issuer": issuer,
            "subject": subject,
            "token_hash": session_token_hash or "",
        },
    )
