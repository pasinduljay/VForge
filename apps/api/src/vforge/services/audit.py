"""Append-only security audit event service."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.models import AuditEvent, AuditOutcome
from vforge.security.validators import redact_metadata


async def record_audit_event(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID | None,
    actor_id: uuid.UUID | None,
    correlation_id: str | None,
    action: str,
    resource_type: str | None = None,
    resource_id: uuid.UUID | None = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    metadata: dict[str, Any] | None = None,
) -> uuid.UUID:
    """Persist an append-only audit event with secret redaction.

    Uses an explicit ``INSERT`` without ``RETURNING`` so system/auth events
    (``organization_id IS NULL``) can be written under strict ``SELECT`` RLS.
    """
    event_id = uuid.uuid4()
    sanitized_meta = redact_metadata(metadata or {})
    meta_dict = sanitized_meta if isinstance(sanitized_meta, dict) else {}

    await db.execute(
        sa.insert(AuditEvent).values(
            id=event_id,
            organization_id=organization_id,
            actor_id=actor_id,
            correlation_id=correlation_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome.value,
            event_metadata=meta_dict,
            created_at=datetime.now(UTC),
        )
    )
    return event_id


async def list_audit_events(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    action: str | None = None,
    resource_type: str | None = None,
    outcome: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[AuditEvent], int]:
    """List paginated audit events for an organization."""
    stmt = select(AuditEvent).where(AuditEvent.organization_id == organization_id)
    count_stmt = (
        select(func.count())
        .select_from(AuditEvent)
        .where(AuditEvent.organization_id == organization_id)
    )

    if action:
        stmt = stmt.where(AuditEvent.action == action)
        count_stmt = count_stmt.where(AuditEvent.action == action)
    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == resource_type)
        count_stmt = count_stmt.where(AuditEvent.resource_type == resource_type)
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
        count_stmt = count_stmt.where(AuditEvent.outcome == outcome)

    total_res = await db.execute(count_stmt)
    total = int(total_res.scalar_one())

    rows_res = await db.execute(
        stmt.order_by(AuditEvent.created_at.desc()).limit(limit).offset(offset)
    )
    return list(rows_res.scalars().all()), total
