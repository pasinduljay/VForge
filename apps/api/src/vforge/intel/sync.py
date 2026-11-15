"""Threat Intelligence Synchronization Engine (Phase 9)."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.intel.connector import IntelligenceConnector
from vforge.intel.connectors.cisa_kev import CisaKevConnector
from vforge.intel.connectors.exploit_db import ExploitDbConnector
from vforge.intel.connectors.first_epss import FirstEpssConnector
from vforge.intel.connectors.gated import ShodanGatedConnector, VirusTotalGatedConnector
from vforge.intel.connectors.nvd_cve import NvdCveConnector
from vforge.intel.connectors.osv import OsvConnector
from vforge.intel.exposure import HudsonRockConnector
from vforge.models.intel import (
    IntelligenceSource,
    IntelRecord,
    IntelRelationship,
    IntelSnapshot,
    IntelSyncRun,
)

logger = logging.getLogger(__name__)


class IntelConnectorRegistry:
    """Registry of active intelligence connectors keyed by source slug."""

    def __init__(self) -> None:
        self._connectors: dict[str, IntelligenceConnector] = {
            "cisa_kev": CisaKevConnector(),
            "first_epss": FirstEpssConnector(),
            "nvd": NvdCveConnector(),
            "osv": OsvConnector(),
            "exploit_db": ExploitDbConnector(),
            "virustotal": VirusTotalGatedConnector(),
            "shodan": ShodanGatedConnector(),
            "hudson_rock": HudsonRockConnector(),
        }

    def register(self, slug: str, connector: IntelligenceConnector) -> None:
        self._connectors[slug] = connector

    def get(self, slug: str) -> IntelligenceConnector | None:
        return self._connectors.get(slug)

    def list_slugs(self) -> list[str]:
        return list(self._connectors.keys())


registry = IntelConnectorRegistry()


async def sync_intelligence_source(
    db: AsyncSession,
    source_slug: str,
    sync_mode: str = "incremental",
    connector_override: IntelligenceConnector | None = None,
) -> IntelSyncRun:
    """Execute a synchronization run for the designated intelligence source.

    Invariants:
    1. Preserves source provenance and SHA-256 hashes.
    2. Fail-closed schema validation: invalid schemas are quarantined.
    3. Stale data resilience: feed failures keep last-known-good snapshots and flag them stale.
    """
    source = (
        await db.execute(select(IntelligenceSource).where(IntelligenceSource.slug == source_slug))
    ).scalar_one_or_none()

    if not source:
        msg = f"Intelligence source with slug '{source_slug}' not found"
        raise ValueError(msg)

    connector = connector_override or registry.get(source_slug)
    if not connector:
        msg = f"No connector registered for intelligence source '{source_slug}'"
        raise ValueError(msg)

    # Lookup last successful sync cursor
    last_successful_run = (
        await db.execute(
            select(IntelSyncRun)
            .where(
                IntelSyncRun.source_id == source.id,
                IntelSyncRun.status == "succeeded",
            )
            .order_by(desc(IntelSyncRun.completed_at))
            .limit(1)
        )
    ).scalar_one_or_none()

    cursor_before = (
        last_successful_run.cursor_after
        if (last_successful_run and sync_mode == "incremental")
        else None
    )

    sync_run = IntelSyncRun(
        id=uuid.uuid4(),
        source_id=source.id,
        sync_mode=sync_mode,
        cursor_before=cursor_before,
        status="running",
        started_at=datetime.now(UTC),
    )
    db.add(sync_run)
    await db.flush()

    try:
        # 1. Health check
        health = await connector.health_check()
        if not health.is_healthy:
            err_msg = (
                health.error_message or f"Feed health check failed (HTTP {health.status_code})"
            )
            sync_run.status = "failed"
            sync_run.error_message = err_msg
            sync_run.completed_at = datetime.now(UTC)

            # Mark existing snapshots as stale
            await _mark_snapshots_stale(db, source.id, err_msg)
            await db.flush()
            return sync_run

        # 2. Fetch incremental batch
        batch = await connector.fetch_incremental(cursor=cursor_before)
        sync_run.records_fetched = batch.record_count
        sync_run.raw_payload_hash = batch.raw_hash

        # 3. Validate batch schema
        val_result = connector.validate(batch)
        if not val_result.is_valid:
            err_msg = f"Validation failed: {'; '.join(val_result.errors)}"
            sync_run.status = "quarantined"
            sync_run.error_message = err_msg
            sync_run.completed_at = datetime.now(UTC)
            await db.flush()
            return sync_run

        # 4. Normalize and persist records
        normalized_records = connector.normalize(batch)
        persisted_count = 0

        for norm_rec in normalized_records:
            existing = (
                await db.execute(
                    select(IntelRecord).where(
                        IntelRecord.source_id == source.id,
                        IntelRecord.source_record_id == norm_rec.source_record_id,
                    )
                )
            ).scalar_one_or_none()

            now_utc = datetime.now(UTC)
            if existing:
                existing.title = norm_rec.title
                existing.summary = norm_rec.summary
                existing.description = norm_rec.description
                existing.cvss_score = norm_rec.cvss_score
                existing.cvss_vector = norm_rec.cvss_vector
                existing.epss_score = norm_rec.epss_score
                existing.epss_percentile = norm_rec.epss_percentile
                existing.is_known_exploited = norm_rec.is_known_exploited
                existing.raw_payload = norm_rec.raw_payload
                existing.raw_hash = norm_rec.raw_hash
                existing.normalized_hash = norm_rec.normalized_hash
                existing.published_at = norm_rec.published_at or existing.published_at
                existing.modified_at = norm_rec.modified_at or now_utc
                existing.retrieved_at = norm_rec.retrieved_at or now_utc
                existing.updated_at = now_utc
                record_id = existing.id
            else:
                new_rec = IntelRecord(
                    id=uuid.uuid4(),
                    source_id=source.id,
                    source_record_id=norm_rec.source_record_id,
                    record_type=norm_rec.record_type,
                    title=norm_rec.title,
                    summary=norm_rec.summary,
                    description=norm_rec.description,
                    cvss_score=norm_rec.cvss_score,
                    cvss_vector=norm_rec.cvss_vector,
                    epss_score=norm_rec.epss_score,
                    epss_percentile=norm_rec.epss_percentile,
                    is_known_exploited=norm_rec.is_known_exploited,
                    raw_payload=norm_rec.raw_payload,
                    raw_hash=norm_rec.raw_hash,
                    normalized_hash=norm_rec.normalized_hash,
                    published_at=norm_rec.published_at,
                    modified_at=norm_rec.modified_at,
                    retrieved_at=norm_rec.retrieved_at or now_utc,
                    created_at=now_utc,
                    updated_at=now_utc,
                )
                db.add(new_rec)
                await db.flush()
                record_id = new_rec.id

            # Persist relationships
            for rel in norm_rec.relationships:
                rel_row = IntelRelationship(
                    id=uuid.uuid4(),
                    intel_record_id=record_id,
                    relationship_type=rel.relationship_type,
                    target_identifier_type=rel.target_identifier_type,
                    target_identifier=rel.target_identifier,
                )
                db.add(rel_row)

            persisted_count += 1

        # 5. Create immutable point-in-time snapshot
        timestamp_str = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        tag_suffix = uuid.uuid4().hex[:6]
        snapshot = IntelSnapshot(
            id=uuid.uuid4(),
            source_id=source.id,
            snapshot_tag=f"{source_slug}-{timestamp_str}-{tag_suffix}",
            snapshot_hash=batch.raw_hash or "empty",
            record_count=persisted_count,
            is_stale=False,
            created_at=datetime.now(UTC),
        )
        db.add(snapshot)

        # 6. Complete sync run
        sync_run.status = "succeeded"
        sync_run.records_persisted = persisted_count
        sync_run.cursor_after = connector.checkpoint(batch)
        sync_run.completed_at = datetime.now(UTC)

        await db.flush()
        return sync_run

    except Exception as exc:  # noqa: BLE001
        logger.exception("Error syncing intelligence source %s", source_slug)
        sync_run.status = "failed"
        sync_run.error_message = str(exc)
        sync_run.completed_at = datetime.now(UTC)
        await _mark_snapshots_stale(db, source.id, str(exc))
        await db.flush()
        return sync_run


async def _mark_snapshots_stale(db: AsyncSession, source_id: uuid.UUID, reason: str) -> None:
    """Flag existing snapshots as stale when upstream synchronization fails.

    Because intel_snapshots is append-only, we record staleness by appending a
    new snapshot record inheriting the previous hash/records but with is_stale=True.
    """
    latest = (
        await db.execute(
            select(IntelSnapshot)
            .where(IntelSnapshot.source_id == source_id)
            .order_by(desc(IntelSnapshot.created_at))
            .limit(1)
        )
    ).scalar_one_or_none()

    timestamp_str = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    tag_suffix = uuid.uuid4().hex[:6]
    stale_tag = f"stale-{timestamp_str}-{tag_suffix}"
    stale_snapshot = IntelSnapshot(
        id=uuid.uuid4(),
        source_id=source_id,
        snapshot_tag=stale_tag,
        snapshot_hash=latest.snapshot_hash if latest else "stale-failure",
        record_count=latest.record_count if latest else 0,
        is_stale=True,
        stale_reason=reason if reason else "Sync failed",
        created_at=datetime.now(UTC),
    )
    db.add(stale_snapshot)
