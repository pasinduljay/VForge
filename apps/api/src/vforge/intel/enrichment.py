"""Threat Intelligence Finding Enrichment Engine (Phase 9)."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.models.intel import (
    IntelEnrichmentEvent,
    IntelligenceSource,
    IntelRecord,
    IntelRelationship,
    IntelSnapshot,
    IntelSyncRun,
)
from vforge.models.scanner import Finding

CVE_PATTERN = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)


async def get_cve_threat_intel(db: AsyncSession, cve_id: str) -> dict[str, Any]:
    """Retrieve unified threat intelligence records and relationships for a CVE."""
    cve_upper = cve_id.strip().upper()

    # Query all intel records matching this CVE directly
    records = (
        (
            await db.execute(
                select(IntelRecord).where(
                    (IntelRecord.source_record_id == cve_upper)
                    | (IntelRecord.title.ilike(f"%{cve_upper}%"))
                )
            )
        )
        .scalars()
        .all()
    )

    # Query cross-references via IntelRelationship
    relationships = (
        await db.execute(
            select(IntelRelationship, IntelRecord)
            .join(IntelRecord, IntelRelationship.intel_record_id == IntelRecord.id)
            .where(
                IntelRelationship.target_identifier == cve_upper,
            )
        )
    ).all()

    result: dict[str, Any] = {
        "cve_id": cve_upper,
        "is_known_exploited": False,
        "epss_score": None,
        "epss_percentile": None,
        "cvss_score": None,
        "cvss_vector": None,
        "cwes": [],
        "kev_details": None,
        "exploit_references": [],
        "advisories": [],
        "sources_used": [],
    }

    # Process direct records
    for rec in records:
        if rec.record_type == "kev":
            result["is_known_exploited"] = True
            result["kev_details"] = rec.raw_payload
            result["sources_used"].append("cisa_kev")
        elif rec.record_type == "epss":
            result["epss_score"] = float(rec.epss_score) if rec.epss_score is not None else None
            result["epss_percentile"] = (
                float(rec.epss_percentile) if rec.epss_percentile is not None else None
            )
            result["sources_used"].append("first_epss")
        elif rec.record_type == "cve":
            result["cvss_score"] = float(rec.cvss_score) if rec.cvss_score is not None else None
            result["cvss_vector"] = rec.cvss_vector
            result["sources_used"].append("nvd")

    # Process relationships
    for rel, parent_rec in relationships:
        if rel.relationship_type == "cve_to_cwe":
            if rel.target_identifier not in result["cwes"]:
                result["cwes"].append(rel.target_identifier)
        elif rel.relationship_type == "cve_to_edb":
            edb_entry = {
                "source": "exploit_db",
                "id": parent_rec.source_record_id,
                "title": parent_rec.title,
            }
            if edb_entry not in result["exploit_references"]:
                result["exploit_references"].append(edb_entry)
            result["sources_used"].append("exploit_db")
        elif rel.relationship_type in ("cve_to_ghsa", "cve_to_purl"):
            adv_entry = {
                "source": parent_rec.record_type,
                "id": parent_rec.source_record_id,
                "title": parent_rec.title,
            }
            if adv_entry not in result["advisories"]:
                result["advisories"].append(adv_entry)
            result["sources_used"].append(parent_rec.record_type)

    result["sources_used"] = sorted(list(set(result["sources_used"])))
    return result


def extract_cve_from_finding(finding: Finding) -> str | None:
    """Extract standard CVE identifier from finding metadata, title, rule_id, or CVE column."""
    if finding.cve_id:
        return finding.cve_id.strip().upper()

    for text_candidate in (finding.title, finding.rule_id, finding.description or ""):
        match = CVE_PATTERN.search(text_candidate)
        if match:
            return match.group(1).upper()
    return None


async def enrich_finding_with_intel(
    db: AsyncSession,
    org_id: uuid.UUID,
    finding: Finding,
    snapshot_id: uuid.UUID | None = None,
) -> dict[str, Any] | None:
    """Enrich a single finding with active threat intelligence signals and log immutable event."""
    cve_id = extract_cve_from_finding(finding)
    if not cve_id:
        return None

    intel = await get_cve_threat_intel(db, cve_id)

    # Apply intelligence to finding
    finding.is_known_exploited = intel.get("is_known_exploited", False)
    if intel.get("epss_score") is not None:
        finding.epss_score = intel["epss_score"]
    if intel.get("epss_percentile") is not None:
        finding.epss_percentile = intel["epss_percentile"]
    if finding.cvss_score is None and intel.get("cvss_score") is not None:
        finding.cvss_score = intel["cvss_score"]
    if not finding.cvss_vector and intel.get("cvss_vector"):
        finding.cvss_vector = intel["cvss_vector"]
    if not finding.cve_id:
        finding.cve_id = cve_id

    # Append immutable enrichment event for deterministic audit replay
    event = IntelEnrichmentEvent(
        id=uuid.uuid4(),
        organization_id=org_id,
        project_id=finding.project_id,
        finding_id=finding.id,
        intel_snapshot_id=snapshot_id,
        enrichment_data=intel,
        created_at=datetime.now(UTC),
    )
    db.add(event)
    return intel


async def batch_enrich_org_findings(
    db: AsyncSession,
    org_id: uuid.UUID,
    project_id: uuid.UUID | None = None,
) -> int:
    """Batch enrich all active findings in the organization with threat intelligence."""
    stmt = select(Finding).where(
        Finding.organization_id == org_id,
        Finding.status.in_(["open", "in_progress", "in_remediation"]),
    )
    if project_id:
        stmt = stmt.where(Finding.project_id == project_id)

    findings = (await db.execute(stmt)).scalars().all()
    enriched_count = 0

    for f in findings:
        intel = await enrich_finding_with_intel(db, org_id, f)
        if intel:
            enriched_count += 1

    await db.flush()
    return enriched_count


async def get_org_threat_intel_summary(db: AsyncSession, org_id: uuid.UUID) -> dict[str, Any]:
    """Calculate aggregated threat intelligence metrics across organization findings."""
    total_findings = (
        await db.execute(select(func.count(Finding.id)).where(Finding.organization_id == org_id))
    ).scalar_one() or 0

    kev_findings = (
        await db.execute(
            select(func.count(Finding.id)).where(
                Finding.organization_id == org_id,
                Finding.is_known_exploited.is_(True),
            )
        )
    ).scalar_one() or 0

    high_epss_findings = (
        await db.execute(
            select(func.count(Finding.id)).where(
                Finding.organization_id == org_id,
                Finding.epss_score >= 0.1,
            )
        )
    ).scalar_one() or 0

    # Query registered sources and their freshness status
    sources = (
        (await db.execute(select(IntelligenceSource).order_by(IntelligenceSource.name)))
        .scalars()
        .all()
    )

    source_summaries = []
    for s in sources:
        last_run = (
            await db.execute(
                select(IntelSyncRun)
                .where(IntelSyncRun.source_id == s.id)
                .order_by(desc(IntelSyncRun.started_at))
                .limit(1)
            )
        ).scalar_one_or_none()

        latest_snapshot = (
            await db.execute(
                select(IntelSnapshot)
                .where(IntelSnapshot.source_id == s.id)
                .order_by(desc(IntelSnapshot.created_at))
                .limit(1)
            )
        ).scalar_one_or_none()

        source_summaries.append(
            {
                "id": str(s.id),
                "slug": s.slug,
                "name": s.name,
                "source_type": s.source_type,
                "is_active": s.is_active,
                "is_gated": s.is_gated,
                "requires_scope_auth": s.requires_scope_auth,
                "allow_binary_upload": s.allow_binary_upload,
                "last_sync_status": last_run.status if last_run else "never_run",
                "last_sync_at": last_run.started_at.isoformat() if last_run else None,
                "records_persisted": last_run.records_persisted if last_run else 0,
                "is_stale": latest_snapshot.is_stale if latest_snapshot else False,
                "stale_reason": latest_snapshot.stale_reason if latest_snapshot else None,
            }
        )

    return {
        "organization_id": str(org_id),
        "total_findings": total_findings,
        "kev_findings_count": kev_findings,
        "high_epss_findings_count": high_epss_findings,
        "sources": source_summaries,
    }
