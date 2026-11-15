"""Phase 5/6 canonical finding normalization, SBOM/DB provenance, persistence, and queries."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from vforge_scanners import (
    CheckovAdapter,
    GitleaksAdapter,
    GrypeAdapter,
    NmapAdapter,
    NormalizedFinding,
    NucleiAdapter,
    OpenGrepAdapter,
    SyftAdapter,
    TestsslAdapter,
    ZAPAdapter,
    extract_grype_db_provenance,
    redact_text_secrets,
    scrub_finding_dict,
)
from sqlalchemy import case, func, literal, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.auth.rbac import Permission, assert_permission
from vforge.config import Settings, get_settings
from vforge.errors import NotFoundError, ValidationError
from vforge.models.enums import (
    ArtifactType,
    CoverageStatus,
    FindingCategory,
    FindingEventType,
    FindingSeverity,
    FindingStatus,
    FindingValidationStatus,
    RetestStatus,
    RiskExceptionStatus,
    Role,
)
from vforge.models.orchestration import RunnerJob, ScanRun
from vforge.models.runner import Artifact, ToolExecution
from vforge.models.scanner import (
    Finding,
    FindingEvent,
    FindingOccurrence,
    RiskException,
    SbomDocument,
    VulnerabilityDbSnapshot,
)
from vforge.schemas import FindingUpdate, RiskExceptionCreate, RiskExceptionReview
from vforge.security.envelope import decrypt_artifact_with_keyring, resolve_keyring

_ADAPTER_TOOL_IDS = frozenset(
    {"opengrep", "gitleaks", "grype", "checkov", "zap", "nuclei", "nmap", "testssl"}
)
_MAX_SUMMARY_COMPONENTS = 500

DEFAULT_SLA_DAYS: dict[str, int] = {
    "critical": 7,
    "high": 14,
    "medium": 30,
    "low": 60,
    "info": 90,
    "unknown": 90,
}


def _decrypt_artifact_bytes(artifact: Artifact, *, cfg: Settings) -> bytes | None:
    """Resolve and decrypt an artifact blob inside the configured artifact root."""
    root = Path(cfg.artifact_root).resolve()
    blob_path = (root / artifact.storage_key).resolve()
    if not blob_path.is_relative_to(root) or not blob_path.exists():
        return None
    keyring = resolve_keyring(cfg)
    return decrypt_artifact_with_keyring(
        ciphertext=blob_path.read_bytes(),
        expected_plaintext_sha256=artifact.sha256,
        expected_ciphertext_sha256=artifact.ciphertext_sha256,
        encryption_key_id=artifact.encryption_key_id or keyring.active_kek_id,
        keyring=keyring.keys,
        wrapped_dek_b64=artifact.wrapped_dek_b64,
        nonce_b64=artifact.nonce_b64,
        aad_b64=artifact.aad_b64,
    )


def _load_execution_raw_artifact_bytes(
    artifacts: list[Artifact],
    *,
    expected_filename_hint: str,
    cfg: Settings,
) -> tuple[Artifact, bytes] | None:
    """Select the primary raw_output artifact matching filename hint and decrypt it."""
    candidates = [
        art
        for art in artifacts
        if art.artifact_type == ArtifactType.RAW_OUTPUT.value
        and not art.storage_key.endswith(".sarif")
        and "cyclonedx" not in (art.content_type or "").lower()
        and "spdx" not in (art.content_type or "").lower()
    ]
    if not candidates:
        return None
    hint = expected_filename_hint.lower()
    chosen = next(
        (a for a in candidates if hint in a.storage_key.lower()),
        candidates[0],
    )
    raw_bytes = _decrypt_artifact_bytes(chosen, cfg=cfg)
    if raw_bytes is None:
        return None
    return chosen, raw_bytes


def _load_execution_raw_json(
    artifacts: list[Artifact],
    *,
    expected_filename_hint: str,
    cfg: Settings,
) -> tuple[Artifact, Any] | None:
    """Select the primary JSON raw_output artifact for a scanner execution and decrypt it."""
    loaded = _load_execution_raw_artifact_bytes(
        artifacts,
        expected_filename_hint=expected_filename_hint,
        cfg=cfg,
    )
    if loaded is None:
        return None
    chosen, raw_bytes = loaded
    return chosen, json.loads(raw_bytes.decode("utf-8"))


async def _load_execution_artifacts(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    run_id: uuid.UUID,
    execution_id: uuid.UUID,
) -> list[Artifact]:
    return list(
        (
            await db.execute(
                select(Artifact)
                .where(
                    Artifact.organization_id == org_id,
                    Artifact.scan_run_id == run_id,
                    Artifact.execution_id == execution_id,
                )
                .order_by(Artifact.created_at.asc())
            )
        )
        .scalars()
        .all()
    )


def _summarize_spdx_document(
    payload: dict[str, Any],
) -> tuple[str, str | None, int, list[dict[str, Any]]]:
    if not isinstance(payload, dict) or not payload.get("spdxVersion"):
        raise ValidationError("Invalid SPDX JSON artifact produced by Syft")
    spec_version = str(payload.get("spdxVersion") or "SPDX-2.3")[:40]
    serial_number = str(payload.get("documentNamespace") or "").strip()[:120] or None
    packages = payload.get("packages") or []
    if not isinstance(packages, list):
        packages = []
    summaries: list[dict[str, Any]] = []
    for pkg in packages[:_MAX_SUMMARY_COMPONENTS]:
        if not isinstance(pkg, dict):
            continue
        name = str(pkg.get("name") or "").strip()
        if not name:
            continue
        purl: str | None = None
        for ref in pkg.get("externalRefs") or []:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                purl = str(ref.get("referenceLocator") or "").strip() or None
                if purl:
                    break
        summaries.append(
            {
                "name": name,
                "version": str(pkg.get("versionInfo") or "unknown").strip(),
                "purl": purl,
                "type": "library",
            }
        )
    return spec_version, serial_number, len(packages), summaries


async def persist_syft_sbom_documents(
    db: AsyncSession,
    *,
    run: ScanRun,
    job: RunnerJob,
    execution: ToolExecution,
    settings: Settings | None = None,
) -> list[SbomDocument]:
    """Validate and persist CycloneDX/SPDX SBOM metadata rows referencing encrypted artifacts."""
    if job.tool_id != "syft":
        return []
    if run.source_snapshot_id is None:
        raise ValidationError("SBOM persistence requires ScanRun.source_snapshot_id")
    cfg = settings or get_settings()
    artifacts = await _load_execution_artifacts(
        db,
        org_id=run.organization_id,
        run_id=run.id,
        execution_id=execution.id,
    )
    adapter = SyftAdapter(pinned_image=job.image_digest)
    fmt_map = {
        "application/vnd.cyclonedx+json": "cyclonedx-json",
        "application/spdx+json": "spdx-json",
    }
    for art in artifacts:
        sbom_fmt = fmt_map.get((art.content_type or "").lower())
        if sbom_fmt is None:
            continue
        raw_bytes = _decrypt_artifact_bytes(art, cfg=cfg)
        if raw_bytes is None:
            raise ValueError(f"Failed to decrypt SBOM artifact '{art.id}'")
        payload = json.loads(raw_bytes.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"SBOM artifact '{art.id}' root JSON must be an object")
        if sbom_fmt == "cyclonedx-json":
            summary = adapter.parse_cyclonedx(payload)
            spec_version = summary.spec_version[:40]
            serial_number = summary.serial_number[:120] if summary.serial_number else None
            component_count = summary.component_count
            components_summary = [
                {
                    "name": c.name,
                    "version": c.version,
                    "purl": c.purl,
                    "type": c.component_type,
                    "ecosystem": c.ecosystem,
                    "locations": list(c.locations),
                }
                for c in summary.components[:_MAX_SUMMARY_COMPONENTS]
            ]
        else:
            spec_version, serial_number, component_count, components_summary = (
                _summarize_spdx_document(payload)
            )

        stmt = (
            pg_insert(SbomDocument)
            .values(
                id=uuid.uuid4(),
                organization_id=run.organization_id,
                project_id=run.project_id,
                scan_run_id=run.id,
                source_snapshot_id=run.source_snapshot_id,
                execution_id=execution.id,
                artifact_id=art.id,
                sbom_format=sbom_fmt,
                spec_version=spec_version,
                serial_number=serial_number,
                bom_sha256=art.sha256,
                tool_id="syft",
                tool_version=job.tool_version,
                image_digest=job.image_digest,
                cataloger_config=scrub_finding_dict({"stage": "sbom"}),
                component_count=component_count,
                components_summary=components_summary,
            )
            .on_conflict_do_nothing(constraint="uq_sbom_documents_org_exec_fmt")
        )
        await db.execute(stmt)

    await db.flush()
    rows = (
        (
            await db.execute(
                select(SbomDocument)
                .where(
                    SbomDocument.organization_id == run.organization_id,
                    SbomDocument.execution_id == execution.id,
                )
                .order_by(SbomDocument.sbom_format.asc())
            )
        )
        .scalars()
        .all()
    )
    sbom_docs = list(rows)
    if not any(doc.sbom_format == "cyclonedx-json" for doc in sbom_docs):
        raise ValueError("Syft execution completed without a valid CycloneDX SBOM document")
    return sbom_docs


async def _upsert_grype_db_snapshot(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    parsed_json: dict[str, Any],
) -> uuid.UUID:
    prov = extract_grype_db_provenance(parsed_json)
    built_dt = datetime.fromisoformat(prov.built_at.replace("Z", "+00:00"))
    stmt = (
        pg_insert(VulnerabilityDbSnapshot)
        .values(
            id=uuid.uuid4(),
            organization_id=org_id,
            tool_id="grype",
            schema_version=prov.schema_version,
            built_at=built_dt,
            source_url=prov.source_url,
            db_archive_sha256=prov.db_archive_sha256,
            valid=prov.valid,
            providers_metadata=scrub_finding_dict(prov.providers),
        )
        .on_conflict_do_nothing(constraint="uq_vuln_db_snapshots_org_tool_ver_hash")
    )
    await db.execute(stmt)
    snapshot_id = (
        await db.execute(
            select(VulnerabilityDbSnapshot.id).where(
                VulnerabilityDbSnapshot.organization_id == org_id,
                VulnerabilityDbSnapshot.tool_id == "grype",
                VulnerabilityDbSnapshot.schema_version == prov.schema_version,
                VulnerabilityDbSnapshot.db_archive_sha256 == prov.db_archive_sha256,
            )
        )
    ).scalar_one()
    return snapshot_id


async def normalize_and_persist_execution_findings(
    db: AsyncSession,
    *,
    run: ScanRun,
    job: RunnerJob,
    execution: ToolExecution,
    now: datetime,
    settings: Settings | None = None,
) -> int:
    """Normalize completed scanner artifacts and persist redacted findings with provenance."""
    if job.tool_id not in _ADAPTER_TOOL_IDS:
        return 0
    cfg = settings or get_settings()
    artifacts = await _load_execution_artifacts(
        db,
        org_id=run.organization_id,
        run_id=run.id,
        execution_id=execution.id,
    )

    sbom_doc_id: uuid.UUID | None = None
    vuln_db_snapshot_id: uuid.UUID | None = None
    normalized: list[NormalizedFinding]
    evidence_artifact: Artifact

    if job.tool_id in {"nuclei", "nmap"}:
        hint = "nuclei.jsonl" if job.tool_id == "nuclei" else "nmap.xml"
        loaded_bytes = _load_execution_raw_artifact_bytes(
            artifacts,
            expected_filename_hint=hint,
            cfg=cfg,
        )
        if loaded_bytes is None:
            raise ValueError(
                f"Missing or unreadable primary artifact '{hint}' for tool '{job.tool_id}'"
            )
        evidence_artifact, raw_bytes = loaded_bytes
        text_payload = raw_bytes.decode("utf-8")
        if job.tool_id == "nuclei":
            normalized = NucleiAdapter(pinned_image=job.image_digest).parse_jsonl_text(text_payload)
        else:
            normalized = NmapAdapter(pinned_image=job.image_digest).parse_xml_text(text_payload)
    else:
        hint = "zap-report.json" if job.tool_id == "zap" else f"{job.tool_id}.json"
        loaded = _load_execution_raw_json(
            artifacts,
            expected_filename_hint=hint,
            cfg=cfg,
        )
        if loaded is None:
            raise ValueError(
                f"Missing or unreadable primary JSON artifact for tool '{job.tool_id}'"
            )
        evidence_artifact, parsed_json = loaded

        if job.tool_id == "opengrep" and isinstance(parsed_json, dict):
            normalized = OpenGrepAdapter(pinned_image=job.image_digest).parse_json_report(
                parsed_json
            )
        elif job.tool_id == "gitleaks" and isinstance(parsed_json, list):
            normalized = GitleaksAdapter(pinned_image=job.image_digest).parse_json_findings(
                parsed_json
            )
        elif job.tool_id == "grype" and isinstance(parsed_json, dict):
            vuln_db_snapshot_id = await _upsert_grype_db_snapshot(
                db,
                org_id=run.organization_id,
                parsed_json=parsed_json,
            )
            sbom_doc_id = (
                await db.execute(
                    select(SbomDocument.id)
                    .where(
                        SbomDocument.organization_id == run.organization_id,
                        SbomDocument.scan_run_id == run.id,
                        SbomDocument.sbom_format == "cyclonedx-json",
                    )
                    .order_by(SbomDocument.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if sbom_doc_id is None:
                raise ValueError("Grype completion requires an upstream CycloneDX SBOM document")
            normalized = GrypeAdapter(pinned_image=job.image_digest).parse_json_report(parsed_json)
        elif job.tool_id == "checkov" and isinstance(parsed_json, (dict, list)):
            normalized = CheckovAdapter(pinned_image=job.image_digest).parse_json_report(
                parsed_json
            )
        elif job.tool_id == "zap" and isinstance(parsed_json, dict):
            normalized = ZAPAdapter(pinned_image=job.image_digest).parse_json_report(parsed_json)
        elif job.tool_id == "testssl" and isinstance(parsed_json, (dict, list)):
            normalized = TestsslAdapter(pinned_image=job.image_digest).parse_json_report(
                parsed_json
            )
        else:
            raise ValueError(f"Unsupported raw payload shape for tool '{job.tool_id}'")

    persisted_count = 0
    for item in sorted(normalized, key=lambda entry: entry.fingerprint):
        safe_title = redact_text_secrets(item.title) or item.rule_id
        safe_desc = redact_text_secrets(item.description)
        safe_snippet = redact_text_secrets(item.code_snippet_redacted)
        safe_meta = scrub_finding_dict(item.raw_metadata)

        sla_days = DEFAULT_SLA_DAYS.get(item.severity.lower(), 90)
        sla_due_at = now + timedelta(days=sla_days)
        priority = (
            item.severity.lower()
            if item.severity.lower() in DEFAULT_SLA_DAYS and item.severity.lower() != "unknown"
            else "medium"
        )

        existing_status = (
            await db.execute(
                select(Finding.status).where(
                    Finding.organization_id == run.organization_id,
                    Finding.project_id == run.project_id,
                    Finding.fingerprint == item.fingerprint,
                )
            )
        ).scalar_one_or_none()

        # Atomic PostgreSQL upsert ordered by fingerprint prevents unique-constraint
        # races and lost occurrence increments when concurrent runs finish together.
        upsert_stmt = (
            pg_insert(Finding)
            .values(
                id=uuid.uuid4(),
                organization_id=run.organization_id,
                project_id=run.project_id,
                fingerprint=item.fingerprint,
                category=item.category,
                scanner_tool_id=item.scanner_tool_id,
                scanner_version=item.scanner_version,
                rule_id=item.rule_id,
                title=safe_title,
                description=safe_desc,
                severity=item.severity,
                confidence=item.confidence,
                validation_status="unverified",
                status="open",
                cwe_ids=list(item.cwe_ids),
                file_path=item.file_path,
                start_line=item.start_line,
                end_line=item.end_line,
                code_snippet_redacted=safe_snippet,
                secret_redacted=item.secret_redacted,
                remediation=item.remediation,
                purl=item.purl,
                package_name=item.package_name,
                package_version=item.package_version,
                fixed_version=item.fixed_version,
                cve_id=item.cve_id,
                iac_resource=item.iac_resource,
                sbom_document_id=sbom_doc_id,
                vulnerability_db_snapshot_id=vuln_db_snapshot_id,
                sla_due_at=sla_due_at,
                sla_breached=False,
                business_priority=priority,
                occurrence_count=1,
                first_seen_at=now,
                last_seen_at=now,
            )
            .on_conflict_do_update(
                constraint="uq_findings_org_proj_fp",
                set_={
                    "last_seen_at": now,
                    "occurrence_count": Finding.occurrence_count + 1,
                    "scanner_version": item.scanner_version,
                    "secret_redacted": or_(Finding.secret_redacted, literal(item.secret_redacted)),
                    "fixed_version": func.coalesce(
                        literal(item.fixed_version), Finding.fixed_version
                    ),
                    "cve_id": func.coalesce(literal(item.cve_id), Finding.cve_id),
                    "iac_resource": func.coalesce(literal(item.iac_resource), Finding.iac_resource),
                    "sbom_document_id": func.coalesce(
                        literal(sbom_doc_id), Finding.sbom_document_id
                    ),
                    "vulnerability_db_snapshot_id": func.coalesce(
                        literal(vuln_db_snapshot_id), Finding.vulnerability_db_snapshot_id
                    ),
                    "status": case(
                        (Finding.status == "resolved", "open"),
                        else_=Finding.status,
                    ),
                    "validation_status": case(
                        (Finding.status == "resolved", "reopened"),
                        else_=Finding.validation_status,
                    ),
                    "retest_status": case(
                        (Finding.status == "resolved", "retest_failed"),
                        else_=Finding.retest_status,
                    ),
                },
            )
            .returning(Finding.id)
        )
        finding_id = (await db.execute(upsert_stmt)).scalar_one()

        if existing_status == FindingStatus.RESOLVED.value:
            db.add(
                FindingEvent(
                    id=uuid.uuid4(),
                    organization_id=run.organization_id,
                    finding_id=finding_id,
                    actor_id=None,
                    event_type=FindingEventType.RETEST_FAILED.value,
                    previous_status=FindingStatus.RESOLVED.value,
                    new_status=FindingStatus.OPEN.value,
                    comment=(
                        f"Finding re-observed in rescan by {item.scanner_tool_id} "
                        f"(rule: {item.rule_id}); retest failed and finding automatically reopened."
                    ),
                    metadata_payload={
                        "scan_run_id": str(run.id),
                        "tool_id": item.scanner_tool_id,
                        "rule_id": item.rule_id,
                    },
                    created_at=now,
                )
            )

        db.add(
            FindingOccurrence(
                id=uuid.uuid4(),
                organization_id=run.organization_id,
                finding_id=finding_id,
                scan_run_id=run.id,
                execution_id=execution.id,
                evidence_artifact_id=evidence_artifact.id,
                scanner_tool_id=item.scanner_tool_id,
                scanner_version=item.scanner_version,
                image_digest=job.image_digest,
                rule_id=item.rule_id,
                file_path=item.file_path,
                start_line=item.start_line,
                end_line=item.end_line,
                severity=item.severity,
                confidence=item.confidence,
                secret_redacted=item.secret_redacted,
                snippet_redacted=safe_snippet,
                purl=item.purl,
                package_name=item.package_name,
                package_version=item.package_version,
                fixed_version=item.fixed_version,
                cve_id=item.cve_id,
                iac_resource=item.iac_resource,
                sbom_document_id=sbom_doc_id,
                vulnerability_db_snapshot_id=vuln_db_snapshot_id,
                raw_finding_sanitized=safe_meta,
                observed_at=now,
            )
        )
        persisted_count += 1

    await db.flush()
    return persisted_count


def resolve_scan_run_coverage_status(
    *,
    coverage_summary: dict[str, Any] | None,
    has_errors: bool,
) -> str:
    """Map honest source language coverage + execution outcome onto ScanRun.coverage_status."""
    if has_errors:
        return CoverageStatus.PARTIAL.value
    assessment = str((coverage_summary or {}).get("assessment_coverage_status") or "").lower()
    if assessment == "complete":
        return CoverageStatus.COMPLETE.value
    if assessment == "partial":
        return CoverageStatus.PARTIAL.value
    if assessment == "not_applicable":
        return CoverageStatus.NOT_APPLICABLE.value
    if not coverage_summary:
        return CoverageStatus.NOT_APPLICABLE.value
    return CoverageStatus.PARTIAL.value


async def list_findings(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    project_id: uuid.UUID | None = None,
    scan_run_id: uuid.UUID | None = None,
    category: FindingCategory | None = None,
    severity: FindingSeverity | None = None,
    status: FindingStatus | None = None,
    purl: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Finding], int]:
    """List tenant-scoped canonical findings with optional filters."""
    assert_permission(actor_role, Permission.FINDING_READ)
    filters: list[Any] = [Finding.organization_id == org_id]
    if project_id is not None:
        filters.append(Finding.project_id == project_id)
    if category is not None:
        filters.append(Finding.category == category.value)
    if severity is not None:
        filters.append(Finding.severity == severity.value)
    if status is not None:
        filters.append(Finding.status == status.value)
    if purl is not None and purl.strip():
        filters.append(Finding.purl == purl.strip())
    if scan_run_id is not None:
        subq = select(FindingOccurrence.finding_id).where(
            FindingOccurrence.organization_id == org_id,
            FindingOccurrence.scan_run_id == scan_run_id,
        )
        filters.append(Finding.id.in_(subq))

    total = int((await db.execute(select(func.count(Finding.id)).where(*filters))).scalar_one())
    rows = (
        (
            await db.execute(
                select(Finding)
                .where(*filters)
                .order_by(Finding.last_seen_at.desc(), Finding.id.asc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


async def get_finding_with_occurrences(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
    actor_role: Role,
) -> tuple[Finding, list[FindingOccurrence]]:
    """Retrieve a finding and its immutable execution occurrences."""
    assert_permission(actor_role, Permission.FINDING_READ)
    finding = (
        await db.execute(
            select(Finding).where(Finding.id == finding_id, Finding.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding not found")

    occ_rows = (
        (
            await db.execute(
                select(FindingOccurrence)
                .where(
                    FindingOccurrence.organization_id == org_id,
                    FindingOccurrence.finding_id == finding.id,
                )
                .order_by(FindingOccurrence.observed_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return finding, list(occ_rows)


async def list_sboms(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    project_id: uuid.UUID | None = None,
    scan_run_id: uuid.UUID | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[SbomDocument], int]:
    """List tenant-scoped immutable SBOM documents."""
    assert_permission(actor_role, Permission.SBOM_READ)
    filters: list[Any] = [SbomDocument.organization_id == org_id]
    if project_id is not None:
        filters.append(SbomDocument.project_id == project_id)
    if scan_run_id is not None:
        filters.append(SbomDocument.scan_run_id == scan_run_id)
    total = int(
        (await db.execute(select(func.count(SbomDocument.id)).where(*filters))).scalar_one()
    )
    rows = (
        (
            await db.execute(
                select(SbomDocument)
                .where(*filters)
                .order_by(SbomDocument.created_at.desc(), SbomDocument.id.asc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


async def get_sbom(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    sbom_id: uuid.UUID,
    actor_role: Role,
) -> SbomDocument:
    """Fetch a single tenant-scoped SBOM document with bounded component inventory."""
    assert_permission(actor_role, Permission.SBOM_READ)
    sbom = (
        await db.execute(
            select(SbomDocument).where(
                SbomDocument.id == sbom_id,
                SbomDocument.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if sbom is None:
        raise NotFoundError("SBOM document not found")
    return sbom


async def list_vulnerability_db_snapshots(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[VulnerabilityDbSnapshot], int]:
    """List offline vulnerability DB snapshots recorded across SCA scans."""
    assert_permission(actor_role, Permission.VULN_DB_READ)
    filters: list[Any] = [VulnerabilityDbSnapshot.organization_id == org_id]
    total = int(
        (
            await db.execute(select(func.count(VulnerabilityDbSnapshot.id)).where(*filters))
        ).scalar_one()
    )
    rows = (
        (
            await db.execute(
                select(VulnerabilityDbSnapshot)
                .where(*filters)
                .order_by(VulnerabilityDbSnapshot.recorded_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


def current_utc() -> datetime:
    return datetime.now(UTC)


async def get_finding_with_details(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
    actor_role: Role,
) -> tuple[Finding, list[FindingOccurrence], list[FindingEvent], RiskException | None]:
    """Retrieve a finding, occurrences, audit events, and any active risk exception."""
    assert_permission(actor_role, Permission.FINDING_READ)
    finding = (
        await db.execute(
            select(Finding).where(Finding.id == finding_id, Finding.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding not found")

    occurrences = list(
        (
            await db.execute(
                select(FindingOccurrence)
                .where(
                    FindingOccurrence.organization_id == org_id,
                    FindingOccurrence.finding_id == finding.id,
                )
                .order_by(FindingOccurrence.observed_at.desc())
            )
        )
        .scalars()
        .all()
    )

    events = list(
        (
            await db.execute(
                select(FindingEvent)
                .where(
                    FindingEvent.organization_id == org_id,
                    FindingEvent.finding_id == finding.id,
                )
                .order_by(FindingEvent.created_at.desc())
            )
        )
        .scalars()
        .all()
    )

    active_exception = (
        await db.execute(
            select(RiskException)
            .where(
                RiskException.organization_id == org_id,
                RiskException.finding_id == finding.id,
                RiskException.status.in_(["pending", "approved"]),
            )
            .order_by(RiskException.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    return finding, occurrences, events, active_exception


async def update_finding(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    payload: FindingUpdate,
) -> tuple[Finding, list[FindingOccurrence], list[FindingEvent], RiskException | None]:
    """Triage and update lifecycle status, assignment, and remediation notes."""
    assert_permission(actor_role, Permission.FINDING_TRIAGE)
    finding = (
        await db.execute(
            select(Finding).where(Finding.id == finding_id, Finding.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding not found")

    prev_status = finding.status
    status_changed = False

    if payload.status is not None and payload.status.value != finding.status:
        finding.status = payload.status.value
        status_changed = True
        if payload.status == FindingStatus.RESOLVED:
            finding.validation_status = FindingValidationStatus.FIXED.value
            finding.retest_status = RetestStatus.PENDING_RETEST.value
        elif payload.status == FindingStatus.OPEN and prev_status == FindingStatus.RESOLVED.value:
            finding.validation_status = FindingValidationStatus.REOPENED.value

    if payload.validation_status is not None:
        finding.validation_status = payload.validation_status.value

    if payload.assigned_to is not None:
        prev_assignee = finding.assigned_to
        finding.assigned_to = payload.assigned_to
        if prev_assignee != payload.assigned_to:
            db.add(
                FindingEvent(
                    id=uuid.uuid4(),
                    organization_id=org_id,
                    finding_id=finding.id,
                    actor_id=actor_id,
                    event_type=FindingEventType.ASSIGNED.value,
                    comment=f"Assigned to user {payload.assigned_to}",
                )
            )

    if payload.remediation_notes is not None:
        finding.remediation_notes = payload.remediation_notes

    if payload.business_priority is not None:
        finding.business_priority = payload.business_priority.value

    if payload.retest_status is not None:
        finding.retest_status = payload.retest_status.value

    finding.updated_at = current_utc()

    if status_changed:
        db.add(
            FindingEvent(
                id=uuid.uuid4(),
                organization_id=org_id,
                finding_id=finding.id,
                actor_id=actor_id,
                event_type=FindingEventType.STATUS_CHANGED.value,
                previous_status=prev_status,
                new_status=finding.status,
                comment=payload.comment,
            )
        )
    elif payload.comment:
        db.add(
            FindingEvent(
                id=uuid.uuid4(),
                organization_id=org_id,
                finding_id=finding.id,
                actor_id=actor_id,
                event_type=FindingEventType.COMMENT_ADDED.value,
                comment=payload.comment,
            )
        )

    await db.flush()
    return await get_finding_with_details(
        db,
        org_id=org_id,
        finding_id=finding.id,
        actor_role=actor_role,
    )


async def list_finding_events(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
    actor_role: Role,
) -> list[FindingEvent]:
    """List audit events for a finding."""
    assert_permission(actor_role, Permission.FINDING_READ)
    return list(
        (
            await db.execute(
                select(FindingEvent)
                .where(
                    FindingEvent.organization_id == org_id,
                    FindingEvent.finding_id == finding_id,
                )
                .order_by(FindingEvent.created_at.desc())
            )
        )
        .scalars()
        .all()
    )


async def request_risk_exception(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
    requested_by: uuid.UUID,
    actor_role: Role,
    payload: RiskExceptionCreate,
) -> RiskException:
    """Request a time-bound risk exception for an unmitigated finding."""
    assert_permission(actor_role, Permission.RISK_EXCEPTION_REQUEST)
    finding = (
        await db.execute(
            select(Finding).where(Finding.id == finding_id, Finding.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding not found")

    now = current_utc()
    if payload.expires_at <= now:
        raise ValidationError("Risk exception expiration must be in the future")

    # Check for existing active or pending exception
    existing = (
        await db.execute(
            select(RiskException).where(
                RiskException.organization_id == org_id,
                RiskException.finding_id == finding.id,
                RiskException.status.in_(["pending", "approved"]),
                RiskException.expires_at > now,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ValidationError("Active or pending risk exception already exists for this finding")

    exc = RiskException(
        id=uuid.uuid4(),
        organization_id=org_id,
        project_id=finding.project_id,
        finding_id=finding.id,
        status=RiskExceptionStatus.PENDING.value,
        requested_by=requested_by,
        reason=payload.reason.strip(),
        mitigating_controls=payload.mitigating_controls.strip(),
        expires_at=payload.expires_at,
        created_at=now,
        updated_at=now,
    )
    db.add(exc)
    db.add(
        FindingEvent(
            id=uuid.uuid4(),
            organization_id=org_id,
            finding_id=finding.id,
            actor_id=requested_by,
            event_type=FindingEventType.RISK_EXCEPTION_REQUESTED.value,
            comment=(
                f"Risk exception requested until {payload.expires_at.isoformat()}: "
                f"{payload.reason[:200]}"
            ),
        )
    )
    await db.flush()
    return exc


async def review_risk_exception(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    exception_id: uuid.UUID,
    reviewer_id: uuid.UUID,
    reviewer_role: Role,
    payload: RiskExceptionReview,
) -> RiskException:
    """Approve or reject a pending risk exception (strictly Security Lead, Admin, or Owner)."""
    assert_permission(reviewer_role, Permission.RISK_EXCEPTION_APPROVE)
    exc = (
        await db.execute(
            select(RiskException).where(
                RiskException.id == exception_id,
                RiskException.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if exc is None:
        raise NotFoundError("Risk exception not found")
    if exc.status != RiskExceptionStatus.PENDING.value:
        raise ValidationError(f"Cannot review risk exception in '{exc.status}' status")
    if exc.requested_by == reviewer_id:
        raise ValidationError(
            "Self-approval forbidden: requester cannot review or approve their own risk exception"
        )

    finding = (
        await db.execute(
            select(Finding).where(Finding.id == exc.finding_id, Finding.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding associated with risk exception not found")

    now = current_utc()
    exc.reviewed_by = reviewer_id
    exc.review_notes = payload.review_notes.strip()
    exc.updated_at = now

    if payload.approved:
        exc.status = RiskExceptionStatus.APPROVED.value
        prev_status = finding.status
        finding.status = FindingStatus.RISK_ACCEPTED.value
        finding.validation_status = FindingValidationStatus.ACCEPTED_RISK.value
        finding.updated_at = now
        db.add(
            FindingEvent(
                id=uuid.uuid4(),
                organization_id=org_id,
                finding_id=finding.id,
                actor_id=reviewer_id,
                event_type=FindingEventType.RISK_EXCEPTION_APPROVED.value,
                previous_status=prev_status,
                new_status=finding.status,
                comment=f"Risk exception approved: {payload.review_notes[:200]}",
            )
        )
    else:
        exc.status = RiskExceptionStatus.REJECTED.value
        db.add(
            FindingEvent(
                id=uuid.uuid4(),
                organization_id=org_id,
                finding_id=finding.id,
                actor_id=reviewer_id,
                event_type=FindingEventType.RISK_EXCEPTION_REJECTED.value,
                comment=f"Risk exception rejected: {payload.review_notes[:200]}",
            )
        )

    await db.flush()
    return exc


async def list_risk_exceptions(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    project_id: uuid.UUID | None = None,
    finding_id: uuid.UUID | None = None,
    status: RiskExceptionStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[RiskException], int]:
    """List tenant-scoped risk exceptions."""
    assert_permission(actor_role, Permission.FINDING_READ)
    filters: list[Any] = [RiskException.organization_id == org_id]
    if project_id is not None:
        filters.append(RiskException.project_id == project_id)
    if finding_id is not None:
        filters.append(RiskException.finding_id == finding_id)
    if status is not None:
        filters.append(RiskException.status == status.value)

    total = int(
        (await db.execute(select(func.count(RiskException.id)).where(*filters))).scalar_one()
    )
    rows = (
        (
            await db.execute(
                select(RiskException)
                .where(*filters)
                .order_by(RiskException.created_at.desc(), RiskException.id.asc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


async def sweep_expired_risk_exceptions(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    now: datetime | None = None,
) -> int:
    """Transition expired approved risk exceptions to expired status and reopen findings."""
    current_time = now or current_utc()
    expired_exceptions = list(
        (
            await db.execute(
                select(RiskException).where(
                    RiskException.organization_id == org_id,
                    RiskException.status == RiskExceptionStatus.APPROVED.value,
                    RiskException.expires_at < current_time,
                )
            )
        )
        .scalars()
        .all()
    )
    count = 0
    for exc in expired_exceptions:
        exc.status = RiskExceptionStatus.EXPIRED.value
        exc.updated_at = current_time
        finding = (
            await db.execute(
                select(Finding).where(
                    Finding.id == exc.finding_id,
                    Finding.organization_id == org_id,
                )
            )
        ).scalar_one_or_none()
        if finding and finding.status == FindingStatus.RISK_ACCEPTED.value:
            finding.status = FindingStatus.OPEN.value
            finding.validation_status = FindingValidationStatus.REOPENED.value
            finding.updated_at = current_time
            db.add(
                FindingEvent(
                    id=uuid.uuid4(),
                    organization_id=org_id,
                    finding_id=finding.id,
                    actor_id=None,
                    event_type=FindingEventType.STATUS_CHANGED.value,
                    previous_status=FindingStatus.RISK_ACCEPTED.value,
                    new_status=FindingStatus.OPEN.value,
                    comment=(
                        f"Risk exception {exc.id} expired; "
                        "finding automatically reopened for remediation."
                    ),
                    metadata_payload={
                        "risk_exception_id": str(exc.id),
                        "expired_at": exc.expires_at.isoformat(),
                    },
                    created_at=current_time,
                )
            )
        count += 1
    if count > 0:
        await db.flush()
    return count


async def check_and_update_sla_breaches(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role | None = None,
) -> int:
    """Evaluate open findings and mark breached SLAs; sweep expired risk exceptions."""
    if actor_role is not None:
        assert_permission(actor_role, Permission.FINDING_TRIAGE)
    now = current_utc()
    await sweep_expired_risk_exceptions(db, org_id=org_id, now=now)
    stmt = (
        update(Finding)
        .where(
            Finding.organization_id == org_id,
            Finding.sla_due_at.is_not(None),
            Finding.sla_due_at < now,
            Finding.sla_breached.is_(False),
            Finding.status.not_in(["resolved", "risk_accepted", "false_positive"]),
        )
        .values(sla_breached=True, updated_at=now)
    )
    res = await db.execute(stmt)
    await db.flush()
    rowcount = getattr(res, "rowcount", 0)
    return int(rowcount or 0)
