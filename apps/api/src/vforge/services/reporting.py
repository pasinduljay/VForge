"""Phase 8 Executive & Technical VAPT reporting service.

Generates HTML, PDF, JSON, and SARIF 2.1.0 reports with explicit coverage provenance,
tool version pinning disclosures, failed stage reporting, and AES-256-GCM artifact encryption.
"""

from __future__ import annotations

import html
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.auth.rbac import Permission, assert_permission
from vforge.config import Settings, get_settings
from vforge.errors import NotFoundError, ValidationError
from vforge.models.domain import Project
from vforge.models.enums import (
    ArtifactType,
    ReportFormat,
    ReportType,
    Role,
)
from vforge.models.orchestration import RunnerJob, ScanRun, ScanStage
from vforge.models.runner import Artifact
from vforge.models.scanner import (
    Finding,
    FindingOccurrence,
    Report,
)
from vforge.security.envelope import (
    decrypt_artifact_with_keyring,
    encrypt_artifact_bytes,
    resolve_kek,
    resolve_keyring,
)


def _current_utc() -> datetime:
    return datetime.now(UTC)


def _write_encrypted_blob(artifact_root: str, storage_key: str, data: bytes) -> None:
    root = Path(artifact_root).resolve()
    target = (root / storage_key).resolve()
    if not target.is_relative_to(root):
        raise ValidationError("Invalid report storage path")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def _read_encrypted_blob(artifact_root: str, storage_key: str) -> bytes:
    root = Path(artifact_root).resolve()
    target = (root / storage_key).resolve()
    if not target.is_relative_to(root) or not target.exists():
        raise NotFoundError("Encrypted report file not found on disk")
    return target.read_bytes()


def _generate_json_report(
    *,
    report_id: uuid.UUID,
    title: str,
    report_type: str,
    project: Project,
    scan_run: ScanRun | None,
    stages: list[ScanStage],
    jobs: list[RunnerJob],
    findings: list[Finding],
    occurrences_by_finding: dict[uuid.UUID, list[FindingOccurrence]],
    summary: dict[str, Any],
) -> bytes:
    payload = {
        "$schema": "https://vforge.internal/schemas/report-v1.json",
        "report_id": str(report_id),
        "title": title,
        "report_type": report_type,
        "generated_at": _current_utc().isoformat(),
        "vforge_version": "0.1.0",
        "project": {
            "id": str(project.id),
            "name": project.name,
            "slug": project.slug,
            "criticality": project.criticality,
        },
        "scan_run": (
            {
                "id": str(scan_run.id),
                "status": scan_run.status,
                "coverage_status": scan_run.coverage_status,
                "error_summary": scan_run.error_summary,
                "created_at": scan_run.created_at.isoformat() if scan_run.created_at else None,
                "completed_at": (
                    scan_run.completed_at.isoformat() if scan_run.completed_at else None
                ),
                "scope_snapshot_id": (
                    str(scan_run.scope_snapshot_id) if scan_run.scope_snapshot_id else None
                ),
            }
            if scan_run
            else None
        ),
        "summary": summary,
        "stages": [
            {
                "id": str(s.id),
                "stage_key": s.stage_key,
                "stage_kind": s.stage_kind,
                "status": s.status,
            }
            for s in stages
        ],
        "tool_inventory": [
            {
                "id": str(j.id),
                "tool_id": j.tool_id,
                "tool_version": j.tool_version,
                "status": j.status,
                "image_digest": j.image_digest,
                "job_type": j.job_type,
            }
            for j in jobs
        ],
        "findings": [
            {
                "id": str(f.id),
                "fingerprint": f.fingerprint,
                "category": f.category,
                "scanner_tool_id": f.scanner_tool_id,
                "scanner_version": f.scanner_version,
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "confidence": f.confidence,
                "validation_status": f.validation_status,
                "status": f.status,
                "business_priority": f.business_priority,
                "sla_due_at": f.sla_due_at.isoformat() if f.sla_due_at else None,
                "sla_breached": f.sla_breached,
                "cwe_ids": f.cwe_ids,
                "file_path": f.file_path,
                "start_line": f.start_line,
                "end_line": f.end_line,
                "purl": f.purl,
                "package_name": f.package_name,
                "package_version": f.package_version,
                "fixed_version": f.fixed_version,
                "cve_id": f.cve_id,
                "iac_resource": f.iac_resource,
                "remediation": f.remediation,
                "occurrence_count": f.occurrence_count,
                "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
                "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
                "occurrences": [
                    {
                        "id": str(occ.id),
                        "scanner_tool_id": occ.scanner_tool_id,
                        "scanner_version": occ.scanner_version,
                        "image_digest": occ.image_digest,
                        "rule_id": occ.rule_id,
                        "file_path": occ.file_path,
                        "start_line": occ.start_line,
                        "end_line": occ.end_line,
                        "severity": occ.severity,
                        "observed_at": occ.observed_at.isoformat() if occ.observed_at else None,
                        "raw_metadata": occ.raw_finding_sanitized,
                    }
                    for occ in occurrences_by_finding.get(f.id, [])
                ],
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def _generate_sarif_report(
    *,
    report_id: uuid.UUID,
    findings: list[Finding],
    occurrences_by_finding: dict[uuid.UUID, list[FindingOccurrence]],
) -> bytes:
    """Generate OASIS SARIF 2.1.0 standard representation."""
    tools_dict: dict[str, dict[str, Any]] = {}

    for f in findings:
        tool_id = f.scanner_tool_id or "generic"
        if tool_id not in tools_dict:
            tools_dict[tool_id] = {
                "name": tool_id,
                "version": f.scanner_version or "unknown",
                "rules": {},
                "results": [],
            }

        rule_id = f.rule_id or "RULE-UNKNOWN"
        if rule_id not in tools_dict[tool_id]["rules"]:
            tools_dict[tool_id]["rules"][rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title[:200]},
                "fullDescription": {"text": f.description or f.title},
                "defaultConfiguration": {
                    "level": (
                        "error"
                        if f.severity in ("critical", "high")
                        else "warning"
                        if f.severity == "medium"
                        else "note"
                    )
                },
            }

        level = (
            "error"
            if f.severity in ("critical", "high")
            else "warning"
            if f.severity == "medium"
            else "note"
        )
        locations: list[dict[str, Any]] = []
        if f.file_path:
            region: dict[str, Any] = {}
            if f.start_line is not None:
                region["startLine"] = f.start_line
            if f.end_line is not None:
                region["endLine"] = f.end_line
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        **({"region": region} if region else {}),
                    }
                }
            )

        tools_dict[tool_id]["results"].append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"{f.title}: {f.description or 'No description provided.'}"},
                "locations": locations,
                "properties": {
                    "vforgeFindingId": str(f.id),
                    "fingerprint": f.fingerprint,
                    "category": f.category,
                    "validationStatus": f.validation_status,
                    "slaBreached": f.sla_breached,
                    "cweIds": f.cwe_ids,
                    "cveId": f.cve_id,
                },
            }
        )

    runs = []
    for tool_info in tools_dict.values():
        runs.append(
            {
                "tool": {
                    "driver": {
                        "name": tool_info["name"],
                        "version": tool_info["version"],
                        "informationUri": "https://vforge.internal",
                        "rules": list(tool_info["rules"].values()),
                    }
                },
                "results": tool_info["results"],
            }
        )

    if not runs:
        runs.append(
            {
                "tool": {
                    "driver": {
                        "name": "vforge",
                        "version": "0.1.0",
                        "rules": [],
                    }
                },
                "results": [],
            }
        )

    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": runs,
    }
    return json.dumps(sarif, indent=2).encode("utf-8")


def _generate_html_report(
    *,
    report_id: uuid.UUID,
    title: str,
    report_type: str,
    project: Project,
    scan_run: ScanRun | None,
    stages: list[ScanStage],
    jobs: list[RunnerJob],
    findings: list[Finding],
    occurrences_by_finding: dict[uuid.UUID, list[FindingOccurrence]],
    summary: dict[str, Any],
) -> str:
    """Generate self-contained, responsive, printable HTML report."""
    safe_title = html.escape(title)
    safe_proj_name = html.escape(project.name)
    now_str = _current_utc().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Severity counters
    sev_counts = summary.get("severity_counts", {})
    crit = sev_counts.get("critical", 0)
    high = sev_counts.get("high", 0)
    med = sev_counts.get("medium", 0)
    low = sev_counts.get("low", 0)
    info = sev_counts.get("info", 0)
    total_f = summary.get("total_findings", len(findings))
    sla_breached = summary.get("sla_breached_count", 0)

    # Failed/skipped stages
    failed_stages = [s for s in stages if s.status in ("failed", "skipped", "cancelled")]
    disclosure_banner = ""
    if failed_stages or (scan_run and scan_run.coverage_status in ("partial", "failed")):
        stage_items = "".join(
            (
                f"<li><strong>Stage:</strong> {html.escape(s.stage_key)} "
                f"({html.escape(s.stage_kind)}) — "
                f"<strong>Status:</strong> {html.escape(s.status)}</li>"
            )
            for s in failed_stages
        )
        disclosure_banner = f"""
        <div class="alert-banner">
            <h3>⚠️ Honesty & Assessment Limitations Disclosure</h3>
            <p>This assessment completed with <strong>partial coverage or stage errors</strong>.
            Zero findings in untested categories does NOT constitute proof of security.</p>
            <ul>{stage_items}</ul>
        </div>
        """

    # Tools table
    tools_rows = (
        "".join(
            f"""<tr>
            <td><code>{html.escape(j.tool_id)}</code></td>
            <td><code>{html.escape(j.image_digest[:24])}...</code></td>
            <td><span class="badge badge-{html.escape(j.status)}">
                {html.escape(j.status)}
            </span></td>
            <td>{html.escape(j.job_type)}</td>
        </tr>"""
            for j in jobs
        )
        or "<tr><td colspan='4'>No tool execution records available.</td></tr>"
    )

    # Findings rows
    findings_rows = []
    for f in findings:
        sev_class = f"sev-{f.severity}"
        cwe_str = ", ".join(f.cwe_ids) if f.cwe_ids else "None"
        loc_str = html.escape(f.file_path or f.purl or f.iac_resource or "N/A")
        if f.start_line is not None:
            loc_str += f":{f.start_line}"

        occs = occurrences_by_finding.get(f.id, [])
        occ_details = "".join(
            (
                f"<li><strong>{html.escape(o.scanner_tool_id)}</strong> "
                f"({html.escape(o.scanner_version)}): "
                f"observed on {o.observed_at.strftime('%Y-%m-%d %H:%M UTC')}</li>"
            )
            for o in occs[:5]
        )

        findings_rows.append(
            f"""
            <div class="finding-card {sev_class}">
                <div class="finding-header">
                    <span class="badge badge-{html.escape(f.severity)}">
                        {html.escape(f.severity.upper())}
                    </span>
                    <span class="finding-title">{html.escape(f.title)}</span>
                    <span class="badge badge-status">{html.escape(f.status)}</span>
                </div>
                <div class="finding-meta">
                    <div><strong>Tool:</strong> <code>{html.escape(f.scanner_tool_id)}</code>
                        (Rule: <code>{html.escape(f.rule_id)}</code>)</div>
                    <div><strong>Location:</strong> <code>{loc_str}</code></div>
                    <div><strong>CWE / CVE:</strong> {html.escape(cwe_str)}
                        {f"/ {html.escape(f.cve_id)}" if f.cve_id else ""}</div>
                    <div><strong>Priority / SLA:</strong> {html.escape(f.business_priority)}
                        {
                ('<span class="badge badge-danger">SLA BREACHED</span>' if f.sla_breached else "")
            }</div>
                </div>
                <div class="finding-body">
                    <p>{html.escape(f.description or "No description provided.")}</p>
                    {
                (
                    '<pre class="code-box"><code>'
                    f"{html.escape(f.code_snippet_redacted)}</code></pre>"
                    if f.code_snippet_redacted
                    else ""
                )
            }
                    {
                (
                    f'<div class="remediation-box"><strong>Remediation:</strong> '
                    f"{html.escape(f.remediation)}</div>"
                    if f.remediation
                    else ""
                )
            }
                </div>
                <div class="occurrences-section">
                    <small>Preserved Occurrences ({len(occs)} total):</small>
                    <ul>{occ_details}</ul>
                </div>
            </div>
            """
        )

    findings_content = (
        "".join(findings_rows) if findings_rows else "<p>No vulnerabilities identified.</p>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_title} — VForge</title>
<style>
    :root {{
        --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI",
            Roboto, Helvetica, Arial, sans-serif;
        --bg-main: #f8fafc;
        --bg-card: #ffffff;
        --text-primary: #0f172a;
        --text-secondary: #475569;
        --border-color: #e2e8f0;
        --sev-critical: #ef4444;
        --sev-high: #f97316;
        --sev-medium: #eab308;
        --sev-low: #3b82f6;
        --sev-info: #64748b;
    }}
    body {{
        font-family: var(--font-sans);
        line-height: 1.5;
        background: var(--bg-main);
        color: var(--text-primary);
        margin: 0;
        padding: 30px;
    }}
    .report-container {{
        max-width: 1100px;
        margin: 0 auto;
        background: var(--bg-card);
        padding: 40px;
        border-radius: 8px;
        box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
    }}
    header {{
        border-bottom: 2px solid var(--border-color);
        padding-bottom: 24px;
        margin-bottom: 30px;
    }}
    h1 {{ margin: 0 0 10px 0; font-size: 28px; }}
    .subtitle {{ color: var(--text-secondary); font-size: 14px; }}
    .stat-cards {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
        gap: 16px;
        margin: 24px 0 32px 0;
    }}
    .stat-card {{
        background: var(--bg-main);
        border: 1px solid var(--border-color);
        padding: 16px;
        border-radius: 6px;
        text-align: center;
    }}
    .stat-card .num {{ font-size: 28px; font-weight: bold; margin-bottom: 4px; }}
    .stat-card .label {{
        font-size: 12px;
        color: var(--text-secondary);
        text-transform: uppercase;
    }}
    .alert-banner {{
        background: #fffbeb;
        border: 1px solid #fef3c7;
        border-left: 6px solid #f59e0b;
        padding: 16px;
        border-radius: 4px;
        margin-bottom: 30px;
    }}
    .alert-banner h3 {{ margin: 0 0 8px 0; color: #b45309; }}
    table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
    th, td {{
        text-align: left;
        padding: 10px 12px;
        border-bottom: 1px solid var(--border-color);
        font-size: 14px;
    }}
    th {{ background: #f1f5f9; }}
    .finding-card {{
        border: 1px solid var(--border-color);
        border-left: 5px solid #cbd5e1;
        padding: 20px;
        border-radius: 6px;
        margin-bottom: 20px;
        background: #fff;
    }}
    .finding-card.sev-critical {{ border-left-color: var(--sev-critical); }}
    .finding-card.sev-high {{ border-left-color: var(--sev-high); }}
    .finding-card.sev-medium {{ border-left-color: var(--sev-medium); }}
    .finding-card.sev-low {{ border-left-color: var(--sev-low); }}
    .finding-card.sev-info {{ border-left-color: var(--sev-info); }}
    .finding-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }}
    .finding-title {{ font-size: 17px; font-weight: 600; flex: 1; }}
    .badge {{
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
    }}
    .badge-critical {{ background: #fee2e2; color: #991b1b; }}
    .badge-high {{ background: #ffedd5; color: #9a3412; }}
    .badge-medium {{ background: #fef9c3; color: #854d0e; }}
    .badge-low {{ background: #dbeafe; color: #1e40af; }}
    .badge-info {{ background: #f1f5f9; color: #475569; }}
    .badge-status {{ background: #f3f4f6; color: #374151; }}
    .badge-danger {{ background: #ef4444; color: #fff; }}
    .finding-meta {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 8px;
        font-size: 13px;
        color: var(--text-secondary);
        margin-bottom: 12px;
        background: #f8fafc;
        padding: 10px;
        border-radius: 4px;
    }}
    .code-box {{
        background: #0f172a;
        color: #f8fafc;
        padding: 12px;
        border-radius: 4px;
        overflow-x: auto;
        font-size: 12px;
    }}
    .remediation-box {{
        background: #f0fdf4;
        border-left: 3px solid #22c55e;
        padding: 10px 14px;
        border-radius: 4px;
        font-size: 13px;
        margin-top: 10px;
    }}
    .occurrences-section {{
        margin-top: 12px;
        font-size: 12px;
        color: var(--text-secondary);
        border-top: 1px dashed var(--border-color);
        padding-top: 8px;
    }}
    @media print {{
        body {{ background: #fff; padding: 0; }}
        .report-container {{ box-shadow: none; padding: 0; max-width: 100%; }}
        .finding-card {{ page-break-inside: avoid; }}
    }}
</style>
</head>
<body>
<div class="report-container">
    <header>
        <h1>{safe_title}</h1>
        <div class="subtitle">
            Project: <strong>{safe_proj_name}</strong> |
            Type: <strong>{html.escape(report_type.upper())}</strong> |
            Generated: {now_str} | VForge v0.1.0
        </div>
    </header>

    {disclosure_banner}

    <section>
        <h2>Executive Summary</h2>
        <div class="stat-cards">
            <div class="stat-card">
                <div class="num">{total_f}</div><div class="label">Total Findings</div>
            </div>
            <div class="stat-card" style="color: var(--sev-critical);">
                <div class="num">{crit}</div><div class="label">Critical</div>
            </div>
            <div class="stat-card" style="color: var(--sev-high);">
                <div class="num">{high}</div><div class="label">High</div>
            </div>
            <div class="stat-card" style="color: var(--sev-medium);">
                <div class="num">{med}</div><div class="label">Medium</div>
            </div>
            <div class="stat-card" style="color: var(--sev-low);">
                <div class="num">{low}</div><div class="label">Low</div>
            </div>
            <div class="stat-card" style="color: var(--sev-info);">
                <div class="num">{info}</div><div class="label">Info</div>
            </div>
            <div class="stat-card" style="color: #ef4444;">
                <div class="num">{sla_breached}</div><div class="label">SLA Breached</div>
            </div>
        </div>
    </section>

    <section>
        <h2>Assessment Engines & Image Locks</h2>
        <table>
            <thead>
                <tr>
                    <th>Tool ID</th>
                    <th>Image Digest Pin</th>
                    <th>Status</th>
                    <th>Risk Class</th>
                </tr>
            </thead>
            <tbody>{tools_rows}</tbody>
        </table>
    </section>

    <section>
        <h2>Detailed Vulnerability Findings ({len(findings)})</h2>
        {findings_content}
    </section>
</div>
</body>
</html>"""


def _pdf_escape(s: str) -> str:
    """Escape text for inclusion inside PDF string literals (...) Tj."""
    return s.replace("\\", "\\\\").replace("(", "[").replace(")", "]")


def _generate_pdf_report(
    *,
    report_id: uuid.UUID,
    title: str,
    project: Project,
    findings: list[Finding],
    summary: dict[str, Any],
) -> bytes:
    """Generate standards-compliant PDF 1.4 document containing the assessment report."""
    safe_title = _pdf_escape(title)
    safe_proj = _pdf_escape(project.name)
    now_str = _current_utc().strftime("%Y-%m-%d %H:%M UTC")

    sev_counts = summary.get("severity_counts", {})
    crit = sev_counts.get("critical", 0)
    high = sev_counts.get("high", 0)
    med = sev_counts.get("medium", 0)
    low = sev_counts.get("low", 0)
    info = sev_counts.get("info", 0)
    total_f = summary.get("total_findings", len(findings))

    # Construct clean PDF 1.4 stream
    content_lines = [
        "BT",
        "/F1 20 Tf",
        "50 750 Td",
        f"({safe_title}) Tj",
        "/F1 10 Tf",
        "0 -24 Td",
        f"(Project: {safe_proj} | Generated: {now_str}) Tj",
        "0 -15 Td",
        "(Platform: VForge Enterprise VAPT) Tj",
        "0 -30 Td",
        "/F1 14 Tf",
        "(Executive Summary) Tj",
        "/F1 10 Tf",
        "0 -20 Td",
        (
            f"(Total Findings: {total_f}  Crit: {crit}  High: {high}  "
            f"Med: {med}  Low: {low}  Info: {info}) Tj"
        ),
        "0 -30 Td",
        "/F1 14 Tf",
        f"(Detailed Findings ({len(findings)})) Tj",
        "/F1 9 Tf",
    ]

    y_pos = -20
    for idx, f in enumerate(findings[:25], start=1):
        clean_title = _pdf_escape(f.title)[:60]
        loc = _pdf_escape(f.file_path or f.purl or f.rule_id or "N/A")[:45]
        content_lines.extend(
            [
                f"0 {y_pos} Td",
                f"({idx}. [{f.severity.upper()}] {clean_title} - Location: {loc}) Tj",
            ]
        )
        y_pos = -16

    if len(findings) > 25:
        content_lines.extend(
            [
                f"0 {y_pos} Td",
                f"(Showing top 25 of {len(findings)} findings. See HTML/JSON report.) Tj",
            ]
        )

    content_lines.extend(["ET"])
    stream_content = "\n".join(content_lines).encode("utf-8")

    objects: list[bytes] = []
    # 1: Catalog
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    # 2: Pages
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    # 3: Page
    objects.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"
    )
    # 4: Contents
    objects.append(
        f"<< /Length {len(stream_content)} >>\nstream\n".encode() + stream_content + b"\nendstream"
    )
    # 5: Font
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    # Build xref
    pdf_header = b"%PDF-1.4\n"
    body = bytearray(pdf_header)
    offsets = [0]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(body))
        body.extend(f"{idx} 0 obj\n".encode() + obj + b"\nendobj\n")

    xref_offset = len(body)
    body.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    body.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        body.extend(f"{off:010d} 00000 n \n".encode())

    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
    )
    body.extend(trailer.encode("utf-8"))
    return bytes(body)


async def generate_report(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    report_type: ReportType,
    format: ReportFormat,
    title: str | None = None,
    scan_run_id: uuid.UUID | None = None,
    settings: Settings | None = None,
) -> Report:
    """Generate, encrypt, and persist a full executive/technical report."""
    assert_permission(actor_role, Permission.REPORT_GENERATE)
    cfg = settings or get_settings()

    project = (
        await db.execute(
            select(Project).where(
                Project.id == project_id,
                Project.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if project is None:
        raise NotFoundError("Project not found")

    scan_run: ScanRun | None = None
    stages: list[ScanStage] = []
    jobs: list[RunnerJob] = []

    if scan_run_id is not None:
        scan_run = (
            await db.execute(
                select(ScanRun).where(
                    ScanRun.id == scan_run_id,
                    ScanRun.organization_id == org_id,
                )
            )
        ).scalar_one_or_none()
        if scan_run is None:
            raise NotFoundError("Scan run not found")

        stages = list(
            (
                await db.execute(
                    select(ScanStage)
                    .where(
                        ScanStage.organization_id == org_id,
                        ScanStage.scan_run_id == scan_run.id,
                    )
                    .order_by(ScanStage.stage_order.asc())
                )
            )
            .scalars()
            .all()
        )
        jobs = list(
            (
                await db.execute(
                    select(RunnerJob)
                    .where(
                        RunnerJob.organization_id == org_id,
                        RunnerJob.scan_run_id == scan_run.id,
                    )
                    .order_by(RunnerJob.created_at.asc())
                )
            )
            .scalars()
            .all()
        )

        # Findings linked to this scan run via occurrences
        subq = select(FindingOccurrence.finding_id).where(
            FindingOccurrence.organization_id == org_id,
            FindingOccurrence.scan_run_id == scan_run_id,
        )
        findings = list(
            (
                await db.execute(
                    select(Finding)
                    .where(Finding.organization_id == org_id, Finding.id.in_(subq))
                    .order_by(Finding.severity.asc(), Finding.title.asc())
                )
            )
            .scalars()
            .all()
        )
    else:
        # Project-level report across all findings
        findings = list(
            (
                await db.execute(
                    select(Finding)
                    .where(Finding.organization_id == org_id, Finding.project_id == project_id)
                    .order_by(Finding.severity.asc(), Finding.title.asc())
                )
            )
            .scalars()
            .all()
        )

    # Load occurrences for findings
    occurrences_by_finding: dict[uuid.UUID, list[FindingOccurrence]] = {}
    if findings:
        finding_ids = [f.id for f in findings]
        all_occs = list(
            (
                await db.execute(
                    select(FindingOccurrence)
                    .where(
                        FindingOccurrence.organization_id == org_id,
                        FindingOccurrence.finding_id.in_(finding_ids),
                    )
                    .order_by(FindingOccurrence.observed_at.desc())
                )
            )
            .scalars()
            .all()
        )
        for occ in all_occs:
            occurrences_by_finding.setdefault(occ.finding_id, []).append(occ)

    # Compute summary
    sev_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    sla_breached_count = 0
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        status_counts[f.status] = status_counts.get(f.status, 0) + 1
        if f.sla_breached:
            sla_breached_count += 1

    summary = {
        "total_findings": len(findings),
        "severity_counts": sev_counts,
        "status_counts": status_counts,
        "sla_breached_count": sla_breached_count,
        "coverage_status": scan_run.coverage_status if scan_run else "not_applicable",
        "failed_stage_count": sum(1 for s in stages if s.status in ("failed", "skipped")),
    }

    report_id = uuid.uuid4()
    report_title = (
        title.strip()
        if title and title.strip()
        else f"{report_type.value.replace('_', ' ').title()} - {project.name}"
    )

    # Render format
    if format == ReportFormat.JSON:
        plaintext_bytes = _generate_json_report(
            report_id=report_id,
            title=report_title,
            report_type=report_type.value,
            project=project,
            scan_run=scan_run,
            stages=stages,
            jobs=jobs,
            findings=findings,
            occurrences_by_finding=occurrences_by_finding,
            summary=summary,
        )
        media_type = "application/json"
        ext = "json"
    elif format == ReportFormat.SARIF:
        plaintext_bytes = _generate_sarif_report(
            report_id=report_id,
            findings=findings,
            occurrences_by_finding=occurrences_by_finding,
        )
        media_type = "application/sarif+json"
        ext = "sarif"
    elif format == ReportFormat.HTML:
        html_text = _generate_html_report(
            report_id=report_id,
            title=report_title,
            report_type=report_type.value,
            project=project,
            scan_run=scan_run,
            stages=stages,
            jobs=jobs,
            findings=findings,
            occurrences_by_finding=occurrences_by_finding,
            summary=summary,
        )
        plaintext_bytes = html_text.encode("utf-8")
        media_type = "text/html"
        ext = "html"
    elif format == ReportFormat.PDF:
        plaintext_bytes = _generate_pdf_report(
            report_id=report_id,
            title=report_title,
            project=project,
            findings=findings,
            summary=summary,
        )
        media_type = "application/pdf"
        ext = "pdf"
    else:
        raise ValidationError(f"Unsupported report format '{format}'")

    # Encrypt artifact bytes
    key_id, kek_bytes = resolve_kek(cfg)
    aad = f"vf:v1|report|{org_id}|{project_id}|{report_id}".encode()
    encrypted_blob = encrypt_artifact_bytes(
        plaintext=plaintext_bytes,
        kek_id=key_id,
        kek_bytes=kek_bytes,
        aad=aad,
    )

    # Write to storage
    storage_key = f"reports/{org_id}/{report_id}.{ext}.enc"
    await anyio.to_thread.run_sync(
        _write_encrypted_blob,
        cfg.artifact_root,
        storage_key,
        encrypted_blob.ciphertext,
    )

    # Insert artifact record
    artifact_id = uuid.uuid4()
    now = _current_utc()
    artifact = Artifact(
        id=artifact_id,
        organization_id=org_id,
        scan_run_id=scan_run.id if scan_run else None,
        execution_id=None,
        artifact_type=ArtifactType.REPORT.value,
        content_type=media_type,
        sha256=encrypted_blob.plaintext_sha256,
        size_bytes=len(plaintext_bytes),
        storage_key=storage_key,
        ciphertext_sha256=encrypted_blob.ciphertext_sha256,
        encryption_algorithm=encrypted_blob.encryption_algorithm,
        encryption_key_id=encrypted_blob.encryption_key_id,
        wrapped_dek_b64=encrypted_blob.wrapped_dek_b64,
        nonce_b64=encrypted_blob.nonce_b64,
        aad_b64=encrypted_blob.aad_b64,
        created_at=now,
    )
    db.add(artifact)

    # Insert report record
    report = Report(
        id=report_id,
        organization_id=org_id,
        project_id=project_id,
        scan_run_id=scan_run.id if scan_run else None,
        report_type=report_type.value,
        format=format.value,
        title=report_title,
        summary=summary,
        artifact_id=artifact_id,
        generated_by=actor_id,
        created_at=now,
    )
    db.add(report)
    await db.flush()
    return report


async def list_reports(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    project_id: uuid.UUID | None = None,
    scan_run_id: uuid.UUID | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Report], int]:
    """List tenant-scoped generated reports."""
    assert_permission(actor_role, Permission.REPORT_READ)
    filters: list[Any] = [Report.organization_id == org_id]
    if project_id is not None:
        filters.append(Report.project_id == project_id)
    if scan_run_id is not None:
        filters.append(Report.scan_run_id == scan_run_id)

    total = int((await db.execute(select(func.count(Report.id)).where(*filters))).scalar_one())
    rows = (
        (
            await db.execute(
                select(Report)
                .where(*filters)
                .order_by(Report.created_at.desc(), Report.id.asc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


async def get_report(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    report_id: uuid.UUID,
    actor_role: Role,
) -> Report:
    """Retrieve report metadata."""
    assert_permission(actor_role, Permission.REPORT_READ)
    report = (
        await db.execute(
            select(Report).where(
                Report.id == report_id,
                Report.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if report is None:
        raise NotFoundError("Report not found")
    return report


async def download_report_bytes(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    report_id: uuid.UUID,
    actor_role: Role,
    settings: Settings | None = None,
) -> tuple[str, str, bytes]:
    """Decrypt and return report bytes, media type, and filename for download."""
    assert_permission(actor_role, Permission.REPORT_READ)
    cfg = settings or get_settings()

    report = await get_report(db, org_id=org_id, report_id=report_id, actor_role=actor_role)
    artifact = (
        await db.execute(
            select(Artifact).where(
                Artifact.id == report.artifact_id,
                Artifact.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if artifact is None:
        raise NotFoundError("Report artifact not found")

    ciphertext = await anyio.to_thread.run_sync(
        _read_encrypted_blob,
        cfg.artifact_root,
        artifact.storage_key,
    )

    keyring = resolve_keyring(cfg)
    decrypted = decrypt_artifact_with_keyring(
        ciphertext=ciphertext,
        expected_plaintext_sha256=artifact.sha256,
        expected_ciphertext_sha256=artifact.ciphertext_sha256,
        encryption_key_id=artifact.encryption_key_id or keyring.active_kek_id,
        keyring=keyring.keys,
        wrapped_dek_b64=artifact.wrapped_dek_b64,
        nonce_b64=artifact.nonce_b64,
        aad_b64=artifact.aad_b64,
    )
    if decrypted is None:
        raise ValidationError("Report artifact decryption integrity verification failed")

    content_type = artifact.content_type or "application/octet-stream"
    ext = report.format
    filename = f"vforge-report-{report.id}.{ext}"
    return filename, content_type, decrypted
