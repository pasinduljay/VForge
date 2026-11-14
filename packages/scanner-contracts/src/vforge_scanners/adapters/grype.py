"""Pinned Grype offline SCA adapter operating strictly on Syft SBOMs + offline DB."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

from vforge_scanners.redaction import redact_text_secrets, scrub_finding_dict
from vforge_scanners.sdk import (
    ExecutionResult,
    ExecutionSpec,
    NormalizedFinding,
    SeverityLevel,
    ToolContext,
    ToolMetadata,
    compute_finding_fingerprint,
    find_artifact_by_name,
    normalize_relative_source_path,
)

DEFAULT_GRYPE_IMAGE = (
    "anchore/grype@sha256:13113eeceab017260370cf540e1d25442c59665fd07d1b09b66d63bb0c282887"
)
_SHA256_RE = re.compile(r"sha256:([0-9a-f]{64})", re.IGNORECASE)

_GRYPE_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "negligible": "info",
    "unknown": "unknown",
}


@dataclass(frozen=True, slots=True)
class GrypeDbProvenance:
    """Recorded offline vulnerability database identity captured with a Grype scan."""

    schema_version: str
    built_at: str
    source_url: str | None
    db_archive_sha256: str
    valid: bool
    providers: dict[str, Any] = field(default_factory=dict)


def extract_grype_db_provenance(report: dict[str, Any]) -> GrypeDbProvenance:
    """Validate and extract DB snapshot provenance from Grype JSON descriptor metadata."""
    descriptor = report.get("descriptor") if isinstance(report, dict) else None
    db_block = descriptor.get("db") if isinstance(descriptor, dict) else None
    status_block = db_block.get("status") if isinstance(db_block, dict) else None
    if not isinstance(status_block, dict):
        raise ValueError("Grype JSON report is missing descriptor.db.status provenance metadata")

    valid = status_block.get("valid") is True
    schema_version = str(status_block.get("schemaVersion") or "").strip()
    built_at = str(status_block.get("built") or "").strip()
    raw_from = str(status_block.get("from") or "").strip()
    if not valid or not schema_version or not built_at:
        raise ValueError("Grype offline vulnerability database status is invalid or incomplete")

    sha256_hex = ""
    sanitized_url: str | None = None
    if raw_from:
        parsed_url = urlparse(raw_from)
        checksum_vals = parse_qs(parsed_url.query).get("checksum", [])
        for candidate in checksum_vals:
            m = _SHA256_RE.search(candidate)
            if m:
                sha256_hex = m.group(1).lower()
                break
        if not sha256_hex:
            m = _SHA256_RE.search(raw_from)
            if m:
                sha256_hex = m.group(1).lower()
        sanitized_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

    if not sha256_hex:
        raise ValueError(
            "Grype offline vulnerability database provenance is missing a valid SHA-256 digest"
        )

    providers_raw = db_block.get("providers") if isinstance(db_block, dict) else {}
    providers = dict(providers_raw) if isinstance(providers_raw, dict) else {}
    return GrypeDbProvenance(
        schema_version=schema_version,
        built_at=built_at,
        source_url=sanitized_url,
        db_archive_sha256=sha256_hex,
        valid=True,
        providers=providers,
    )


def _extract_cve_id(vuln: dict[str, Any], match: dict[str, Any]) -> str | None:
    vuln_id = str(vuln.get("id") or "").strip()
    if vuln_id.upper().startswith("CVE-"):
        return vuln_id.upper()
    related = match.get("relatedVulnerabilities")
    if isinstance(related, list):
        for rel in related:
            if isinstance(rel, dict):
                rel_id = str(rel.get("id") or "").strip().upper()
                if rel_id.startswith("CVE-"):
                    return rel_id
    return vuln_id or None


def _extract_cwe_ids(vuln: dict[str, Any]) -> tuple[str, ...]:
    extracted: list[str] = []
    for raw_cwe in vuln.get("cwes") or []:
        if isinstance(raw_cwe, dict):
            code = str(raw_cwe.get("cwe") or "").strip().upper()
        else:
            code = str(raw_cwe).strip().upper()
        if code.startswith("CWE-") and code not in extracted:
            extracted.append(code)
    return tuple(extracted)


def _extract_fixed_version(vuln: dict[str, Any]) -> str | None:
    fix = vuln.get("fix")
    if not isinstance(fix, dict):
        return None
    if str(fix.get("state") or "").lower() != "fixed":
        return None
    versions = fix.get("versions")
    if isinstance(versions, list) and versions:
        cleaned = [str(v).strip() for v in versions if str(v).strip()]
        if cleaned:
            return ", ".join(cleaned[:3])
    return None


class GrypeAdapter:
    """ScannerAdapter contract for pinned offline Grype SCA against recorded Syft SBOMs."""

    def __init__(
        self,
        *,
        pinned_image: str = DEFAULT_GRYPE_IMAGE,
        db_cache_dir: str = "/work/db",
    ) -> None:
        self._pinned_image = pinned_image
        self._db_cache_dir = db_cache_dir

    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            tool_id="grype",
            tool_version="0.121.3",
            adapter_version="0.1.0",
            capabilities=("sca", "sbom-matching", "json"),
            risk_class="static",
            supported_input_types=("cyclonedx_sbom",),
            output_formats=("json",),
            pinned_image=self._pinned_image,
        )

    def validate(self, context: ToolContext) -> None:
        if not context.job_id.strip() or not context.scan_run_id.strip():
            raise ValueError("ToolContext requires non-empty job_id and scan_run_id")
        if not context.input_paths:
            raise ValueError("GrypeAdapter requires a validated SBOM input path")

    def build_execution_spec(self, context: ToolContext) -> ExecutionSpec:
        self.validate(context)
        sbom_path = context.input_paths[0]
        sbom_target = (
            sbom_path.as_posix()
            if sbom_path.name.endswith(".json")
            else (sbom_path / "sbom.cdx.json").as_posix()
        )
        out_file = (context.output_dir / "grype.json").as_posix()
        command: tuple[str, ...] = (
            f"sbom:{sbom_target}",
            "-o",
            "json",
            "--file",
            out_file,
        )
        return ExecutionSpec(
            tool_id="grype",
            image=self._pinned_image,
            command=command,
            env={
                "GRYPE_DB_CACHE_DIR": self._db_cache_dir,
                "GRYPE_DB_AUTO_UPDATE": "false",
                "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                "HOME": "/tmp",  # noqa: S108
            },
            network_mode="none",
            expected_outputs=("grype.json",),
            allowed_exit_codes=(0,),
            read_only_root=True,
        )

    def execute(self, context: ToolContext) -> ExecutionResult:
        """Execute grype CLI safely with shell=False inside offline harness."""
        spec = self.build_execution_spec(context)
        context.output_dir.mkdir(parents=True, exist_ok=True)
        timeout = int(context.limits.get("timeout_seconds", 300))
        exe = shutil.which("grype") or "grype"
        try:
            proc = subprocess.run(  # noqa: S603
                [exe, *spec.command],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=dict(spec.env),
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                status="timed_out",
                exit_code=None,
                error_code="grype_timeout",
                error_message_sanitized="Grype timed out during offline SBOM analysis",
            )
        artifacts = [
            p for name in spec.expected_outputs if (p := context.output_dir / name).is_file()
        ]
        return ExecutionResult(
            status="completed" if proc.returncode in spec.allowed_exit_codes else "failed",
            exit_code=proc.returncode,
            artifacts=artifacts,
        )

    def validate_outputs(self, result: ExecutionResult) -> None:
        if result.status != "completed":
            raise ValueError(result.error_message_sanitized or "Grype execution did not complete")
        report_path = find_artifact_by_name(result.artifacts, "grype.json")
        if report_path is None:
            raise ValueError("Grype execution completed without grype.json output")
        parsed = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict) or not isinstance(parsed.get("matches"), list):
            raise ValueError("Grype output is missing required 'matches' list")
        extract_grype_db_provenance(parsed)

    def parse_json_report(self, report: dict[str, Any]) -> list[NormalizedFinding]:
        """Parse Grype JSON output with strict DB snapshot validation & PURL traceability."""
        db_prov = extract_grype_db_provenance(report)
        matches = report.get("matches")
        if not isinstance(matches, list):
            return []

        findings: list[NormalizedFinding] = []
        seen_fps: set[str] = set()
        for match in matches:
            if not isinstance(match, dict):
                continue
            vuln = match.get("vulnerability")
            artifact = match.get("artifact")
            if not isinstance(vuln, dict) or not isinstance(artifact, dict):
                continue

            vuln_id = str(vuln.get("id") or "").strip()
            pkg_name = str(artifact.get("name") or "").strip()
            pkg_version = str(artifact.get("version") or "unknown").strip()
            if not vuln_id or not pkg_name:
                continue

            purl_raw = artifact.get("purl")
            purl = str(purl_raw).strip() if purl_raw else None
            cve_id = _extract_cve_id(vuln, match)
            fixed_version = _extract_fixed_version(vuln)
            raw_sev = str(vuln.get("severity") or "unknown").strip().lower()
            severity: SeverityLevel = _GRYPE_SEVERITY_MAP.get(raw_sev, "unknown")

            file_path = "dependency-manifest"
            locations = artifact.get("locations")
            if isinstance(locations, list) and locations:
                loc0 = locations[0]
                if isinstance(loc0, dict) and loc0.get("path"):
                    file_path = normalize_relative_source_path(str(loc0["path"]))

            discriminator = f"{purl or pkg_name}@{pkg_version}"
            fingerprint = compute_finding_fingerprint(
                category="sca",
                tool_id="grype",
                rule_id=vuln_id,
                file_path=file_path,
                start_line=None,
                discriminator=discriminator,
            )
            if fingerprint in seen_fps:
                continue
            seen_fps.add(fingerprint)

            title = f"{vuln_id} in {pkg_name}@{pkg_version}"
            if fixed_version:
                title += f" (fixed in {fixed_version})"
            desc = redact_text_secrets(
                str(vuln.get("description") or f"Vulnerable dependency {discriminator}: {vuln_id}")
            )
            remediation = (
                f"Upgrade {pkg_name} from {pkg_version} to {fixed_version}."
                if fixed_version
                else (
                    f"Review advisory {vuln_id} for {pkg_name}@{pkg_version}; "
                    "no upstream fix recorded yet."
                )
            )
            findings.append(
                NormalizedFinding(
                    scanner_tool_id="grype",
                    scanner_version="0.121.3",
                    category="sca",
                    rule_id=vuln_id,
                    title=redact_text_secrets(title) or vuln_id,
                    description=desc or title,
                    severity=severity,
                    confidence="high",
                    file_path=file_path,
                    start_line=None,
                    end_line=None,
                    start_column=None,
                    end_column=None,
                    cwe_ids=_extract_cwe_ids(vuln),
                    fingerprint=fingerprint,
                    remediation=remediation,
                    purl=purl,
                    package_name=pkg_name,
                    package_version=pkg_version,
                    fixed_version=fixed_version,
                    cve_id=cve_id,
                    raw_metadata=scrub_finding_dict(
                        {
                            "vulnerability_id": vuln_id,
                            "cve_id": cve_id,
                            "purl": purl,
                            "package": pkg_name,
                            "version": pkg_version,
                            "fixed_version": fixed_version,
                            "db_schema_version": db_prov.schema_version,
                            "db_built_at": db_prov.built_at,
                            "db_archive_sha256": db_prov.db_archive_sha256,
                            "urls": list(vuln.get("urls") or [])[:3],
                        }
                    ),
                )
            )
        return findings

    def normalize(self, result: ExecutionResult) -> list[NormalizedFinding]:
        self.validate_outputs(result)
        report_path = find_artifact_by_name(result.artifacts, "grype.json")
        if report_path is None:
            return []
        parsed = json.loads(report_path.read_text(encoding="utf-8"))
        return self.parse_json_report(parsed)

    def cleanup(self, context: ToolContext) -> None:
        return None
