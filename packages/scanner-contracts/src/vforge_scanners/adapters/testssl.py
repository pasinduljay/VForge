"""Pinned testssl.sh TLS & cipher suite assessment adapter."""

from __future__ import annotations

import json
import subprocess
from typing import Any
from urllib.parse import urlsplit

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
)

DEFAULT_TESTSSL_IMAGE = (
    "drwetter/testssl.sh@sha256:e42cb1ba9445ea861e8b6eec96b97f6f293ce4e5908eebc75c28bdd96d66108e"
)

_TESTSSL_SEV_MAP: dict[str, SeverityLevel] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "WARN": "medium",
    "INFO": "info",
}

_IGNORED_SEVERITIES = {"OK", "DEBUG"}


class TestsslAdapter:
    """ScannerAdapter contract for testssl.sh TLS configuration and vulnerability analysis."""

    def __init__(self, *, pinned_image: str = DEFAULT_TESTSSL_IMAGE) -> None:
        self._pinned_image = pinned_image

    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            tool_id="testssl",
            tool_version="3.2.5",
            adapter_version="0.1.0",
            capabilities=("tls_assessment", "cipher_suites", "protocols", "certificates"),
            risk_class="network",
            supported_input_types=("host", "url", "domain"),
            output_formats=("json",),
            pinned_image=self._pinned_image,
        )

    def validate(self, context: ToolContext) -> None:
        if not context.job_id.strip() or not context.scan_run_id.strip():
            raise ValueError("ToolContext requires non-empty job_id and scan_run_id")
        target = str(
            context.config.get("target_host") or context.config.get("target_url") or ""
        ).strip()
        if not target:
            raise ValueError(
                "TestsslAdapter requires config['target_host'] or config['target_url']"
            )

    def build_execution_spec(self, context: ToolContext) -> ExecutionSpec:
        self.validate(context)
        raw_target = str(
            context.config.get("target_host") or context.config.get("target_url") or ""
        ).strip()
        if "://" in raw_target:
            parsed = urlsplit(raw_target)
            default_port = 443 if parsed.scheme == "https" else 80
            target = f"{parsed.hostname}:{parsed.port or default_port}"
        else:
            target = raw_target

        cmd: tuple[str, ...] = (
            "testssl.sh",
            "--quiet",
            "--warnings",
            "batch",
            "--jsonfile-pretty",
            "/work/out/testssl.json",
            target,
        )

        return ExecutionSpec(
            tool_id="testssl",
            image=self._pinned_image,
            command=cmd,
            env={"HOME": "/tmp"},  # noqa: S108
            network_mode="scoped-http-egress",
            expected_outputs=("testssl.json",),
            allowed_exit_codes=(0, 1),
            read_only_root=True,
        )

    def execute(self, context: ToolContext) -> ExecutionResult:
        spec = self.build_execution_spec(context)
        completed = subprocess.run(  # noqa: S603
            list(spec.command),
            capture_output=True,
            text=True,
            check=False,
        )
        return ExecutionResult(
            status="completed" if completed.returncode in spec.allowed_exit_codes else "failed",
            exit_code=completed.returncode,
            metrics={"stderr_bytes": len(completed.stderr or "")},
        )

    def validate_outputs(self, result: ExecutionResult) -> None:
        json_path = find_artifact_by_name(result.artifacts, "testssl.json")
        if json_path is None or not json_path.exists():
            raise ValueError("Missing required testssl report artifact: testssl.json")
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            is_valid_dict = isinstance(payload, dict) and "scanResult" in payload
            if not isinstance(payload, list) and not is_valid_dict:
                raise ValueError("Invalid testssl report JSON shape")
        except (OSError, ValueError) as err:
            raise ValueError(f"Corrupted testssl report JSON: {err}") from err

    def normalize(
        self,
        result: ExecutionResult,
        context: ToolContext | None = None,
    ) -> list[NormalizedFinding]:
        json_path = find_artifact_by_name(result.artifacts, "testssl.json")
        if json_path is None:
            return []
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        return self.parse_json_report(payload)

    def parse_json_report(self, payload: Any) -> list[NormalizedFinding]:
        """Parse a testssl.sh JSON report structure into NormalizedFinding objects."""
        records: list[dict[str, Any]]
        if isinstance(payload, list):
            records = [r for r in payload if isinstance(r, dict)]
        elif isinstance(payload, dict):
            scan_res = payload.get("scanResult")
            records = scan_res if isinstance(scan_res, list) else []
        else:
            return []

        findings: list[NormalizedFinding] = []
        seen_fps: set[str] = set()
        for rec in records:
            finding_id = str(rec.get("id") or "").strip()
            if not finding_id:
                continue

            raw_sev = str(rec.get("severity") or "INFO").strip().upper()
            if raw_sev in _IGNORED_SEVERITIES:
                continue

            finding_text = str(rec.get("finding") or finding_id).strip()
            if finding_text.lower().startswith(("not vulnerable", "not offered", "ok")):
                continue

            severity: SeverityLevel = _TESTSSL_SEV_MAP.get(raw_sev, "low")
            cwe_raw = str(rec.get("cwe") or "").strip()
            cwe_ids: tuple[str, ...] = (f"CWE-{cwe_raw}",) if cwe_raw.isdigit() else ()
            cve_raw = str(rec.get("cve") or "").strip()
            cve_id = cve_raw if cve_raw.upper().startswith("CVE-") else None

            title_raw = f"TLS Configuration: {finding_id} ({finding_text[:100]})"
            title = str(redact_text_secrets(title_raw) or title_raw)
            desc_raw = f"testssl.sh flagged {finding_id}: {finding_text}"
            desc = str(redact_text_secrets(desc_raw) or desc_raw)
            rule_id = f"testssl-{finding_id.lower()}"
            locator = "tls"

            fingerprint = compute_finding_fingerprint(
                category="network",
                tool_id="testssl",
                rule_id=rule_id,
                file_path=locator,
                start_line=None,
                discriminator=finding_id,
            )
            if fingerprint in seen_fps:
                continue
            seen_fps.add(fingerprint)

            findings.append(
                NormalizedFinding(
                    scanner_tool_id="testssl",
                    scanner_version="3.2.5",
                    category="network",
                    rule_id=rule_id,
                    title=title,
                    description=desc,
                    severity=severity,
                    confidence="high",
                    file_path=locator,
                    start_line=None,
                    end_line=None,
                    start_column=None,
                    end_column=None,
                    cwe_ids=cwe_ids or ("CWE-326",),
                    fingerprint=fingerprint,
                    cve_id=cve_id,
                    remediation=(
                        "Upgrade TLS to TLS 1.2/1.3 and disable deprecated ciphers or protocols."
                    ),
                    raw_metadata=scrub_finding_dict(
                        {
                            "id": finding_id,
                            "severity": raw_sev,
                            "finding": finding_text,
                        }
                    ),
                )
            )

        return findings

    def cleanup(self, context: ToolContext) -> None:
        return None
