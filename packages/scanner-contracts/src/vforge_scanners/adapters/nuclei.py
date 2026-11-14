"""Pinned ProjectDiscovery Nuclei adapter with rate limits and pinned template snapshot."""

from __future__ import annotations

import json
import subprocess
from urllib.parse import urlsplit

from vforge_scanners.redaction import redact_text_secrets, scrub_finding_dict
from vforge_scanners.sdk import (
    ConfidenceLevel,
    ExecutionResult,
    ExecutionSpec,
    NormalizedFinding,
    SeverityLevel,
    ToolContext,
    ToolMetadata,
    compute_finding_fingerprint,
    find_artifact_by_name,
)

DEFAULT_NUCLEI_IMAGE = (
    "projectdiscovery/nuclei@sha256:"
    "582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb"
)

_NUCLEI_SEV_MAP: dict[str, SeverityLevel] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "UNKNOWN": "unknown",
}


def _normalize_matched_path(matched_at: str) -> str:
    parsed = urlsplit(matched_at)
    path = parsed.path or "/"
    return path if path.startswith("/") else f"/{path}"


class NucleiAdapter:
    """ScannerAdapter contract for pinned Nuclei execution with rate caps and offline templates."""

    def __init__(self, *, pinned_image: str = DEFAULT_NUCLEI_IMAGE) -> None:
        self._pinned_image = pinned_image

    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            tool_id="nuclei",
            tool_version="3.11.1",
            adapter_version="0.1.0",
            capabilities=("dast_active", "dast_passive", "templates", "cve", "misconfig"),
            risk_class="active",
            supported_input_types=("url", "host", "templates"),
            output_formats=("jsonl",),
            pinned_image=self._pinned_image,
        )

    def validate(self, context: ToolContext) -> None:
        if not context.job_id.strip() or not context.scan_run_id.strip():
            raise ValueError("ToolContext requires non-empty job_id and scan_run_id")
        target = str(
            context.config.get("target_url") or context.config.get("target_host") or ""
        ).strip()
        if not target:
            raise ValueError("NucleiAdapter requires config['target_url'] or config['target_host']")

    def build_execution_spec(self, context: ToolContext) -> ExecutionSpec:
        self.validate(context)
        target = str(
            context.config.get("target_url") or context.config.get("target_host") or ""
        ).strip()
        raw_rps = (
            context.limits.get("max_requests_per_second") or context.config.get("max_rps") or 2
        )
        rate_limit = max(1, min(int(raw_rps), 20))
        concurrency = max(1, min(int(context.config.get("concurrency") or 1), 5))

        templates_path = str(context.config.get("templates_path") or "/work/in/templates")
        cmd: list[str] = [
            "nuclei",
            "-target",
            target,
            "-templates",
            templates_path,
            "-disable-update-check",
            "-no-interactsh",
            "-rate-limit",
            str(rate_limit),
            "-concurrency",
            str(concurrency),
            "-jsonl-export",
            "/work/out/nuclei.jsonl",
            "-silent",
        ]
        tags = str(context.config.get("tags") or "").strip()
        if tags:
            cmd.extend(["-tags", tags])
        auth_header = str(context.config.get("auth_header") or "").strip()
        if auth_header:
            cmd.extend(["-H", auth_header])

        return ExecutionSpec(
            tool_id="nuclei",
            image=self._pinned_image,
            command=tuple(cmd),
            env={"HOME": "/tmp"},  # noqa: S108
            network_mode="scoped-http-egress",
            expected_outputs=("nuclei.jsonl",),
            allowed_exit_codes=(0,),
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
        jsonl_path = find_artifact_by_name(result.artifacts, "nuclei.jsonl")
        if jsonl_path is None or not jsonl_path.exists():
            raise ValueError("Missing required Nuclei report artifact: nuclei.jsonl")
        lines = jsonl_path.read_text(encoding="utf-8").splitlines()
        for line in lines:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if not isinstance(record, dict) or "template-id" not in record:
                    raise ValueError("Nuclei report line is not a valid JSON record with template-id")
            except (OSError, ValueError) as err:
                raise ValueError(f"Corrupted Nuclei report JSONL: {err}") from err

    def normalize(
        self,
        result: ExecutionResult,
        context: ToolContext | None = None,
    ) -> list[NormalizedFinding]:
        jsonl_path = find_artifact_by_name(result.artifacts, "nuclei.jsonl")
        if jsonl_path is None:
            return []
        return self.parse_jsonl_text(jsonl_path.read_text(encoding="utf-8"))

    def parse_jsonl_text(self, text: str) -> list[NormalizedFinding]:
        """Parse Nuclei JSONL report output into NormalizedFinding objects."""
        findings: list[NormalizedFinding] = []
        seen_fps: set[str] = set()
        for line in text.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            record = json.loads(line_str)
            if not isinstance(record, dict):
                continue

            template_id = str(
                record.get("template-id") or record.get("templateID") or "nuclei-rule"
            )
            info = record.get("info") or {}
            raw_title = str(info.get("name") or template_id)
            title = str(redact_text_secrets(raw_title) or raw_title)
            raw_desc = str(info.get("description") or title)
            desc = str(redact_text_secrets(raw_desc) or raw_desc)
            raw_sev = str(info.get("severity") or "medium").strip().upper()
            severity: SeverityLevel = _NUCLEI_SEV_MAP.get(raw_sev, "medium")
            confidence: ConfidenceLevel = "high" if severity in {"critical", "high"} else "medium"

            classification = info.get("classification") or {}
            cwe_raw = classification.get("cwe-id") or []
            if isinstance(cwe_raw, str):
                cwe_raw = [cwe_raw]
            cwe_ids: list[str] = []
            for item in cwe_raw:
                val = str(item).strip().upper()
                if val.startswith("CWE-"):
                    cwe_ids.append(val)
                elif val.isdigit():
                    cwe_ids.append(f"CWE-{val}")

            cve_raw = classification.get("cve-id") or []
            if isinstance(cve_raw, str):
                cve_raw = [cve_raw]
            cve_id = str(cve_raw[0]).strip().upper() if cve_raw else None

            matched_at = str(record.get("matched-at") or record.get("host") or "/")
            clean_matched = str(redact_text_secrets(matched_at) or matched_at)
            locator_path = _normalize_matched_path(clean_matched)
            extracted = record.get("extracted-results") or []
            curl_cmd = redact_text_secrets(str(record.get("curl-command") or "")) or None
            raw_rem = str(info.get("remediation") or info.get("reference") or "")
            remediation = redact_text_secrets(raw_rem) or None

            snippet_text: str | None = None
            if isinstance(extracted, list) and extracted:
                joined = ", ".join(str(e) for e in extracted[:5])
                redacted_joined = redact_text_secrets(joined)
                snippet_text = redacted_joined[:500] if redacted_joined else None
            elif curl_cmd:
                snippet_text = curl_cmd[:500]

            discriminator = f"{clean_matched}:{record.get('type', '')}"
            fingerprint = compute_finding_fingerprint(
                category="dast",
                tool_id="nuclei",
                rule_id=f"nuclei-{template_id}",
                file_path=locator_path,
                start_line=None,
                discriminator=discriminator,
            )
            if fingerprint in seen_fps:
                continue
            seen_fps.add(fingerprint)

            http_url = clean_matched if clean_matched.startswith(("http://", "https://")) else None
            findings.append(
                NormalizedFinding(
                    scanner_tool_id="nuclei",
                    scanner_version="3.11.1",
                    category="dast",
                    rule_id=f"nuclei-{template_id}",
                    title=title,
                    description=desc,
                    severity=severity,
                    confidence=confidence,
                    file_path=locator_path,
                    start_line=None,
                    end_line=None,
                    start_column=None,
                    end_column=None,
                    cwe_ids=tuple(cwe_ids),
                    fingerprint=fingerprint,
                    code_snippet_redacted=snippet_text,
                    secret_redacted=bool(snippet_text and "[REDACTED" in snippet_text),
                    remediation=remediation,
                    cve_id=cve_id,
                    http_url=http_url,
                    raw_metadata=scrub_finding_dict(
                        {
                            "template_id": template_id,
                            "type": record.get("type"),
                            "matched_at": clean_matched,
                            "timestamp": record.get("timestamp"),
                            "matcher_name": record.get("matcher-name"),
                        }
                    ),
                )
            )
        return findings

    def cleanup(self, context: ToolContext) -> None:
        return None
