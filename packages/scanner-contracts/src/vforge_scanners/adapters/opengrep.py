"""Pinned OpenGrep SAST scanner adapter implementing ScannerAdapter (JSON + SARIF)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

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
    normalize_relative_source_path,
)

DEFAULT_OPENGREP_IMAGE = (
    "vforge-opengrep:1.33.1@sha256:"
    "a92cb260fea66c388fdf32924ae67ae933be6f13473e3e5c945182c1e4c01365"
)
DEFAULT_OPENGREP_RULES_PATH = "/opt/opengrep/rules/vforge-baseline.yaml"

_OPENGREP_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "CRITICAL": "critical",
    "ERROR": "high",
    "HIGH": "high",
    "WARNING": "medium",
    "MEDIUM": "medium",
    "INFO": "low",
    "LOW": "low",
    "NOTE": "low",
}

_CONFIDENCE_MAP: dict[str, ConfidenceLevel] = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _clean_opengrep_rule_id(raw_rule_id: str) -> str:
    cleaned = raw_rule_id.strip()
    for prefix in ("opt.opengrep.rules.", "opengrep.rules."):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
    return cleaned or "opengrep-rule"


def _extract_cwes(metadata: dict[str, Any]) -> tuple[str, ...]:
    raw_cwe = metadata.get("cwe")
    items = raw_cwe if isinstance(raw_cwe, list) else ([raw_cwe] if raw_cwe else [])
    extracted: list[str] = []
    for item in items:
        text = str(item).strip()
        if not text:
            continue
        code = text.split(":", 1)[0].strip().upper()
        if code.startswith("CWE-") and code not in extracted:
            extracted.append(code)
    return tuple(extracted)


class OpenGrepAdapter:
    """ScannerAdapter contract for pinned OpenGrep offline SAST execution."""

    def __init__(
        self,
        *,
        pinned_image: str = DEFAULT_OPENGREP_IMAGE,
        rules_path: str = DEFAULT_OPENGREP_RULES_PATH,
    ) -> None:
        self._pinned_image = pinned_image
        self._rules_path = rules_path

    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            tool_id="opengrep",
            tool_version="1.33.1",
            adapter_version="0.1.0",
            capabilities=("sast", "taint-local", "sarif", "json"),
            risk_class="static",
            supported_input_types=("source_snapshot",),
            output_formats=("json", "sarif"),
            pinned_image=self._pinned_image,
        )

    def validate(self, context: ToolContext) -> None:
        if not context.job_id.strip() or not context.scan_run_id.strip():
            raise ValueError("ToolContext requires non-empty job_id and scan_run_id")
        if not context.input_paths:
            raise ValueError("OpenGrepAdapter requires at least one validated read-only input path")

    def build_execution_spec(self, context: ToolContext) -> ExecutionSpec:
        self.validate(context)
        return ExecutionSpec(
            tool_id="opengrep",
            image=self._pinned_image,
            command=(
                "scan",
                "--config",
                self._rules_path,
                "--json-output",
                "/work/out/opengrep.json",
                "--sarif-output",
                "/work/out/opengrep.sarif",
                "--no-git-ignore",
                "/work/in/source",
            ),
            env={
                "HOME": "/tmp",  # noqa: S108 - ephemeral container tmpfs mount
                "XDG_CACHE_HOME": "/opt/opengrep/cache",
                "OPENGREP_SEND_METRICS": "off",
            },
            network_mode="none",
            expected_outputs=("opengrep.json", "opengrep.sarif"),
            allowed_exit_codes=(0,),
            read_only_root=True,
        )

    def execute(self, context: ToolContext) -> ExecutionResult:
        spec = self.build_execution_spec(context)
        context.output_dir.mkdir(parents=True, exist_ok=True)
        json_out = context.output_dir / "opengrep.json"
        sarif_out = context.output_dir / "opengrep.sarif"
        source_dir = context.input_paths[0]
        cmd = [
            "opengrep",
            "scan",
            "--config",
            self._rules_path,
            "--json-output",
            str(json_out),
            "--sarif-output",
            str(sarif_out),
            "--no-git-ignore",
            str(source_dir),
        ]
        timeout_s = int(context.limits.get("timeout_seconds", 300))
        completed = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        artifacts = [p for p in (json_out, sarif_out) if p.exists()]
        if completed.returncode in spec.allowed_exit_codes:
            return ExecutionResult(
                status="completed",
                exit_code=completed.returncode,
                artifacts=artifacts,
                metrics={"exit_code": completed.returncode},
            )
        return ExecutionResult(
            status="failed",
            exit_code=completed.returncode,
            artifacts=artifacts,
            error_code="opengrep_execution_failed",
            error_message_sanitized=redact_text_secrets(completed.stderr[:500]),
        )

    def validate_outputs(self, result: ExecutionResult) -> None:
        if result.status != "completed":
            raise ValueError(f"Cannot validate outputs for non-completed run: {result.status}")
        if result.exit_code != 0:
            raise ValueError(f"Unexpected OpenGrep exit code: {result.exit_code}")
        json_artifact = self._find_artifact(result.artifacts, preferred_name="opengrep.json")
        sarif_artifact = self._find_artifact(result.artifacts, preferred_name="opengrep.sarif")
        if json_artifact is None and sarif_artifact is None:
            raise ValueError("Missing required OpenGrep JSON or SARIF output artifact")
        if json_artifact is not None:
            payload = json.loads(json_artifact.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or "results" not in payload:
                raise ValueError("Invalid OpenGrep JSON payload: missing 'results'")
            if payload.get("errors"):
                fatal = [
                    e
                    for e in payload["errors"]
                    if isinstance(e, dict) and e.get("level") == "error"
                ]
                if fatal:
                    raise ValueError(f"OpenGrep reported fatal scan errors: {len(fatal)}")
        if sarif_artifact is not None:
            sarif = json.loads(sarif_artifact.read_text(encoding="utf-8"))
            if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
                raise ValueError("Invalid OpenGrep SARIF payload: missing 'runs'")

    def normalize(self, result: ExecutionResult) -> list[NormalizedFinding]:
        self.validate_outputs(result)
        json_artifact = self._find_artifact(result.artifacts, preferred_name="opengrep.json")
        if json_artifact is not None:
            payload = json.loads(json_artifact.read_text(encoding="utf-8"))
            return self.parse_json_report(payload)
        sarif_artifact = self._find_artifact(result.artifacts, preferred_name="opengrep.sarif")
        assert sarif_artifact is not None
        sarif = json.loads(sarif_artifact.read_text(encoding="utf-8"))
        return self.parse_sarif_report(sarif)

    def parse_json_report(self, payload: dict[str, Any]) -> list[NormalizedFinding]:
        """Parse OpenGrep native JSON report into canonical NormalizedFinding objects."""
        version = str(payload.get("version") or "1.33.1")
        findings: list[NormalizedFinding] = []
        for item in payload.get("results") or []:
            if not isinstance(item, dict):
                continue
            extra = item.get("extra") or {}
            metadata = extra.get("metadata") or {}
            rule_id = _clean_opengrep_rule_id(str(item.get("check_id") or "opengrep-rule"))
            file_path = normalize_relative_source_path(str(item.get("path") or "unknown"))
            start = item.get("start") or {}
            end = item.get("end") or {}
            start_line = _as_int_or_none(start.get("line"))
            end_line = _as_int_or_none(end.get("line"))
            start_col = _as_int_or_none(start.get("col"))
            end_col = _as_int_or_none(end.get("col"))
            raw_sev = str(extra.get("severity") or "WARNING").upper()
            severity: SeverityLevel = _OPENGREP_SEVERITY_MAP.get(raw_sev, "medium")
            raw_conf = str(metadata.get("confidence") or "MEDIUM").upper()
            confidence: ConfidenceLevel = _CONFIDENCE_MAP.get(raw_conf, "medium")
            cwes = _extract_cwes(metadata)
            message = redact_text_secrets(str(extra.get("message") or rule_id)) or rule_id
            lines_snippet = redact_text_secrets(str(extra.get("lines") or "")) or None
            remediation = redact_text_secrets(
                str(metadata.get("remediation")) if metadata.get("remediation") else None
            )
            fingerprint = compute_finding_fingerprint(
                category="sast",
                tool_id="opengrep",
                rule_id=rule_id,
                file_path=file_path,
                start_line=start_line,
                discriminator="",
            )
            findings.append(
                NormalizedFinding(
                    scanner_tool_id="opengrep",
                    scanner_version=version,
                    category="sast",
                    rule_id=rule_id,
                    title=rule_id.replace(".", " ").replace("-", " ").title()[:180],
                    description=message,
                    severity=severity,
                    confidence=confidence,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    start_column=start_col,
                    end_column=end_col,
                    cwe_ids=cwes,
                    fingerprint=fingerprint,
                    code_snippet_redacted=lines_snippet,
                    secret_redacted=False,
                    remediation=remediation,
                    raw_metadata=scrub_finding_dict(
                        {
                            "engine_kind": extra.get("engine_kind"),
                            "validation_state": extra.get("validation_state"),
                            "rule_id": rule_id,
                            "cwe": list(cwes),
                        }
                    ),
                )
            )
        return findings

    def parse_sarif_report(self, sarif: dict[str, Any]) -> list[NormalizedFinding]:
        """Fallback parser converting SARIF 2.1.0 runs[].results[] into NormalizedFinding."""
        findings: list[NormalizedFinding] = []
        for run in sarif.get("runs") or []:
            if not isinstance(run, dict):
                continue
            driver = (run.get("tool") or {}).get("driver") or {}
            version = str(driver.get("semanticVersion") or "1.33.1")
            for res in run.get("results") or []:
                if not isinstance(res, dict):
                    continue
                rule_id = _clean_opengrep_rule_id(str(res.get("ruleId") or "opengrep-rule"))
                loc = ((res.get("locations") or [{}])[0]).get("physicalLocation") or {}
                uri = str((loc.get("artifactLocation") or {}).get("uri") or "unknown")
                file_path = normalize_relative_source_path(uri)
                region = loc.get("region") or {}
                start_line = _as_int_or_none(region.get("startLine"))
                end_line = _as_int_or_none(region.get("endLine"))
                start_col = _as_int_or_none(region.get("startColumn"))
                end_col = _as_int_or_none(region.get("endColumn"))
                snippet = redact_text_secrets((region.get("snippet") or {}).get("text"))
                raw_msg = str((res.get("message") or {}).get("text") or rule_id)
                msg = redact_text_secrets(raw_msg) or rule_id
                fingerprint = compute_finding_fingerprint(
                    category="sast",
                    tool_id="opengrep",
                    rule_id=rule_id,
                    file_path=file_path,
                    start_line=start_line,
                    discriminator="",
                )
                findings.append(
                    NormalizedFinding(
                        scanner_tool_id="opengrep",
                        scanner_version=version,
                        category="sast",
                        rule_id=rule_id,
                        title=rule_id.replace(".", " ").replace("-", " ").title()[:180],
                        description=msg,
                        severity="high",
                        confidence="medium",
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        start_column=start_col,
                        end_column=end_col,
                        cwe_ids=(),
                        fingerprint=fingerprint,
                        code_snippet_redacted=snippet,
                        secret_redacted=False,
                        remediation=None,
                        raw_metadata={"format": "sarif", "rule_id": rule_id},
                    )
                )
        return findings

    def cleanup(self, context: ToolContext) -> None:
        return None

    @staticmethod
    def _find_artifact(artifacts: list[Path], *, preferred_name: str) -> Path | None:
        for path in artifacts:
            if path.name.lower() == preferred_name:
                return path
        return None


def _as_int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None
