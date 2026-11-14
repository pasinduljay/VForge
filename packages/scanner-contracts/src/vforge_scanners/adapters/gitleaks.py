"""Pinned Gitleaks v8.24.0 secrets scanner adapter implementing ScannerAdapter."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from vforge_scanners.redaction import (
    mask_secret_preview,
    redact_secret_value,
    redact_text_secrets,
    scrub_finding_dict,
)
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

DEFAULT_GITLEAKS_IMAGE = (
    "zricethezav/gitleaks@sha256:2bcceac45179b3a91bff11a824d0fb952585b429e54fc928728b1d4d5c3e5176"
)
GITLEAKS_FINDINGS_EXIT_CODE = 10

_HIGH_CRITICAL_RULE_HINTS = (
    "private-key",
    "aws-access",
    "aws-secret",
    "gcp-api",
    "github-pat",
    "stripe-access",
    "jwt",
)


def _classify_gitleaks_severity(
    rule_id: str, entropy: float | None
) -> tuple[SeverityLevel, ConfidenceLevel]:
    lowered = rule_id.lower()
    if any(token in lowered for token in _HIGH_CRITICAL_RULE_HINTS):
        return ("critical" if "private-key" in lowered or "aws" in lowered else "high"), "high"
    if entropy is not None and entropy >= 4.0:
        return "high", "medium"
    return "medium", "medium"


class GitleaksAdapter:
    """ScannerAdapter contract for pinned Gitleaks directory secret detection."""

    def __init__(self, *, pinned_image: str = DEFAULT_GITLEAKS_IMAGE) -> None:
        self._pinned_image = pinned_image

    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            tool_id="gitleaks",
            tool_version="8.24.0",
            adapter_version="0.1.0",
            capabilities=("secrets", "credentials", "private-keys"),
            risk_class="static",
            supported_input_types=("source_snapshot",),
            output_formats=("json",),
            pinned_image=self._pinned_image,
        )

    def validate(self, context: ToolContext) -> None:
        if not context.job_id.strip() or not context.scan_run_id.strip():
            raise ValueError("ToolContext requires non-empty job_id and scan_run_id")
        if not context.input_paths:
            raise ValueError("GitleaksAdapter requires at least one validated read-only input path")

    def build_execution_spec(self, context: ToolContext) -> ExecutionSpec:
        self.validate(context)
        return ExecutionSpec(
            tool_id="gitleaks",
            image=self._pinned_image,
            command=(
                "dir",
                "--no-banner",
                "--no-color",
                "--redact=100",
                f"--exit-code={GITLEAKS_FINDINGS_EXIT_CODE}",
                "--report-format=json",
                "--report-path=/work/out/gitleaks.json",
                "/work/in/source",
            ),
            env={
                "HOME": "/tmp",  # noqa: S108 - ephemeral container tmpfs mount
            },
            network_mode="none",
            expected_outputs=("gitleaks.json",),
            allowed_exit_codes=(0, GITLEAKS_FINDINGS_EXIT_CODE),
            read_only_root=True,
        )

    def execute(self, context: ToolContext) -> ExecutionResult:
        spec = self.build_execution_spec(context)
        context.output_dir.mkdir(parents=True, exist_ok=True)
        report_path = context.output_dir / "gitleaks.json"
        source_dir = context.input_paths[0]
        cmd = [
            "gitleaks",
            "dir",
            "--no-banner",
            "--no-color",
            "--redact=100",
            f"--exit-code={GITLEAKS_FINDINGS_EXIT_CODE}",
            "--report-format=json",
            f"--report-path={report_path}",
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
        artifacts = [report_path] if report_path.exists() else []
        if completed.returncode in spec.allowed_exit_codes:
            return ExecutionResult(
                status="completed",
                exit_code=completed.returncode,
                artifacts=artifacts,
                metrics={"leaks_exit_code": completed.returncode},
            )
        return ExecutionResult(
            status="failed",
            exit_code=completed.returncode,
            artifacts=artifacts,
            error_code="gitleaks_execution_failed",
            error_message_sanitized=redact_text_secrets(completed.stderr[:500]),
        )

    def validate_outputs(self, result: ExecutionResult) -> None:
        if result.status != "completed":
            raise ValueError(f"Cannot validate outputs for non-completed run: {result.status}")
        if result.exit_code not in (0, GITLEAKS_FINDINGS_EXIT_CODE):
            raise ValueError(f"Unexpected Gitleaks exit code: {result.exit_code}")
        json_artifact = self._find_report_artifact(result.artifacts)
        if json_artifact is None or not json_artifact.exists():
            raise ValueError("Missing required gitleaks.json output artifact")
        parsed = json.loads(json_artifact.read_text(encoding="utf-8"))
        if not isinstance(parsed, list):
            raise ValueError("Gitleaks JSON output must be a JSON array")

    def normalize(self, result: ExecutionResult) -> list[NormalizedFinding]:
        self.validate_outputs(result)
        json_artifact = self._find_report_artifact(result.artifacts)
        assert json_artifact is not None
        raw_items = json.loads(json_artifact.read_text(encoding="utf-8"))
        return self.parse_json_findings(raw_items)

    def parse_json_findings(self, raw_items: list[dict[str, Any]]) -> list[NormalizedFinding]:
        """Parse Gitleaks JSON items and aggressively redact any leaked secret values."""
        findings: list[NormalizedFinding] = []
        for entry in raw_items:
            if not isinstance(entry, dict):
                continue
            rule_id = str(entry.get("RuleID") or entry.get("Rule") or "generic-secret").strip()
            description = str(
                entry.get("Description") or f"Potential hardcoded secret detected by {rule_id}"
            )
            raw_file = str(entry.get("File") or entry.get("SymlinkFile") or "unknown")
            file_path = normalize_relative_source_path(raw_file)
            start_line = _as_int_or_none(entry.get("StartLine"))
            end_line = _as_int_or_none(entry.get("EndLine"))
            start_col = _as_int_or_none(entry.get("StartColumn"))
            end_col = _as_int_or_none(entry.get("EndColumn"))

            raw_secret = str(entry.get("Secret") or "")
            raw_match = str(entry.get("Match") or "")
            secret_token = (
                redact_secret_value(raw_secret or raw_match)
                if (raw_secret or raw_match)
                else "[REDACTED]"
            )
            snippet_redacted = mask_secret_preview(raw_match, raw_secret)
            entropy_val = entry.get("Entropy")
            entropy = float(entropy_val) if isinstance(entropy_val, (int, float)) else None
            severity, confidence = _classify_gitleaks_severity(rule_id, entropy)

            # Use rule/file/line + redacted token hash so rescanning the commit is deterministic
            # while never leaking cleartext secrets into the fingerprint input outside SHA-256.
            fingerprint = compute_finding_fingerprint(
                category="secret",
                tool_id="gitleaks",
                rule_id=rule_id,
                file_path=file_path,
                start_line=start_line,
                discriminator=secret_token,
            )
            scrubbed_meta = scrub_finding_dict(
                {
                    "rule_id": rule_id,
                    "entropy": entropy,
                    "tags": entry.get("Tags") or [],
                    "secret": raw_secret,
                    "match": raw_match,
                },
                known_secrets=[raw_secret] if raw_secret else [],
            )

            findings.append(
                NormalizedFinding(
                    scanner_tool_id="gitleaks",
                    scanner_version="8.24.0",
                    category="secret",
                    rule_id=rule_id,
                    title=(
                        redact_text_secrets(
                            f"Hardcoded secret detected ({rule_id})", known_secrets=[raw_secret]
                        )
                        or rule_id
                    ),
                    description=(
                        redact_text_secrets(description, known_secrets=[raw_secret]) or description
                    ),
                    severity=severity,
                    confidence=confidence,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    start_column=start_col,
                    end_column=end_col,
                    cwe_ids=("CWE-798",),
                    fingerprint=fingerprint,
                    code_snippet_redacted=snippet_redacted or secret_token,
                    secret_redacted=True,
                    remediation=(
                        "Revoke/rotate the exposed credential immediately, remove it from source "
                        "and git history, and inject runtime secrets via OpenBao / SecretProvider."
                    ),
                    raw_metadata=scrubbed_meta,
                )
            )
        return findings

    def cleanup(self, context: ToolContext) -> None:
        return None

    @staticmethod
    def _find_report_artifact(artifacts: list[Path]) -> Path | None:
        for path in artifacts:
            if path.name.lower() == "gitleaks.json" or path.suffix.lower() == ".json":
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
