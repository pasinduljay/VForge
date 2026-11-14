"""Pinned Checkov offline IaC & custom YAML policy adapter."""

from __future__ import annotations

import json
import shutil
import subprocess
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
    find_artifact_by_name,
    normalize_relative_source_path,
)

DEFAULT_CHECKOV_IMAGE = (
    "bridgecrew/checkov@sha256:ccead19bd9201d43872ceb7e78bb5868eabfc0d3960d3756fc75f4896067372a"
)

_CHECKOV_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}

_CHECKOV_PREFIX_SEVERITY: tuple[tuple[str, SeverityLevel], ...] = (
    ("CKV_AWS_20", "critical"),
    ("CKV_AWS_21", "medium"),
    ("CKV_AWS_", "high"),
    ("CKV_DOCKER_", "medium"),
    ("CKV_K8S_", "high"),
    ("CKV2_VF_", "medium"),
)


def _infer_checkov_severity(check: dict[str, Any]) -> SeverityLevel:
    raw_sev = str(check.get("severity") or "").strip().upper()
    if raw_sev in _CHECKOV_SEVERITY_MAP:
        return _CHECKOV_SEVERITY_MAP[raw_sev]
    check_id = str(check.get("check_id") or "").strip().upper()
    for prefix, mapped in _CHECKOV_PREFIX_SEVERITY:
        if check_id.startswith(prefix):
            return mapped
    return "medium"


def _format_code_block(raw_block: Any) -> str | None:
    if not isinstance(raw_block, list):
        return None
    lines: list[str] = []
    for entry in raw_block[:12]:
        if isinstance(entry, (list, tuple)) and len(entry) >= 2:
            lines.append(f"{entry[0]}: {str(entry[1]).rstrip()}")
    joined = "\n".join(lines).strip()
    return redact_text_secrets(joined) if joined else None


class CheckovAdapter:
    """ScannerAdapter contract for pinned Checkov offline IaC scanning with YAML custom rules."""

    def __init__(
        self,
        *,
        pinned_image: str = DEFAULT_CHECKOV_IMAGE,
        custom_policies_mount: str = "/work/policies",
    ) -> None:
        self._pinned_image = pinned_image
        self._custom_policies_mount = custom_policies_mount

    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            tool_id="checkov",
            tool_version="3.2.435",
            adapter_version="0.1.0",
            capabilities=("iac", "terraform", "dockerfile", "kubernetes", "json", "sarif"),
            risk_class="static",
            supported_input_types=("source_snapshot",),
            output_formats=("json", "sarif"),
            pinned_image=self._pinned_image,
        )

    def validate(self, context: ToolContext) -> None:
        if not context.job_id.strip() or not context.scan_run_id.strip():
            raise ValueError("ToolContext requires non-empty job_id and scan_run_id")
        if not context.input_paths:
            raise ValueError("CheckovAdapter requires a validated read-only source path")

    def build_execution_spec(self, context: ToolContext) -> ExecutionSpec:
        self.validate(context)
        source_path = context.input_paths[0].as_posix()
        output_dir = context.output_dir.as_posix()
        command_list: list[str] = [
            "-d",
            source_path,
            "--output",
            "json",
            "--output",
            "sarif",
            "--output-file-path",
            output_dir,
            "--soft-fail",
            "--skip-download",
            "--quiet",
        ]
        if bool(context.config.get("enable_custom_policies")):
            # Restrict custom policies to mounted declarative YAML rules directory only.
            command_list.extend(["--external-checks-dir", self._custom_policies_mount])

        return ExecutionSpec(
            tool_id="checkov",
            image=self._pinned_image,
            command=tuple(command_list),
            env={
                "HOME": "/tmp",  # noqa: S108
                "CHECKOV_RUN_SCA_PACKAGE_SCAN": "false",
                "LOG_LEVEL": "WARNING",
            },
            network_mode="none",
            expected_outputs=("results_json.json", "results_sarif.sarif"),
            allowed_exit_codes=(0,),
            read_only_root=True,
        )

    def execute(self, context: ToolContext) -> ExecutionResult:
        """Execute checkov CLI safely with shell=False inside offline harness."""
        spec = self.build_execution_spec(context)
        context.output_dir.mkdir(parents=True, exist_ok=True)
        timeout = int(context.limits.get("timeout_seconds", 300))
        exe = shutil.which("checkov") or "checkov"
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
                error_code="checkov_timeout",
                error_message_sanitized="Checkov timed out during IaC policy evaluation",
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
            raise ValueError(result.error_message_sanitized or "Checkov execution did not complete")
        json_path = find_artifact_by_name(result.artifacts, "results_json.json")
        if json_path is None:
            raise ValueError("Checkov execution completed without results_json.json output")
        parsed = json.loads(json_path.read_text(encoding="utf-8"))
        if not isinstance(parsed, (dict, list)):
            raise ValueError("Checkov results_json.json must be a JSON object or array")

    def parse_json_report(self, report: dict[str, Any] | list[Any]) -> list[NormalizedFinding]:
        """Parse Checkov JSON output (single object or multi-framework array) with line evidence."""
        blocks = report if isinstance(report, list) else [report]
        findings: list[NormalizedFinding] = []
        seen_fps: set[str] = set()

        for block in blocks:
            if not isinstance(block, dict):
                continue
            check_type = str(block.get("check_type") or "iac").strip()
            results = block.get("results")
            if not isinstance(results, dict):
                continue
            failed = results.get("failed_checks")
            if not isinstance(failed, list):
                continue

            for item in failed:
                if not isinstance(item, dict):
                    continue
                check_id = str(item.get("check_id") or "").strip()
                if not check_id:
                    continue
                check_name = str(item.get("check_name") or check_id).strip()
                raw_path = str(
                    item.get("file_abs_path")
                    or item.get("repo_file_path")
                    or item.get("file_path")
                    or "unknown"
                )
                file_path = normalize_relative_source_path(raw_path)
                line_range = item.get("file_line_range")
                start_line: int | None = None
                end_line: int | None = None
                if isinstance(line_range, list) and line_range:
                    if isinstance(line_range[0], int) and line_range[0] > 0:
                        start_line = line_range[0]
                    if len(line_range) > 1 and isinstance(line_range[1], int) and line_range[1] > 0:
                        end_line = line_range[1]

                resource = str(item.get("resource") or "").strip() or None
                severity = _infer_checkov_severity(item)
                confidence: ConfidenceLevel = "high" if resource else "medium"
                snippet = _format_code_block(item.get("code_block"))
                fingerprint = compute_finding_fingerprint(
                    category="iac",
                    tool_id="checkov",
                    rule_id=check_id,
                    file_path=file_path,
                    start_line=start_line,
                    discriminator=resource or check_type,
                )
                if fingerprint in seen_fps:
                    continue
                seen_fps.add(fingerprint)

                desc = f"[{check_type}] {check_name}"
                if resource:
                    desc += f" (resource: {resource})"
                findings.append(
                    NormalizedFinding(
                        scanner_tool_id="checkov",
                        scanner_version="3.2.435",
                        category="iac",
                        rule_id=check_id,
                        title=redact_text_secrets(check_name) or check_id,
                        description=redact_text_secrets(desc) or check_id,
                        severity=severity,
                        confidence=confidence,
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        start_column=None,
                        end_column=None,
                        cwe_ids=(),
                        fingerprint=fingerprint,
                        code_snippet_redacted=snippet,
                        secret_redacted=False,
                        remediation=redact_text_secrets(str(item.get("guideline") or "").strip())
                        or None,
                        iac_resource=resource,
                        raw_metadata=scrub_finding_dict(
                            {
                                "check_type": check_type,
                                "check_id": check_id,
                                "resource": resource,
                                "file_line_range": line_range,
                                "check_class": item.get("check_class"),
                            }
                        ),
                    )
                )
        return findings

    def normalize(self, result: ExecutionResult) -> list[NormalizedFinding]:
        self.validate_outputs(result)
        json_path = find_artifact_by_name(result.artifacts, "results_json.json")
        if json_path is None:
            return []
        parsed = json.loads(json_path.read_text(encoding="utf-8"))
        return self.parse_json_report(parsed)

    def cleanup(self, context: ToolContext) -> None:
        return None
