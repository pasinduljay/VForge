"""Pinned OWASP ZAP Automation Framework adapter (passive-first + sequential active + OpenAPI)."""

from __future__ import annotations

import json
import re
import subprocess
from typing import Any
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

DEFAULT_ZAP_IMAGE = (
    "ghcr.io/zaproxy/zaproxy@sha256:"
    "391f66efa53b30de40d4a1c6e28146477263552fc828bc7613c9cd11a2949908"
)

_RISK_CODE_MAP: dict[str, SeverityLevel] = {
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "info",
}

_CONFIDENCE_CODE_MAP: dict[str, ConfidenceLevel] = {
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "low",
}

_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    cleaned = _HTML_TAG_RE.sub(" ", text)
    return " ".join(cleaned.split()).strip()


def _format_scalar(val: Any) -> str:
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    return json.dumps(str(val))


def _to_yaml(value: Any, indent: int = 0) -> str:
    """Deterministic YAML emitter for strictly typed ZAP Automation Framework dicts."""
    prefix = "  " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for k, v in value.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{prefix}{k}:")
                lines.append(_to_yaml(v, indent + 1))
            elif isinstance(v, list):
                lines.append(f"{prefix}{k}: []")
            elif isinstance(v, dict):
                lines.append(f"{prefix}{k}: {{}}")
            else:
                lines.append(f"{prefix}{k}: {_format_scalar(v)}")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, dict) and item:
                first_key = next(iter(item))
                first_val = item[first_key]
                rest = {k: v for k, v in item.items() if k != first_key}
                if isinstance(first_val, (dict, list)) and first_val:
                    lines.append(f"{prefix}- {first_key}:")
                    lines.append(_to_yaml(first_val, indent + 2))
                else:
                    lines.append(f"{prefix}- {first_key}: {_format_scalar(first_val)}")
                if rest:
                    lines.append(_to_yaml(rest, indent + 1))
            else:
                lines.append(f"{prefix}- {_format_scalar(item)}")
        return "\n".join(lines)
    return f"{prefix}{_format_scalar(value)}"


def build_zap_automation_plan(
    *,
    target_url: str,
    active_scan: bool = False,
    has_openapi_spec: bool = False,
    max_rps: int = 2,
    spider_max_duration_mins: int = 2,
    spider_max_depth: int = 3,
    active_max_duration_mins: int = 10,
) -> str:
    """Build deterministic OWASP ZAP Automation Framework YAML configuration."""
    parsed = urlsplit(target_url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid HTTP/HTTPS target URL for ZAP: {target_url!r}")

    safe_rps = max(1, min(int(max_rps), 20))
    delay_ms = max(50, int(1000 / safe_rps))
    base_url = target_url.rstrip("/") or target_url

    jobs: list[dict[str, Any]] = []
    if has_openapi_spec:
        jobs.append(
            {
                "type": "openapi",
                "parameters": {
                    "apiFile": "/work/in/openapi.json",
                    "targetUrl": base_url,
                    "context": "vforge-target",
                },
            }
        )

    jobs.append(
        {
            "type": "spider",
            "parameters": {
                "context": "vforge-target",
                "url": base_url,
                "maxDuration": max(1, min(spider_max_duration_mins, 15)),
                "maxDepth": max(1, min(spider_max_depth, 8)),
                "threadCount": 2,
            },
        }
    )
    jobs.append(
        {
            "type": "passiveScan-wait",
            "parameters": {
                "maxDuration": 3,
            },
        }
    )

    if active_scan:
        jobs.append(
            {
                "type": "activeScan",
                "parameters": {
                    "context": "vforge-target",
                    "maxRuleDurationInMins": 2,
                    "maxScanDurationInMins": max(1, min(active_max_duration_mins, 30)),
                    "threadPerHost": 1,
                    "delayInMs": delay_ms,
                    "handleAntiCSRFTokens": True,
                },
            }
        )

    jobs.append(
        {
            "type": "report",
            "parameters": {
                "template": "traditional-json",
                "reportDir": "/work/out",
                "reportFile": "zap-report.json",
                "reportTitle": "VForge ZAP Assessment",
            },
        }
    )

    plan_doc = {
        "env": {
            "contexts": [
                {
                    "name": "vforge-target",
                    "urls": [base_url],
                    "includePaths": [f"{base_url}.*"],
                    "excludePaths": [
                        ".*(logout|signout|logoff|password-reset|delete-account).*",
                    ],
                }
            ],
            "parameters": {
                "failOnError": False,
                "failOnWarning": False,
                "progressToStdout": True,
            },
        },
        "jobs": jobs,
    }
    return _to_yaml(plan_doc) + "\n"


def _normalize_uri_path(uri: str, fallback: str = "/") -> str:
    parsed = urlsplit(uri)
    path = parsed.path or fallback
    return path if path.startswith("/") else f"/{path}"


class ZAPAdapter:
    """ScannerAdapter contract for OWASP ZAP Automation Framework (passive & active)."""

    def __init__(self, *, pinned_image: str = DEFAULT_ZAP_IMAGE) -> None:
        self._pinned_image = pinned_image

    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            tool_id="zap",
            tool_version="2.16.0",
            adapter_version="0.1.0",
            capabilities=("dast_passive", "dast_active", "openapi", "http_headers"),
            risk_class="active",
            supported_input_types=("url", "api_endpoint", "openapi_spec"),
            output_formats=("json",),
            pinned_image=self._pinned_image,
        )

    def validate(self, context: ToolContext) -> None:
        if not context.job_id.strip() or not context.scan_run_id.strip():
            raise ValueError("ToolContext requires non-empty job_id and scan_run_id")
        target_url = str(context.config.get("target_url") or "").strip()
        if not target_url:
            raise ValueError("ZAPAdapter requires config['target_url']")
        parsed = urlsplit(target_url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("ZAPAdapter target_url must be a valid HTTP/HTTPS URL")

    def build_execution_spec(self, context: ToolContext) -> ExecutionSpec:
        self.validate(context)
        cmd: list[str] = [
            "zap.sh",
            "-cmd",
            "-dir",
            "/tmp/.ZAP",  # noqa: S108
        ]
        if context.config.get("has_config_properties"):
            cmd.extend(["-configfile", "/work/in/zap-runtime.prop"])
        cmd.extend(["-autorun", "/work/in/zap.yaml"])
        return ExecutionSpec(
            tool_id="zap",
            image=self._pinned_image,
            command=tuple(cmd),
            env={
                "HOME": "/tmp",  # noqa: S108
                "_JAVA_OPTIONS": "-Djava.util.prefs.userRoot=/tmp/.java",
            },
            network_mode="scoped-http-egress",
            expected_outputs=("zap-report.json",),
            allowed_exit_codes=(0, 2),
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
        report_path = find_artifact_by_name(result.artifacts, "zap-report.json")
        if report_path is None or not report_path.exists():
            raise ValueError("Missing required ZAP report artifact: zap-report.json")
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as err:
            raise ValueError(f"Corrupted ZAP report JSON: {err}") from err
        if not isinstance(payload, dict) or not isinstance(payload.get("site"), list):
            raise ValueError("Invalid ZAP report JSON: missing 'site' array")

    def normalize(
        self,
        result: ExecutionResult,
        context: ToolContext | None = None,
    ) -> list[NormalizedFinding]:
        report_path = find_artifact_by_name(result.artifacts, "zap-report.json")
        if report_path is None:
            return []
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        return self.parse_json_report(payload)

    def parse_json_report(self, payload: dict[str, Any]) -> list[NormalizedFinding]:
        """Parse an OWASP ZAP traditional-json report dict into NormalizedFinding objects."""
        sites = payload.get("site") or []
        if not isinstance(sites, list):
            return []

        findings: list[NormalizedFinding] = []
        seen_fps: set[str] = set()
        for site in sites:
            if not isinstance(site, dict):
                continue
            alerts = site.get("alerts") or []
            if not isinstance(alerts, list):
                continue
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                plugin_id = str(alert.get("pluginid") or alert.get("alertRef") or "zap-alert")
                raw_name = str(alert.get("name") or alert.get("alert") or plugin_id)
                title = str(redact_text_secrets(_strip_html(raw_name)) or raw_name)
                desc = str(
                    redact_text_secrets(_strip_html(str(alert.get("desc") or title))) or title
                )
                raw_sol = str(alert.get("solution") or "")
                remediation = redact_text_secrets(_strip_html(raw_sol)) or None
                risk_code = str(alert.get("riskcode") or "1").strip()
                conf_code = str(alert.get("confidence") or "2").strip()
                severity = _RISK_CODE_MAP.get(risk_code, "medium")
                confidence = _CONFIDENCE_CODE_MAP.get(conf_code, "medium")
                cwe_raw = str(alert.get("cweid") or "").strip()
                cwe_ids: tuple[str, ...] = (
                    (f"CWE-{cwe_raw}",) if cwe_raw.isdigit() and int(cwe_raw) > 0 else ()
                )

                instances = alert.get("instances") or [{}]
                if not isinstance(instances, list) or not instances:
                    instances = [{}]
                for inst in instances:
                    if not isinstance(inst, dict):
                        continue
                    raw_uri = str(inst.get("uri") or site.get("@name") or "/")
                    clean_uri = str(redact_text_secrets(raw_uri) or raw_uri)
                    method = str(inst.get("method") or "GET").upper()[:16]
                    param = redact_text_secrets(str(inst.get("param") or "")) or None
                    evidence = redact_text_secrets(str(inst.get("evidence") or "")) or None
                    attack = redact_text_secrets(str(inst.get("attack") or "")) or None
                    locator_path = _normalize_uri_path(clean_uri)
                    rule_key = f"zap-{plugin_id}"
                    discriminator = f"{method}:{param or ''}"
                    fingerprint = compute_finding_fingerprint(
                        category="dast",
                        tool_id="zap",
                        rule_id=rule_key,
                        file_path=locator_path,
                        start_line=None,
                        discriminator=discriminator,
                    )
                    if fingerprint in seen_fps:
                        continue
                    seen_fps.add(fingerprint)

                    snippet_parts = [p for p in (evidence, attack) if p]
                    snippet = " | ".join(snippet_parts)[:500] if snippet_parts else None
                    findings.append(
                        NormalizedFinding(
                            scanner_tool_id="zap",
                            scanner_version="2.16.0",
                            category="dast",
                            rule_id=rule_key,
                            title=title,
                            description=desc,
                            severity=severity,
                            confidence=confidence,
                            file_path=locator_path,
                            start_line=None,
                            end_line=None,
                            start_column=None,
                            end_column=None,
                            cwe_ids=cwe_ids,
                            fingerprint=fingerprint,
                            code_snippet_redacted=snippet,
                            secret_redacted=bool(snippet and "[REDACTED" in snippet),
                            remediation=remediation,
                            http_method=method,
                            http_url=clean_uri,
                            http_param=param,
                            raw_metadata=scrub_finding_dict(
                                {
                                    "pluginid": plugin_id,
                                    "method": method,
                                    "uri": clean_uri,
                                    "param": param,
                                    "wascid": alert.get("wascid"),
                                }
                            ),
                        )
                    )
        return findings

    def cleanup(self, context: ToolContext) -> None:
        return None
