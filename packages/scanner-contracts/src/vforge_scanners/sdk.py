"""Shared ScannerAdapter SDK protocol, execution specs, and normalized finding models."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

RiskClass = Literal["static", "passive", "active", "network", "destructive"]
SeverityLevel = Literal["critical", "high", "medium", "low", "info", "unknown"]
ConfidenceLevel = Literal["high", "medium", "low"]


@dataclass(frozen=True, slots=True)
class ToolMetadata:
    """Immutable metadata describing a pinned VForge scanner engine & adapter."""

    tool_id: str
    tool_version: str
    adapter_version: str
    capabilities: tuple[str, ...]
    risk_class: RiskClass
    supported_input_types: tuple[str, ...]
    output_formats: tuple[str, ...]
    pinned_image: str


@dataclass(frozen=True, slots=True)
class ToolContext:
    """Validated execution context handed to a ScannerAdapter."""

    job_id: str
    scan_run_id: str
    workspace: Path
    input_paths: tuple[Path, ...]
    output_dir: Path
    config: dict[str, Any] = field(default_factory=dict)
    limits: dict[str, Any] = field(default_factory=dict)
    approved_scope: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ExecutionSpec:
    """Restricted internal execution model preventing raw shell or user-supplied flags."""

    tool_id: str
    image: str
    command: tuple[str, ...]
    env: dict[str, str]
    network_mode: Literal["none", "scoped-http-egress"]
    expected_outputs: tuple[str, ...]
    allowed_exit_codes: tuple[int, ...] = (0,)
    read_only_root: bool = True


@dataclass(slots=True)
class ExecutionResult:
    """Captured bounded outputs and metrics from an isolated scanner execution."""

    status: Literal["completed", "failed", "timed_out", "cancelled"]
    exit_code: int | None
    artifacts: list[Path] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    error_message_sanitized: str | None = None


@dataclass(frozen=True, slots=True)
class NormalizedFinding:
    """Canonical sanitized observation produced by an adapter's normalize() pass."""

    scanner_tool_id: str
    scanner_version: str
    category: Literal["sast", "secret", "sca", "iac", "dast", "network"]
    rule_id: str
    title: str
    description: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    file_path: str
    start_line: int | None
    end_line: int | None
    start_column: int | None
    end_column: int | None
    cwe_ids: tuple[str, ...]
    fingerprint: str
    code_snippet_redacted: str | None = None
    secret_redacted: bool = False
    remediation: str | None = None
    purl: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    cve_id: str | None = None
    iac_resource: str | None = None
    http_method: str | None = None
    http_url: str | None = None
    http_param: str | None = None
    network_port: int | None = None
    network_protocol: str | None = None
    raw_metadata: dict[str, Any] = field(default_factory=dict)


class ScannerAdapter(Protocol):
    """Unified Phase 5+ contract implemented by every scanner integration."""

    def metadata(self) -> ToolMetadata: ...

    def validate(self, context: ToolContext) -> None: ...

    def build_execution_spec(self, context: ToolContext) -> ExecutionSpec: ...

    def execute(self, context: ToolContext) -> ExecutionResult: ...

    def validate_outputs(self, result: ExecutionResult) -> None: ...

    def normalize(self, result: ExecutionResult) -> list[NormalizedFinding]: ...

    def cleanup(self, context: ToolContext) -> None: ...


def compute_finding_fingerprint(
    *,
    category: str,
    tool_id: str,
    rule_id: str,
    file_path: str,
    start_line: int | None,
    discriminator: str = "",
) -> str:
    """Produce a deterministic SHA-256 finding fingerprint independent of absolute paths."""
    clean_path = file_path.replace("\\", "/").lstrip("./")
    line_part = str(start_line) if start_line is not None else "0"
    raw = "|".join(
        [category.strip().lower(), tool_id, rule_id, clean_path, line_part, discriminator]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def normalize_relative_source_path(raw_path: str) -> str:
    """Strip container mount prefixes (/work/in/source/) and normalize slashes."""
    normalized = str(raw_path or "").replace("\\", "/")
    for prefix in ("/work/in/source/", "/work/in/", "work/in/source/", "./"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
    while normalized.startswith("/"):
        normalized = normalized[1:]
    if ".." in Path(normalized).parts:
        return "[invalid-path]"
    return normalized or "unknown"


def find_artifact_by_name(artifacts: list[Path], filename: str) -> Path | None:
    """Return the first existing file artifact matching filename."""
    for artifact in artifacts:
        if artifact.name == filename and artifact.is_file():
            return artifact
    return None
