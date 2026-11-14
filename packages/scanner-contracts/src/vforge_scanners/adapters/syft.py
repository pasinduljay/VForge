"""Pinned Syft offline SBOM generator adapter (CycloneDX JSON + SPDX JSON)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

from vforge_scanners.sdk import (
    ExecutionResult,
    ExecutionSpec,
    NormalizedFinding,
    ToolContext,
    ToolMetadata,
    find_artifact_by_name,
    normalize_relative_source_path,
)

DEFAULT_SYFT_IMAGE = (
    "anchore/syft@sha256:03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060"
)
_SAFE_SOURCE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _sanitize_source_name(raw_name: Any) -> str:
    cleaned = _SAFE_SOURCE_NAME_RE.sub("-", str(raw_name or "")).strip("-._")
    return (cleaned or "source-snapshot")[:80]


@dataclass(frozen=True, slots=True)
class SbomComponentRecord:
    """Normalized software component entry extracted from CycloneDX JSON."""

    name: str
    version: str
    purl: str | None
    component_type: str
    ecosystem: str | None = None
    found_by: str | None = None
    locations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SbomDocumentSummary:
    """Parsed metadata and bounded component index for an immutable Syft SBOM."""

    bom_format: str
    spec_version: str
    serial_number: str | None
    tool_version: str
    component_count: int
    components: tuple[SbomComponentRecord, ...] = field(default_factory=tuple)


class SyftAdapter:
    """ScannerAdapter contract for deterministic offline CycloneDX & SPDX SBOM generation."""

    def __init__(self, *, pinned_image: str = DEFAULT_SYFT_IMAGE) -> None:
        self._pinned_image = pinned_image

    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            tool_id="syft",
            tool_version="1.57.1",
            adapter_version="0.1.0",
            capabilities=("sbom", "cyclonedx-json", "spdx-json"),
            risk_class="static",
            supported_input_types=("source_snapshot",),
            output_formats=("cyclonedx-json", "spdx-json"),
            pinned_image=self._pinned_image,
        )

    def validate(self, context: ToolContext) -> None:
        if not context.job_id.strip() or not context.scan_run_id.strip():
            raise ValueError("ToolContext requires non-empty job_id and scan_run_id")
        if not context.input_paths:
            raise ValueError("SyftAdapter requires a validated read-only source path")

    def build_execution_spec(self, context: ToolContext) -> ExecutionSpec:
        self.validate(context)
        input_path = context.input_paths[0].as_posix()
        cdx_out = (context.output_dir / "sbom.cdx.json").as_posix()
        spdx_out = (context.output_dir / "sbom.spdx.json").as_posix()
        source_name = _sanitize_source_name(
            context.config.get("source_name") or f"run-{context.scan_run_id}"
        )
        command: tuple[str, ...] = (
            "scan",
            f"dir:{input_path}",
            "--output",
            f"cyclonedx-json={cdx_out}",
            "--output",
            f"spdx-json={spdx_out}",
            "--source-name",
            source_name,
        )
        return ExecutionSpec(
            tool_id="syft",
            image=self._pinned_image,
            command=command,
            env={
                "SYFT_CHECK_FOR_APP_UPDATE": "false",
                "HOME": "/tmp",  # noqa: S108
            },
            network_mode="none",
            expected_outputs=("sbom.cdx.json", "sbom.spdx.json"),
            allowed_exit_codes=(0,),
            read_only_root=True,
        )

    def execute(self, context: ToolContext) -> ExecutionResult:
        """Execute syft CLI safely with shell=False when invoked locally in test harnesses."""
        spec = self.build_execution_spec(context)
        context.output_dir.mkdir(parents=True, exist_ok=True)
        timeout = int(context.limits.get("timeout_seconds", 300))
        exe = shutil.which("syft") or "syft"
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
                error_code="syft_timeout",
                error_message_sanitized="Syft timed out during SBOM generation",
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
            raise ValueError(result.error_message_sanitized or "Syft execution did not complete")
        cdx_path = find_artifact_by_name(result.artifacts, "sbom.cdx.json")
        if cdx_path is None:
            raise ValueError("Syft execution completed without sbom.cdx.json output")
        parsed = json.loads(cdx_path.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict) or parsed.get("bomFormat") != "CycloneDX":
            raise ValueError("Syft sbom.cdx.json output is not a valid CycloneDX JSON document")

    def parse_cyclonedx(self, payload: dict[str, Any]) -> SbomDocumentSummary:
        """Parse and validate a CycloneDX JSON document emitted by Syft."""
        if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
            raise ValueError("Expected CycloneDX JSON object with bomFormat='CycloneDX'")
        raw_components = payload.get("components")
        if not isinstance(raw_components, list):
            raw_components = []

        parsed_components: list[SbomComponentRecord] = []
        for entry in raw_components:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            if not name:
                continue
            version = str(entry.get("version") or "unknown").strip()
            purl_raw = entry.get("purl")
            purl = str(purl_raw).strip() if purl_raw else None
            comp_type = str(entry.get("type") or "library").strip()
            ecosystem: str | None = None
            found_by: str | None = None
            locations: list[str] = []
            for prop in entry.get("properties") or []:
                if not isinstance(prop, dict):
                    continue
                pname = str(prop.get("name") or "")
                pval = str(prop.get("value") or "").strip()
                if not pval:
                    continue
                if pname == "syft:package:type":
                    ecosystem = pval
                elif pname == "syft:package:foundBy":
                    found_by = pval
                elif pname.startswith("syft:location:") and pname.endswith(":path"):
                    norm_loc = normalize_relative_source_path(pval)
                    if norm_loc not in locations:
                        locations.append(norm_loc)
            parsed_components.append(
                SbomComponentRecord(
                    name=name,
                    version=version,
                    purl=purl,
                    component_type=comp_type,
                    ecosystem=ecosystem,
                    found_by=found_by,
                    locations=tuple(locations[:5]),
                )
            )

        parsed_components.sort(key=lambda c: (c.purl or "", c.name, c.version))
        return SbomDocumentSummary(
            bom_format="CycloneDX",
            spec_version=str(payload.get("specVersion") or "1.6"),
            serial_number=(
                str(payload["serialNumber"]).strip() if payload.get("serialNumber") else None
            ),
            tool_version="1.57.1",
            component_count=len(parsed_components),
            components=tuple(parsed_components),
        )

    def normalize(self, result: ExecutionResult) -> list[NormalizedFinding]:
        """SBOM generation emits package inventory artifacts rather than vulnerability findings."""
        self.validate_outputs(result)
        return []

    def cleanup(self, context: ToolContext) -> None:
        return None
