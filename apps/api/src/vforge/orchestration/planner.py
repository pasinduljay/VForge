"""Declarative scan plan builder for Phase 3-5 orchestration and runner jobs."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from vforge.errors import ValidationError
from vforge.models.domain import Asset, ScanProfile
from vforge.models.enums import LeaseRiskClass, ScanProfileStatus

_NOOP_IMAGE_DIGEST = "sha256:" + ("0" * 64)
_DEFAULT_DUMMY_RUNNER_IMAGE = (
    "vforge/dummy-scanner@sha256:"
    "0000000000000000000000000000000000000000000000000000000000000001"
)

_STRICTLY_ACTIVE_STAGE_RISK_MAP: dict[str, str] = {
    "active_dast": LeaseRiskClass.ACTIVE_HTTP.value,
    "active_web_testing": LeaseRiskClass.ACTIVE_HTTP.value,
    "active_http_scan": LeaseRiskClass.ACTIVE_HTTP.value,
    "active_probe": LeaseRiskClass.ACTIVE_HTTP.value,
    "api_fuzz": LeaseRiskClass.ACTIVE_HTTP.value,
    "auth_probe": LeaseRiskClass.ACTIVE_HTTP.value,
    "approved_exploit_validation": LeaseRiskClass.ACTIVE_HTTP.value,
    "network_discovery": LeaseRiskClass.NETWORK_SCAN.value,
    "network_scan": LeaseRiskClass.NETWORK_SCAN.value,
    "port_scan": LeaseRiskClass.NETWORK_SCAN.value,
    "service_enum": LeaseRiskClass.NETWORK_SCAN.value,
    "ai_eval": LeaseRiskClass.AI_SANDBOX.value,
    "llm_probe": LeaseRiskClass.AI_SANDBOX.value,
    "mcp_probe": LeaseRiskClass.AI_SANDBOX.value,
}

_CONDITIONAL_ACTIVE_STAGE_RISK_MAP: dict[str, str] = {
    "api_testing": LeaseRiskClass.ACTIVE_HTTP.value,
    "authenticated_testing": LeaseRiskClass.ACTIVE_HTTP.value,
    "tls_assessment": LeaseRiskClass.NETWORK_SCAN.value,
}


@dataclass(frozen=True)
class PlannedJobSpec:
    job_type: str
    tool_id: str
    tool_version: str
    image_digest: str
    adapter_version: str
    timeout_seconds: int
    max_attempts: int
    configuration: dict[str, Any]


@dataclass(frozen=True)
class PlannedStageSpec:
    stage_key: str
    stage_order: int
    stage_kind: str
    depends_on_stage_key: str | None
    requires_target_lease: bool
    lease_risk_class: str | None
    jobs: list[PlannedJobSpec]


@dataclass(frozen=True)
class DeclarativeScanPlan:
    runner_pool: str
    stages: list[PlannedStageSpec]
    manifest: dict[str, Any]


def classify_stage_lease(stage_token: str, *, passive_only: bool) -> tuple[bool, str | None]:
    """Determine whether a stage requires an exclusive target lease and its risk class."""
    normalized = stage_token.strip().lower()
    if normalized in _STRICTLY_ACTIVE_STAGE_RISK_MAP:
        if passive_only:
            raise ValidationError(
                f"Scan profile cannot request active stage '{normalized}' while passive_only=true"
            )
        return True, _STRICTLY_ACTIVE_STAGE_RISK_MAP[normalized]
    if normalized in _CONDITIONAL_ACTIVE_STAGE_RISK_MAP and not passive_only:
        return True, _CONDITIONAL_ACTIVE_STAGE_RISK_MAP[normalized]
    return False, None


def build_declarative_scan_plan(
    *,
    profile: ScanProfile,
    asset: Asset,
    execution_mode: str = "simulated",
    runner_pool_slug: str = "control-preflight",
    runner_image_digest: str | None = None,
    opengrep_image_digest: str | None = None,
    gitleaks_image_digest: str | None = None,
    syft_image_digest: str | None = None,
    grype_image_digest: str | None = None,
    checkov_image_digest: str | None = None,
    zap_image_digest: str | None = None,
    nuclei_image_digest: str | None = None,
    nmap_image_digest: str | None = None,
    testssl_image_digest: str | None = None,
    tool_versions: dict[str, str] | None = None,
    adapter_versions: dict[str, str] | None = None,
    allowed_image_digests: Sequence[str] | None = None,
    source_snapshot_present: bool = False,
    coverage_summary: dict[str, Any] | None = None,
    simulation_mode: str = "success",
    simulation_delay_ms: int = 0,
    timeout_seconds_override: int | None = None,
    max_attempts: int = 3,
) -> DeclarativeScanPlan:
    """Compile a ScanProfile + Asset into a declarative execution plan.

    In 'simulated' mode (Phase 3), jobs execute control-plane dummy tasks.
    In 'runner' mode (Phase 4), jobs require mTLS runner claim, signed
    manifests, and ephemeral container execution of pinned images.
    """
    if profile.status != ScanProfileStatus.ACTIVE.value:
        raise ValidationError(
            f"Scan profile '{profile.name}' is not active (status={profile.status})"
        )

    cfg = profile.configuration or {}
    raw_stages = cfg.get("stages") or []
    if not isinstance(raw_stages, list) or not raw_stages:
        raise ValidationError("Scan profile must define at least one stage")

    passive_only = bool(cfg.get("passive_only", True))
    profile_timeout = int(cfg.get("timeout_seconds", 900))
    effective_timeout = (
        max(1, min(int(timeout_seconds_override), 14400))
        if timeout_seconds_override is not None
        else max(1, min(profile_timeout, 14400))
    )

    is_runner_mode = execution_mode == "runner"
    effective_image = (
        runner_image_digest or _DEFAULT_DUMMY_RUNNER_IMAGE if is_runner_mode else _NOOP_IMAGE_DIGEST
    )
    extra_probe_url = str(cfg.get("probe_url", "")).strip()

    stages: list[PlannedStageSpec] = []

    preflight_job = PlannedJobSpec(
        job_type="runner_container_task" if is_runner_mode else "dummy_orchestration_task",
        tool_id="vforge-dummy-scanner" if is_runner_mode else "vforge-preflight-noop",
        tool_version="4.0.0-runner" if is_runner_mode else "3.0.0-preflight",
        image_digest=effective_image,
        adapter_version="phase4-dummy" if is_runner_mode else "phase3-noop",
        timeout_seconds=min(effective_timeout, 120),
        max_attempts=max(1, min(max_attempts, 5)),
        configuration={
            "simulated": not is_runner_mode,
            "execution_mode": execution_mode,
            "stage": "preflight",
            "network_profile": "none",
            "target_locator": asset.normalized_locator,
            "asset_type": asset.asset_type,
            "simulation_mode": "success",
            "simulation_delay_ms": 0,
        },
    )
    stages.append(
        PlannedStageSpec(
            stage_key="preflight",
            stage_order=0,
            stage_kind="preflight",
            depends_on_stage_key=None,
            requires_target_lease=False,
            lease_risk_class=None,
            jobs=[preflight_job],
        )
    )

    tv = tool_versions or {}
    av = adapter_versions or {}
    real_scanner_specs: dict[str, tuple[str, str, str | None, str]] = {
        "sast": (
            "opengrep",
            tv.get("opengrep", "1.33.1"),
            opengrep_image_digest,
            av.get("opengrep", "1.0.0"),
        ),
        "secrets": (
            "gitleaks",
            tv.get("gitleaks", "8.24.0"),
            gitleaks_image_digest,
            av.get("gitleaks", "1.0.0"),
        ),
        "sbom": ("syft", tv.get("syft", "1.57.1"), syft_image_digest, av.get("syft", "1.0.0")),
        "sca": ("grype", tv.get("grype", "0.121.3"), grype_image_digest, av.get("grype", "1.0.0")),
        "iac": (
            "checkov",
            tv.get("checkov", "3.2.435"),
            checkov_image_digest,
            av.get("checkov", "1.0.0"),
        ),
    }
    normalized_stages: list[str] = []
    raw_cleaned = [str(s).strip().lower() for s in raw_stages if str(s).strip()]
    for stage_token in raw_cleaned:
        if (
            is_runner_mode
            and stage_token == "sca"  # noqa: S105
            and "sbom" not in normalized_stages
        ):
            normalized_stages.append("sbom")
        if (
            is_runner_mode
            and stage_token == "active_dast"  # noqa: S105
            and "passive_dast" not in normalized_stages
        ):
            normalized_stages.append("passive_dast")
        if stage_token not in normalized_stages:
            normalized_stages.append(stage_token)

    prev_key = "preflight"
    has_real_scanner = False
    has_supply_chain = False
    has_dast = False
    for idx, stage_token in enumerate(normalized_stages, start=1):
        stage_key = f"stage_{idx}_{stage_token}"
        requires_lease, risk_class = classify_stage_lease(
            stage_token,
            passive_only=passive_only,
        )
        tool_id = "vforge-dummy-scanner" if is_runner_mode else f"vforge-dummy-{stage_token}"
        tool_version = "4.0.0-runner" if is_runner_mode else "3.0.0-preflight"
        job_image_digest = effective_image
        adapter_version = "phase4-dummy" if is_runner_mode else "phase3-noop"

        if is_runner_mode and stage_token in real_scanner_specs:
            spec_tool_id, spec_tool_version, spec_digest, spec_adapter = real_scanner_specs[
                stage_token
            ]
            if allowed_image_digests is None or (
                spec_digest and spec_digest in allowed_image_digests
            ):
                if not source_snapshot_present:
                    raise ValidationError(
                        f"Runner stage '{stage_token}' requires a valid source_snapshot_id"
                    )
                has_real_scanner = True
                if stage_token in {"sbom", "sca", "iac"}:
                    has_supply_chain = True
                tool_id = spec_tool_id
                tool_version = spec_tool_version
                job_image_digest = spec_digest or effective_image
                adapter_version = spec_adapter

        dast_specs: dict[str, tuple[str, str, str | None, str]] = {
            "passive_dast": (
                "zap",
                tv.get("zap", "2.16.0"),
                zap_image_digest,
                av.get("zap", "1.0.0"),
            ),
            "active_dast": (
                ("zap", tv.get("zap", "2.16.0"), zap_image_digest, av.get("zap", "1.0.0"))
                if str(cfg.get("dast_tool", "")).strip().lower() == "zap"
                else (
                    "nuclei",
                    tv.get("nuclei", "3.11.1"),
                    nuclei_image_digest,
                    av.get("nuclei", "1.0.0"),
                )
            ),
            "network_discovery": (
                "nmap",
                tv.get("nmap", "7.98"),
                nmap_image_digest,
                av.get("nmap", "1.0.0"),
            ),
            "network_scan": (
                "nmap",
                tv.get("nmap", "7.98"),
                nmap_image_digest,
                av.get("nmap", "1.0.0"),
            ),
            "tls_assessment": (
                "testssl",
                tv.get("testssl", "3.2.5"),
                testssl_image_digest,
                av.get("testssl", "1.0.0"),
            ),
            "tls_scan": (
                "testssl",
                tv.get("testssl", "3.2.5"),
                testssl_image_digest,
                av.get("testssl", "1.0.0"),
            ),
        }
        if is_runner_mode and stage_token in dast_specs:
            dast_tool_id, dast_tool_version, dast_digest, dast_adapter = dast_specs[stage_token]
            if allowed_image_digests is None or (
                dast_digest and dast_digest in allowed_image_digests
            ):
                has_real_scanner = True
                has_dast = True
                tool_id = dast_tool_id
                tool_version = dast_tool_version
                job_image_digest = dast_digest or effective_image
                adapter_version = dast_adapter

        job_configuration: dict[str, Any] = {
            "simulated": not is_runner_mode,
            "execution_mode": execution_mode,
            "stage": stage_token,
            "probe_url": extra_probe_url,
            "target_locator": asset.normalized_locator,
            "asset_type": asset.asset_type,
            "requires_target_lease": requires_lease,
            "lease_risk_class": risk_class,
            "simulation_mode": simulation_mode,
            "simulation_delay_ms": simulation_delay_ms,
        }
        if stage_token == "iac":  # noqa: S105
            job_configuration["enable_custom_policies"] = bool(
                cfg.get("enable_custom_policies", False)
            )
        if stage_token in {
            "passive_dast",
            "active_dast",
            "network_discovery",
            "network_scan",
            "tls_assessment",
            "tls_scan",
        }:
            if cfg.get("auth_profile_id"):
                job_configuration["auth_profile_id"] = str(cfg["auth_profile_id"])
            if cfg.get("openapi_spec"):
                job_configuration["openapi_spec"] = cfg["openapi_spec"]
            if cfg.get("health_check_path"):
                job_configuration["health_check_path"] = str(cfg["health_check_path"])
            if cfg.get("max_rps") is not None:
                job_configuration["max_rps"] = int(cfg["max_rps"])
            if cfg.get("dast_tool"):
                job_configuration["dast_tool"] = str(cfg["dast_tool"])

        job = PlannedJobSpec(
            job_type="runner_container_task" if is_runner_mode else "dummy_orchestration_task",
            tool_id=tool_id,
            tool_version=tool_version,
            image_digest=job_image_digest,
            adapter_version=adapter_version,
            timeout_seconds=effective_timeout,
            max_attempts=max(1, min(max_attempts, 5)),
            configuration=job_configuration,
        )
        stages.append(
            PlannedStageSpec(
                stage_key=stage_key,
                stage_order=idx,
                stage_kind=stage_token,
                depends_on_stage_key=prev_key,
                requires_target_lease=requires_lease,
                lease_risk_class=risk_class,
                jobs=[job],
            )
        )
        prev_key = stage_key

    phase_num = (
        7
        if has_dast
        else (6 if has_supply_chain else (5 if has_real_scanner else (4 if is_runner_mode else 3)))
    )
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "phase": phase_num,
        "scanners_enabled": has_real_scanner,
        "supply_chain_enabled": has_supply_chain,
        "dast_enabled": has_dast,
        "simulated": not is_runner_mode,
        "execution_mode": execution_mode,
        "runner_pool": runner_pool_slug,
        "stages": [
            {
                "stage_key": s.stage_key,
                "stage_order": s.stage_order,
                "stage_kind": s.stage_kind,
                "depends_on_stage_key": s.depends_on_stage_key,
                "requires_target_lease": s.requires_target_lease,
                "lease_risk_class": s.lease_risk_class,
                "job_count": len(s.jobs),
            }
            for s in stages
        ],
    }
    if coverage_summary is not None:
        manifest["coverage_summary"] = coverage_summary

    return DeclarativeScanPlan(
        runner_pool=runner_pool_slug,
        stages=stages,
        manifest=manifest,
    )
