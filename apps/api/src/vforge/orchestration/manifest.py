"""Ed25519-signed ExecutionManifest builder and verifier for Phase 4 Runner Jobs."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from vforge.config import Settings
from vforge.errors import ForbiddenError, ValidationError
from vforge.models.domain import ScopeSnapshot
from vforge.models.orchestration import RunnerJob, ScanRun
from vforge.security.signing import (
    SignedSnapshotBundle,
    SigningKeyRecord,
    SnapshotSigner,
    parse_public_keyring_json,
)

_IMAGE_WITH_DIGEST_RE = re.compile(
    r"^(?!.*:latest@)[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$",
    re.IGNORECASE,
)
_EGRESS_STAGE_TOKENS = frozenset(
    {
        "discovery",
        "dast_passive",
        "dast_active",
        "passive_dast",
        "active_dast",
        "active_web_testing",
        "passive_web_testing",
        "active_http_scan",
        "active_probe",
        "api_testing",
        "api_fuzz",
        "authenticated_testing",
        "tls_assessment",
        "network_discovery",
        "network_scan",
        "port_scan",
        "service_enum",
        "approved_exploit_validation",
    }
)


@dataclass(frozen=True, slots=True)
class SignedManifestEnvelope:
    """Canonical job manifest paired with its Ed25519 signature metadata."""

    manifest: dict[str, Any]
    bundle: SignedSnapshotBundle
    expires_at: datetime


def validate_pinned_image_digest(image: str, allowed_digests: list[str] | tuple[str, ...]) -> str:
    """Enforce immutable @sha256 digest format and explicit registry allowlist membership."""
    cleaned = image.strip()
    if ":latest@" in cleaned.lower() or cleaned.lower().endswith(":latest"):
        raise ValidationError(
            "Execution image must be formatted as '<repository>@sha256:<64-hex>' without ':latest'"
        )
    if not _IMAGE_WITH_DIGEST_RE.match(cleaned):
        raise ValidationError(
            "Execution image must be formatted as '<repository>@sha256:<64-hex>' without ':latest'"
        )
    allowed_set = {entry.strip() for entry in allowed_digests if entry.strip()}
    if cleaned not in allowed_set:
        raise ForbiddenError("Execution image digest is not in the approved runner allowlist")
    return cleaned


def resolve_network_profile(stage_kind: str, configured_profile: str | None = None) -> str:
    """Resolve network isolation profile: static jobs run 'none', HTTP jobs run scoped egress."""
    if configured_profile in {"none", "scoped-http-egress"}:
        return configured_profile
    if stage_kind.strip().lower() in _EGRESS_STAGE_TOKENS:
        return "scoped-http-egress"
    return "none"


def build_execution_manifest(
    *,
    run: ScanRun,
    job: RunnerJob,
    snapshot: ScopeSnapshot,
    settings: Settings,
    expires_at: datetime,
    allowed_image_digests: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Construct the canonical v1 RunnerJob ExecutionManifest (Architecture §9.2)."""
    effective_allowlist = (
        allowed_image_digests
        if allowed_image_digests is not None
        else settings.runner_allowed_image_digests
    )
    image = validate_pinned_image_digest(job.image_digest, effective_allowlist)
    job_cfg = job.job_configuration or {}
    target_snap = run.target_snapshot or {}
    stage_kind = str(job_cfg.get("stage", "")).strip().lower()
    net_profile = resolve_network_profile(
        stage_kind,
        str(job_cfg.get("network_profile", "")).strip() or None,
    )

    pinned_ips = [str(ip) for ip in (snapshot.resolved_ips or []) if str(ip).strip()]
    allowed_ports = [int(p) for p in (snapshot.allowed_ports or [443])]
    allow_private = bool((snapshot.scope_definition or {}).get("allow_private_networks", False))
    target_asset_id = str(target_snap.get("asset_id") or snapshot.asset_id)

    return {
        "apiVersion": "vforge.io/v1",
        "kind": "RunnerJob",
        "metadata": {
            "jobId": str(job.id),
            "scanRunId": str(run.id),
            "organizationId": str(run.organization_id),
            "stageKey": stage_kind or "task",
            "expiresAt": expires_at.astimezone(UTC).isoformat(),
            "attempt": int(job.attempt_count),
        },
        "execution": {
            "toolId": job.tool_id,
            "toolVersion": job.tool_version,
            "image": image,
            "adapterVersion": job.adapter_version,
            "profile": str(job_cfg.get("profile_mode", "phase4-dummy")),
            "enableCustomPolicies": bool(job_cfg.get("enable_custom_policies", False)),
            "requiresSbomInput": job.tool_id == "grype",
            "authProfileId": str(run.auth_profile_id) if run.auth_profile_id else None,
            "hasOpenapiSpec": bool(job_cfg.get("openapi_spec")),
            "healthCheckPath": str(job_cfg.get("health_check_path", "")).strip() or None,
            "dastTool": str(job_cfg.get("dast_tool", "")).strip() or None,
        },
        "inputs": {
            "targetAssetIds": [target_asset_id],
            "targetSnapshotId": str(snapshot.id),
            "targetSnapshotHash": snapshot.payload_sha256,
            "canonicalLocator": snapshot.canonical_locator,
            "targetType": snapshot.target_type,
            "sourceSnapshotId": str(run.source_snapshot_id) if run.source_snapshot_id else None,
            "sourceSnapshotSha256": run.source_snapshot_hash,
        },
        "limits": {
            "cpu": int(job_cfg.get("cpu_limit", 1)),
            "memoryMb": int(job_cfg.get("memory_limit_mb", 512)),
            "pidsLimit": int(job_cfg.get("pids_limit", 64)),
            "timeoutSeconds": int(job.timeout_seconds),
            "maxOutputMb": int(job_cfg.get("max_output_mb", 25)),
            "maxHttpRequests": int(job_cfg.get("max_http_requests", 1000)),
            "maxRequestsPerSecond": int(job_cfg.get("max_rps", 2)),
        },
        "network": {
            "profile": net_profile,
            "allowedAssetIds": [target_asset_id],
            "allowedTargets": [snapshot.canonical_locator] if net_profile != "none" else [],
            "allowedPorts": allowed_ports if net_profile != "none" else [],
            "pinnedIps": pinned_ips if net_profile != "none" else [],
            "allowPrivateNetworks": allow_private,
            "probeUrl": str(job_cfg.get("probe_url") or snapshot.canonical_locator)
            if net_profile != "none"
            else "",
        },
        "security": {
            "readOnlyRootFilesystem": True,
            "runAsNonRoot": True,
            "dropCapabilities": ["ALL"],
            "noNewPrivileges": True,
            "approvalId": str(run.authorization_id),
        },
    }


def sign_execution_manifest(
    *,
    run: ScanRun,
    job: RunnerJob,
    snapshot: ScopeSnapshot,
    settings: Settings,
    signer: SnapshotSigner | None = None,
    now: datetime | None = None,
    allowed_image_digests: list[str] | tuple[str, ...] | None = None,
) -> SignedManifestEnvelope:
    """Build and Ed25519-sign a canonical ExecutionManifest for a runner-mode job."""
    current = now or datetime.now(UTC)
    ttl = max(60, min(settings.runner_manifest_ttl_seconds, job.timeout_seconds + 300))
    expires_at = current + timedelta(seconds=ttl)
    manifest = build_execution_manifest(
        run=run,
        job=job,
        snapshot=snapshot,
        settings=settings,
        expires_at=expires_at,
        allowed_image_digests=allowed_image_digests,
    )
    active_signer = signer or SnapshotSigner.from_settings(settings)
    bundle = active_signer.sign_payload(manifest)
    return SignedManifestEnvelope(manifest=manifest, bundle=bundle, expires_at=expires_at)


def verify_execution_manifest(
    *,
    manifest: dict[str, Any],
    expected_sha256: str,
    signing_key_id: str,
    signature: str,
    public_keyring_json: str,
    allowed_image_digests: list[str] | tuple[str, ...],
    expected_org_id: uuid.UUID | None = None,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Independently verify signed ExecutionManifest signature, expiry, image digest, & posture."""
    try:
        keyring: dict[str, SigningKeyRecord] = parse_public_keyring_json(public_keyring_json)
    except (ValueError, TypeError):
        return False, "invalid_keyring"

    # Public-only verifier (never needs private key)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    verifier = SnapshotSigner(
        active_key_id="__verify_only__",
        private_key=Ed25519PrivateKey.generate(),
        keyring=keyring,
    )
    sig_res = verifier.verify_payload(
        payload=manifest,
        expected_sha256=expected_sha256,
        signing_key_id=signing_key_id,
        signature_algorithm="Ed25519",
        signature=signature,
    )
    if not sig_res.valid:
        return False, sig_res.reason

    meta = manifest.get("metadata") or {}
    if expected_org_id is not None and str(meta.get("organizationId", "")) != str(expected_org_id):
        return False, "tenant_mismatch"

    raw_exp = meta.get("expiresAt")
    try:
        exp_dt = datetime.fromisoformat(str(raw_exp))
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return False, "invalid_expiry"

    if (now or datetime.now(UTC)) >= exp_dt:
        return False, "manifest_expired"

    exec_block = manifest.get("execution") or {}
    try:
        validate_pinned_image_digest(str(exec_block.get("image", "")), allowed_image_digests)
    except (ValidationError, ForbiddenError):
        return False, "unapproved_image_digest"

    sec = manifest.get("security") or {}
    if (
        sec.get("readOnlyRootFilesystem") is not True
        or sec.get("runAsNonRoot") is not True
        or sec.get("noNewPrivileges") is not True
        or sec.get("dropCapabilities") != ["ALL"]
    ):
        return False, "unsafe_security_posture"

    return True, "valid"
