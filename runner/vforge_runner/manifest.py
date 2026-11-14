"""Standalone Ed25519 manifest signature, expiry, digest, and security verification."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_IMAGE_WITH_DIGEST_RE = re.compile(
    r"^(?!.*:latest@)[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class VerifiedJobManifest:
    """Validated job manifest trusted for isolated execution on the Runner Agent."""

    job_id: str
    scan_run_id: str
    organization_id: str
    image: str
    tool_id: str
    timeout_seconds: int
    cpu: int
    memory_mb: int
    pids_limit: int
    max_output_bytes: int
    network_profile: str
    allowed_targets: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    pinned_ips: tuple[str, ...]
    allow_private_networks: bool
    probe_url: str
    raw_manifest: dict[str, Any]
    source_snapshot_id: str | None = None
    source_snapshot_sha256: str | None = None
    enable_custom_policies: bool = False
    requires_sbom_input: bool = False
    auth_profile_id: str | None = None
    has_openapi_spec: bool = False
    health_check_path: str | None = None
    dast_tool: str | None = None
    max_requests_per_second: int = 10
    target_locator: str | None = None
    target_type: str | None = None


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _verify_signed_payload(
    *,
    payload: dict[str, Any],
    expected_sha256: str,
    signing_key_id: str,
    signature: str,
    trusted_public_keyring_json: str,
) -> None:
    """Verify canonical JSON SHA-256 and Ed25519 signature against trusted public keyring."""
    computed_sha256 = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    if not hmac.compare_digest(computed_sha256, expected_sha256.lower()):
        raise ValueError("Signed payload SHA-256 mismatch")

    try:
        keyring = json.loads(trusted_public_keyring_json)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid trusted public keyring JSON") from exc

    if not isinstance(keyring, dict) or signing_key_id not in keyring:
        raise ValueError("Unknown manifest signing key ID")

    key_entry = keyring[signing_key_id]
    if not isinstance(key_entry, dict) or key_entry.get("status") not in {"active", "verify_only"}:
        raise ValueError("Manifest signing key is revoked or invalid")

    pub = serialization.load_pem_public_key(
        str(key_entry.get("public_key_pem", "")).encode("utf-8")
    )
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("Manifest signing key must be Ed25519")

    try:
        pub.verify(_b64url_decode(signature), computed_sha256.encode("ascii"))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Manifest Ed25519 signature invalid") from exc


def verify_signed_allowlist(
    *,
    payload: dict[str, Any],
    expected_sha256: str,
    signing_key_id: str,
    signature: str,
    trusted_public_keyring_json: str,
) -> list[str]:
    """Verify Control-Plane signed dynamic image digest allowlist payload."""
    _verify_signed_payload(
        payload=payload,
        expected_sha256=expected_sha256,
        signing_key_id=signing_key_id,
        signature=signature,
        trusted_public_keyring_json=trusted_public_keyring_json,
    )
    raw = payload.get("allowed_image_digests")
    if not isinstance(raw, list):
        raise ValueError("Signed allowlist payload missing list 'allowed_image_digests'")
    verified_digests: list[str] = []
    for item in raw:
        candidate = str(item).strip()
        if (
            not candidate
            or ":latest@" in candidate.lower()
            or candidate.lower().endswith(":latest")
        ):
            raise ValueError("Signed allowlist contains invalid or mutable :latest digest")
        if not _IMAGE_WITH_DIGEST_RE.match(candidate):
            raise ValueError(f"Signed allowlist entry invalid: {candidate}")
        verified_digests.append(candidate)
    return verified_digests


def verify_signed_job_manifest(
    *,
    manifest: dict[str, Any],
    expected_sha256: str,
    signing_key_id: str,
    signature: str,
    trusted_public_keyring_json: str,
    allowed_image_digests: list[str] | tuple[str, ...],
    expected_organization_id: str | None = None,
    now: datetime | None = None,
) -> VerifiedJobManifest:
    """Fail closed if signature, expiry, image digest allowlist, or security flags fail."""
    _verify_signed_payload(
        payload=manifest,
        expected_sha256=expected_sha256,
        signing_key_id=signing_key_id,
        signature=signature,
        trusted_public_keyring_json=trusted_public_keyring_json,
    )

    meta = manifest.get("metadata") or {}
    org_id = str(meta.get("organizationId", "")).strip()
    if expected_organization_id and org_id != expected_organization_id:
        raise ValueError("Job manifest organization mismatch")

    try:
        expires_at = datetime.fromisoformat(str(meta.get("expiresAt", "")))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
    except ValueError as exc:
        raise ValueError("Job manifest missing valid expiresAt") from exc

    if (now or datetime.now(UTC)) >= expires_at:
        raise ValueError("Job manifest has expired")

    exec_block = manifest.get("execution") or {}
    image = str(exec_block.get("image", "")).strip()
    if not _IMAGE_WITH_DIGEST_RE.match(image):
        raise ValueError("Job manifest image must use an immutable @sha256 digest")

    allowed_set = {entry.strip() for entry in allowed_image_digests if entry.strip()}
    if image not in allowed_set:
        raise ValueError(f"Image '{image}' is not in the runner's approved digest allowlist")

    sec = manifest.get("security") or {}
    if (
        sec.get("readOnlyRootFilesystem") is not True
        or sec.get("runAsNonRoot") is not True
        or sec.get("noNewPrivileges") is not True
        or sec.get("dropCapabilities") != ["ALL"]
    ):
        raise ValueError("Job manifest violates mandatory hardened container security posture")

    limits = manifest.get("limits") or {}
    net = manifest.get("network") or {}
    net_profile = str(net.get("profile", "none")).strip()
    if net_profile not in {"none", "scoped-http-egress"}:
        raise ValueError(f"Unsupported network profile: {net_profile}")

    inputs_block = manifest.get("inputs") or {}
    source_snap_id = str(inputs_block.get("sourceSnapshotId") or "").strip() or None
    source_snap_sha = str(inputs_block.get("sourceSnapshotSha256") or "").strip() or None
    tool_id = str(exec_block.get("toolId", "vforge-dummy-scanner"))
    enable_custom_policies = bool(exec_block.get("enableCustomPolicies", False))
    requires_sbom_input = bool(exec_block.get("requiresSbomInput", False)) or tool_id == "grype"
    auth_profile_id = str(exec_block.get("authProfileId") or "").strip() or None
    has_openapi_spec = bool(exec_block.get("hasOpenapiSpec", False))
    health_check_path = str(exec_block.get("healthCheckPath") or "").strip() or None
    dast_tool = str(exec_block.get("dastTool") or "").strip() or None
    max_rps = max(1, min(int(limits.get("maxRequestsPerSecond", 10)), 100))
    target_locator = str(inputs_block.get("canonicalLocator") or "").strip() or None
    target_type = str(inputs_block.get("targetType") or "").strip() or None

    return VerifiedJobManifest(
        job_id=str(meta.get("jobId", "")),
        scan_run_id=str(meta.get("scanRunId", "")),
        organization_id=org_id,
        image=image,
        tool_id=tool_id,
        timeout_seconds=max(1, min(int(limits.get("timeoutSeconds", 300)), 14400)),
        cpu=max(1, min(int(limits.get("cpu", 1)), 8)),
        memory_mb=max(64, min(int(limits.get("memoryMb", 512)), 16384)),
        pids_limit=max(16, min(int(limits.get("pidsLimit", 64)), 2048)),
        max_output_bytes=max(1024, int(limits.get("maxOutputMb", 25)) * 1024 * 1024),
        network_profile=net_profile,
        allowed_targets=tuple(str(x) for x in (net.get("allowedTargets") or [])),
        allowed_ports=tuple(int(p) for p in (net.get("allowedPorts") or [])),
        pinned_ips=tuple(str(ip) for ip in (net.get("pinnedIps") or [])),
        allow_private_networks=bool(net.get("allowPrivateNetworks", False)),
        probe_url=str(net.get("probeUrl", "") or "").strip(),
        raw_manifest=manifest,
        source_snapshot_id=source_snap_id,
        source_snapshot_sha256=source_snap_sha,
        enable_custom_policies=enable_custom_policies,
        requires_sbom_input=requires_sbom_input,
        auth_profile_id=auth_profile_id,
        has_openapi_spec=has_openapi_spec,
        health_check_path=health_check_path,
        dast_tool=dast_tool,
        max_requests_per_second=max_rps,
        target_locator=target_locator,
        target_type=target_type,
    )
