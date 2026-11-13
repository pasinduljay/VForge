"""Cryptographic signing and key-rotation verification for immutable scope snapshots."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vforge.config import Settings

KeyStatus = Literal["active", "verify_only", "revoked"]


@dataclass(frozen=True, slots=True)
class SigningKeyRecord:
    """Public verification key entry in the snapshot key registry."""

    key_id: str
    public_key: Ed25519PublicKey
    status: KeyStatus


@dataclass(frozen=True, slots=True)
class SignedSnapshotBundle:
    """Signed snapshot metadata generated at authorization approval time."""

    payload_sha256: str
    signing_key_id: str
    signature_algorithm: str
    signature: str


@dataclass(frozen=True, slots=True)
class SnapshotVerificationResult:
    """Verification outcome for an immutable scope snapshot."""

    valid: bool
    reason: str
    computed_sha256: str
    signing_key_id: str
    key_status: str | None = None


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize snapshot payload into deterministic UTF-8 JSON bytes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_payload_sha256(payload: dict[str, Any]) -> str:
    """Compute lowercase hexadecimal SHA-256 digest of canonical snapshot JSON."""
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def generate_ed25519_keypair_pem() -> tuple[str, str]:
    """Generate a fresh Ed25519 PKCS8 private / SubjectPublicKeyInfo PEM pair."""
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return private_pem, public_pem


def _load_private_key_from_pem(pem_text: str) -> Ed25519PrivateKey:
    loaded = serialization.load_pem_private_key(pem_text.encode("utf-8"), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("Scope signing private key must use Ed25519")
    return loaded


def _load_public_key_from_pem(pem_text: str) -> Ed25519PublicKey:
    loaded = serialization.load_pem_public_key(pem_text.encode("utf-8"))
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("Scope verification public key must use Ed25519")
    return loaded


class SnapshotSigner:
    """Ed25519 signer/verifier supporting key-rotation registries and fail-closed defaults."""

    def __init__(
        self,
        *,
        active_key_id: str,
        private_key: Ed25519PrivateKey,
        keyring: dict[str, SigningKeyRecord] | None = None,
    ) -> None:
        self.active_key_id = active_key_id
        self._private_key = private_key
        self._keyring: dict[str, SigningKeyRecord] = dict(keyring or {})
        if active_key_id not in self._keyring:
            self._keyring[active_key_id] = SigningKeyRecord(
                key_id=active_key_id,
                public_key=private_key.public_key(),
                status="active",
            )

    @classmethod
    def from_settings(cls, settings: Settings) -> SnapshotSigner:
        """Build signer from mounted key file or keyring config; fail closed in prod."""
        active_key_id = settings.scope_signing_key_id.strip() or "vf-scope-dev-1"
        private_key: Ed25519PrivateKey | None = None

        key_path = settings.scope_signing_private_key_path.strip()
        if key_path:
            pem_text = Path(key_path).read_text(encoding="utf-8")
            private_key = _load_private_key_from_pem(pem_text)
        elif settings.scope_signing_private_key_pem.strip():
            if settings.vforge_env not in {"development", "test"}:
                raise RuntimeError(
                    "Inline scope_signing_private_key_pem is forbidden outside development/test"
                )
            private_key = _load_private_key_from_pem(settings.scope_signing_private_key_pem)
        else:
            if settings.vforge_env not in {"development", "test"}:
                raise RuntimeError(
                    "SCOPE_SIGNING_PRIVATE_KEY_PATH is required outside development/test"
                )
            private_key = _get_or_create_dev_ephemeral_key(active_key_id)

        keyring: dict[str, SigningKeyRecord] = {}
        raw_keyring = settings.scope_signing_public_keys_json.strip()
        if raw_keyring:
            keyring.update(parse_public_keyring_json(raw_keyring))

        return cls(active_key_id=active_key_id, private_key=private_key, keyring=keyring)

    def sign_payload(self, payload: dict[str, Any]) -> SignedSnapshotBundle:
        """Compute canonical SHA-256 hash and Ed25519 signature over the digest bytes."""
        payload_sha256 = compute_payload_sha256(payload)
        sig_bytes = self._private_key.sign(payload_sha256.encode("ascii"))
        return SignedSnapshotBundle(
            payload_sha256=payload_sha256,
            signing_key_id=self.active_key_id,
            signature_algorithm="Ed25519",
            signature=_b64url_encode(sig_bytes),
        )

    def export_public_keyring_json(self) -> str:
        """Export non-secret public verification keys for distributed verifiers (e.g. runners)."""
        exported: dict[str, dict[str, str]] = {}
        for key_id, rec in self._keyring.items():
            pem = rec.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")
            exported[key_id] = {"public_key_pem": pem, "status": rec.status}
        return json.dumps(exported, sort_keys=True)

    def verify_payload(
        self,
        *,
        payload: dict[str, Any],
        expected_sha256: str,
        signing_key_id: str,
        signature_algorithm: str,
        signature: str,
        keyring_overrides: dict[str, SigningKeyRecord] | None = None,
    ) -> SnapshotVerificationResult:
        """Verify canonical SHA-256 hash, key lifecycle status, and Ed25519 signature."""
        computed_sha256 = compute_payload_sha256(payload)
        if not hmac.compare_digest(computed_sha256, expected_sha256.lower()):
            return SnapshotVerificationResult(
                valid=False,
                reason="hash_mismatch",
                computed_sha256=computed_sha256,
                signing_key_id=signing_key_id,
            )

        if signature_algorithm != "Ed25519":
            return SnapshotVerificationResult(
                valid=False,
                reason="unsupported_signature_algorithm",
                computed_sha256=computed_sha256,
                signing_key_id=signing_key_id,
            )

        registry = dict(self._keyring)
        if keyring_overrides:
            registry.update(keyring_overrides)

        record = registry.get(signing_key_id)
        if record is None:
            return SnapshotVerificationResult(
                valid=False,
                reason="unknown_signing_key",
                computed_sha256=computed_sha256,
                signing_key_id=signing_key_id,
            )

        if record.status == "revoked":
            return SnapshotVerificationResult(
                valid=False,
                reason="signing_key_revoked",
                computed_sha256=computed_sha256,
                signing_key_id=signing_key_id,
                key_status=record.status,
            )

        try:
            sig_bytes = _b64url_decode(signature)
            record.public_key.verify(sig_bytes, computed_sha256.encode("ascii"))
        except (InvalidSignature, ValueError):
            return SnapshotVerificationResult(
                valid=False,
                reason="invalid_signature",
                computed_sha256=computed_sha256,
                signing_key_id=signing_key_id,
                key_status=record.status,
            )

        return SnapshotVerificationResult(
            valid=True,
            reason="signature_valid",
            computed_sha256=computed_sha256,
            signing_key_id=signing_key_id,
            key_status=record.status,
        )


def parse_public_keyring_json(raw_json: str) -> dict[str, SigningKeyRecord]:
    """Parse JSON mapping {key_id: {public_key_pem, status}} into SigningKeyRecord map."""
    decoded = json.loads(raw_json)
    if not isinstance(decoded, dict):
        raise ValueError("scope_signing_public_keys_json must decode to a JSON object")

    records: dict[str, SigningKeyRecord] = {}
    for key_id, entry in decoded.items():
        if not isinstance(key_id, str) or not isinstance(entry, dict):
            raise ValueError("Invalid keyring entry format")
        pem = str(entry.get("public_key_pem", ""))
        status = str(entry.get("status", "active"))
        if status not in {"active", "verify_only", "revoked"}:
            raise ValueError(f"Unsupported signing key status: {status}")
        records[key_id] = SigningKeyRecord(
            key_id=key_id,
            public_key=_load_public_key_from_pem(pem),
            status=status,  # type: ignore[arg-type]
        )
    return records


_DEV_EPHEMERAL_KEYS: dict[str, Ed25519PrivateKey] = {}


def _get_or_create_dev_ephemeral_key(key_id: str) -> Ed25519PrivateKey:
    if key_id not in _DEV_EPHEMERAL_KEYS:
        _DEV_EPHEMERAL_KEYS[key_id] = Ed25519PrivateKey.generate()
    return _DEV_EPHEMERAL_KEYS[key_id]
