"""AES-256-GCM envelope encryption, multi-KEK rotation, & PQC crypto-agility baselines."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vforge.config import Settings

ENVELOPE_ALGORITHM = "AES-256-GCM"


@dataclass(frozen=True, slots=True)
class EncryptedArtifactEnvelope:
    """Ciphertext and cryptographic envelope metadata persisted alongside artifact files."""

    plaintext_sha256: str
    ciphertext_sha256: str
    ciphertext: bytes
    encryption_algorithm: str
    encryption_key_id: str
    wrapped_dek_b64: str
    nonce_b64: str
    aad_b64: str


@dataclass(frozen=True, slots=True)
class KeyringBundle:
    """Active encryption KEK plus historical verification/decryption keyring."""

    active_kek_id: str
    keys: dict[str, bytes]


@dataclass(frozen=True, slots=True)
class RewrappedDekResult:
    """Outcome of zero-downtime DEK re-wrapping under a new KEK epoch."""

    old_kek_id: str
    new_kek_id: str
    wrapped_dek_b64: str
    roundtrip_verified: bool


@dataclass(frozen=True, slots=True)
class CryptoAlgorithmProfile:
    """Descriptor for classical baseline and post-quantum readiness profiles (§26)."""

    purpose: str
    classical_algorithm: str
    pqc_migration_target: str
    nist_standard: str
    pqc_live_enabled: bool
    notes: str


CRYPTO_BASELINE_PROFILES: tuple[CryptoAlgorithmProfile, ...] = (
    CryptoAlgorithmProfile(
        purpose="data_at_rest_envelope",
        classical_algorithm="AES-256-GCM (random 256-bit DEK per object)",
        pqc_migration_target="AES-256-GCM (remains NIST-approved post-quantum symmetric baseline)",
        nist_standard="NIST SP 800-38D",
        pqc_live_enabled=False,
        notes=(
            "Authenticated encryption with canonical AAD binding; KEK wrapping separated from data."
        ),
    ),
    CryptoAlgorithmProfile(
        purpose="key_establishment_and_transport",
        classical_algorithm="TLS 1.3 (ECDHE X25519/P-256) + runner mTLS P-256",
        pqc_migration_target="Hybrid X25519MLKEM768 when TLS stack & proxies natively interoperate",
        nist_standard="FIPS 203 (ML-KEM)",
        pqc_live_enabled=False,
        notes="Custom hybrid protocols are strictly forbidden; awaiting validated stack rollout.",
    ),
    CryptoAlgorithmProfile(
        purpose="scope_and_manifest_signatures",
        classical_algorithm="Ed25519 deterministic signatures",
        pqc_migration_target="ML-DSA-65 / SLH-DSA dual/migrated signing suite",
        nist_standard="FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)",
        pqc_live_enabled=False,
        notes="Key ID and algorithm agile metadata tracked on every signature bundle.",
    ),
)


@lru_cache
def _get_dev_fallback_kek() -> bytes:
    """Process-local ephemeral dev/test KEK used only outside production/staging."""
    return os.urandom(32)


def _decode_kek_bytes(raw_b64: str) -> bytes:
    cleaned = raw_b64.strip()
    if not cleaned or not all(
        c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/=" for c in cleaned
    ):
        raise ValueError("Artifact KEK must be valid base64/base64url characters")
    if "+" in cleaned or "/" in cleaned:
        key = base64.b64decode(cleaned.encode("ascii"), validate=True)
    else:
        padded = cleaned + "=" * (-len(cleaned) % 4)
        key = base64.urlsafe_b64decode(padded.encode("ascii"))
    if len(key) != 32:
        raise ValueError("Artifact KEK must decode to exactly 32 bytes (AES-256)")
    return key


def resolve_kek(settings: Settings) -> tuple[str, bytes]:
    """Resolve KEK ID and 256-bit key material; fail closed in production/staging."""
    key_id = settings.artifact_encryption_key_id.strip() or "vf-artifact-dev-1"
    raw = settings._resolve_secret(
        settings.artifact_encryption_key_b64, "ARTIFACT_ENCRYPTION_KEY_B64"
    )
    if raw:
        return key_id, _decode_kek_bytes(raw)
    if settings.vforge_env.strip().lower() not in {"development", "test"}:
        raise RuntimeError(
            "ARTIFACT_ENCRYPTION_KEY_B64 is required outside development/test environments"
        )
    return key_id, _get_dev_fallback_kek()


def build_artifact_aad(
    *,
    organization_id: str,
    scan_run_id: str,
    runner_job_id: str,
    plaintext_sha256: str,
) -> bytes:
    """Build deterministic AAD binding ciphertext to tenant, run, job, and digest."""
    return (
        f"vf:v1|{organization_id}|{scan_run_id}|{runner_job_id}|{plaintext_sha256.lower()}".encode()
    )


def encrypt_artifact_bytes(
    *,
    plaintext: bytes,
    kek_id: str,
    kek_bytes: bytes,
    aad: bytes,
) -> EncryptedArtifactEnvelope:
    """Encrypt artifact bytes with a fresh per-artifact DEK wrapped by the KEK."""
    if len(kek_bytes) != 32:
        raise ValueError("KEK must be 32 bytes")
    plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()
    dek = os.urandom(32)
    data_nonce = os.urandom(12)
    wrap_nonce = os.urandom(12)

    ciphertext = AESGCM(dek).encrypt(data_nonce, plaintext, aad)
    wrapped_dek = AESGCM(kek_bytes).encrypt(wrap_nonce, dek, aad)
    wrapped_dek_blob = wrap_nonce + wrapped_dek

    ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
    return EncryptedArtifactEnvelope(
        plaintext_sha256=plaintext_sha256,
        ciphertext_sha256=ciphertext_sha256,
        ciphertext=ciphertext,
        encryption_algorithm=ENVELOPE_ALGORITHM,
        encryption_key_id=kek_id,
        wrapped_dek_b64=base64.b64encode(wrapped_dek_blob).decode("ascii"),
        nonce_b64=base64.b64encode(data_nonce).decode("ascii"),
        aad_b64=base64.b64encode(aad).decode("ascii"),
    )


def decrypt_artifact_bytes(
    *,
    ciphertext: bytes,
    expected_plaintext_sha256: str,
    expected_ciphertext_sha256: str,
    kek_bytes: bytes,
    wrapped_dek_b64: str,
    nonce_b64: str,
    aad_b64: str,
) -> bytes:
    """Unwrap DEK, decrypt artifact bytes, verify AAD, and confirm SHA-256 digests."""
    actual_ct_sha = hashlib.sha256(ciphertext).hexdigest()
    if not hmac.compare_digest(actual_ct_sha, expected_ciphertext_sha256.lower()):
        raise ValueError("Artifact ciphertext integrity verification failed")

    aad = base64.b64decode(aad_b64.encode("ascii"))
    data_nonce = base64.b64decode(nonce_b64.encode("ascii"))
    wrapped_blob = base64.b64decode(wrapped_dek_b64.encode("ascii"))
    if len(wrapped_blob) <= 12:
        raise ValueError("Malformed wrapped DEK payload")

    wrap_nonce, wrapped_dek = wrapped_blob[:12], wrapped_blob[12:]
    dek = AESGCM(kek_bytes).decrypt(wrap_nonce, wrapped_dek, aad)
    plaintext = AESGCM(dek).decrypt(data_nonce, ciphertext, aad)

    actual_pt_sha = hashlib.sha256(plaintext).hexdigest()
    if not hmac.compare_digest(actual_pt_sha, expected_plaintext_sha256.lower()):
        raise ValueError("Artifact plaintext SHA-256 verification failed")
    return plaintext


def resolve_backup_kek(settings: Settings) -> tuple[str, bytes]:
    """Resolve dedicated backup KEK separately from artifact KEK when configured (§26.2)."""
    backup_id = settings.backup_encryption_key_id.strip() or "vf-backup-dev-1"
    raw = settings._resolve_secret(settings.backup_encryption_key_b64, "BACKUP_ENCRYPTION_KEY_B64")
    if raw:
        return backup_id, _decode_kek_bytes(raw)
    if settings.vforge_env.strip().lower() not in {"development", "test"}:
        raise RuntimeError(
            "BACKUP_ENCRYPTION_KEY_B64 is required outside development/test environments"
        )
    fallback_id, fallback_bytes = resolve_kek(settings)
    if fallback_id == backup_id:
        return backup_id, fallback_bytes
    # Derive deterministic test/dev domain-separated backup key from ephemeral dev key
    derived = hashlib.sha256(b"vf:backup:" + fallback_bytes).digest()
    return backup_id, derived


def resolve_keyring(settings: Settings) -> KeyringBundle:
    """Build active + historical KEK keyring from configuration/secret provider."""
    keys: dict[str, bytes] = {}
    active_id, active_bytes = resolve_kek(settings)
    keys[active_id] = active_bytes

    backup_id, backup_bytes = resolve_backup_kek(settings)
    keys.setdefault(backup_id, backup_bytes)

    raw_ring = settings._resolve_secret(
        settings.artifact_encryption_keyring_json,
        "ARTIFACT_ENCRYPTION_KEYRING_JSON",
    )
    if raw_ring:
        parsed = json.loads(raw_ring)
        if not isinstance(parsed, dict):
            raise ValueError("ARTIFACT_ENCRYPTION_KEYRING_JSON must be a JSON object")
        for key_id, key_b64 in parsed.items():
            if not isinstance(key_id, str) or not isinstance(key_b64, str):
                raise ValueError("Keyring entries must map string key_id to base64 key material")
            cleaned_id = key_id.strip()
            if not cleaned_id:
                raise ValueError("Keyring key_id must be non-empty")
            decoded = _decode_kek_bytes(key_b64)
            if cleaned_id in keys and not hmac.compare_digest(keys[cleaned_id], decoded):
                raise ValueError(
                    f"Keyring key_id '{cleaned_id}' collides with active or backup KEK"
                )
            keys.setdefault(cleaned_id, decoded)

    return KeyringBundle(active_kek_id=active_id, keys=keys)


def decrypt_artifact_with_keyring(
    *,
    ciphertext: bytes,
    expected_plaintext_sha256: str,
    expected_ciphertext_sha256: str,
    encryption_key_id: str,
    keyring: Mapping[str, bytes],
    wrapped_dek_b64: str,
    nonce_b64: str,
    aad_b64: str,
    revoked_key_ids: frozenset[str] = frozenset(),
) -> bytes:
    """Decrypt envelope using key ID lookup while rejecting missing or revoked KEKs."""
    if encryption_key_id in revoked_key_ids:
        raise ValueError(f"Encryption key '{encryption_key_id}' is revoked")
    kek_bytes = keyring.get(encryption_key_id)
    if kek_bytes is None:
        raise ValueError(f"Encryption key '{encryption_key_id}' not found in keyring")
    return decrypt_artifact_bytes(
        ciphertext=ciphertext,
        expected_plaintext_sha256=expected_plaintext_sha256,
        expected_ciphertext_sha256=expected_ciphertext_sha256,
        kek_bytes=kek_bytes,
        wrapped_dek_b64=wrapped_dek_b64,
        nonce_b64=nonce_b64,
        aad_b64=aad_b64,
    )


def rewrap_artifact_dek(
    *,
    old_kek_id: str,
    old_kek_bytes: bytes,
    new_kek_id: str,
    new_kek_bytes: bytes,
    wrapped_dek_b64: str,
    aad_b64: str,
) -> RewrappedDekResult:
    """Re-wrap an existing per-object DEK from old KEK to new KEK without decrypting payload."""
    if len(old_kek_bytes) != 32 or len(new_kek_bytes) != 32:
        raise ValueError("Both old and new KEKs must be 32 bytes (AES-256)")
    if not new_kek_id.strip():
        raise ValueError("new_kek_id must be non-empty")

    aad = base64.b64decode(aad_b64.encode("ascii"))
    wrapped_blob = base64.b64decode(wrapped_dek_b64.encode("ascii"))
    if len(wrapped_blob) <= 12:
        raise ValueError("Malformed wrapped DEK payload")

    old_wrap_nonce, old_wrapped_dek = wrapped_blob[:12], wrapped_blob[12:]
    dek = AESGCM(old_kek_bytes).decrypt(old_wrap_nonce, old_wrapped_dek, aad)

    new_wrap_nonce = os.urandom(12)
    new_wrapped_dek = AESGCM(new_kek_bytes).encrypt(new_wrap_nonce, dek, aad)
    new_wrapped_b64 = base64.b64encode(new_wrap_nonce + new_wrapped_dek).decode("ascii")

    # Roundtrip unwrap verification under the new KEK before committing rotation
    check_blob = base64.b64decode(new_wrapped_b64.encode("ascii"))
    roundtrip_dek = AESGCM(new_kek_bytes).decrypt(check_blob[:12], check_blob[12:], aad)
    verified = hmac.compare_digest(dek, roundtrip_dek)
    if not verified:
        raise RuntimeError("DEK re-wrap roundtrip verification failed")

    return RewrappedDekResult(
        old_kek_id=old_kek_id,
        new_kek_id=new_kek_id.strip(),
        wrapped_dek_b64=new_wrapped_b64,
        roundtrip_verified=verified,
    )


def evaluate_crypto_agility(settings: Settings) -> dict[str, Any]:
    """Return honest Phase 14 cryptography baseline & PQC migration readiness posture."""
    keyring = resolve_keyring(settings)
    return {
        "envelope_algorithm": ENVELOPE_ALGORITHM,
        "active_artifact_kek_id": keyring.active_kek_id,
        "backup_kek_id": settings.backup_encryption_key_id.strip() or "vf-backup-dev-1",
        "keyring_key_count": len(keyring.keys),
        "pqc_hybrid_live_enabled": False,
        "custom_hybrid_protocol_allowed": False,
        "fips_validated_claim": False,
        "fips_notice": (
            "FIPS compliance is NOT claimed merely by selecting AES-256-GCM; "
            "a validated FIPS module and operational configuration are required (§26.4)."
        ),
        "profiles": [
            {
                "purpose": p.purpose,
                "classical_algorithm": p.classical_algorithm,
                "pqc_migration_target": p.pqc_migration_target,
                "nist_standard": p.nist_standard,
                "pqc_live_enabled": p.pqc_live_enabled,
                "notes": p.notes,
            }
            for p in CRYPTO_BASELINE_PROFILES
        ],
    }
