"""Input validation, asset locator normalization, secret-ref enforcement, and redaction."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from vforge_scope import ScopeValidationError, TargetType, canonicalize_target

from vforge.errors import ValidationError
from vforge.logging import redact_text
from vforge.models.enums import AssetType

_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$")

_ASSET_TO_TARGET_TYPE: dict[AssetType, TargetType] = {
    AssetType.WEB_APPLICATION: TargetType.EXACT_URL,
    AssetType.REST_API: TargetType.REST_API,
    AssetType.SOURCE_REPOSITORY: TargetType.SOURCE_REPOSITORY,
    AssetType.CONTAINER_IMAGE: TargetType.CONTAINER_IMAGE,
    AssetType.IP_ADDRESS: TargetType.IPV4,  # Fallback handled below for IPv6
    AssetType.CIDR_RANGE: TargetType.CIDR_RANGE,
    AssetType.NETWORK_SERVICE: TargetType.NETWORK_SERVICE,
    AssetType.INFRASTRUCTURE_DEFINITION: TargetType.INFRASTRUCTURE_DEFINITION,
}

_SECRET_REF_SCHEMES = frozenset({"vault", "aws-sm", "gcp-sm", "azure-kv", "k8s-secret", "env-ref"})
_PLAINTEXT_SECRET_MARKERS = (
    "-----begin ",
    "bearer ",
    "akia",
    "ghp_",
    "glpat-",
    "xoxb-",
    "password=",
    "secret=",
    "token=",
    "eyj",
)
_SENSITIVE_METADATA_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "private_key",
        "client_secret",
        "csrf_token",
    }
)


def validate_slug(value: str) -> str:
    """Validate and normalize a URL-safe lowercase slug."""
    normalized = value.strip().lower()
    if not _SLUG_RE.match(normalized):
        raise ValidationError(
            "Slug must be 2-100 lowercase alphanumeric characters or hyphens, "
            "starting and ending with an alphanumeric character."
        )
    return normalized


def normalize_asset_locator(asset_type: AssetType, raw_locator: str) -> str:
    """Validate and normalize an asset locator using the shared `vforge_scope` package."""
    raw = raw_locator.strip()
    if not raw or len(raw) > 2048:
        raise ValidationError("Asset locator must be between 1 and 2048 characters")

    try:
        if asset_type == AssetType.IP_ADDRESS:
            from vforge_scope import canonicalize_ip

            return canonicalize_ip(raw).compressed
        target_type = _ASSET_TO_TARGET_TYPE.get(asset_type)
        if target_type is None:
            raise ValidationError(f"Unsupported asset type: {asset_type}")
        return canonicalize_target(target_type, raw).normalized
    except ScopeValidationError as exc:
        raise ValidationError(exc.message) from exc


def validate_secret_manager_ref(raw_ref: str) -> str:
    """Ensure auth_profiles store only secret-manager references, never plaintext secrets."""
    ref = raw_ref.strip()
    if not ref or len(ref) > 512 or any(ch.isspace() for ch in ref):
        raise ValidationError("Secret manager reference must be a compact non-empty URI")

    lowered = ref.lower()
    if any(marker in lowered for marker in _PLAINTEXT_SECRET_MARKERS):
        raise ValidationError("Plaintext credentials or tokens are forbidden in secret_manager_ref")

    parts = urlsplit(ref)
    if parts.scheme.lower() not in _SECRET_REF_SCHEMES:
        allowed = ", ".join(sorted(_SECRET_REF_SCHEMES))
        raise ValidationError(f"secret_manager_ref scheme must be one of: {allowed}")
    if parts.username or parts.password:
        raise ValidationError("secret_manager_ref must not contain embedded credentials")
    if not parts.netloc and not parts.path.strip("/"):
        raise ValidationError("secret_manager_ref must specify a secret path or identifier")

    return f"{parts.scheme.lower()}://{parts.netloc}{parts.path}" + (
        f"?{parts.query}" if parts.query else ""
    )


def redact_metadata(value: Any) -> Any:
    """Recursively redact sensitive keys and credential substrings for audit storage."""
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for k, v in value.items():
            key_str = str(k)
            if key_str.lower() in _SENSITIVE_METADATA_KEYS:
                sanitized[key_str] = "[REDACTED]"
            else:
                sanitized[key_str] = redact_metadata(v)
        return sanitized
    if isinstance(value, list):
        return [redact_metadata(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
