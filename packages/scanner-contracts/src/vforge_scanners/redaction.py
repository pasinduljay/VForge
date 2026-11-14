"""Defense-in-depth secret redaction utilities applied before persistence or logging."""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Common credential patterns scrubbed regardless of scanner configuration.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"(?i)([a-z0-9+.-]+://[^/\s:@]+:)([^@\s]+)(@)"),
    re.compile(
        r"(?i)((?:password|passwd|secret|api_key|apikey|token|private_key)\s*[=:]\s*['\"]?)([^'\"\s,;}{]{6,})"
    ),
)


def secret_sha256_prefix(value: str) -> str:
    """Return an 8-hex-char SHA-256 digest tag without exposing any bytes of the secret."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]


def redact_secret_value(value: str) -> str:
    """Convert any raw secret string into an opaque redacted placeholder."""
    stripped = value.strip()
    if not stripped:
        return ""
    if stripped.startswith("[REDACTED:") and stripped.endswith("]"):
        return stripped
    return f"[REDACTED:{secret_sha256_prefix(stripped)}]"


def redact_text_secrets(
    text: str | None,
    *,
    known_secrets: tuple[str, ...] | list[str] = (),
) -> str | None:
    """Replace explicit secret literals and known credential regex matches in arbitrary text."""
    if text is None:
        return None
    result = text
    for literal in sorted({s for s in known_secrets if s and len(s) >= 4}, key=len, reverse=True):
        if literal in result:
            result = result.replace(literal, redact_secret_value(literal))

    result = _SECRET_PATTERNS[9].sub(
        lambda m: f"{m.group(1)}{redact_secret_value(m.group(2))}{m.group(3)}",
        result,
    )
    result = _SECRET_PATTERNS[10].sub(
        lambda m: f"{m.group(1)}{redact_secret_value(m.group(2))}",
        result,
    )
    for pattern in _SECRET_PATTERNS[:9]:
        result = pattern.sub(lambda m: redact_secret_value(m.group(0)), result)
    return result


def scrub_finding_dict(
    payload: dict[str, Any],
    *,
    known_secrets: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
    """Recursively remove or mask sensitive keys and patterns from raw finding metadata."""
    scrubbed: dict[str, Any] = {}
    for key, val in payload.items():
        lowered = key.lower()
        if lowered in {"secret", "raw_secret", "token", "password", "private_key", "credential"}:
            scrubbed[key] = (
                redact_secret_value(str(val)) if isinstance(val, str) and val else "[REDACTED]"
            )
            continue
        if isinstance(val, str):
            scrubbed[key] = redact_text_secrets(val, known_secrets=known_secrets)
        elif isinstance(val, dict):
            scrubbed[key] = scrub_finding_dict(val, known_secrets=known_secrets)
        elif isinstance(val, list):
            scrubbed[key] = [
                scrub_finding_dict(item, known_secrets=known_secrets)
                if isinstance(item, dict)
                else (
                    redact_text_secrets(item, known_secrets=known_secrets)
                    if isinstance(item, str)
                    else item
                )
                for item in val
            ]
        else:
            scrubbed[key] = val
    return scrubbed


def mask_secret_preview(match_line: str, secret: str) -> str:
    """Redact a matched secret inside its surrounding source line without revealing cleartext."""
    masked = redact_text_secrets(match_line, known_secrets=(secret,) if secret else ())
    return masked or ""
