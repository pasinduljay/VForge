"""Phase 12 pre-egress data classification, secret/PII redaction, and injection defenses."""

from __future__ import annotations

import hashlib
import html
import re
from dataclasses import dataclass

from vforge.models.enums import DataClassification

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
            r"[\s\S]*?-----END [A-Z0-9 ]*(?:PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
        ),
    ),
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b")),
    (
        "API_TOKEN",
        re.compile(r"\b(?:sk|ghp|gho|github_pat|glpat|xoxb|xoxp|hf|npm|whsec)[-_A-Za-z0-9]{10,}\b"),
    ),
    ("RAW_JWT", re.compile(r"\beyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\b")),
    (
        "OPAQUE_AUTH_HEADER",
        re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9\-_=+/.]{12,}"),
    ),
    ("DB_URI_CREDENTIAL", re.compile(r"[a-zA-Z0-9+.-]+://[^:\s/]+:[^@\s]+@[^\s]+")),
    (
        "URL_CREDENTIAL",
        re.compile(r"(?i)([?&](?:token|api_key|apikey|secret|password|auth|key)=)([^&\s]+)"),
    ),
    (
        "CREDENTIAL_ASSIGNMENT",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|api_key|apikey|access_token)\b"
            r"\s*[:=]\s*(['\"]?)([^\s'\",;]{4,})\2"
        ),
    ),
)

_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
)

_CONFIDENTIAL_CODE_RE = re.compile(
    r"(?i)(cve-\d{4}-\d+|def\s+|class\s+|select\s+.+from\s+|vulnerability|exploit|stack\s*trace)"
)

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)ignore\s+(?:all\s+)?previous\s+instructions"),
    re.compile(r"(?i)(?:reveal|print|dump)\s+(?:the\s+)?system\s+prompt"),
    re.compile(r"(?i)\b(?:modify_opa|opa:modify|scope:modify|bypass[_\s]+scope)\b"),
    re.compile(r"(?i)\b(?:promote_stable|sign_pack|auto_confirm|shell:exec)\b"),
)

_CLASSIFICATION_RANK: dict[str, int] = {
    DataClassification.PUBLIC.value: 0,
    DataClassification.INTERNAL.value: 1,
    DataClassification.CONFIDENTIAL.value: 2,
    DataClassification.RESTRICTED.value: 3,
}

_SECRET_LABELS = frozenset(
    {
        "PRIVATE_KEY",
        "AWS_KEY",
        "GOOGLE_API_KEY",
        "API_TOKEN",
        "RAW_JWT",
        "OPAQUE_AUTH_HEADER",
        "DB_URI_CREDENTIAL",
        "URL_CREDENTIAL",
        "CREDENTIAL_ASSIGNMENT",
    }
)


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    """Result of deterministic pre-egress classification, redaction, and framing."""

    classification: DataClassification
    redacted_text: str
    wrapped_untrusted_text: str
    redacted_categories: tuple[str, ...]
    redaction_applied: bool
    prompt_injection_detected: bool
    injection_signals: tuple[str, ...]
    raw_sha256: str


def _max_classification(a: DataClassification, b: DataClassification) -> DataClassification:
    return a if _CLASSIFICATION_RANK[a.value] >= _CLASSIFICATION_RANK[b.value] else b


def classify_and_redact_payload(
    raw_text: str,
    *,
    requested_classification: str | None = None,
    wrapper_tag: str = "untrusted_data",
) -> ClassificationResult:
    """Classify sensitivity, redact secrets/PII, and isolate untrusted input as quoted data."""
    raw_sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    redacted = raw_text
    categories: list[str] = []

    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(redacted):
            categories.append(label)
            if label == "URL_CREDENTIAL":
                redacted = pattern.sub(r"\1[REDACTED:URL_CREDENTIAL]", redacted)
            elif label == "CREDENTIAL_ASSIGNMENT":
                redacted = pattern.sub(r"\1=[REDACTED:CREDENTIAL_ASSIGNMENT]", redacted)
            else:
                redacted = pattern.sub(f"[REDACTED:{label}]", redacted)

    for label, pattern in _PII_PATTERNS:
        if pattern.search(redacted):
            categories.append(label)
            redacted = pattern.sub(f"[REDACTED:{label}]", redacted)

    if requested_classification and requested_classification in {
        m.value for m in DataClassification
    }:
        inferred = DataClassification(requested_classification)
    else:
        inferred = DataClassification.INTERNAL

    if any(cat in _SECRET_LABELS for cat in categories):
        inferred = _max_classification(inferred, DataClassification.RESTRICTED)
    elif categories or _CONFIDENTIAL_CODE_RE.search(raw_text):
        inferred = _max_classification(inferred, DataClassification.CONFIDENTIAL)

    injection_signals: list[str] = []
    for pat in _INJECTION_PATTERNS:
        if pat.search(raw_text):
            injection_signals.append(pat.pattern)

    # Entity-escape all angle brackets to eliminate any case/whitespace XML breakout
    escaped = html.escape(redacted, quote=False)
    safe_tag = re.sub(r"[^a-z0-9_]", "_", wrapper_tag.lower())
    wrapped = f'<{safe_tag} sha256="{raw_sha256}">\n{escaped}\n</{safe_tag}>'

    return ClassificationResult(
        classification=inferred,
        redacted_text=redacted,
        wrapped_untrusted_text=wrapped,
        redacted_categories=tuple(categories),
        redaction_applied=bool(categories),
        prompt_injection_detected=bool(injection_signals),
        injection_signals=tuple(injection_signals),
        raw_sha256=raw_sha256,
    )
