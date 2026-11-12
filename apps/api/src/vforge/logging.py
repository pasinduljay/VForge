"""Structured JSON logging with credential/secret redaction and correlation IDs."""

from __future__ import annotations

import contextvars
import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

correlation_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id",
    default=None,
)

_URL_CREDENTIALS_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:/\s]*:)([^@\s]+)(@)")
_BEARER_RE = re.compile(r"(?i)((?:bearer|basic)\s+)([A-Za-z0-9._~+/=-]+)")
_KV_SECRET_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|secret|token|api_key|apikey|authorization|cookie|"
    r"client_secret|rediscli_auth|pgpassword|private_key"
    r")\s*([:=])\s*([^\s,;\"'&]+)"
)


def redact_text(value: str) -> str:
    """Redact credentials embedded in URLs, auth headers, and key=value pairs."""
    sanitized = _URL_CREDENTIALS_RE.sub(r"\1[REDACTED]\3", value)
    sanitized = _BEARER_RE.sub(r"\1[REDACTED]", sanitized)
    sanitized = _KV_SECRET_RE.sub(r"\1\2[REDACTED]", sanitized)
    return sanitized


def sanitize_exception_message(exc: BaseException) -> str:
    """Return a redacted single-line summary of an exception without raw secrets."""
    return redact_text(f"{type(exc).__name__}: {exc}")


class JsonFormatter(logging.Formatter):
    """Format log records as single-line UTC JSON with redacted secrets."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        corr_id = correlation_id_var.get()
        if corr_id:
            payload["correlation_id"] = corr_id
        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, separators=(",", ":"))


def configure_logging(level: str = "INFO") -> None:
    """Configure root logger with redacted JSON output."""
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
