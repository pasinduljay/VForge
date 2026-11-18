"""Unit tests verifying log redaction of credentials and tokens."""

from __future__ import annotations

import json
import logging

from vforge.logging import JsonFormatter, redact_text


def test_redact_text_masks_url_credentials() -> None:
    raw = (
        "Failed connecting to postgresql+psycopg://vforge:SuperSecret123@postgres:5432/vforge"
    )
    redacted = redact_text(raw)
    assert "SuperSecret123" not in redacted
    assert "vforge:[REDACTED]@postgres:5432" in redacted


def test_redact_text_masks_bearer_and_kv_secrets() -> None:
    raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc password=my-dev-pw token=tok_12345"
    redacted = redact_text(raw)
    assert "eyJhbGciOiJIUzI1NiJ9" not in redacted
    assert "my-dev-pw" not in redacted
    assert "tok_12345" not in redacted


def test_json_formatter_emits_utc_json_without_secrets() -> None:
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="vforge.test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="amqp://vforge:secretPass99@rabbitmq:5672/%2F failed",
        args=(),
        exc_info=None,
    )
    rendered = formatter.format(record)
    parsed = json.loads(rendered)
    assert parsed["level"] == "ERROR"
    assert "secretPass99" not in parsed["message"]
    assert parsed["timestamp"].endswith("+00:00")
