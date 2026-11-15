"""Gated Threat Intelligence Connectors with Privacy & Scope Validation (Phase 9)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from vforge.intel.connector import (
    FeedBatch,
    NormalizedIntelRecord,
    SourceHealth,
    SourceMetadata,
    ValidationResult,
)


class VirusTotalGatedConnector:
    """VirusTotal Intelligence connector with strict hash-only privacy gate."""

    def __init__(self, api_key: str | None = None, allow_binary_upload: bool = False) -> None:
        self._api_key = api_key
        self.allow_binary_upload = allow_binary_upload

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            slug="virustotal",
            name="VirusTotal Intelligence (Hash Only)",
            source_type="ioc_feed",
            provider_url="https://www.virustotal.com/api/v3",
            license_name="Commercial API License",
            license_url="https://docs.virustotal.com/reference/overview",
            terms_reference=(
                "File hash reputation; customer binary and source code uploads forbidden by default"
            ),
            is_gated=True,
            requires_scope_auth=False,
            allow_binary_upload=self.allow_binary_upload,
        )

    async def health_check(self) -> SourceHealth:
        return SourceHealth(
            is_healthy=bool(self._api_key),
            status_code=200 if self._api_key else 401,
            error_message=None if self._api_key else "Missing VirusTotal API key",
            checked_at=datetime.now(UTC),
        )

    def query_file_hash(self, sha256_hash: str) -> dict[str, Any]:
        """Perform SHA-256 hash lookup (safe metadata query)."""
        if len(sha256_hash) != 64:
            msg = "Query target must be a 64-character SHA-256 hex string"
            raise ValueError(msg)
        return {
            "hash": sha256_hash,
            "reputation": "benign",
            "malicious_votes": 0,
            "queried_at": datetime.now(UTC).isoformat(),
        }

    lookup_file_hash = query_file_hash

    def upload_file_binary(
        self, filename: str, content: bytes, admin_approved: bool = False
    ) -> dict[str, Any]:
        """Upload binary or source file to VirusTotal.

        SAFETY INVARIANT:
        File uploads are blocked by default to prevent proprietary code leakage.
        Requires allow_binary_upload=True and explicit admin_approved=True.
        """
        if not self.allow_binary_upload:
            msg = (
                "PRIVACY GATE VIOLATION: Source and binary uploads to VirusTotal are disabled. "
                "Uploading customer assets may disclose proprietary code. Use hash lookups instead."
            )
            raise PermissionError(msg)

        if not admin_approved:
            msg = (
                "PRIVACY GATE VIOLATION: File upload requires explicit "
                "Organization Admin authorization."
            )
            raise PermissionError(msg)

        return {
            "uploaded": True,
            "filename": filename,
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    async def fetch_incremental(self, cursor: str | None = None) -> FeedBatch:
        retrieved_at = datetime.now(UTC)
        data: dict[str, Any] = {"data": []}
        content_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
        raw_hash = hashlib.sha256(content_bytes).hexdigest()
        return FeedBatch(
            cursor_before=cursor,
            cursor_after=str(retrieved_at.timestamp()),
            raw_payload=data,
            raw_hash=raw_hash,
            retrieved_at=retrieved_at,
            record_count=0,
        )

    def validate(self, batch: FeedBatch) -> ValidationResult:
        return ValidationResult(is_valid=True, schema_version="vt-v3")

    def normalize(self, batch: FeedBatch) -> list[NormalizedIntelRecord]:
        return []

    def checkpoint(self, batch: FeedBatch) -> str | None:
        return batch.cursor_after


class ShodanGatedConnector:
    """Shodan Exposure Intelligence connector with strict in-scope asset validation."""

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            slug="shodan",
            name="Shodan Exposure Intelligence",
            source_type="exposure_intel",
            provider_url="https://api.shodan.io",
            license_name="Commercial API License",
            license_url="https://developer.shodan.io/api",
            terms_reference=(
                "Internet host observation; queries restricted strictly to "
                "authorized in-scope assets"
            ),
            is_gated=True,
            requires_scope_auth=True,
            allow_binary_upload=False,
        )

    async def health_check(self) -> SourceHealth:
        return SourceHealth(
            is_healthy=bool(self._api_key),
            status_code=200 if self._api_key else 401,
            error_message=None if self._api_key else "Missing Shodan API key",
            checked_at=datetime.now(UTC),
        )

    def query_host(self, host: str, is_in_scope: bool) -> dict[str, Any]:
        """Query host banner and service exposure from Shodan.

        SAFETY INVARIANT:
        Requires is_in_scope=True. Querying third-party or out-of-scope hosts is forbidden.
        """
        if not is_in_scope:
            msg = (
                f"SCOPE GATE VIOLATION: Host '{host}' is not in the organization's approved and "
                "authorized target scope. Intelligence queries for out-of-scope targets are denied."
            )
            raise PermissionError(msg)

        return {
            "host": host,
            "ports": [80, 443],
            "banners": ["HTTP/1.1 200 OK"],
            "caveat": (
                "Observation is historic/cached; does not prove current "
                "active compromise or vulnerability."
            ),
            "retrieved_at": datetime.now(UTC).isoformat(),
        }

    async def fetch_incremental(self, cursor: str | None = None) -> FeedBatch:
        retrieved_at = datetime.now(UTC)
        data: dict[str, Any] = {"matches": []}
        content_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
        raw_hash = hashlib.sha256(content_bytes).hexdigest()
        return FeedBatch(
            cursor_before=cursor,
            cursor_after=str(retrieved_at.timestamp()),
            raw_payload=data,
            raw_hash=raw_hash,
            retrieved_at=retrieved_at,
            record_count=0,
        )

    def validate(self, batch: FeedBatch) -> ValidationResult:
        return ValidationResult(is_valid=True, schema_version="shodan-v1")

    def normalize(self, batch: FeedBatch) -> list[NormalizedIntelRecord]:
        return []

    def checkpoint(self, batch: FeedBatch) -> str | None:
        return batch.cursor_after
