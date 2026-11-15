"""FIRST Exploit Prediction Scoring System (EPSS) Connector (Phase 9)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import httpx

from vforge.intel.connector import (
    FeedBatch,
    NormalizedIntelRecord,
    NormalizedRelationship,
    SourceHealth,
    SourceMetadata,
    ValidationResult,
)


class FirstEpssConnector:
    """Connects to the FIRST EPSS API for probabilistic exploitation prediction scoring."""

    def __init__(
        self,
        endpoint_url: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.endpoint_url = endpoint_url or "https://api.first.org/data/v1/epss"
        self._client = http_client

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            slug="first_epss",
            name="FIRST Exploit Prediction Scoring System",
            source_type="probability_feed",
            provider_url=self.endpoint_url,
            license_name="FIRST Data License",
            license_url="https://www.first.org/epss/data",
            terms_reference=(
                "Daily empirical model estimating near-term probability of exploitation in the wild"
            ),
            is_gated=False,
            requires_scope_auth=False,
            allow_binary_upload=False,
        )

    async def health_check(self) -> SourceHealth:
        start = datetime.now(UTC)
        try:
            if self._client:
                resp = await self._client.get(
                    self.endpoint_url,
                    params={"cve": "CVE-2021-44228"},
                    timeout=5.0,
                )
                latency = (datetime.now(UTC) - start).total_seconds() * 1000
                return SourceHealth(
                    is_healthy=resp.status_code == 200,
                    status_code=resp.status_code,
                    latency_ms=latency,
                    checked_at=datetime.now(UTC),
                )
            return SourceHealth(
                is_healthy=True,
                status_code=200,
                latency_ms=1.0,
                checked_at=datetime.now(UTC),
            )
        except Exception as exc:  # noqa: BLE001
            return SourceHealth(
                is_healthy=False,
                status_code=503,
                error_message=str(exc),
                checked_at=datetime.now(UTC),
            )

    async def fetch_incremental(self, cursor: str | None = None) -> FeedBatch:
        retrieved_at = datetime.now(UTC)
        params: dict[str, Any] = {"limit": 100}
        if cursor:
            params["offset"] = cursor

        if self._client:
            resp = await self._client.get(self.endpoint_url, params=params, timeout=15.0)
            resp.raise_for_status()
            data = resp.json()
            next_offset = str(int(cursor or "0") + len(data.get("data", [])))
        else:
            data = {"status": "OK", "data": []}
            next_offset = cursor or "0"

        content_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
        raw_hash = hashlib.sha256(content_bytes).hexdigest()
        records = data.get("data", [])

        return FeedBatch(
            cursor_before=cursor,
            cursor_after=next_offset,
            raw_payload=data,
            raw_hash=raw_hash,
            retrieved_at=retrieved_at,
            record_count=len(records),
            metadata={"status": data.get("status"), "total": data.get("total")},
        )

    def validate(self, batch: FeedBatch) -> ValidationResult:
        if not isinstance(batch.raw_payload, dict):
            return ValidationResult(is_valid=False, errors=["Raw payload is not a JSON object"])
        items = batch.raw_payload.get("data")
        if not isinstance(items, list):
            return ValidationResult(
                is_valid=False, errors=["Missing 'data' array in EPSS response"]
            )
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                return ValidationResult(is_valid=False, errors=[f"Item {idx} is not an object"])
            if "cve" not in item:
                return ValidationResult(is_valid=False, errors=[f"Item {idx} is missing 'cve'"])
            if "epss" not in item:
                return ValidationResult(
                    is_valid=False, errors=[f"Item {idx} is missing 'epss' score"]
                )
        return ValidationResult(is_valid=True, schema_version="v1")

    def normalize(self, batch: FeedBatch) -> list[NormalizedIntelRecord]:
        normalized: list[NormalizedIntelRecord] = []
        items = batch.raw_payload.get("data", [])
        for item in items:
            cve_id = item.get("cve", "").strip().upper()
            if not cve_id:
                continue

            try:
                epss_score = float(item.get("epss", 0.0))
            except (ValueError, TypeError):
                epss_score = None

            try:
                epss_percentile = float(item.get("percentile", 0.0))
            except (ValueError, TypeError):
                epss_percentile = None

            date_str = item.get("date")
            published_at = None
            if date_str:
                try:
                    published_at = datetime.fromisoformat(date_str).replace(tzinfo=UTC)
                except ValueError:
                    pass

            item_bytes = json.dumps(item, sort_keys=True).encode("utf-8")
            raw_hash = hashlib.sha256(item_bytes).hexdigest()
            norm_content = f"{cve_id}:{epss_score}:{epss_percentile}".encode()
            norm_hash = hashlib.sha256(norm_content).hexdigest()

            if epss_score is not None and epss_percentile is not None:
                title = (
                    f"EPSS Score for {cve_id}: {epss_score:.4f} "
                    f"({epss_percentile * 100:.1f}th percentile)"
                )
            else:
                title = f"EPSS Score for {cve_id}"

            relationships = [
                NormalizedRelationship(
                    relationship_type="cve_to_epss",
                    target_identifier_type="cve",
                    target_identifier=cve_id,
                )
            ]

            normalized.append(
                NormalizedIntelRecord(
                    source_record_id=cve_id,
                    record_type="epss",
                    title=title,
                    summary=f"Exploit probability {epss_score}",
                    epss_score=epss_score,
                    epss_percentile=epss_percentile,
                    raw_payload=item,
                    raw_hash=raw_hash,
                    normalized_hash=norm_hash,
                    published_at=published_at,
                    retrieved_at=batch.retrieved_at,
                    relationships=relationships,
                )
            )
        return normalized

    def checkpoint(self, batch: FeedBatch) -> str | None:
        return batch.cursor_after
