"""CISA Known Exploited Vulnerabilities (KEV) Catalog Connector (Phase 9)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import httpx

from vforge.intel.connector import (
    FeedBatch,
    NormalizedIntelRecord,
    NormalizedRelationship,
    SourceHealth,
    SourceMetadata,
    ValidationResult,
)


class CisaKevConnector:
    """Connects to CISA's official Known Exploited Vulnerabilities catalog."""

    def __init__(
        self,
        endpoint_url: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.endpoint_url = (
            endpoint_url
            or "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )
        self._client = http_client

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            slug="cisa_kev",
            name="CISA Known Exploited Vulnerabilities Catalog",
            source_type="exploit_catalog",
            provider_url=self.endpoint_url,
            license_name="Public Domain / CC0",
            license_url="https://www.cisa.gov/terms-use",
            terms_reference=(
                "Official catalog of vulnerabilities with confirmed in-the-wild exploitation"
            ),
            is_gated=False,
            requires_scope_auth=False,
            allow_binary_upload=False,
        )

    async def health_check(self) -> SourceHealth:
        start = datetime.now(UTC)
        try:
            if self._client:
                resp = await self._client.head(self.endpoint_url, timeout=5.0)
                latency = (datetime.now(UTC) - start).total_seconds() * 1000
                return SourceHealth(
                    is_healthy=resp.status_code in (200, 302, 304),
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
        if self._client:
            headers = {}
            if cursor:
                headers["If-None-Match"] = cursor
            resp = await self._client.get(self.endpoint_url, headers=headers, timeout=15.0)
            if resp.status_code == 304:
                return FeedBatch(
                    cursor_before=cursor,
                    cursor_after=cursor,
                    raw_payload={"vulnerabilities": []},
                    raw_hash=hashlib.sha256(b"").hexdigest(),
                    retrieved_at=retrieved_at,
                    record_count=0,
                )
            resp.raise_for_status()
            data = resp.json()
            etag = (
                resp.headers.get("ETag")
                or data.get("catalogVersion")
                or str(retrieved_at.timestamp())
            )
        else:
            # Default empty / mock structure if client not configured
            data = {"vulnerabilities": []}
            etag = str(retrieved_at.timestamp())

        content_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
        raw_hash = hashlib.sha256(content_bytes).hexdigest()
        records = data.get("vulnerabilities", [])

        return FeedBatch(
            cursor_before=cursor,
            cursor_after=etag,
            raw_payload=data,
            raw_hash=raw_hash,
            retrieved_at=retrieved_at,
            record_count=len(records),
            metadata={
                "title": data.get("title"),
                "catalogVersion": data.get("catalogVersion"),
            },
        )

    def validate(self, batch: FeedBatch) -> ValidationResult:
        if not isinstance(batch.raw_payload, dict):
            return ValidationResult(is_valid=False, errors=["Raw payload is not a JSON object"])
        vulnerabilities = batch.raw_payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            return ValidationResult(
                is_valid=False, errors=["Missing 'vulnerabilities' array in catalog"]
            )
        for idx, item in enumerate(vulnerabilities):
            if not isinstance(item, dict):
                return ValidationResult(is_valid=False, errors=[f"Item {idx} is not an object"])
            if "cveID" not in item:
                return ValidationResult(is_valid=False, errors=[f"Item {idx} is missing 'cveID'"])
        return ValidationResult(
            is_valid=True,
            schema_version=batch.raw_payload.get("catalogVersion", "1.0"),
        )

    def normalize(self, batch: FeedBatch) -> list[NormalizedIntelRecord]:
        normalized: list[NormalizedIntelRecord] = []
        vulnerabilities = batch.raw_payload.get("vulnerabilities", [])
        for item in vulnerabilities:
            cve_id = item.get("cveID", "").strip().upper()
            if not cve_id:
                continue

            vendor = item.get("vendorProject", "")
            product = item.get("product", "")
            vuln_name = item.get("vulnerabilityName", "")
            title = f"{vendor} {product}: {vuln_name}".strip()
            summary = item.get("shortDescription")
            action = item.get("requiredAction")
            due_date = item.get("dueDate")
            ransomware = item.get("knownRansomwareCampaignUse", "Unknown")
            description = (
                f"{summary}\n\nRequired Action: {action}\nDue Date: {due_date}\n"
                f"Known Ransomware Campaign Use: {ransomware}"
            )

            date_added_str = item.get("dateAdded")
            published_at = None
            if date_added_str:
                try:
                    published_at = datetime.fromisoformat(date_added_str).replace(tzinfo=UTC)
                except ValueError:
                    pass

            item_bytes = json.dumps(item, sort_keys=True).encode("utf-8")
            raw_hash = hashlib.sha256(item_bytes).hexdigest()
            norm_content = f"{cve_id}:{title}:{action}:{due_date}".encode()
            norm_hash = hashlib.sha256(norm_content).hexdigest()

            relationships = [
                NormalizedRelationship(
                    relationship_type="cve_to_kev",
                    target_identifier_type="cve",
                    target_identifier=cve_id,
                )
            ]

            normalized.append(
                NormalizedIntelRecord(
                    source_record_id=cve_id,
                    record_type="kev",
                    title=title,
                    summary=summary,
                    description=description,
                    is_known_exploited=True,
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
