"""NIST National Vulnerability Database (NVD) API 2.0 Connector (Phase 9)."""

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


class NvdCveConnector:
    """Connects to NIST NVD API 2.0 for official CVE definitions, CVSS metrics, and CWE mappings."""

    def __init__(
        self,
        endpoint_url: str | None = None,
        api_key: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.endpoint_url = endpoint_url or "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self._api_key = api_key
        self._client = http_client

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            slug="nvd",
            name="NIST National Vulnerability Database",
            source_type="cve_catalog",
            provider_url=self.endpoint_url,
            license_name="NIST Open Government Data",
            license_url="https://nvd.nist.gov/general/terms-of-use",
            terms_reference=(
                "Official NIST CVE dictionary, CVSS v3.1/v4.0 base scores, and CWE taxonomy"
            ),
            is_gated=False,
            requires_scope_auth=False,
            allow_binary_upload=False,
        )

    async def health_check(self) -> SourceHealth:
        start = datetime.now(UTC)
        try:
            if self._client:
                headers = {"apiKey": self._api_key} if self._api_key else {}
                resp = await self._client.get(
                    self.endpoint_url,
                    params={"cveId": "CVE-2021-44228"},
                    headers=headers,
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
        params: dict[str, Any] = {"resultsPerPage": 50}
        if cursor:
            params["startIndex"] = cursor

        if self._client:
            headers = {"apiKey": self._api_key} if self._api_key else {}
            resp = await self._client.get(
                self.endpoint_url, params=params, headers=headers, timeout=15.0
            )
            resp.raise_for_status()
            data = resp.json()
            next_start = str(int(cursor or "0") + len(data.get("vulnerabilities", [])))
        else:
            data = {"vulnerabilities": []}
            next_start = cursor or "0"

        content_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
        raw_hash = hashlib.sha256(content_bytes).hexdigest()
        records = data.get("vulnerabilities", [])

        return FeedBatch(
            cursor_before=cursor,
            cursor_after=next_start,
            raw_payload=data,
            raw_hash=raw_hash,
            retrieved_at=retrieved_at,
            record_count=len(records),
            metadata={
                "format": data.get("format"),
                "version": data.get("version"),
                "totalResults": data.get("totalResults"),
            },
        )

    def validate(self, batch: FeedBatch) -> ValidationResult:
        if not isinstance(batch.raw_payload, dict):
            return ValidationResult(is_valid=False, errors=["Raw payload is not a JSON object"])
        vulns = batch.raw_payload.get("vulnerabilities")
        if not isinstance(vulns, list):
            return ValidationResult(
                is_valid=False, errors=["Missing 'vulnerabilities' list in NVD response"]
            )
        for idx, item in enumerate(vulns):
            if not isinstance(item, dict) or "cve" not in item:
                return ValidationResult(is_valid=False, errors=[f"Item {idx} missing 'cve' block"])
            cve_block = item["cve"]
            if "id" not in cve_block:
                return ValidationResult(is_valid=False, errors=[f"Item {idx} missing CVE id"])
        return ValidationResult(
            is_valid=True, schema_version=batch.raw_payload.get("version", "2.0")
        )

    def normalize(self, batch: FeedBatch) -> list[NormalizedIntelRecord]:
        normalized: list[NormalizedIntelRecord] = []
        vulns = batch.raw_payload.get("vulnerabilities", [])
        for item in vulns:
            cve_block = item.get("cve", {})
            cve_id = cve_block.get("id", "").strip().upper()
            if not cve_id:
                continue

            # Descriptions
            descriptions = cve_block.get("descriptions", [])
            summary = None
            for desc in descriptions:
                if desc.get("lang") == "en":
                    summary = desc.get("value")
                    break
            if not summary and descriptions:
                summary = descriptions[0].get("value")

            # CVSS Metrics (prefer v3.1 then v3.0 then v2.0)
            metrics = cve_block.get("metrics", {})
            cvss_score = None
            cvss_vector = None

            for v31_item in metrics.get("cvssMetricV31", []):
                cvss_data = v31_item.get("cvssData", {})
                if "baseScore" in cvss_data:
                    cvss_score = float(cvss_data["baseScore"])
                    cvss_vector = cvss_data.get("vectorString")
                    break

            if cvss_score is None:
                for v30_item in metrics.get("cvssMetricV30", []):
                    cvss_data = v30_item.get("cvssData", {})
                    if "baseScore" in cvss_data:
                        cvss_score = float(cvss_data["baseScore"])
                        cvss_vector = cvss_data.get("vectorString")
                        break

            # Weaknesses (CWEs)
            relationships: list[NormalizedRelationship] = []
            weaknesses = cve_block.get("weaknesses", [])
            for w in weaknesses:
                for d in w.get("description", []):
                    cwe_val = d.get("value", "").strip()
                    if cwe_val.startswith("CWE-"):
                        relationships.append(
                            NormalizedRelationship(
                                relationship_type="cve_to_cwe",
                                target_identifier_type="cwe",
                                target_identifier=cwe_val,
                            )
                        )

            pub_str = cve_block.get("published")
            mod_str = cve_block.get("lastModified")
            published_at = None
            modified_at = None
            if pub_str:
                try:
                    published_at = datetime.fromisoformat(pub_str).replace(tzinfo=UTC)
                except ValueError:
                    pass
            if mod_str:
                try:
                    modified_at = datetime.fromisoformat(mod_str).replace(tzinfo=UTC)
                except ValueError:
                    pass

            item_bytes = json.dumps(item, sort_keys=True).encode("utf-8")
            raw_hash = hashlib.sha256(item_bytes).hexdigest()
            norm_content = f"{cve_id}:{cvss_score}:{cvss_vector}".encode()
            norm_hash = hashlib.sha256(norm_content).hexdigest()

            normalized.append(
                NormalizedIntelRecord(
                    source_record_id=cve_id,
                    record_type="cve",
                    title=f"NVD Vulnerability {cve_id}",
                    summary=summary,
                    description=summary,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    raw_payload=item,
                    raw_hash=raw_hash,
                    normalized_hash=norm_hash,
                    published_at=published_at,
                    modified_at=modified_at,
                    retrieved_at=batch.retrieved_at,
                    relationships=relationships,
                )
            )
        return normalized

    def checkpoint(self, batch: FeedBatch) -> str | None:
        return batch.cursor_after
