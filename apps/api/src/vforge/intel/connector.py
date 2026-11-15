"""Threat Intelligence Connector protocol and shared data contracts (Phase 9)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True)
class SourceMetadata:
    slug: str
    name: str
    source_type: str
    provider_url: str
    license_name: str
    license_url: str | None = None
    terms_reference: str | None = None
    is_gated: bool = False
    requires_scope_auth: bool = False
    allow_binary_upload: bool = False


@dataclass(frozen=True)
class SourceHealth:
    is_healthy: bool
    status_code: int = 200
    latency_ms: float = 0.0
    error_message: str | None = None
    checked_at: datetime | None = None


@dataclass
class FeedBatch:
    cursor_before: str | None
    cursor_after: str | None
    raw_payload: Any
    raw_hash: str
    retrieved_at: datetime
    record_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ValidationResult:
    is_valid: bool
    errors: list[str] = field(default_factory=list)
    schema_version: str | None = None


@dataclass
class NormalizedRelationship:
    relationship_type: str
    target_identifier_type: str
    target_identifier: str


@dataclass
class NormalizedIntelRecord:
    source_record_id: str
    record_type: str
    title: str | None = None
    summary: str | None = None
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_known_exploited: bool = False
    raw_payload: dict[str, Any] = field(default_factory=dict)
    raw_hash: str = ""
    normalized_hash: str = ""
    published_at: datetime | None = None
    modified_at: datetime | None = None
    retrieved_at: datetime | None = None
    relationships: list[NormalizedRelationship] = field(default_factory=list)


class IntelligenceConnector(Protocol):
    """Protocol implemented by every VForge threat intelligence feed connector."""

    def metadata(self) -> SourceMetadata:
        """Return provider identity, schema, licensing, and gate requirements."""
        ...

    async def health_check(self) -> SourceHealth:
        """Check live feed availability, endpoint response, and authentication."""
        ...

    async def fetch_incremental(self, cursor: str | None = None) -> FeedBatch:
        """Fetch a page/batch of feed data using cursors or timestamps."""
        ...

    def validate(self, batch: FeedBatch) -> ValidationResult:
        """Validate batch schema, integrity, and structural invariants."""
        ...

    def normalize(self, batch: FeedBatch) -> list[NormalizedIntelRecord]:
        """Normalize raw feed items into canonical IntelRecord representations."""
        ...

    def checkpoint(self, batch: FeedBatch) -> str | None:
        """Return the next resumption cursor from the completed batch."""
        ...
