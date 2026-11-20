# ADR-0011: Phase 9 Provenance-Aware Threat Intelligence Connectors, Offline Sync, and Gated Enrichment

**Status:** Accepted  
**Date:** 2026-11-13  
**Deciders:** VForge Principal Architect & DevSecOps Engineering Team  
**Scope:** Phase 9 — Threat Intelligence Feeds (NVD, EPSS, CISA KEV, OSV, GHSA, Exploit-DB), Provenance Preservation, Privacy Gates, Stale Data Handling, and Deterministic Replay

---

## Context

Vulnerability assessment without threat intelligence produces static findings that treat all CVEs of equal CVSS score identically, ignoring whether a vulnerability is actively exploited in the wild (CISA KEV), its probability of near-term exploitation (FIRST EPSS), or public exploit research availability (Exploit-DB).

However, integrating external threat intelligence introduces critical security and reliability challenges:
1. **Source of Truth & Provenance:** Different sources serve different purposes. CISA KEV indicates observed wild exploitation; FIRST EPSS provides probabilistic risk likelihood; NVD provides NIST CVSS and CPE applicability; OSV/GHSA provides ecosystem package matching; Exploit-DB provides research references. Conflating these leads to inaccurate risk decisions.
2. **Deterministic Snapshot Replay:** Regulatory compliance and historical audits require proving *what intelligence was known at the exact time a scan or report was generated*. Running an audit on a 6-month-old scan against live feeds would alter findings and invalidate assessment integrity.
3. **Fail-Closed Stale Data Handling:** External feeds experience network outages, rate limits, or API deprecations. Reporting an outage as "zero vulnerabilities found" or "no risk" is catastrophic. The system must retain last-known-good snapshots, flag data as stale, and disclose feed outages honestly.
4. **Privacy & Egress Gates:** Commercial and third-party threat services (e.g., Shodan, Pulsedive, VirusTotal) present data leakage risks. Uploading customer source code or binaries to public scanners violates non-disclosure and intellectual property boundaries.
5. **Rate Limiting & Bounded Sync:** Public feeds enforce strict rate limits (e.g., NVD API 2.0 without key: 5 requests / 30s; with key: 50 requests / 30s). Synchronizations must be incremental with cursors, ETags, and backoff.

---

## Decisions

### 1. Database Schema (`0010_phase9_threat_intel`)

1. **`intelligence_sources` Table (Platform Reference Data):**
   - Identifier `id` (UUID), `slug` (VARCHAR unique e.g., `nvd`, `cisa_kev`, `first_epss`, `osv`, `ghsa`, `exploit_db`, `shodan`, `virustotal`, `pulsedive`).
   - `name`, `source_type` (`cve_catalog`, `exploit_catalog`, `probability_feed`, `package_advisory`, `exposure_intel`, `ioc_feed`).
   - `provider_url`, `license_name`, `license_url`, `terms_reference`.
   - `is_active` (BOOL), `is_gated` (BOOL), `requires_scope_auth` (BOOL), `allow_binary_upload` (BOOL default `false`).
   - `created_at`, `updated_at`.
   - Permissions: Read access for `vforge_app`; management restricted to `vforge_migrator` / admin services.

2. **`intel_sync_runs` Table:**
   - Tracks every sync execution: `id`, `source_id` (FK), `sync_mode` (`full`, `incremental`), `cursor_before`, `cursor_after`.
   - `status` (`pending`, `running`, `succeeded`, `failed`, `stale`, `quarantined`).
   - `records_fetched`, `records_persisted`, `error_message`, `raw_payload_hash` (SHA-256 hex).
   - `started_at`, `completed_at`.

3. **`intel_snapshots` Table (Immutable Audit Snapshots):**
   - Point-in-time reference snapshot used for deterministic replay: `id`, `source_id` (FK), `snapshot_tag`, `snapshot_hash` (SHA-256).
   - `storage_uri` (reference to local compressed cache or encrypted artifact), `record_count`.
   - `is_stale` (BOOL default `false`), `stale_reason` (TEXT nullable).
   - `created_at`.
   - Append-only trigger preventing UPDATE / DELETE.

4. **`intel_records` Table:**
   - Normalized records: `id`, `source_id` (FK), `source_record_id` (VARCHAR e.g. `CVE-2024-1234`, `EDB-51234`, `GHSA-xxxx`).
   - `record_type` (`cve`, `kev`, `epss`, `osv`, `ghsa`, `cwe`, `edb`, `ioc`).
   - `title`, `summary`, `description`.
   - `cvss_score`, `cvss_vector`, `epss_score` (FLOAT nullable), `epss_percentile` (FLOAT nullable), `is_known_exploited` (BOOL default `false`).
   - `raw_payload` (JSONB), `raw_hash` (VARCHAR(64)), `normalized_hash` (VARCHAR(64)).
   - `published_at`, `modified_at`, `retrieved_at`, `created_at`, `updated_at`.
   - Unique constraint `(source_id, source_record_id)`.

5. **`intel_relationships` Table:**
   - Mappings between records and target identifiers: `id`, `intel_record_id` (FK), `relationship_type` (`cve_to_cwe`, `cve_to_epss`, `cve_to_kev`, `cve_to_purl`, `cve_to_edb`), `target_identifier_type` (`cve`, `cwe`, `purl`, `edb`, `capec`, `att_ck`), `target_identifier`.

6. **`intel_enrichment_events` Table (Tenant-Scoped with RLS):**
   - Records every enrichment event applied to a finding: `id`, `organization_id`, `project_id`, `finding_id`, `intel_snapshot_id`, `intel_record_id`, `enrichment_data` (JSONB: snapshot of KEV status, EPSS score, CVSS at enrichment time), `created_at`.
   - `ENABLE` and `FORCE ROW LEVEL SECURITY`.
   - Append-only trigger preventing mutation.

---

### 2. Connector Architecture & Protocol

Every connector implements `IntelligenceConnector`:
```python
class IntelligenceConnector(Protocol):
    def metadata(self) -> SourceMetadata: ...
    async def health_check(self) -> SourceHealth: ...
    async def fetch_incremental(self, cursor: str | None = None) -> FeedBatch: ...
    def validate(self, batch: FeedBatch) -> ValidationResult: ...
    def normalize(self, batch: FeedBatch) -> list[NormalizedIntelRecord]: ...
    def checkpoint(self, batch: FeedBatch) -> str | None: ...
```

Built-in connectors:
- **`CisaKevConnector`**: Fetches the official CISA KEV JSON catalog, verifies schema and dateAdded timestamps, marks CVEs as known exploited.
- **`FirstEpssConnector`**: Fetches EPSS probabilistic likelihood and percentile scores, handles both bulk CSV/JSON and point queries.
- **`NvdCveConnector`**: Parses NVD API 2.0 / CVE List v5 records with CVSS v3.1/v4.0 vectors, metric breakdowns, and CWE mappings.
- **`OsvGhsaConnector`**: Parses Open Source Vulnerability format for ecosystem-specific PURL and package version matches.
- **`ExploitDbConnector`**: Parses local SearchSploit database records with EDB-ID, title, platform, author, and CVE cross-references.
- **`GatedExposureConnector` (Shodan / Pulsedive / VirusTotal)**: Enforces privacy gates, scope verification, and hash-only lookups.

---

### 3. Privacy, Licensing & Safety Gates

1. **VirusTotal Gate:**
   - Default binary/source code upload is hard-disabled (`allow_binary_upload: false`).
   - Only SHA-256 / SHA-1 hash lookups are permitted by default.
   - Any upload proposal requires explicit organization admin approval and verified private scanning license.
2. **Shodan & Pulsedive Asset Verification:**
   - Connectors reject queries for IP addresses or hostnames that are not in the organization's verified and approved target scope.
   - Stored results record query timestamp and observational caveats (banner data may be historic).
3. **Exploit-DB Isolation:**
   - SearchSploit results are indexed strictly as descriptive research references.
   - Automated execution of retrieved exploit payloads is strictly prohibited.

---

### 4. Stale-Data & Replay Semantics

- When a feed is unreachable, the sync run records `status = 'failed'` and updates the snapshot with `is_stale = true` and `stale_reason`.
- The enrichment service continues using the last-known-good snapshot but attaches `intel_stale: true` and the age of the snapshot to the enriched finding.
- Scan runs and reports record the exact `intel_snapshot_id` used. Retrospective report generation uses the historical snapshot, ensuring deterministic reproducibility.

---

## Consequences

### Positive
- Finding triage and SLA prioritization gain quantitative signals (`is_known_exploited`, `epss_score`).
- Clean provenance: Every enrichment links to an exact feed snapshot, record hash, and retrieval timestamp.
- No accidental data exfiltration: Strict privacy gates prevent uploading proprietary source code or binaries to public services.
- Resilient to network outages: Last-known-good cached snapshots prevent scanning failures while honestly disclosing staleness.

### Negative / Trade-offs
- Local storage footprint increases with cached threat records and snapshots.
- Requires periodic synchronization background jobs or on-demand cache refresh.
