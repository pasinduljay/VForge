# ADR-0010: Phase 8 Canonical Findings Correlation, Triage/Retest Lifecycle, SLA Tracking, and Multi-Format Reporting

**Status:** Accepted  
**Date:** 2026-11-13  
**Deciders:** VForge Principal Architect & DevSecOps Engineering Team  
**Scope:** Phase 8 — Findings Domain, Lifecycle Auditing, Risk Exceptions, SLA Tracking, and Executive/Technical Reporting

---

## Context

VForge captures vulnerability observations across multiple scanning engines (SAST, Secrets, SCA, IaC, DAST, Network, TLS). Each scanner emits tool-native findings with varying identifiers, severities, and confidence levels. 

In Phases 5–7, VForge established:
- Canonical deduplicated `findings` keyed by deterministic fingerprint `(organization_id, project_id, fingerprint)`.
- Immutable `finding_occurrences` preserving the exact tool, image digest, raw artifact, and source evidence.
- SBOM documents and Vulnerability DB snapshot references.

Phase 8 requires completing the operational vulnerability management and reporting capabilities:
1. **Finding Triage & Retest Lifecycle:** Tracking finding status (`open`, `in_progress`, `resolved`, `risk_accepted`, `false_positive`), validation status (`unverified`, `reproduced`, `human_confirmed`, `fixed`, `reopened`), assignment, and retest verification across rescans.
2. **Append-Only Lifecycle Events:** An audit table `finding_events` recording every status change, triage note, assignment, and retest result with actor attribution.
3. **Time-Bound Risk Exceptions:** Formal risk acceptance workflow (`risk_exceptions`) with business justifications, mitigating controls, explicit expiration dates, and role-gated approvals restricted to `security_lead` / `admin` / `owner`.
4. **SLA Tracking & Risk Prioritization:** Calculating resolution deadlines (`sla_due_at`) based on severity policies (Critical: 7d, High: 14d, Medium: 30d, Low: 60d, Info: 90d), breach flags (`sla_breached`), and business priority scoring.
5. **Multi-Format Enterprise Reporting:** Professional executive and technical reporting in HTML, PDF, machine-readable JSON, and standard OASIS SARIF 2.1.0, preserving explicit scan coverage, tool version provenance, and disclosures of failed or skipped stages.

---

## Decisions

### 1. Database Schema Extensions (`0009_phase8_findings_reporting`)

1. **`finding_events` Table:**
   - Columns: `id`, `organization_id`, `finding_id`, `actor_id` (nullable for system/orchestrator events), `event_type` (`status_changed`, `assigned`, `unassigned`, `comment_added`, `risk_exception_requested`, `risk_exception_approved`, `risk_exception_rejected`, `retest_passed`, `retest_failed`, `severity_overridden`), `previous_status`, `new_status`, `comment`, `metadata` (JSONB), `created_at` (TIMESTAMPTZ UTC).
   - Invariants: `ENABLE` + `FORCE ROW LEVEL SECURITY`, composite FK `(organization_id, finding_id) -> findings(organization_id, id)`, append-only trigger + `REVOKE UPDATE, DELETE FROM vforge_app`.

2. **`risk_exceptions` Table:**
   - Columns: `id`, `organization_id`, `project_id`, `finding_id`, `status` (`pending`, `approved`, `rejected`, `expired`, `revoked`), `requested_by` (FK `app_users.id`), `reviewed_by` (FK `app_users.id`, nullable), `reason` (TEXT), `mitigating_controls` (TEXT), `review_notes` (TEXT, nullable), `expires_at` (TIMESTAMPTZ), `created_at`, `updated_at`.
   - Invariants: `ENABLE` + `FORCE ROW LEVEL SECURITY`, composite FKs.
   - Lifecycle: Only `security_lead`, `admin`, or `owner` can approve/reject. When approved, finding status automatically updates to `risk_accepted` with `accepted_risk` validation status and logs an entry in `finding_events`. Expired exceptions automatically flag the finding for reassessment.

3. **`reports` Table:**
   - Columns: `id`, `organization_id`, `project_id`, `scan_run_id` (nullable for project-level reports), `report_type` (`executive`, `technical_vapt`, `compliance_summary`, `sarif_export`), `format` (`html`, `pdf`, `json`, `sarif`), `title`, `summary` (JSONB: finding counts, severity breakdown, coverage status), `artifact_id` (FK `artifacts.id` referencing encrypted stored report content), `generated_by` (FK `app_users.id`), `created_at`.
   - Invariants: `ENABLE` + `FORCE ROW LEVEL SECURITY`, composite tenant FKs.

4. **Extended Columns on `findings`:**
   - `sla_due_at`: TIMESTAMPTZ UTC, computed on creation from severity policy.
   - `sla_breached`: BOOLEAN NOT NULL DEFAULT FALSE.
   - `assigned_to`: UUID nullable FK to `app_users.id`.
   - `remediation_notes`: TEXT nullable.
   - `retest_status`: VARCHAR(30) nullable (`pending_retest`, `retest_passed`, `retest_failed`).
   - `business_priority`: VARCHAR(20) NOT NULL DEFAULT 'medium'.
   - `cvss_score`: NUMERIC(3, 1) nullable.
   - `cvss_vector`: VARCHAR(100) nullable.

### 2. SLA Policies & Risk Prioritization

- Default SLA windows from first observation:
  - `critical`: 7 days
  - `high`: 14 days
  - `medium`: 30 days
  - `low`: 60 days
  - `info`: 90 days
- Evaluation query / hook checks `sla_due_at < now()` and `status NOT IN ('resolved', 'risk_accepted', 'false_positive')` to update `sla_breached`.

### 3. Report Generation Engine (`vforge.services.reporting`)

- **HTML Report:** Clean, responsive, self-contained HTML document with inline CSS styling optimized for screen and print (`@media print`). Displays executive summary, severity matrix, scope snapshot and authorization references, tool version lock catalog, scan coverage disclosures (explicitly noting any failed or skipped stages), and sanitized finding details with occurrences.
- **PDF Report:** Rendered from the HTML document using a secure, zero-network HTML-to-PDF generator (WeasyPrint if available or hardened standalone print-ready HTML artifact with embedded pagination and SVG charts).
- **JSON Report:** Complete machine-readable VForge export including organization, project, scan run details, execution records, tool versions, and full finding occurrences.
- **SARIF 2.1.0 Export:** Standards-compliant OASIS SARIF document (`https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json`). Groups results under separate `runs[]` entries per tool with exact driver versions, rule definitions, and locations.

### 4. Encryption & Artifact Storage for Reports

All generated report files (HTML, PDF, JSON, SARIF) are treated as sensitive artifacts containing sanitized scan data. They are:
- Encrypted using AES-256-GCM envelope encryption via the control-plane `resolve_kek` and `encrypt_artifact_bytes`.
- Stored under `vforge_artifacts` volume with an entry in the `artifacts` table (`artifact_type = "report"`).
- Decrypted on-the-fly when authorized users download via `GET /reports/{report_id}/download`.

---

## Consequences & Mitigations

1. **Security & Least Privilege:**
   - All new tables have `ENABLE` and `FORCE ROW LEVEL SECURITY` with `vforge_app` policy `organization_id = current_setting('app.current_org_id')::uuid`.
   - `finding_events` is append-only; update and delete permissions are revoked from `vforge_app`.
   - Risk acceptance approvals are strictly guarded by OPA policy (`authz.rego`) and service checks (`assert_permission`).

2. **Honesty Invariant:**
   - Reports explicitly disclose partial scan coverage, failed stages, or unverified findings.
   - When a tool stage fails or is skipped, the report header displays `Coverage: Partial (Stage errors detected)` and never reports a zero-finding result as clean.

3. **Performance:**
   - Indexed composite keys for fast finding list queries and SLA breach monitoring.
   - Report generation is fast, memory-bounded, and does not hold database transactions open during file rendering or encryption.
