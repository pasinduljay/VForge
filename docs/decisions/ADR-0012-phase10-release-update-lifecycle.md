# ADR-0012: Phase 10 Four-Stream Release & Update Lifecycle Management, Canary Promotion, and Instant Rollback

**Status:** Accepted  
**Date:** 2026-11-13  
**Deciders:** VForge Principal Architect & DevSecOps Engineering Team  
**Scope:** Phase 10 — Release Monitor, Four-Stream / Ten-Channel Update Registry (`tool_catalog`, `tool_versions`, `tool_updates`, `feed_snapshots`, `update_test_results`, `update_audit_events`), Validation Gates, Canary/Stable Promotion, Emergency Updates, and Zero-Rebuild Rollback

---

## Context

Security platforms depend on rapidly evolving scanner engines, native rules/templates, vulnerability databases, and platform dependencies. Treating all components as a single monolithic update or floating `:latest` tags creates three critical failure modes:
1. **Broken or Unverified Scanner Upgrades:** Updating a scanner binary (e.g., OpenGrep or Nuclei) without running adapter contract and regression corpus tests can silently break SARIF/JSON parsing or introduce high false-negative rates.
2. **Audit Non-Reproducibility:** If historical scan runs do not bind immutable digests and feed snapshot versions at scan creation time, auditing a historical finding months later becomes impossible after an engine upgrade or rollback.
3. **High-Friction Emergency Response:** Critical zero-day advisories in scanner dependencies or vulnerability databases require an expedited approval track with explicit auditability and instant rollback, without bypassing baseline safety or contract checks.

---

## Decision

### 1. Four Independent Update Streams & Ten Channels
In alignment with Architecture §5 & §28 and `lifecycle/image-lock/schema.json`, VForge strictly separates update management into four independent streams across ten channels:
1. **Engines & Base Images (`engines_and_base_images`):** `scanner_engine_versions`, `container_base_images`, `cryptographic_and_security_components`.
2. **Rules, Templates & Add-ons (`rules_templates_addons`):** `scanner_addons`, `scanner_rules_and_templates`, `ai_rule_packs_and_skills`.
3. **Vulnerability & Intelligence Databases (`vulnerability_intel_dbs`):** `vulnerability_databases`, `threat_intelligence_feeds`.
4. **Adapters & Dependencies (`adapters_and_dependencies`):** `ai_models`, `application_dependencies`.

`automerge` is permanently disabled (`automerge_allowed = false`) for scanner engine images and cryptographic security components.

### 2. Digest Pinning & Promotion State Machine
- Every container/image version (`tool_versions`) **must** carry an immutable `sha256:<64-hex>` digest and explicit non-`:latest` tag (`ck_tool_versions_not_latest_tag`).
- Update candidates flow strictly through the controlled state machine:
  `detected (candidate)` -> `validating` -> `validated` -> `approved` -> `canary` -> `stable` (with terminal/recovery states `rejected` and `rolled_back`).
- Promotion to `approved`, `canary`, or `stable` is blocked server-side unless required verification gates (`signature_provenance`, `sbom_and_image_scan`, `adapter_contract`, `regression_corpus`) are recorded as `passed` in the append-only `update_test_results` table.
- **Emergency Security Update Path:** Critical security patches may bypass routine non-safety gates (such as `regression_corpus` full soak) **only** when `is_emergency = true`, `emergency_justification` is provided, `adapter_contract` and `signature_provenance` pass, and an `owner`, `admin`, or `security_lead` explicitly authorizes the action, recording an immutable `emergency_approved` event in `update_audit_events`.

### 3. Zero-Rebuild Rollback & Immutable Scan Provenance
- `tool_versions` enforces at most one `is_active_stable` and one `is_active_canary` per `tool_id` via PostgreSQL partial unique indexes (`uq_tool_versions_active_stable`, `uq_tool_versions_active_canary`), while retaining all prior promoted rows and `previous_stable_version_id` pointers.
- Instant rollback demotes the faulty version (`approval_channel = 'rolled_back'`) and atomically restores `previous_stable_version_id` (or an explicit target historical version) as `is_active_stable = true`.
- `scan_runs` captures `tool_version_pins` (JSONB frozen snapshot of resolved `tool_version`, `image_digest`, `adapter_version`, and active `feed_snapshots`) at scan creation time alongside per-job `RunnerJob.tool_version` and `RunnerJob.image_digest`. Subsequent promotions or rollbacks **never** mutate historical scans.

### 4. Immutable Evidence & Role Governance
- `update_test_results` and `update_audit_events` are protected by PostgreSQL trigger `prevent_phase10_immutable_mutation()` (`SQLSTATE 55000`) and `REVOKE UPDATE, DELETE` from `vforge_app`.
- OPA policy (`authz.rego`) & backend RBAC (`Permission.UPDATE_READ`, `Permission.UPDATE_MANAGE`) restrict update approvals, promotions, and rollbacks strictly to `owner`, `admin`, and `security_lead`.
- Dedicated `update-controller` Control Plane service (`python -m vforge.lifecycle.update_controller`) monitors release/image-lock manifests with non-root UID `10001`, `read_only: true`, `cap_drop: [ALL]`, and zero Docker socket access.

---

## Consequences

### Positive
- Safe, auditable scanner engine upgrades decoupled from daily vulnerability DB/template refreshes.
- Historical scan runs remain deterministically bound to exact scanner digests and DB snapshots across promotions and rollbacks.
- Instant 1-action rollback with zero container rebuilds.

### Negative / Trade-offs
- Additional database tables and governance steps required before new scanner engine digests become active in production scans.
