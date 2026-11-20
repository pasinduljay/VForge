# ADR-0016: Phase 14 Hardening, Multi-KEK Rotation, Encrypted DR & Observability

- **Status:** Accepted
- **Date:** 2026-11-13
- **Deciders:** VForge Autonomous Architecture & Platform Security Team
- **Related:** [ADR-0004](ADR-0004-security-preflight-role-separation-and-secrets.md), [ADR-0006](ADR-0006-phase4-runner-agent-mtls-isolation.md), [`docs/DEVELOPMENT_ROADMAP.md`](../../docs/DEVELOPMENT_ROADMAP.md) §26 & §32, [`docs/runbooks/BACKUP_AND_DR.md`](../runbooks/BACKUP_AND_DR.md)

---

## 1. Context

Before optional AI red teaming (Phase 15) and final §32 release acceptance, VForge must operationalize cryptographic agility, multi-KEK rotation across existing encrypted artifacts, workload-identity OpenBao dynamic leasing, runner/gateway/CA certificate expiry & revocation monitoring, non-destructive PostgreSQL & tenant DR verification drills, API abuse protections, parser/sanitizer fuzzing, and scrubbed Prometheus/Grafana observability without making dishonest compliance or PQC claims.

## 2. Decision

1. **Multi-KEK Envelope Keyring & Online Re-Wrapping (`vforge.security.envelope`, `vforge.hardening.service`):**
   - Extend `Settings` and `envelope.py` with `ARTIFACT_ENCRYPTION_KEYRING_JSON`, `BACKUP_ENCRYPTION_KEY_ID`, `BACKUP_ENCRYPTION_KEY_B64`, `resolve_keyring()`, `decrypt_artifact_with_keyring(..., revoked_key_ids=...)`, and `rewrap_artifact_dek()`.
   - Migrate all production decryption paths (`findings.py`, `reporting.py`, `runners.py`, `source_snapshots.py`) onto `resolve_keyring()` so historical artifacts/reports/SBOMs/snapshots remain readable across KEK rotations while honoring key revocation.
   - Preserve append-only `REVOKE UPDATE, DELETE` invariants on `artifacts` and `source_snapshots` while supporting online atomic DEK re-wrapping on mutable `dr_backup_manifests` (`POST /hardening/keys/rewrap-persisted`) and live synthetic DEK re-wrap verification drills (`POST /hardening/keys/rewrap-drill`).

2. **Cryptographic Honesty & OPA Enforcement (§26.3, §26.4):**
   - `evaluate_crypto_agility()` exposes active classical primitives (`AES-256-GCM`, `Ed25519`, `ECDSA P-256`, `Argon2id`, `TLS 1.3`), PQC agility metadata targets (`FIPS 203 ML-KEM`, `FIPS 204 ML-DSA`, `FIPS 205 SLH-DSA` with `pqc_live_enabled: False` and `pqc_hybrid_live_enabled: False`), and `fips_validated_claim: False`.
   - `0015_phase14_hardening_dr.py`, `schemas.py`, `hardening/service.py`, and `authz.rego` fail closed (`403`/`422`) on unverified FIPS validation claims or experimental/custom PQC protocols, and enforce `hardening:read` / `hardening:manage` OPA checks on both read and mutating routes.

3. **OpenBao Workload Identity & Startup Fail-Closed Gates (`vforge.secrets.provider`, `config.py`):**
   - Upgrade `OpenBaoProvider` with production HTTPS enforcement, thread-safe workload authentication (`approle`, `kubernetes`, `jwt`, `oidc` mount), 401/403 re-auth retry, path segment allowlisting, dynamic PostgreSQL credential leasing (`get_database_credentials`, `renew_lease`), and explicit exclusion of static `BAO_TOKEN`/`VAULT_TOKEN` tokens.
   - Extend `Settings.validate_startup_configuration()` to fail closed in production/staging if artifact/backup KEKs or required `/metrics` bearer tokens are absent.

4. **Database Schema, RLS, Atomic Key Epochs & Encrypted DR Drills (`0015_phase14_hardening_dr.py`):**
   - Add `encryption_key_records` (with partial unique index `ix_ekr_org_purpose_active` `WHERE status = 'active'` and parent-org `FOR UPDATE` serialization), `dr_backup_manifests` (AES-256-GCM under dedicated backup KEK + tenant AAD), immutable `dr_restore_drills`, and immutable `hardening_audit_events`.
   - Enforce `ENABLE` + `FORCE ROW LEVEL SECURITY` (`NULLIF(current_setting('app.current_org_id', true), '')::uuid`), least-privilege `vforge_app` grants, composite tenant FK `fk_drd_org_manifest`, and `prevent_phase14_immutable_mutation` triggers.
   - Provide `scripts/dr/backup_and_verify.ps1` executing non-destructive inside-container `pg_dump -Fc`, full `pg_restore --list` validation, persistent volume presence checks, and `alembic_version` assertion.

5. **Scrubbed Observability & Bounded Cardinality (`vforge.observability.metrics`, `main.py`, `infrastructure/monitoring/`):**
   - Resolve matched FastAPI route templates (`"__unmatched__"` for 404 probes), enforce UUID/integer normalization + 256-route cap (`"__overflow__"`), omit tenant IDs/PII/secrets, and enforce constant-time `Authorization: Bearer` validation on `/metrics` when `metrics_bearer_token_required=True` or in production/staging.
   - Deliver opt-in, loopback-bound, non-root, read-only `infrastructure/monitoring/compose.observability.yaml` (`--profile monitoring`) with `alerts.yml`.

## 3. Consequences

- **Positive:** Seamless zero-downtime KEK rotation across historical encrypted data; atomic monotonic key epoch management; production-safe fail-closed startup & `/metrics` authentication; non-destructive DR verification; Hypothesis property-based fuzzing across tar/zip canonicalizers, XML parsers, and YAML validators.
- **Limitation / Operational Follow-Up:** Prometheus metrics are accumulated per API worker process in memory; multi-worker production deployments should scrape per-worker targets or aggregate via external collectors, and production deployments must set immutable `@sha256:` image pins plus HTTPS termination for Grafana `Secure` cookies and `METRICS_BEARER_TOKEN`.
