# VForge Implementation Status

> **Current Phase:** Final Independent Verification, Security Audit & Release Acceptance (`chore/final-release-verification`) — All Phases 0–15 Independently Audited & Verified
> **Last Updated:** 2026-11-15
> **Phase 0 Exit Gate:** PASSED (preserved)
> **Phase 1 Exit Gate:** PASSED (preserved)
> **Phase 2 Exit Gate:** PASSED (preserved)
> **Pre-Phase 3 Security Preflight:** PASSED (preserved)
> **Phase 3 Exit Gate:** PASSED (preserved)
> **Phase 4 Exit Gate:** PASSED (preserved)
> **Phase 5 Exit Gate:** PASSED (preserved)
> **Phase 6 Exit Gate:** PASSED (preserved)
> **Phase 7 Exit Gate:** PASSED (preserved)
> **Phase 8 Exit Gate:** PASSED (preserved)
> **Phase 9 Exit Gate:** PASSED (preserved)
> **Phase 10 Exit Gate:** PASSED (preserved)
> **Phase 11 Exit Gate:** PASSED (preserved)
> **Phase 12 Exit Gate:** PASSED (preserved)
> **Phase 13 Exit Gate:** PASSED (preserved)
> **Phase 14 Exit Gate:** PASSED (preserved)
> **Phase 15 Exit Gate:** PASSED (verified on `feature/phase-15-ai-red-teaming` at `d29b3a6` / `6bc0119`)
> **Final Independent Verification & DR Restore Audit:** PASSED (verified on `chore/final-release-verification`)

## Completed Items (Final Independent Verification, Security Audit & DR Restore — `chore/final-release-verification`)

- **Full Disposable-Container Disaster Recovery Restore Drill (`scripts/dr/backup_and_verify.ps1`, `docs/DISASTER_RECOVERY_RESTORE_REPORT.md`):**
  - Upgraded `scripts/dr/backup_and_verify.ps1` (`VF-AUDIT-002`) from a `pg_restore --list` check to a complete isolated-container restore drill (`vforge_dr_verify_pg_*` on `--internal` Docker network `vforge_dr_verify_net_*` with `--tmpfs` storage), verifying `pg_restore --exit-on-error`, Alembic head `0016_phase15_ai_redteam`, `81` tables, `63` forced-RLS tenant tables, `172` FKs, `35` triggers, `0` invalid indexes, seeded catalogs, and `vforge_app` (`NOBYPASSRLS`) runtime read isolation.
- **Disposable-Database Full Migration Chain Verification (`scripts/db/verify_migrations_disposable.ps1`, `VF-AUDIT-001`, `VF-AUDIT-003`):**
  - Created `scripts/db/verify_migrations_disposable.ps1` verifying `alembic upgrade head` (`base -> 0016`), `alembic downgrade base` (`0016 -> base`), and `alembic upgrade head` (`base -> 0016`) on a fresh disposable database without downgrading the persistent `vforge` database.
  - Remediated `0002` role-management guard under `vforge_migrator`, `0009`/`0010` RLS `NULLIF(..., '')` casts, 7 composite FKs (`ON DELETE RESTRICT` / `ON DELETE SET NULL (<col>)`), and `0009` `downgrade()` report artifact cleanup.
- **Adversarial Security Audit Remediations (`VF-AUDIT-004`..`VF-AUDIT-012`, `docs/FINAL_SECURITY_AUDIT.md`):**
  - Remediated `/api/v1/meta` honesty (`ai_redteam_governance_enabled: true`, `ai_redteam_sandbox_enabled: false` by default), `POST /findings/evaluate-sla` `Permission.FINDING_TRIAGE` enforcement (`VF-AUDIT-007`), `delete_project` savepoint `ConflictError` (`HTTP 409`) on immutable child records (`VF-AUDIT-008`), global `/api/v1/intel/*` active-org RBAC (`VF-AUDIT-009`), `DockerSecretProvider` `<NAME>_FILE` path traversal containment (`VF-AUDIT-010`), bounded 10 MiB upstream HTTP reads in `ScopedEgressGateway` (`VF-AUDIT-011`), and `@sha256` digest pinning in `compose.observability.yaml` (`VF-AUDIT-012`).
- **Final Release Deliverables (`docs/`):**
  - Produced [`docs/FINAL_VERIFICATION_REPORT.md`](FINAL_VERIFICATION_REPORT.md), [`docs/PRODUCTION_READINESS_ASSESSMENT.md`](PRODUCTION_READINESS_ASSESSMENT.md), [`docs/DISASTER_RECOVERY_RESTORE_REPORT.md`](DISASTER_RECOVERY_RESTORE_REPORT.md), [`docs/FINAL_SECURITY_AUDIT.md`](FINAL_SECURITY_AUDIT.md), and [`docs/FINAL_REQUIREMENT_TRACEABILITY.md`](FINAL_REQUIREMENT_TRACEABILITY.md).

## Completed Items (Phase 15)

- **Opt-In Isolated AI Red-Team Sandbox Compose (`infrastructure/redteam/compose.redteam.yaml`, `vforge.redteam.policy`, `ADR-0017`):**
  - Declared `ai-redteam-agent` under `--profile redteam` attached exclusively to the external isolated learning-lab network (`vforge-lab_lab_internal`, `internal: true`), with `read_only: true`, non-root `user: "10001:10001"`, `cap_drop: [ALL]`, `no-new-privileges:true`, `restart: "no"`, `tmpfs` `/tmp` & `/home/agent`, CPU/memory/PIDs caps, zero ports, zero volumes, zero secret env vars, and mandatory `@sha256` digest pinning (`${REDTEAM_AGENT_IMAGE:?...}`).
  - Programmatically verified before every session request and start via `verify_redteam_compose_isolation()` and `verify_lab_compose_isolation()`.
- **Additive Schema, Tenant RLS, SoD Constraints & Immutability Triggers (`0016_phase15_ai_redteam.py`, `models/redteam.py`):**
  - Added 4 tenant-scoped tables owned by `vforge_migrator` (`ai_redteam_sessions`, `ai_redteam_observations`, `ai_redteam_events`, `ai_redteam_benchmarks`) with `ENABLE` + `FORCE ROW LEVEL SECURITY`, composite tenant FKs, SoD & budget `CHECK` constraints (`ck_rts_approver_not_requester`, `ck_rts_approval_required`, `ck_rto_confirmed_requires_independent_review`), and PostgreSQL triggers freezing session parameters (`guard_phase15_session_update`), observation evidence (`guard_phase15_observation_update`), and append-only events/benchmarks (`prevent_phase15_immutable_mutation`).
- **Per-Session Human Approval, Tool/Target/Budget Gates, Hypothesis Review & Benchmark Harness (`vforge.redteam.service`, `api/routers/redteam.py`, `auth/rbac.py`, `policies/rego/vforge/authz.rego`):**
  - Enforced fixed safe tool allowlist (`http_probe`, `browser_navigate`, `dom_inspect`, `template_lookup`, `note_hypothesis`) and permanent `FORBIDDEN_TOOLS` (`shell_exec`, `shell:exec`, `docker`, `raw_docker_socket`, `scope:modify`, `opa:modify`, `rule:sign`, `rule:promote`, `finding:auto_confirm`, `network:expand_scope`), isolated lab target URL checks (`validate_session_targets`, `assert_url_within_session_targets`), per-session human approval (`approved_by != requested_by`), wall-clock duration & tool/token budgets, mandatory `cleanup_attested=True` on close, `hypothesis`-only AI observations requiring independent human confirmation (`reviewed_by != recorded_by`), and immutable ZAP/Nuclei/AI recall benchmarks (`compute_benchmark_metrics`).
- **Next.js UI, Runbooks & Final Release Acceptance (`apps/web/src/app/organizations/[orgId]/redteam/page.tsx`, `docs/RELEASE_ACCEPTANCE_REPORT.md`, `docs/runbooks/DEPLOYMENT_AND_UPGRADE.md`):**
  - Delivered `/organizations/[orgId]/redteam` UI, updated `/api/v1/meta` (`phase: 15`, `ai_redteam_sandbox_enabled: true`, `planned_capabilities: []`), and completed full §32 release acceptance documentation.

## Completed Items (Phase 14)

- **Multi-KEK Envelope Keyring, Online DEK Re-Wrapping & Cryptographic Honesty (`vforge.security.envelope`, `services/{findings,reporting,runners,source_snapshots}.py`, `ADR-0016`):**
  - Added `ARTIFACT_ENCRYPTION_KEYRING_JSON` and dedicated `BACKUP_ENCRYPTION_KEY_ID` / `BACKUP_ENCRYPTION_KEY_B64` support with strict base64 validation, key collision guards, revoked-key checks, and production startup fail-closed KEK enforcement (`config.py`).
  - Migrated all production decryption paths (`findings.py`, `reporting.py`, `runners.py`, `source_snapshots.py`) onto `resolve_keyring()` + `decrypt_artifact_with_keyring(...)`, and added atomic online `dr_backup_manifests` DEK re-wrapping (`POST /hardening/keys/rewrap-persisted`) + live DEK re-wrap verification drills (`POST /hardening/keys/rewrap-drill`).
  - Exposed honest §26.3/§26.4 `evaluate_crypto_agility()` posture (`fips_validated_claim: False`, `pqc_hybrid_live_enabled: False`), blocking unverified FIPS claims and experimental custom PQC protocols across schema, service, and OPA `authz.rego`.
- **OpenBao Workload Identity & Certificate Expiry/Revocation Monitoring (`vforge.secrets.provider`, `vforge.security.mtls`):**
  - Upgraded `OpenBaoProvider` with production HTTPS enforcement, thread-safe workload auth (`approle`, `kubernetes`, `jwt`, `oidc`), 401/403 re-auth retry, path validation, and dynamic DB credential lease fetch + renewal (`get_database_credentials`, `renew_lease`).
  - Added X.509 PEM certificate health inspection (`inspect_pem_cert_expiry`, `inspect_runner_certificate_health`) tracking healthy, `not_yet_valid`, expiring-soon, expired, `malformed_pem`, and revoked runner/CA/gateway certs.
- **Schema, Tenant RLS, Atomic Epoch Rotation & Encrypted DR Drills (`0015_phase14_hardening_dr.py`, `hardening/`, `scripts/dr/backup_and_verify.ps1`, `docs/runbooks/BACKUP_AND_DR.md`):**
  - Added `encryption_key_records` (with active-epoch partial unique index `ix_ekr_org_purpose_active` + `Organization` `FOR UPDATE` serialization), `dr_backup_manifests`, and immutable `dr_restore_drills` / `hardening_audit_events` (`FORCE ROW LEVEL SECURITY`, composite tenant FKs, least-privilege `vforge_app` grants, append-only triggers).
  - Delivered `scripts/dr/backup_and_verify.ps1` running non-destructive volume checks, `pg_dump -Fc`, full `pg_restore --list`, and `alembic_version` assertion (`0015_phase14_hardening_dr`).
- **Scrubbed Prometheus Observability, UI & Fuzz Security Suites (`vforge.observability.metrics`, `main.py`, `infrastructure/monitoring/`, `security-ops/page.tsx`):**
  - Enforced matched route-template labels, 256-route cardinality capping (`__overflow__` / `__unmatched__`), PII/tenant scrubbing, and constant-time Bearer token validation on `/metrics`, plus opt-in hardened `infrastructure/monitoring/compose.observability.yaml` (`--profile monitoring`).
  - Delivered `/organizations/[orgId]/security-ops` UI, Hypothesis property fuzzing across archive canonicalizers/Nmap XML/YAML validators, SSRF matrix, and expanded HTTP RBAC/IDOR tests (`tests/test_phase14_hardening_dr.py`).
- **Verification & Security Audit (`tests/smoke/phase14_smoke.ps1`):**
  - Independent Phase 14 security audit completed (`d215cd60-b3b7-4b16-87c1-1d0464b0745f`): all Critical/High/Medium findings remediated and covered by automated regression tests.
  - Full smoke suite exited `0` across all 8 gates: `alembic` head `0015` + `compose.observability.yaml`, `backup_and_verify.ps1`, OPA (`34/34 PASS`), `scanner-contracts` (`15 passed in 0.78s`), API (`ruff check`, `ruff format --check` `140 files already formatted`, `mypy` `0 issues in 104 source files`, `pytest` `121 passed, 2 skipped in 26.71s`), Runner (`ruff`, `mypy` `0 issues in 9 source files`, `pytest` `11 passed, 2 skipped in 1.47s`), Next.js `typecheck`/`lint`/`build`, and live HTTP probes (`/api/v1/meta`, `/metrics`, `/api/health`, `401` denial).

## Completed Items (Phase 13)

- **Opt-In Egress-Denied Lab Compose & Digest Pinning (`infrastructure/lab/compose.lab.yaml`, `lifecycle/image-lock/phase13-images.json`, `ADR-0015`):**
  - Built an isolated opt-in lab stack (`vforge-lab` with `--profile lab`) running `bkimminich/juice-shop:v17.1.1`, `webgoat/webgoat:v2023.8`, `crapi/crapi-web:develop`, `crapi/crapi-identity:develop`, and disposable `postgres:18` pinned via `@sha256:` digests on `lab_internal` (`internal: true`), `127.0.0.1` loopback-only ports (`3100..3102`), `cap_drop: [ALL]`, `no-new-privileges:true`, and disposable `tmpfs` mounts with zero control-plane network or DB links.
- **Schema, Tenant RLS, Consent Constraints & Immutability (`0014_phase13_learning_lab.py`, `models/lab.py`):**
  - Seeded 4 curated tracks (`beginner`, `intermediate`, `advanced`, `expert_practice`) in `lab_challenges` and added 5 tenant-scoped tables owned by `vforge_migrator` (`lab_workspaces`, `lab_challenge_progress`, `lab_validation_runs`, `lab_self_scans`, `lab_audit_events`) with `ENABLE` + `FORCE ROW LEVEL SECURITY`, composite tenant FKs, safety/consent `CHECK` constraints, and append-only triggers + `REVOKE UPDATE, DELETE` from `vforge_app`.
- **Exploitation Boundary Enforcement, Consent/Reset Lifecycle & Honest Self-Scans (`apps/api/src/vforge/lab/`, `authz.rego`):**
  - Implemented `safety.py` blocking non-lab URLs, IMDS/private IPs, control-plane services/ports, and query-string credentials while programmatically verifying Compose isolation invariants and failing closed on OPA unavailability/malformed JSON.
  - Enforced positive allowlisting in `authz.rego` (`lab_practice_action_allowed` + `lab_forbidden_boundary` blocking persistence/exfiltration/stealth/dos_flood/unknown modes) and fail-closed OPA gating across `lab:manage` & `lab:practice`.
  - Enforced epoch-scoped disposable accounts, secret-redacted non-empty validation evidence (`>= 12 chars`), consent-gated `LabChallengeProgress` persistence (clearing & suppressing progress on consent revocation with `CONSENT_UPDATED` audit), workspace epoch reset, and honest `run_vforge_self_scan` inspection across mounted Compose files, OPA authz policy, and raw JSON image-lock manifests.
- **API & Next.js Learning Lab Workspace (`api/routers/lab.py`, `main.py`, `apps/web/.../lab/page.tsx`):**
  - Exposed `/api/v1/organizations/{org_id}/lab/*`, reported honest Phase 13 `/api/v1/meta` (`phase: 13`, `learning_lab_enabled: true`), and delivered `/organizations/[orgId]/lab` with isolation verification status, workspace consent/reset controls, disposable identity manager, track filtering, safe validation/remediation workflow, and self-scan history.
- **Verification & Security Audit (`tests/smoke/phase13_smoke.ps1`):**
  - Independent Phase 13 security review completed (`2b1d0cf4-98c6-45f9-a153-05add54a0997`): all 9 findings (High/Medium/Low) remediated cleanly and covered by tests (`tests/test_phase13_learning_lab.py`).
  - Full smoke suite exited `0` across all 7 gates: `alembic` head `0014` + `compose.lab.yaml`, OPA (`33/33 PASS`), `scanner-contracts` PASS, API (`ruff`, `mypy`, `pytest` `102 passed, 2 skipped`), Runner (`ruff`, `mypy` `0 issues in 9 source files`, `pytest` `11 passed, 2 skipped`), Next.js `typecheck`/`lint`/`build` (including `/organizations/[orgId]/lab`), and live HTTP probes.

## Completed Items (Phase 12)

- **Additive Schema, RLS, Constraints & Audit Immutability (`0013_phase12_ai_governance.py`, `models/ai_governance.py`, `ADR-0014`):**
  - Seeded active `ai_model_catalog` entries (`managed-fast-v1`, `managed-reasoning-v2`, `enterprise-30d-v1` with `retention_days=30` and `requires_retention_consent=true`, `gpt-5-codex`, `openai-compatible-default`, `ollama/qwen3-coder`).
  - Added 9 tenant-scoped tables owned by `vforge_migrator` with `ENABLE` + `FORCE ROW LEVEL SECURITY` (`NULLIF(current_setting('app.current_org_id', true), '')::uuid`), composite tenant FKs (`ondelete="RESTRICT"` on provider references), and DB `CHECK` constraints enforcing tenant-namespaced `secret_ref` (`VF_AI_%` or `ai/orgs/%`) and blocking cross-tenant learning (`ck_afl_no_cross_tenant`): `ai_provider_configs`, `ai_task_requests`, `ai_runs`, `ai_tool_proposals`, `knowledge_documents`, `knowledge_chunks`, `ai_feedback_labels`, `model_evaluation_runs`, and append-only `ai_audit_events` (`prevent_phase12_audit_mutation` trigger + `REVOKE UPDATE, DELETE` from `vforge_app`).
  - Verified migration reversibility: `alembic downgrade 0012_phase11_rule_skill_studio && alembic upgrade head && alembic current` (`0013_phase12_ai_governance (head)`).
- **Pre-Egress Classification, Provider Security, RAG & Governed Rule Authoring (`apps/api/src/vforge/ai_gateway/`):**
  - Implemented `classification.py` (`classify_and_redact_payload`) with token/credential redaction (`sk-*`, `AIza*`, `ghp_*`, `github_pat_*`, `hf_*`, `npm_*`, `whsec_*`, `eyJ*` JWTs, `PGP`, `Bearer`/`Basic` auth headers, URL/URI credentials, password/secret assignments), PII/IP masking (`EMAIL`, `SSN`, `PRIVATE_IP`), prompt-injection flagging, and entity-escaped `<untrusted_data>`/`<untrusted_rag_context>` wrappers.
  - Implemented `providers.py` enforcing tenant-namespaced `secret_ref`, vendor-host pinning (`api.managed-zdr.example.com`, `api.managed-retained.example.com`, `api.openai.com`), SSRF/IMDS/internal-service blocking (including IPv4-mapped IPv6 and DNS checks), `follow_redirects=False`, schema-bounded response parsing, and offline deterministic execution when hosted endpoints are unconfigured.
  - Replaced Phase 11 stub with `GovernedRuleAuthorGateway` (`rule_author.py`), fixing summary slice truncation so `<untrusted_data>` tags remain balanced.
  - Implemented tenant-isolated curated RAG (`rag.py`) enforcing `curated://`/`https://` schemes, pre-storage secret redaction, and savepoint-safe duplicate slug `ConflictError`.
- **Consent Gates, Budget Locking, OPA Tool Broker, SoD & UI (`service.py`, `api/routers/ai_gateway.py`, `authz.rego`, `apps/web/.../ai-governance/page.tsx`):**
  - Enforced dual admin retention consent + operator acknowledgment for 30-day retained (`enterprise-30d-v1`) and `restricted` external payloads, org-wide `local_only_mode`, `SELECT ... FOR UPDATE` worst-case budget reservations, primary-policy failover isolation, and `require_independent_model` checks against `prior_model_slug`.
  - Brokered agent tool proposals fail-closed through OPA (`authz.rego` normalizing `tool_action` and denying privileged actions + self-approval), enforced `decided_by != requested_by` SoD, persisted `TASK_BLOCKED` records across HTTP error rollbacks, reported honest `/api/v1/meta` (`phase: 12`, `ai_gateway_enabled: true`, `ai_execution_mode: "offline_deterministic_unless_endpoint_configured"`), and delivered `/organizations/[orgId]/ai-governance`.
- **Verification & Security Audit (`tests/smoke/phase12_smoke.ps1`):**
  - Independent Phase 12 security review completed (`c0bdb4f4-f83d-4698-9eed-64fbfc28ce94`): all Critical/High/Medium/Low findings remediated and covered by expanded tests (`tests/test_phase12_ai_governance.py`).
  - Full smoke suite exited `0` across all 7 gates: `alembic` head `0013`, OPA (`32/32 PASS`), `scanner-contracts` (`15 passed in 0.62s`), API (`ruff check`, `ruff format --check` `125 files already formatted`, `mypy` `0 issues in 93 source files`, `pytest` `95 passed, 2 skipped in 24.20s`), Runner (`ruff`, `mypy` `0 issues in 9 source files`, `pytest` `11 passed, 2 skipped in 1.80s`), Next.js `typecheck`/`lint`/`build` (including `/organizations/[orgId]/ai-governance`), and live HTTP probes.

## Completed Items (Phase 11)

- **Additive Schema, RLS & Post-Signing Immutability (`0012_phase11_rule_skill_studio.py`, `ADR-0013`):**
  - Added seven tenant-scoped tables owned by `vforge_migrator` with `ENABLE` + `FORCE ROW LEVEL SECURITY` (`NULLIF(current_setting('app.current_org_id', true), '')::uuid`) and composite tenant FKs: `rule_packs`, `rule_pack_versions`, `rules`, `rule_fixture_runs`, `assessment_skills`, `skill_versions`, and `studio_audit_events`.
  - Added single-active channel partial unique indexes (`uq_rpv_active_canary`, `uq_rpv_active_stable`, `uq_sv_active_canary`, `uq_sv_active_stable`), DB SoD/consistency `CHECK` constraints (`ck_rpv_signer_not_author`, `ck_rpv_regression_zero_errors`, `ck_rpv_channel_active_consistency`, `ck_sv_signer_not_author`, `ck_sv_channel_active_consistency`), and PostgreSQL triggers blocking mutations on `rule_fixture_runs`, `studio_audit_events`, and signed `rule_pack_versions`, `skill_versions`, and child `rules` (`SQLSTATE 55000`).
  - Verified migration reversibility: `alembic downgrade 0011_phase10_update_lifecycle && alembic upgrade head && alembic current` (`0012_phase11_rule_skill_studio (head)`).
- **Native Engine Validators, Bounded Skills & Fixture Harness (`apps/api/src/vforge/studio/`):**
  - Implemented `validators.py` covering `opengrep` (YAML), `nuclei` (YAML), `checkov` (YAML/Python AST), `gitleaks` (TOML/JSON), `zap` (YAML), and `nmap` (Lua); blocked YAML aliases/depth (`_NoAliasSafeLoader`), multi-rule execution directives, Nuclei forbidden blocks (`headless`/`javascript`/`file`/`websocket`/`workflows`/`self-contained`/`code`), Checkov AST dynamic bypasses (`getattr`/dunders/top-level statements), Nmap comment-spoofed categories & obfuscated primitives, and catastrophic nested-quantifier regexes.
  - Implemented `harness.py` requiring positive, negative, and near-miss fixtures (`evaluate_pack_version_fixtures`) with zero false positives/negatives and failing closed on Checkov Python inline execution (requiring offline runner execution).
  - Implemented `ai_author.py` (`Phase12StubRuleAuthorGateway`) sanitizing untrusted snippets into `ai_assisted`/`ai_agent` `draft` candidates with JSON-escaped rule metadata.
- **SoD, Ed25519 Signing, Scan Execution Gate, OPA & UI (`service.py`, `api/routers/studio.py`, `authz.rego`, `orchestration/service.py`, `apps/web/.../studio/page.tsx`):**
  - Enforced `PENDING_REVIEW` workflow, `reviewer_id != author_id` and `signer_id != author_id` SoD, OPA `studio:read`/`studio:author`/`studio:review`/`studio:promote` with AI/SoD denial rules (`authz.rego`), server-backed `_resolve_actor_type` rejecting `"system"` header spoofing, and `enforce_sensitive_rate_limit` across all mutating endpoints.
  - Signed canonical pack & skill manifests (`vforge.rulepack.v1`, `vforge.skill.v1`) via Ed25519 `SnapshotSigner`, recomputed live SHA-256 & manifest payloads before promotion/rollback/scan dispatch (`resolve_and_verify_rule_packs_for_scan` via `ScanProfileConfiguration.rule_pack_version_ids`), demoted superseded active channel versions to `rolled_back`, and supported instant quarantine rollback blocking re-promotion and scan usage.
  - Delivered Next.js `/organizations/[orgId]/studio` workspace showing rule `native_content` previews, `cwe_id`, `known_limitations`, fixture counts, SoD-gated review/sign/promote/quarantine controls, bounded skill list, and audit trail (`encodeURIComponent` route params).
- **Verification & Security Audit (`tests/smoke/phase11_smoke.ps1`):**
  - Independent Phase 11 adversarial security review completed (`196ecdd3-9a41-4ef1-8199-3d04f5592592`): all 12 findings remediated and covered by expanded regression tests (`test_phase11_rule_skill_studio.py`: `10 passed in 3.66s`).
  - Full smoke suite exited `0` across all 7 gates: `alembic` head `0012`, OPA (`31/31 PASS`), `scanner-contracts` (`15 passed in 0.58s`), API (`ruff check`, `ruff format --check` `114 files already formatted`, `mypy` `0 issues in 84 source files`, `pytest` `88 passed, 2 skipped in 20.09s`), Runner (`ruff`, `mypy` `0 issues in 9 source files`, `pytest` `11 passed, 2 skipped in 1.63s`), Next.js `typecheck`/`lint`/`build`, and live HTTP probes (`/api/v1/meta`, `/api/health`, unauthenticated `401` denial).

## Completed Items (Phase 10)

- **Additive Schema & Immutable Audit Controls (`0011_phase10_update_lifecycle.py`, `ADR-0012`):**
  - Added platform release lifecycle tables owned by `vforge_migrator`: `tool_catalog`, `tool_versions`, `update_candidates`, `validation_results`, `promotion_events` (append-only immutable trigger + `REVOKE UPDATE, DELETE` from `vforge_app`), `feed_snapshots`, and `update_audit_events` (append-only immutable trigger + `REVOKE UPDATE, DELETE` from `vforge_app`).
  - Added database `CHECK` constraints blocking `:latest` tags and `:latest` image repository suffixes (`ck_tool_versions_not_latest_repo`, `ck_tool_versions_not_latest_tag`, `ck_feed_snapshots_not_latest_tag`).
  - Extended `scan_runs` with `tool_version_pins` (`JSONB`) so historical scans retain exact promoted/canary/stable digest provenance across subsequent upgrades and rollbacks.
  - Seeded 12 built-in platform tools aligned with pinned scanner contracts (`opengrep`, `gitleaks 8.24.0`, `syft 1.57.1`, `grype 0.121.3`, `checkov 3.2.435`, `zap`, `nuclei`, `nmap`, `testssl.sh`, etc.).
- **Lifecycle Pipeline, Dynamic Runner Allowlists & Integrity Gates (`apps/api/src/vforge/lifecycle/`, `orchestration/`, `runner/`):**
  - Implemented `monitor.py` (`inspect_image_lock_files()`, `validate_image_repository()`, `validate_version_tag_and_digest()`) and `update_controller.py` running continuously as a dedicated Compose worker (`update-controller` under `vforge_app` with zero Docker socket).
  - Implemented `pipeline.py` with `FOR UPDATE` row locking on candidate validation/approval/promotion/rollback transitions, `assert_automerge_allowed()` blocking unapproved automated merges, fail-closed `run_automated_validation_gates()` verifying signatures, lockfiles, and SBOM digests, and dynamic `resolve_active_tool_pins()`.
  - Integrated dynamically promoted tool digests into `orchestration/planner.py`, `orchestration/service.py`, `orchestration/manifest.py`, `services/runners.py`, and `runner/vforge_runner/` via signed dynamic allowlist payloads (`signed_allowlist_payload`, `allowlist_signature`, `allowlist_signing_key_id`) verified by the Runner Agent without static `.env` edits, while rejecting `:latest` refs across manifest builders and verifiers.
- **Platform Operator RBAC, Read-Only Org Overview & UI (`api/routers/updates.py`, `policies/rego/vforge/authz.rego`, `apps/web/.../updates/page.tsx`):**
  - Scoped global update mutations (`POST /api/v1/updates/detect`, `/candidates`, `/{update_id}/validate`, `/approve`, `/promote`, `/tools/{tool_slug}/rollback`, `/feeds/*`) to platform operators (`owner`/`admin`/`security_lead` + optional `Settings.platform_admin_emails`), blocking HTTP client-supplied `passed` validation bypasses.
  - Exposed read-only org-scoped `GET /api/v1/organizations/{org_id}/updates/overview` with cross-tenant audit actor email redaction (`[redacted]`), plus Next.js Release & Update Center UI with explicit `Rollback Canary` / `Rollback Stable` and feed promotion/rollback controls.
- **Verification & Security Audit (`tests/smoke/phase10_smoke.ps1`):**
  - Independent Phase 10 security review completed: all 5 findings remediated (dynamic runner allowlist sync, fail-closed validation gates, platform operator scoping & redaction, `:latest` / lockfile / seed alignment, `FOR UPDATE` locking & `automerge_allowed` guard).
  - Full smoke suite passed all 8 gates: OPA (`30/30`), `scanner-contracts` (`15 passed`), API (`ruff`, `mypy` 0 issues / 77 files, `pytest` `78 passed, 2 skipped`), Runner (`ruff`, `mypy` 0 issues / 9 files, `pytest` `11 passed, 2 skipped`), `update-controller --once`, Next.js `typecheck`/`lint`/`build`, and live endpoint probes.

## Completed Items (Phase 9)

- **Additive Schema & Tenant Isolation (`0010_phase9_threat_intel.py`, `ADR-0011`):**
  - Added global catalog tables: `intelligence_sources`, `intel_sync_runs`, `intel_snapshots` (with SHA-256 integrity, record counts, and immutable append-only trigger `prevent_intel_snapshots_mutation`), `intel_records` (composite unique `source_id` + `record_id`, JSONB payload, CVSS, EPSS, KEV flags), and `intel_relationships` (directional graph edges between CVEs, exploits, advisories).
  - Extended `findings` table with threat intelligence enrichment columns (`is_known_exploited`, `epss_score`, `epss_percentile`).
  - Added immutable tenant-scoped `intel_enrichment_events` table (`ENABLE` + `FORCE ROW LEVEL SECURITY`, append-only trigger `prevent_intel_enrichment_events_mutation`, composite tenant FK `(organization_id, finding_id) -> findings(organization_id, id)`).
  - Seeded built-in feed catalog (`cisa_kev`, `first_epss`, `nvd`, `osv`, `ghsa`, `exploit_db`, `virustotal`, `shodan`, `pulsedive`).
  - Verified migration reversibility: `alembic downgrade 0009_phase8_findings_reporting && alembic upgrade head` passed cleanly.
- **Threat Intelligence Connectors & Privacy Gates (`apps/api/src/vforge/intel/`):**
  - Protocol-driven `IntelligenceConnector` base with pagination, cursors, rate-limiting, and validation.
  - CISA KEV connector: parses Known Exploited Vulnerabilities catalog with required remediation action dates and ransomware flags.
  - FIRST EPSS connector: parses daily CSV/JSON probability scores and percentiles.
  - NVD CVE 2.0 connector: full NIST vulnerability feeds with CVSS v3.1 vector breakdown and CWE taxonomy.
  - OSV & GHSA connector: open-source package ecosystem advisories with affected SemVer ranges and commits.
  - Exploit-DB connector: reference-only proof-of-concept catalog with explicit security caveat and multi-value CVE cross-references.
  - Privacy Gates: VirusTotal default binary/source upload is hard-disabled (`allow_binary_upload: false`) to prevent IP leakage; Shodan queries enforce verified target scope validation.
  - Fail-closed stale data handling: network or API outages mark snapshots stale (`is_stale: true`); never return "zero vulnerabilities" on lookup failure.
- **Enrichment Engine & RBAC Authorization (`apps/api/src/vforge/intel/enrichment.py`, `policies/rego/vforge/authz.rego`):**
  - Automated finding enrichment querying local synced snapshots for KEV status, EPSS scores, exploit references, and advisories without external telemetry leakage during scans.
  - RBAC permissions: `intel:read` and `intel:manage` added to OPA policy and verified with 29/29 policy tests.
- **Frontend Web UI (`apps/web`):**
  - Navigation bar updated with "Threat Intel" tab in `OrgShell.tsx`.
  - Threat Intel Hub page (`/organizations/[orgId]/threat-intel`) with KPI cards (CISA KEV tracked, High EPSS, Exploit-DB refs), batch finding enrichment trigger, interactive CVE point-lookup tool, and feed catalog status with on-demand sync triggers.
  - Verified Next.js compilation: `tsc` 0 errors, `eslint` clean, production build succeeded.
- **Verification & Acceptance Results:**
  - OPA unit tests: 29/29 PASS.
  - Scanner contracts tests: 15/15 PASS.
  - API suite: `ruff check` PASS, `ruff format --check` (97 files formatted), `mypy` (0 issues in 71 source files), `pytest` (68 passed, 2 skipped in 22.03s).
  - Runner suite: `ruff check` PASS, `ruff format --check` (10 files formatted), `mypy` (0 issues in 9 source files), `pytest` (11 passed, 2 skipped in 1.79s).
  - Smoke script (`tests/smoke/phase9_smoke.ps1`): all 8 gates verified.
  - Metadata verification: `/api/v1/meta` honestly reports `phase: 9`, `threat_intel_enabled: true`, and all Phase 9 capabilities.

## Completed Items (Phase 8)

- **Additive Schema & Tenant Isolation (`0009_phase8_findings_reporting.py`, `ADR-0010`):**
  - Extended `findings` table with SLA columns (`sla_due_at`, `sla_breached`), assignments (`assigned_to`), retest tracking (`retest_status`, `remediation_notes`), and risk prioritization (`business_priority`, `cvss_score`, `cvss_vector`).
  - Added immutable tenant-scoped `finding_events` table (`ENABLE` + `FORCE ROW LEVEL SECURITY`, append-only trigger `trg_finding_events_append_only`, composite tenant FK `(organization_id, finding_id) -> findings(organization_id, id)`).
  - Added `risk_exceptions` table with role-gated approval workflow, justification, mitigating controls, and time-bound expiration (`expires_at`).
  - Added `reports` table with tenant FKs, RLS, and least-privilege `vforge_app` grants.
  - Verified migration reversibility: `alembic downgrade 0008_phase7_dast && alembic upgrade head` passed cleanly.
- **Triage Lifecycle, SLA Tracking & RBAC Permissions (`apps/api/src/vforge/services/findings.py`, `apps/api/src/vforge/auth/rbac.py`, `policies/rego/vforge/authz.rego`):**
  - Implemented SLA calculation based on severity policies (Critical: 7d, High: 14d, Medium: 30d, Low: 60d, Info: 90d) and automated breach detection (`check_and_update_sla_breaches`).
  - Implemented finding triage status transitions (`open`, `in_progress`, `resolved`, `risk_accepted`, `false_positive`), retest status tracking (`pending_retest`, `retest_passed`, `retest_failed`), and append-only event logging.
  - Added formal time-bound risk exception workflow: requester submission and two-person review restricted to `security_lead`, `admin`, or `owner`.
  - Added RBAC permissions: `FINDING_TRIAGE` (`finding:triage`), `RISK_EXCEPTION_REQUEST` (`risk_exception:request`), `RISK_EXCEPTION_REVIEW` (`risk_exception:review`), `REPORT_GENERATE` (`report:generate`), `REPORT_READ` (`report:read`).
- **Multi-Format Enterprise Reporting Engine & Envelope Encryption (`apps/api/src/vforge/services/reporting.py`, `apps/api/src/vforge/security/envelope.py`):**
  - Responsive self-contained HTML report generator with executive summary, severity matrix, scope snapshot/authorization references, tool version provenance, and explicit scan coverage disclosures.
  - Standalone binary PDF 1.4 report generator with embedded structure and printable layout.
  - Complete machine-readable JSON report generator with full project, scan run, tool inventory, and finding occurrences.
  - OASIS SARIF 2.1.0 standard representation grouped by scanner driver runs.
  - Sensitive report artifact encryption using AES-256-GCM envelope encryption with tenant-bound AAD and streaming decryption.
  - Honesty invariant: partial or failed scan stages are explicitly surfaced and never reported as clean passes.
- **Frontend Web UI (`apps/web`):**
  - Navigation bar updated with "Reports".
  - Findings triage page (`/organizations/[orgId]/findings`) with SLA breach badges, business priority indicators, status filters, retest triggers, time-bound risk exception modal, and full event audit trail.
  - Reports management page (`/organizations/[orgId]/reports`) with multi-format report generation modal (HTML, PDF, JSON, SARIF), reports listing, SHA-256 checksums, and AES-256-GCM decrypted streaming download.
  - Updated web health route (`/api/health`) reporting `phase: 8`.
- **Verification & Acceptance Results:**
  - OPA unit tests: 28/28 PASS.
  - Scanner contracts tests: 15/15 PASS.
  - API suite: `ruff check` PASS, `ruff format --check` PASS, `mypy` (0 issues in 60 source files), `pytest` (57 passed, 2 skipped in 11.31s).
  - Runner suite: `ruff check` PASS, `ruff format --check` PASS, `mypy` (0 issues in 9 source files), `pytest` (11 passed, 2 skipped in 1.28s).
  - Next.js: `tsc --noEmit` PASS, `eslint` PASS, `next build` (Turbopack optimized production build) PASS.
  - Smoke script (`tests/smoke/phase8_smoke.ps1`): all 8 steps passed cleanly.
  - Metadata verification: `/api/v1/meta` honestly reports `phase: 8`, `reporting_enabled: true`, and all Phase 8 capabilities.

## Completed Items (Phase 7)

- **DAST & Network Image Lock (`lifecycle/image-lock/phase7-images.json`, `ADR-0009`):**
  - Pinned upstream images by immutable SHA-256 digests: `ghcr.io/zaproxy/zaproxy:2.16.0` (`sha256:391f66efa5...`), `projectdiscovery/nuclei:v3.11.1` (`sha256:582d5546...`), `instrumentisto/nmap:7.98` (`sha256:96f6ed19...`), `drwetter/testssl.sh:3.2.5` (`sha256:e42cb1ba...`).
- **Scanner Adapters (`packages/scanner-contracts/`):**
  - Added `ZAPAdapter` (OWASP ZAP Automation Framework plan generator with passive spider/scan before active attack, OpenAPI import support, and JSON report normalizer).
  - Added `NucleiAdapter` (pinned vulnerability/misconfiguration template execution with `-jsonl`, rate/concurrency limits, and JSONL normalizer).
  - Added `NmapAdapter` (port discovery/service fingerprinting with `-sV -T3 -oX`, XML parser, and port findings).
  - Added `TestsslAdapter` (TLS/SSL cipher, protocol, and vulnerability evaluation with `--json-pretty`, JSON parser, and TLS findings).
  - Standalone parser methods verified against clean and vulnerable fixtures without requiring running daemon.
- **Additive DAST Schema, Target Leases & Health Probes (`0008_phase7_dast.py`):**
  - Added `scan_target_leases` model & table with unique partial index on `(asset_id, lease_risk_class)` where `status = 'active'` preventing concurrent high-risk active attacks on the same asset.
  - Added immutable tenant-scoped `target_health_probes` (`ENABLE` + `FORCE ROW LEVEL SECURITY`, append-only triggers, composite tenant FKs) recording baseline and active latency/status codes.
  - Added `auth_profile_id` to `scan_runs` and `AuthProfile` secret-ref resolution via `SecretProvider` over mTLS gateway.
  - Updated `authz.rego` with `SCAN_READ` permission for health probe queries.
- **Orchestration, Safety Tripwire & Runner Isolation:**
  - `orchestration/planner.py` compiles DAST stages (`passive_dast`, `active_dast`, `network_discovery`, `tls_assessment`) with lease risk classification, auto-prepending `passive_dast` before `active_dast`.
  - `runner/vforge_runner/health_monitor.py` implements `TargetHealthMonitor` with baseline health check, periodic safety loop, consecutive error/5xx tripwires, and automatic scan abort on threshold breach.
  - Scan runs aborted by tripwire breach are honestly recorded as `failed` / `target_health_tripwire_aborted` with full probe history in `target_health_probes`, never returning synthetic clean passes.
  - Runner gateway exposes `/api/v1/runner/jobs/{job_id}/health-probes`, `/target-auth`, and `/openapi-spec`.
  - Next.js UI updated with DAST profile options, live safety health probes table, and status alerts.
- **Verification & Acceptance Results:**
  - Migration reversible: `0008_phase7_dast -> 0007_phase6_supply_chain_iac -> 0008_phase7_dast` PASS.
  - OPA unit tests: 27/27 PASS.
  - Scanner contracts tests: 15 passed in 0.55s.
  - API suite: `ruff check` PASS, `ruff format --check` (79 files already formatted), `mypy` (0 issues in 57 source files), `pytest` 53 passed, 2 skipped in 17.90s.
  - Runner suite: `ruff check` PASS, `ruff format --check` (9 files already formatted), `mypy` (0 issues in 8 source files), `pytest` 8 passed, 2 skipped in 1.69s.
  - Smoke script (`tests/smoke/phase7_smoke.ps1`): all 8 steps passed cleanly.
  - Next.js: typecheck PASS, lint PASS, standalone production build PASS.
  - Full platform metadata: `/api/v1/meta` honestly reports `phase: 7`, `dast_enabled: true`, and all Phase 7 capabilities.

## Completed Items (Phase 6)

- **Supply-Chain Image Lock & Offline DB/Policy Artifacts (`lifecycle/image-lock/phase6-images.json`, `runner/images/checkov/policies/`):**
  - Pinned upstream images by immutable SHA-256 digests (`anchore/syft:v1.57.1`, `anchore/grype:v0.121.3` per `ADR-0008` after `v0.93.0` v6 DB schema constraint failure, `bridgecrew/checkov:3.2.435`).
  - Pre-hydrated dedicated `vforge_grype_db` volume (v6.1.10 schema, world-readable `0o755`/`0o644` for UID `10001:10001` offline containers) and bundled declarative YAML Checkov policy pack (`CKV2_VF_CUSTOM_1`).
- **Scanner Adapters (`packages/scanner-contracts/`):**
  - Added `SyftAdapter` (deterministic CycloneDX + SPDX JSON generation & parsing), `GrypeAdapter` (strict `sbom:` offline analysis with `GRYPE_DB_AUTO_UPDATE=false`, PURL/CVE/fixed-version extraction, and mandatory `extract_grype_db_provenance()` with fail-closed SHA-256 validation), and `CheckovAdapter` (`--skip-download` offline IaC JSON/SARIF normalization with file/line/resource traceability, guideline remediation redaction, & YAML-only custom policy support).
  - Extended `NormalizedFinding` (`sca`/`iac`, `purl`, `package_name`, `package_version`, `fixed_version`, `cve_id`, `iac_resource`) and polyglot coverage registry (`syft`, `checkov`).
- **Additive Supply-Chain Schema, RBAC & OPA (`0007_phase6_supply_chain_iac.py`):**
  - Added immutable tenant-scoped `sbom_documents` (`ENABLE` + `FORCE ROW LEVEL SECURITY`, append-only triggers) and `vulnerability_db_snapshots` (`ENABLE` + `FORCE ROW LEVEL SECURITY`, unique on `(organization_id, tool_id, schema_version, db_archive_sha256)`).
  - Extended `findings` and `finding_occurrences` with PURL, package, fixed version, CVE, IaC resource, and composite FK links to `sbom_documents` & `vulnerability_db_snapshots`.
  - Added `SBOM_READ` (`sbom:read`) and `VULN_DB_READ` (`vuln_db:read`) permissions across all 7 RBAC roles and `policies/rego/vforge/authz.rego`.
- **Orchestration, mTLS SBOM-Input Gateway, Runner Isolation & UI:**
  - Updated `orchestration/planner.py`, `manifest.py`, and `service.py` to plan `sbom`/`sca`/`iac` stages, automatically prepend upstream `syft` before `grype` (`sca`) even when unnormalized profiles supply `["sca", "sbom"]`, and sign `requiresSbomInput`/`enableCustomPolicies` flags.
  - Added `persist_syft_sbom_documents()`, `_upsert_grype_db_snapshot()`, `/api/v1/runner/jobs/{job_id}/sbom-input` (owner-only mTLS SBOM streaming with SHA-256 integrity check), `/sboms`, `/sboms/{sbom_id}`, `/vulnerability-db-snapshots`, `/findings?purl=...`, and `/api/v1/meta` (`phase: 6`, `supply_chain_enabled: true`).
  - Hardened `container_executor.py` (`--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777`, validated `/work/*:ro` `extra_ro_mounts` preserved across digest fallback, CycloneDX/SPDX MIME types) and `runner_agent.py` (fail-closed when offline `vforge_grype_db` is missing, fail-closed `X-SBOM-SHA256` verification, and fail-closed non-YAML policy checks).
  - Added Next.js `/organizations/[orgId]/supply-chain` view with offline DB warning banners and updated `/findings` + `OrgShell` navigation.
- **Verification & Acceptance Results:**
  - Migration reversible: `0007_phase6_supply_chain_iac -> 0006_phase5_scanners -> 0007_phase6_supply_chain_iac` PASS.
  - OPA unit tests: 27/27 PASS.
  - Scanner contracts tests: 10 passed.
  - API suite: `ruff check` PASS, `ruff format --check` (77 files already formatted), `mypy` (0 issues in 57 files), `pytest` 51 passed, 2 skipped.
  - Runner suite: `ruff check` PASS, `ruff format --check` (9 files already formatted), `mypy` (0 issues in 8 files), `pytest` 8 passed, 2 skipped.
  - Live hardened containers: Syft CycloneDX/SPDX generated, Grype offline DB v6.1.10 valid with CVE matches, Checkov CKV2_VF_CUSTOM_1 + AWS checks evaluated with file/line evidence.
  - Next.js: typecheck PASS, lint PASS, standalone production build PASS.
  - Regression: Phases 0–5 smoke scripts ALL PASSED sequentially.

## Completed Items (Phase 5 — Preserved)

- **Shared Scanner Contract SDK & Coverage Engine (`packages/scanner-contracts/`, `vforge_scanners`):**
  - Implemented `ScannerAdapter`, `ScannerMetadata`, `ToolContext`, `ExecutionSpec`, `ExecutionResult`, and `NormalizedFinding` (`sdk.py`) with zero control-plane DB/broker imports.
  - Added polyglot file extension, manifest, and ecosystem detection (`languages.py`) and `CAPABILITY_REGISTRY` + `evaluate_coverage()` (`registry.py`) distinguishing full support vs. partial/unsupported languages honestly (`assessment_coverage_status`: `complete`/`partial`/`unsupported`/`not_applicable`).
  - Added canonical archive sanitizer (`archive.py`: deterministic gzipped tarballs blocking `..` traversal, absolute paths, symlinks/hardlinks, special nodes, and bomb expansion ratios) and secret redaction utilities (`redaction.py`).
  - Implemented pinned `OpenGrepAdapter` (`vforge-opengrep:1.33.1`, JSON + SARIF normalization) and `GitleaksAdapter` (`zricethezav/gitleaks:v8.24.0@sha256:2bcceac4...`, `--redact=100 --exit-code=10` handling and double-redacted finding extraction).
- **Additive Source Snapshot & Canonical Finding Schema (`0006_phase5_scanners.py`, owned by `vforge_migrator`):**
  - Added tenant-scoped `source_snapshots`, `findings`, and append-only `finding_occurrences` (`REVOKE UPDATE, DELETE` + `trg_finding_occurrences_append_only`) enforced with `ENABLE` + `FORCE ROW LEVEL SECURITY` (`vforge_app`) and composite tenant FKs.
  - Extended `scan_runs` (`source_snapshot_id`, `source_snapshot_hash`, `coverage_summary`) and added `SOURCE_SNAPSHOT_READ`, `SOURCE_SNAPSHOT_CREATE`, and `FINDING_READ` permissions across Python RBAC and OPA `policies/rego/vforge/authz.rego`.
- **Control Plane Integration, Runner Adapter Execution & Canonical Lock Ordering (`apps/api/`, `runner/`):**
  - Implemented `services/source_snapshots.py` (archive sanitization, AES-256-GCM envelope encryption via `vforge.security.envelope`, coverage evaluation) and `services/findings.py` (deterministic deduplication by `(org_id, project_id, scanner_tool_id, fingerprint)`, append-only occurrences, pre-persistence secret redaction).
  - Updated `orchestration/planner.py` (`sast` -> `opengrep`, `secrets` -> `gitleaks`), `orchestration/service.py` (snapshot validation & per-run `coverage_summary`), `runner_gateway.py` (`GET /api/v1/runner/jobs/{job_id}/source-snapshot` + completion normalization), and `services/runners.py` (including canonical lock ordering `ScanRun -> RunnerJob` in `upload_runner_artifact`).
  - Registered `/api/v1/organizations/{org_id}/projects/{project_id}/source-snapshots`, `/findings`, `/findings/{finding_id}`, and `/scanner-coverage`, and updated `/api/v1/meta` (`phase: 5`, `scanners_enabled: true`, `opengrep-sast`, `gitleaks-secrets`).
  - Updated `runner/` (`container_executor.py`, `runner_agent.py`) for SHA-256 verified source snapshot extraction, `OpenGrepAdapter`/`GitleaksAdapter` command resolution, exit code `10` handling, and stdout/stderr secret redaction.
- **Hardened Pinned Scanner Containers, Next.js UI & Verification:**
  - Built `vforge-opengrep:1.33.1` (`runner/images/opengrep/Dockerfile`, `XDG_CACHE_HOME=/opt/opengrep/cache`, non-root `10001`, bundled baseline rules) and pinned Gitleaks in `lifecycle/image-lock/phase5-images.json`.
  - Updated Next.js `/scans/[scanId]` (source snapshot & coverage summary card) and added `/organizations/[orgId]/findings` viewer (`Findings` link in `OrgShell`).
  - Added `test_scanner_contracts.py`, `test_phase5_scanners.py`, Gitleaks redaction/exit-10 tests in `test_runner_isolation.py`, `tests/smoke/phase5_smoke.ps1`, and [`docs/decisions/ADR-0007-phase5-scanner-adapter-sast-secrets.md`](decisions/ADR-0007-phase5-scanner-adapter-sast-secrets.md).

## Completed Items (Phase 4 — Preserved)

- **Additive Runner Isolation Schema (`0005_phase4_runner_isolation.py`, owned by `vforge_migrator`):**
  - Added tenant-scoped `runner_pools`, `runners`, `runner_heartbeats`, `runner_events`, `tool_executions`, and `artifacts` tables with composite tenant FKs, pinned X.509 `cert_sha256` + `runner_identity` uniqueness, and `ENABLE` + `FORCE ROW LEVEL SECURITY` scoped to `vforge_app`.
  - Enforced append-only immutability on `runner_events` and `artifacts` via `REVOKE UPDATE, DELETE` + `trg_*_append_only` triggers.
  - Added trigger-maintained `public.runner_liveness` index table (`REVOKE ALL` from `PUBLIC` and `vforge_app`) and `SECURITY DEFINER` function `public.count_online_runners(p_cutoff)` so `/api/v1/meta` reports honest live runner connectivity without `BYPASSRLS`.
  - Extended `scan_runs`, `runner_jobs`, and `scan_profiles` cleanly for `execution_mode` (`simulated` / `runner`), `target_pool_id`, runner claim/cancel fields, and Ed25519 manifest digests/expirations.
- **Dedicated TLS 1.3 + mTLS Runner Gateway & Cryptography (`apps/api/src/vforge/`):**
  - `security/mtls.py`: CA-signed ECDSA P-256 certificate issuance (`SubjectKeyIdentifier`, `AuthorityKeyIdentifier`, leaf `KeyUsage`, SPIFFE SAN `spiffe://vforge/org/<org_id>/runner/<runner_id>`), DER validation (`verify_runner_cert_der`), and PEM registration claim extraction.
  - `security/envelope.py`: AES-256-GCM per-artifact DEK + KEK wrapping bound with canonical AAD (`org_id|scan_run_id|job_id|sha256`) and atomic storage helpers.
  - `orchestration/manifest.py`: Canonical Ed25519-signed `ExecutionManifest` construction (`build_execution_manifest`), keyring verification (`verify_execution_manifest`), expiration enforcement, and allowlisted immutable `@sha256:` digest validation.
  - `runner_gateway.py`: Dedicated TLS 1.3 + `ssl.CERT_REQUIRED` FastAPI/uvicorn server (`Tls13MtlsUvicornConfig`, `MtlsH11Protocol`) on port `8443` (`/api/v1/runner/*`) isolated from the public Control Plane API (`main.py`, port `8000`).
  - `api/routers/runners.py` & `services/runners.py`: Control-plane RBAC endpoints (`runner-pools`, `runners`, `runner-events`, `revoke`, encrypted artifact list & decrypted download), `authz.rego` runner permissions, and honest `/api/v1/meta` (`phase: 4`, `scanners_enabled: false`, `docker_socket_mounted: false`, live `runner_connected`).
- **Isolated Runner Agent, Ephemeral Container Executor & Scoped Egress Gateway (`runner/`):**
  - Standalone `vforge-runner` package holding zero Control Plane Postgres/RabbitMQ/Valkey credentials, communicating exclusively over TLS 1.3 mTLS.
  - `vforge_runner/executor/container_executor.py`: Enforces `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `runner/network-policy/seccomp-scanner.json`, `--user=10001:10001`, memory/CPU/PID/tmpfs limits, read-only input mount + bounded output mount, strict timeout & cancel termination, and mandatory container/workdir cleanup (`cleanup_failed` security event on failure).
  - `vforge_runner/network_policy/egress_gateway.py`: Async `ScopedEgressGateway` enforcing `vforge_scope` target allowlists, independent DNS resolution, cloud metadata/RFC1918/rebinding blocking, socket-connect IP pinning (`_open_pinned_tcp_socket`), HTTP redirect revalidation, and `egress_blocked` event reporting.
  - Added minimal non-root dummy scanner image (`runner/images/dummy-scanner/`) and development-only `runner/docker-compose.runner.yml`.
- **Frontend UI & Verification:**
  - Added Next.js `/organizations/[orgId]/runners` pool/runner registration & revocation view and updated `/scans` and `/scans/[scanId]` for `runner` execution mode and encrypted artifact inspection/download.
  - Added `apps/api/tests/test_phase4_runner_isolation.py`, `runner/tests/test_runner_isolation.py`, `tests/smoke/phase4_smoke.ps1`, and [`docs/decisions/ADR-0006-phase4-runner-agent-mtls-isolation.md`](decisions/ADR-0006-phase4-runner-agent-mtls-isolation.md).

## Completed Items (Phase 3 — Preserved)

- **Additive Orchestration Schema (`0004_phase3_orchestration.py`, owned by `vforge_migrator`):**
  - Added tenant-scoped `scan_runs`, `scan_stages`, `runner_jobs`, `scan_target_leases`, and `outbox_events` tables with composite tenant FKs, idempotency unique key (`(org_id, idempotency_key)`), partial unique active target-lease constraint (`ix_scan_target_leases_active_unique`), and `ENABLE` + `FORCE ROW LEVEL SECURITY` scoped to `vforge_app`.
  - Added trigger-maintained queue index table `orchestration_wakeups` (`REVOKE ALL` from `PUBLIC` and `vforge_app`) + `SECURITY DEFINER` function `public.list_due_orchestration_work(p_limit, p_work_kinds)` (`ix_orchestration_wakeups_kind_due`) so the control-plane orchestrator discovers due multi-tenant outbox/lease/timeout/retry work without `BYPASSRLS`.
- **Declarative Scan Plan, State Machine & Orchestration Engine (`apps/api/src/vforge/orchestration/`):**
  - `planner.py`: Deterministic, declarative scan plan builder mapping asset types, scope snapshots, capabilities, and scan profiles into ordered stages (`discovery`, `sast`, `secrets`, `sca`, `iac`, `dast_passive`, `dast_active`, `network`) with serialized active vs. parallel passive target-lease classification.
  - `state_machine.py`: Strict validated status transitions across `ScanRun`, `ScanStage`, `RunnerJob`, and `OutboxEvent`.
  - `service.py`: Transactional outbox emission (`dispatch_pending_outbox_once`), idempotent run creation serialized by transaction-scoped advisory lock (`pg_advisory_xact_lock`), canonical lock ordering (`ScanRun -> ScanStage -> RunnerJob -> ScanTargetLease -> OutboxEvent`), pre-dispatch authorization/expiry/decommission + Ed25519 `scope_snapshot` + OPA `scope.rego` verification, exclusive target lease acquisition with `lease_epoch` fencing, bounded retry backoff, run cancellation (`CANCELLING -> CANCELLED`), and lease/timeout reconciliation (`reconcile_orchestration_once`).
  - `broker.py` & `worker.py`: Separate-channel RabbitMQ `vforge.orchestration` direct + DLX (`vforge.orchestration.dlx`) publisher/consumer on `/vforge`, graceful transient `nack(requeue=True)` vs. malformed `reject(requeue=False)`, and non-root `orchestrator` Compose service running under `vforge_app` with zero Docker socket.
- **API, Policy, UI & Smoke Verification:**
  - Added `/api/v1/organizations/{org_id}/scans` (create with `Idempotency-Key`, list, detail, cancel, leases) with `authz.rego` RBAC (`scan:create`, `scan:read`, `scan:cancel`) and honest `/api/v1/meta` (`phase: 3`, `scanners_enabled: false`, `runner_connected: false`, `docker_socket_mounted: false`).
  - Added Next.js App Router views at `/organizations/[orgId]/scans` and `/organizations/[orgId]/scans/[scanId]`.
  - Added `tests/test_phase3_orchestration.py`, `tests/smoke/phase3_smoke.ps1`, and [`docs/decisions/ADR-0005-phase3-orchestration-outbox-leases.md`](decisions/ADR-0005-phase3-orchestration-outbox-leases.md).

## Security Preflight (Pre-Phase 3 — Completed)

- **Credential Rotation & Zero-Downtime Preservation:**
  - Created ACL-protected local backups outside the Git repository prior to rotation and preserved all existing Docker volumes (`vforge_postgres_data`, `vforge_rabbitmq_data`, `vforge_valkey_data`, `vforge_artifacts`) and database rows.
  - Rotated local credentials with independent >=32-byte CSPRNG secrets (`base64url`) for PostgreSQL, RabbitMQ, Valkey, and local dev Keycloak.
- **PostgreSQL Administrative / Migration / Runtime Role Separation:**
  - Separated bootstrap superuser (`vforge`), non-superuser schema/migration owner (`vforge_migrator`), and least-privilege runtime role (`vforge_app`: `NOSUPERUSER`, `NOBYPASSRLS`, `NOCREATEROLE`, `NOCREATEDB`, `NOINHERIT`, owns zero tables).
  - Removed the legacy `SET LOCAL ROLE vforge_app` workaround from `apps/api/src/vforge/api/deps.py` and added fail-closed `verify_runtime_db_identity()` at API startup (`lifespan`) and `Settings.validate_startup_configuration()`.
  - Added dedicated `migrator` Compose profile (`--profile ops`) so ordinary `api` runtime containers never receive `MIGRATION_DATABASE_URL` or `POSTGRES_MIGRATOR_PASSWORD`.
- **RabbitMQ & Valkey Hardening:**
  - RabbitMQ configured with dedicated `vforge` vhost, separated `vforge_admin` (`administrator`) and tag-free `vforge_app` restricted to `^(vforge\..*|amq\.gen-.*)$` / `amq.default` on `/vforge` only; retired legacy `vforge` broker user after verification.
  - Valkey 9.1.3 migrated from `--requirepass` CLI argument to external SHA-256-hashed ACL file (`.secrets/valkey/users.acl` mounted read-only at `/etc/valkey/users.acl`), disabling `default` (`user default off`) and scoping `vforge_app` to `~vf:*` and minimal required commands, with `vforge_health` dedicated to Docker healthchecks.
- **Configuration, `SecretProvider` & OpenBao Readiness:**
  - Added `apps/api/src/vforge/secrets/` (`SecretProvider`, `LocalDevelopmentProvider`, `DockerSecretProvider`, `OpenBaoProvider`, `FutureExternalSecretProvider`) and safe URL builders (`build_postgres_url`, `build_amqp_url`, `build_valkey_url`).
  - Fixed `logging.redact_text()` to mask empty-username URLs (`redis://:secret@host`), `Basic` auth headers, `REDISCLI_AUTH`, `PGPASSWORD`, and `client_secret`, and added `sanitize_exception_message()` and credential-free `Settings.__repr__()`.
  - Documented OpenBao KV v2, Database (`postgresql-database-plugin`, `valkey-database-plugin`), and RabbitMQ secrets engine architecture in `docs/SECRET_MANAGEMENT_AND_OPENBAO.md`.
- **Image-Lock & Renovate Lifecycle Improvements:**
  - Added `lifecycle/image-lock/schema.json` and `lifecycle/image-lock/phase2-images.json` capturing all 11 required supply-chain fields and 10 update channels; enhanced `renovate.json` with `custom.regex` tracking for `lifecycle/image-lock/*.json` and `.env.example`.

## Completed Items (Phase 2)

- **Shared Scope Validator Package (`packages/scope-validator/`, `vforge_scope`):**
  - Typed, deny-by-default target canonicalization and matching across `fqdn`, `domain_and_subdomains`, `exact_url`, `url_path_prefix`, `ipv4`, `ipv6`, `cidr_range`, `network_service` (ports), `rest_api`, `source_repository`, `container_image`, and `infrastructure_definition`.
  - Strict IDNA/Punycode domain normalization, trailing DNS dot removal, segment-safe URL path normalization (`..`/backslash/percent-encoded traversal and embedded credential rejection), IPv4-mapped IPv6 unwrapping, and exact non-substring domain matching (`example.com` never matches `notexample.com`).
  - A/AAAA DNS resolution validation with mixed allowed/disallowed IP blocking, cloud metadata IP/hostname blocking, explicit-only private-network (`allow_private_networks`) and loopback gating, DNS rebinding detection against pinned snapshot IPs, and HTTP redirect destination revalidation (blocking HTTPS→HTTP downgrades and redirect hop limit bypasses).
- **Authorization Engine & OPA Integration (`policies/rego/vforge/scope.rego`, `opa_client.py`, `scope.py`):**
  - Expanded explicit capability model (`passive_web_testing`, `active_web_testing`, `api_testing`, `authenticated_testing`, `network_discovery`, `tls_assessment`, `container_assessment`, `source_code_analysis`, `infrastructure_analysis`, `approved_exploit_validation`) while permanently forbidding DoS, destructive, and unrestricted exploitation capabilities.
  - Default-deny OPA Rego v1 policy `data.vforge.scope.decision` returning `ALLOW`, `DENY`, or `REQUIRES_APPROVAL` with structured reasons across tenant/project/environment/asset ownership, RBAC (`authz.rego` expanded for `scope:evaluate`, `snapshot:read`, `snapshot:verify`), expiry/start windows, separation of duties (`approved_by <> requested_by`), allowed ports, intensity limits, production safeguards, and snapshot freshness.
  - Fail-closed `OpaScopeClient` (`POST /v1/data/vforge/scope/decision`); editing an approved authorization's scope/capabilities/ports/timing clears approval (`status -> pending`) and requires fresh second-person approval.
- **Immutable Cryptographically Signed Scope Snapshots (`0003_phase2_scope_snapshots.py`, `signing.py`):**
  - Additive Alembic migration `0003_phase2_scope_snapshots` adds `assets.version`, Phase 2 authorization metadata (`permitted_intensity`, `allow_private_networks`, `policy_version`, `revoked_by`, `revoked_at`, `revocation_reason`), and `scope_snapshots` enforced with `FORCE ROW LEVEL SECURITY` (`vforge_app`) and append-only DB protections (`trg_scope_snapshots_immutable` + `REVOKE UPDATE/DELETE`).
  - Deterministic canonical JSON + SHA-256 hash + Ed25519 signature (`SnapshotSigner`) with keyring key-rotation states (`active`, `verify_only`, `revoked`) documented in `ADR-0003`.
  - `POST /api/v1/organizations/{org_id}/snapshots/{snapshot_id}/verify` verifies SHA-256 hash, Ed25519 signature + key status, policy version currency, `asset.version` currency, optional live DNS revalidation, and OPA decision.
- **Frontend Scope Management & Diagnostics (`apps/web/`):**
  - New `/organizations/[orgId]/scope` workspace and enhanced `/organizations/[orgId]/authorizations` workflow supporting asset inventory inspection, structured domain/IP/port/capability/intensity authorization authoring and editing, second-person approval, revocation, expired authorization filtering (`?status=expired`), authorization revision history, interactive OPA + DNS/redirect pre-flight scope evaluation, and signed snapshot inspection/verification without exposing raw scanner CLI flags.
- **Governance & ADRs:**
  - Created `docs/decisions/ADR-0003-phase2-scope-authorization-snapshots.md` and `tests/smoke/phase2_smoke.ps1`; updated `docs/diagrams/architecture.mmd`, traceability matrix, threat model, risk register, security baseline, implementation plan, and README.

## Completed Items (Phase 1 — Preserved)

- **Database & Migration (`0002_phase1_domain_rls.py`):**
  - Additive Phase 1 migration preserving `0001_phase0_foundation.py` untouched.
  - Domain tables implemented: `organizations`, `app_users` (`(oidc_issuer, oidc_subject)` identity key), `memberships` (7 roles), `projects`, `environments` (5 environment types), `assets` (8 asset types), `authorizations` (separation of duties `approved_by <> requested_by`), `auth_profiles` (secret-manager URI refs only), `scan_profiles` (versioned configuration), `audit_events` (append-only via `REVOKE` + PostgreSQL trigger `trg_audit_events_append_only`), plus server-side `auth_sessions` and `oidc_auth_states`.
  - Composite tenant foreign keys preventing cross-tenant parent linkages.
- **PostgreSQL Row-Level Security (`vforge_app`):**
  - Dedicated non-superuser, `NOBYPASSRLS` application role `vforge_app` (separated from migration owner role `vforge_migrator` and bootstrap superuser `vforge` in Security Preflight).
  - `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` across all tenant-scoped tables and `app_users`/`audit_events`.
  - Transaction-scoped context via parameterized `SELECT set_config(..., true)`, direct `vforge_app` runtime authentication (`verify_runtime_db_identity()`), and SQLAlchemy `pool_reset_on_return="rollback"`.
- **OIDC Authentication, Sessions & CSRF:**
  - Authorization Code Flow with PKCE (`S256`), discovery caching, JWKS key rotation refresh, strict validation of signature, `iss`, `aud`, `exp`, `nbf`, `nonce`, `state`, and algorithm allowlist (`RS256`, `ES256`, `EdDSA`).
  - Short-lived HTTP-only `SameSite=Lax` cookies (`vf_session`), double-submit CSRF protection (`vf_csrf` / `X-CSRF-Token`), Valkey-backed rate limiting with in-memory fallback, and zero browser `localStorage` tokens.
  - Opt-in local dev Keycloak `26.4.0` service (`--profile dev-oidc`) isolated on `edge` + `idp` networks (`infrastructure/keycloak/realm-vforge.json`).
- **Centralized RBAC & OPA Policies:**
  - Explicit 7-role matrix (`owner`, `admin`, `security_lead`, `security_analyst`, `developer`, `auditor`, `viewer`) enforced in `vforge.auth.rbac`, API services/dependencies, and `policies/rego/vforge/authz.rego`.
- **Versioned `/api/v1` REST API & Next.js Frontend:**
  - Full `/api/v1` endpoints for auth, organizations, memberships, projects, environments, assets, authorizations, auth profiles, scan profiles, and audit logs with Pydantic `extra="forbid"`, correlation IDs, structured UTC JSON logging, and metadata redaction.
  - Next.js App Router pages (`/`, `/login`, `/organizations`, `/organizations/[orgId]`, `members`, `projects`, `projects/[projectId]`, `assets`, `authorizations`, `scan-profiles`, `audit`) connected to the live API via same-origin proxy `/api/v1/[...path]`.
- **Governance & ADRs:**
  - Created `docs/decisions/ADR-0002-phase1-identity-rls-rbac.md`, `lifecycle/image-lock/phase1-images.json`, `tests/smoke/phase1_smoke.ps1`; updated traceability matrix, threat model, risk register, security baseline, implementation plan, and README.

## Verification Evidence (2026-11-12 — Phase 4)

- `docker compose --profile runner config --quiet` and `docker compose --profile dev-oidc --profile ops config --quiet` — **PASS**
- `docker compose run --rm --no-deps opa test /policies -v` — **PASS (25/25)** (11 in `authz_test.rego`, 14 in `scope_test.rego`)
- `docker compose --profile ops run --rm migrator sh -c "alembic upgrade head && alembic downgrade 0004_phase3_orchestration && alembic upgrade head && alembic current"` — **PASS (`0005_phase4_runner_isolation (head)`)**
- `docker compose --profile ops run --rm migrator pytest -v tests/test_rls_isolation.py` — **PASS (2/2)**
- `docker compose exec -T api` (`ruff check`, `ruff format --check` across 69 files, `mypy src` across 53 source files, `pytest -v tests`) — **PASS (48 passed, 2 skipped)** across Phases 0–4
- `docker compose -f runner/docker-compose.runner.yml --profile runner run --rm --no-deps --entrypoint sh vforge-runner -c "ruff check vforge_runner tests && ruff format --check vforge_runner tests && mypy vforge_runner && pytest -v tests"` — **PASS (4 passed, 1 skipped [conditional docker.sock live test]; 9 files formatted; 8 mypy source files clean)**
- `vforge-dummy-scanner:smoke` built and verified non-root `uid=10001` under `--read-only --cap-drop=ALL --security-opt=no-new-privileges:true --network=none` — **PASS**
- `npm.cmd --prefix apps/web run typecheck`, `lint`, `build` — **PASS (0 errors)**
- `tests/smoke/phase0_smoke.ps1`, `phase1_smoke.ps1`, `phase2_smoke.ps1`, `phase3_smoke.ps1`, and `phase4_smoke.ps1` run sequentially — **ALL PASS**
- Live `vforge-api-1`, `vforge-orchestrator-1`, `vforge-frontend-1`, and `vforge-opa-1` verified with `ReadonlyRootfs=true`, `CapDrop=["ALL"]`, `Privileged=false`, and zero `docker.sock` mount.

## Known Limitations (Phase 4)

- **Scanner Adapters Pending Phases 5–7:** Real scanner adapters (`OpenGrep`, `Gitleaks`, `Syft`, `Grype`, `Checkov`, `ZAP`, `Nuclei`, `Nmap`, `testssl.sh`) remain disabled (`scanners_enabled: false`) until Phases 5–7; Phase 4 exercises the hardened dummy-scanner contract and mTLS/egress/encryption runtime isolation.
- **Development vs. Production Runner Topology:** `runner/docker-compose.runner.yml` is explicitly development-only for WSL2/Docker Desktop verification; production deployments run `runner/` on dedicated isolated Linux Runner VMs with host-level firewall egress controls (`ADR-0006`).
- **KMS Integration Pending Phase 14:** `security/envelope.py` uses local KEK configuration (`ARTIFACT_ENCRYPTION_KEY_B64`); OpenBao Transit KMS wrapping and automated CA/KEK rotation land in Phase 14.
- `auth_profiles` stores validated secret-manager URI references only; runtime secret resolution for authenticated DAST/code scans integrates in Phases 5–7/14.
- Local `dev-oidc` Keycloak uses `start-dev` with HTTP loopback (`127.0.0.1:8080`) for developer evaluation only.

## Next Milestone

**Phase 5 — Scanner Adapter SDK & SAST/Secrets Vertical Slice (`feature/phase-5-scanner-integration`):** `packages/scanner-contracts/` typed `ScannerAdapter` contract, polyglot language/capability coverage registry, read-only workspace snapshot acquisition, pinned `OpenGrep` (SAST) & `Gitleaks` (Secrets) scanner images, SARIF/JSON parsing & normalization, and mandatory secret redaction before control-plane persistence.
