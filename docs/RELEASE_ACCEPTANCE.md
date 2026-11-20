# VForge Release Acceptance Criteria

VForge may be declared complete for release candidate review **only** when Phases 0–15 pass and every gate in [`docs/DEVELOPMENT_ROADMAP.md`](docs/DEVELOPMENT_ROADMAP.md) §32 and the release checklist below is backed by observed verification evidence:

## 1. Functional & Execution Integrity Gates (Arch §32)
- End-to-end project, environment, asset, authorization, signed snapshot, orchestration run/stage/job/lease, runner execution, scanner normalization/correlation, intelligence enrichment, update lifecycle, rule studio, AI gateway, lab validation, and reporting workflows verified.
- Failed, timed-out, or aborted scanners surface explicitly (`failed` / `completed_with_errors` / `partial`), never as clean passes.
- Every finding and report links to exact source commit/snapshot, engine digest, adapter version, rule-pack hash, template snapshot, and feed snapshot IDs.
- HTML, PDF, JSON, and SARIF report exports validate cleanly and remain role-restricted.

## 2. Security & Isolation Gates (Arch §32)
- Zero Docker socket mounts (`docker.sock`) or privileged flags on control-plane or scanner containers.
- Dedicated Runner Agent mTLS registration/claim/heartbeat/upload/revocation, ephemeral container limits (`cap_drop: ALL`, `read_only`, seccomp, cgroups), and network-level egress gateway + DNS pinning verified.
- Tenant isolation (RLS + composite FKs + cross-tenant negative suites), RBAC/OPA authorization, SSRF/redirect/rebinding tests, prompt-injection tests, and API abuse/rate-limit tests pass.
- OpenBao dynamic secrets + AES-256-GCM envelope encryption + key/certificate rotation + backup/restore DR drills verified; zero secrets in logs, errors, reports, AI prompts, or Git.
- Parser/archive fuzz tests, dependency audits, and self-scan findings reviewed with zero unresolved Critical or High platform defects.

## 3. Lifecycle, Intelligence & AI Governance Gates (Arch §32)
- 10 update channels managed through `candidate -> validated -> approved -> canary -> stable` with non-destructive rollback tested.
- Intelligence connectors replay from stored snapshots and surface stale/outage warnings accurately.
- Rule & Skill Studio enforces fixture regression (positive/negative/near-miss) and independent human signing; AI cannot self-approve, alter scope/OPA, or violate provider data-retention policies.
- Isolated OWASP learning lab resets cleanly and blocks public/control-plane access.

## 4. Final Release Deliverables
Before final completion, verify and produce/update:
1. Final architecture & implementation status documentation ([`docs/IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md), [`docs/TRACEABILITY_MATRIX.md`](TRACEABILITY_MATRIX.md), [`docs/FINAL_REQUIREMENT_TRACEABILITY.md`](FINAL_REQUIREMENT_TRACEABILITY.md)).
2. Complete feature inventory and explicit known limitations ([`docs/RELEASE_ACCEPTANCE_REPORT.md`](RELEASE_ACCEPTANCE_REPORT.md), [`docs/FINAL_VERIFICATION_REPORT.md`](FINAL_VERIFICATION_REPORT.md)).
3. Security assessment & §32 test/verification report ([`docs/FINAL_SECURITY_AUDIT.md`](FINAL_SECURITY_AUDIT.md), [`docs/RELEASE_ACCEPTANCE_REPORT.md`](RELEASE_ACCEPTANCE_REPORT.md), [`docs/RISK_REGISTER.md`](RISK_REGISTER.md)).
4. Deployment, backup/recovery, and update/maintenance runbooks ([`docs/runbooks/DEPLOYMENT_AND_UPGRADE.md`](runbooks/DEPLOYMENT_AND_UPGRADE.md), [`docs/runbooks/BACKUP_AND_DR.md`](runbooks/BACKUP_AND_DR.md), [`docs/DISASTER_RECOVERY_RESTORE_REPORT.md`](DISASTER_RECOVERY_RESTORE_REPORT.md)).
5. Complete Git branch/commit summary and recommended production-readiness operational actions ([`docs/IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md), [`docs/PRODUCTION_READINESS_ASSESSMENT.md`](PRODUCTION_READINESS_ASSESSMENT.md), [`docs/RELEASE_ACCEPTANCE_REPORT.md`](RELEASE_ACCEPTANCE_REPORT.md)).
