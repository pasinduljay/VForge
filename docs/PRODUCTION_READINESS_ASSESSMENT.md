# VForge Production Readiness Assessment

> **Audit Scope:** Section 8 & Section 11.2 Honest Production Readiness Evaluation (`chore/final-release-verification`)  
> **Architecture Baseline:** [`docs/DEVELOPMENT_ROADMAP.md`](../docs/DEVELOPMENT_ROADMAP.md) §§23–28, §32  
> **Runbooks:** [`docs/runbooks/DEPLOYMENT_AND_UPGRADE.md`](runbooks/DEPLOYMENT_AND_UPGRADE.md) and [`docs/runbooks/BACKUP_AND_DR.md`](runbooks/BACKUP_AND_DR.md)

---

## 1. Maturity Level Classification Summary

In accordance with Section 8 of the Final Release Verification protocol, VForge's current operational maturity is classified across four distinct levels without conflating local/code verification with external production infrastructure testing:

| Maturity Level | Status | Honest Summary |
|---|---|---|
| **Level 1 — Development Environment Verified** | **ACHIEVED (`PASS`)** | All Phases 0–15 services, 16 Alembic migrations (`0001..0016`), 81 PostgreSQL tables, 63 forced-RLS tenant tables, 35 immutability/guard triggers, 35 OPA Rego tests, 131 API integration/negative tests (`130 passed` in `api` + `1 passed` in `migrator`), 31 scope-validator tests, 15 scanner-contract tests, 13 runner tests (`11 passed` in non-root `vforge-runner` + `2 passed` in live-Docker runner container), live ephemeral scanner container executions (`opengrep`, `gitleaks`, `syft`, `grype`, `checkov`, `zap`, `nuclei`, `nmap`, `testssl`), Next.js production build, and multi-service isolated-container DR restore drills (`PostgreSQL`, `RabbitMQ`, `Valkey`, `Artifacts`, `Grype DB` provenance) are verified and passing locally. |
| **Level 2 — Production Configuration & Guardrails Verified** | **ACHIEVED (`PASS`)** | Fail-closed startup guardrails (`validate_startup_configuration` when `VFORGE_ENV=production`), `OpenBaoProvider` / `DockerSecretProvider` workload identity, multi-KEK `AES-256-GCM` keyring rotation, `METRICS_BEARER_TOKEN` enforcement, `@sha256` digest pinning across all Compose files, non-root `read_only: true` + `cap_drop: [ALL]` + `no-new-privileges:true` container posture, and deployment/upgrade/DR runbooks are implemented and verified by automated unit and integration tests. |
| **Level 3 — Production Deployment Actually Tested** | **EXTERNAL PREREQUISITE (`NOT VERIFIABLE` locally)** | Not yet executed against a live multi-node cloud/enterprise production cluster with external TLS ingress, production OIDC IdP (e.g., Okta/Entra ID/Keycloak HA), live OpenBao KMS cluster, dedicated Linux Runner hosts, and remote S3/WORM object storage. |
| **Level 4 — Independent External Security Assessment Completed** | **EXTERNAL PREREQUISITE (`NOT VERIFIABLE` locally)** | Internal adversarial subagent audits (`Phase 3`..`Phase 15` + `Final Release Independent Auditor`) and automated self-scan/fuzz suites have been completed and remediated; however, an independent third-party human penetration test and external cryptographic/compliance audit have not yet been conducted. |

---

## 2. Detailed Production Readiness Checklist

| Requirement | Classification | What Is Verified in Repository & Local Runtime | What Requires External Production Infrastructure |
|---|---|---|---|
| **PostgreSQL Role Separation (`vforge`, `vforge_migrator`, `vforge_app`)** | **PASS** | Verified live in `vforge-postgres-1`, in disposable migration DB (`scripts/db/verify_migrations_disposable.ps1`), and in restored DR container (`scripts/dr/backup_and_verify.ps1`). `vforge_app` has `NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS` and owns `0` tables. | Provisioning separate secrets in production Vault/OpenBao and enabling PostgreSQL server TLS (`ssl=on`). |
| **Multi-Tenant Row-Level Security (`ENABLE` + `FORCE RLS`)** | **PASS** | All `63` tenant-scoped tables enforce `ENABLE` and `FORCE ROW LEVEL SECURITY` with composite tenant foreign keys (`(organization_id, id)`). Unscoped queries as `vforge_app` return `0` rows. | None (enforced at PostgreSQL schema layer). |
| **Secret Management & OpenBao Integration** | **PASS** (Code & Contract) / **PARTIAL** (Live Prod KMS) | `SecretProvider` (`LocalDevelopmentProvider`, `DockerSecretProvider`, `OpenBaoProvider`) implemented and unit-tested (`test_security_preflight.py`, `test_phase14_hardening_dr.py`). Fail-closed startup blocks `LocalDevelopmentProvider` and default KEK IDs when `VFORGE_ENV=production`. | Connecting `OpenBaoProvider` to a live production OpenBao/Vault cluster over TLS with AppRole/Kubernetes/JWT workload identity. |
| **Envelope Encryption & Online KEK Rotation (`AES-256-GCM`)** | **PASS** | Per-artifact and per-backup 256-bit DEKs wrapped with active KEK and canonical AAD; online multi-KEK keyring decryption and persisted DEK re-wrapping (`POST /hardening/keys/rewrap-persisted`) verified in `test_phase14_hardening_dr.py`. | Backing the root KEK with a hardware HSM / cloud KMS transit engine in production. |
| **Control Plane / Execution Plane Separation & Runner mTLS** | **PASS** | Control Plane containers mount zero Docker sockets (`docker_socket_mounted: false`). Runner gateway enforces `ECDSA P-256` mTLS client certificate validation, certificate revocation checks, and `Ed25519` signed job manifests. | Deploying `vforge-runner` on dedicated Linux VM/bare-metal hosts physically/network-separated from Control Plane nodes. |
| **Container Hardening & `@sha256` Digest Pinning** | **PASS** | Every service in `docker-compose.yml`, `runner/docker-compose.runner.yml`, `infrastructure/lab/compose.lab.yaml`, `infrastructure/redteam/compose.redteam.yaml`, and `infrastructure/monitoring/compose.observability.yaml` uses `@sha256` digests, non-root UIDs, `read_only: true`, `cap_drop: [ALL]`, and `no-new-privileges:true`. | Enforcing admission controller policies (e.g., Kyverno/OPA Gatekeeper) in production Kubernetes/orchestrator clusters. |
| **Observability, Metrics & Alerting** | **PASS** (Application & Compose) / **PARTIAL** (Live Alert Routing) | `/metrics` exposes Prometheus v0.0.4 counters/gauges scrubbed of PII/tenant IDs (`{id}` path normalization) with mandatory Bearer token auth in production; `infrastructure/monitoring/` defines hardened Prometheus + Grafana + alert rules (`alerts.yml`). | Connecting Prometheus Alertmanager to production PagerDuty/Slack/SIEM receivers. |
| **Disaster Recovery Backup & Isolated Restore** | **PASS** (Local Multi-Service) / **PARTIAL** (Off-Site WORM) | Full `pg_dump -Fc` backup and isolated disposable PostgreSQL container restore (`pg_restore --exit-on-error`), RabbitMQ definitions export/import in isolated container, Valkey `/data` + `users.acl` isolated restore, `vforge_artifacts` archive extraction parity, and `vforge_grype_db` v6 SQLite provenance verified end-to-end by `scripts/dr/backup_and_verify.ps1`, plus encrypted tenant DR manifests and restore drills in `apps/api/src/vforge/hardening/service.py`. | Replicating encrypted backups to off-site, immutable object storage (e.g., S3 Object Lock / WORM), configuring continuous PostgreSQL WAL archiving, and testing multi-region failover. |
| **Cryptographic Standards & PQC Agility Honesty** | **PASS** | Classical cryptography (`AES-256-GCM`, `Ed25519`, `ECDSA P-256`, `SHA-256`, `TLS 1.3`) active; PQC agility metadata (`ML-KEM`, `ML-DSA`, `SLH-DSA`) tracked with `pqc_live_enabled: false` and `fips_validated_module: false` (no false FIPS claim). | Deploying FIPS 140-3 validated cryptographic modules if required by regulated government/enterprise customers. |

---

## 3. Pre-Production Go-Live Operator Checklist

Before exposing a VForge deployment to production traffic, operators must complete the following steps documented in [`docs/runbooks/DEPLOYMENT_AND_UPGRADE.md`](runbooks/DEPLOYMENT_AND_UPGRADE.md):

1. Set `VFORGE_ENV=production` and configure `SECRET_PROVIDER=openbao` (or `docker_secrets` with `/run/secrets` mounts).
2. Provision production `ARTIFACT_ENCRYPTION_KEY_B64` (`ARTIFACT_ENCRYPTION_KEY_ID` != `vf-kek-dev-1`), `BACKUP_ENCRYPTION_KEY_B64` (`BACKUP_ENCRYPTION_KEY_ID` != `vf-bkek-dev-1`), and `METRICS_BEARER_TOKEN`.
3. Provision distinct production credentials for `POSTGRES_USER`, `POSTGRES_MIGRATOR_USER`, `POSTGRES_APP_USER`, `RABBITMQ_DEFAULT_USER`, `RABBITMQ_APP_USER`, `VALKEY_ADMIN_USER`, and `VALKEY_APP_USER`.
4. Provision production OIDC identity provider (`OIDC_ENABLED=true`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI` over HTTPS).
5. Provision Runner CA and per-runner mTLS certificates (`RUNNER_MTLS_CA_CERT_PATH`, `RUNNER_MTLS_SERVER_CERT_PATH`, `RUNNER_MTLS_SERVER_KEY_PATH`) on dedicated Linux Runner hosts.
6. Keep optional `--profile lab` (`compose.lab.yaml`) and `--profile redteam` (`compose.redteam.yaml`) disabled on production Control Plane nodes.
