# VForge Enterprise Deployment, Upgrade & Maintenance Runbook

> **Authority:** Production & Self-Hosted Enterprise Operations Guide (`docs/DEVELOPMENT_ROADMAP.md` §§23–28, §32)
> **Related Runbooks:** [`BACKUP_AND_DR.md`](BACKUP_AND_DR.md)

---

## 1. Architecture Topology & Plane Separation

VForge enforces a strict two-plane architecture:

1. **Control Plane (`docker-compose.yml`):**
   - `frontend` (Next.js App Router UI, port `3000`)
   - `api` (FastAPI Control Plane API, port `8000`, runs as `vforge_app` with `NOBYPASSRLS`)
   - `orchestrator` (Declarative scan state machine, transactional outbox & target lease manager)
   - `update-controller` (Four-stream, 10-channel digest-pinned release & feed lifecycle worker)
   - `postgres` (PostgreSQL 16 with `FORCE ROW LEVEL SECURITY` on all tenant tables)
   - `rabbitmq` (RabbitMQ 3.13 with vhost `vforge` and scoped user `vforge_app`)
   - `valkey` (Valkey 8.0 with default user disabled and ACL-scoped users)
   - `opa` (Open Policy Agent 1.x evaluating `/policies/vforge/authz.rego` and `scope.rego`)
   - `migrator` (Isolated `ops` profile service running Alembic as `vforge_migrator`)
2. **Execution Plane (`runner/docker-compose.runner.yml`):**
   - `vforge-runner` (Dedicated Runner Agent authenticating via mTLS + Ed25519-signed job manifests, executing digest-pinned scanner containers with scoped egress gateway enforcement).
3. **Optional Isolated Environments (Opt-In Profiles Only):**
   - `infrastructure/lab/compose.lab.yaml` (`--profile lab`): Intentionally vulnerable learning lab attached strictly to `lab_internal` (`internal: true`).
   - `infrastructure/redteam/compose.redteam.yaml` (`--profile redteam`): Experimental Strix/PentAGI AI red-team sandbox attached strictly to `vforge-lab_lab_internal` (`internal: true`).
   - `infrastructure/monitoring/compose.observability.yaml` (`--profile monitoring`): Local Prometheus + Grafana observability stack.

---

## 2. Production Secret & Cryptographic Prerequisites

Before starting VForge in `staging` or `production` (`VFORGE_ENV=production`):

1. **Secret Provider (`SecretProvider`):**
   - Configure OpenBao workload identity (`SECRET_PROVIDER_BACKEND=openbao`, `OPENBAO_ADDR`, `OPENBAO_AUTH_METHOD=approle|jwt|oidc|kubernetes`, `OPENBAO_AUTH_ROLE`) or Docker/Kubernetes file mounts (`*_FILE`).
   - Never commit `.env`, `.secrets/`, or private keys to Git.
2. **Envelope Encryption Keyring (`AES-256-GCM`):**
   - Set distinct 32-byte base64url keys for `ARTIFACT_ENCRYPTION_KEY_B64` (`ARTIFACT_ENCRYPTION_KEY_ID`) and `BACKUP_ENCRYPTION_KEY_B64` (`BACKUP_ENCRYPTION_KEY_ID`).
   - Historical keys for online decryption/re-wrapping are supplied in `ARTIFACT_ENCRYPTION_KEYRING_JSON`.
   - Note: `startup.validate_startup_configuration()` fails closed if `VFORGE_ENV` is `production`/`staging` and development default KEK IDs or missing `METRICS_BEARER_TOKEN` are detected.
3. **Database & Broker Role Separation:**
   - `POSTGRES_USER` (bootstrap superuser), `POSTGRES_MIGRATOR_USER` (`vforge_migrator`, schema DDL owner), and `POSTGRES_APP_USER` (`vforge_app`, runtime `NOSUPERUSER NOBYPASSRLS`) must use distinct high-entropy credentials.
   - `RABBITMQ_DEFAULT_USER` (`vforge_admin`) and `RABBITMQ_APP_USER` (`vforge_app`) must use distinct credentials.
   - `VALKEY_ADMIN_USER` and `VALKEY_APP_USER` must use distinct SHA-256 ACL passwords.
4. **Runner mTLS & Ed25519 Signing Keys:**
   - Provision the Runner CA, Gateway server certificate, and per-runner client certificates (`RUNNER_MTLS_CA_CERT_PATH`, `RUNNER_MTLS_SERVER_CERT_PATH`, `RUNNER_MTLS_SERVER_KEY_PATH`) and monitor expiration via `GET /api/v1/organizations/{org_id}/hardening/certs/posture`.

---

## 3. Initial Deployment & Controlled Schema Migration Procedure

1. **Verify Persistent Volumes:**
   ```powershell
   docker volume ls
   ```
   Ensure `vforge_postgres_data`, `vforge_rabbitmq_data`, `vforge_valkey_data`, and `vforge_artifacts` exist (or are created by Compose on first boot). **Never** run `docker compose down -v`.
2. **Start Core Infrastructure Dependencies:**
   ```powershell
   docker compose up -d postgres rabbitmq valkey opa
   ```
3. **Run Isolated Database Migrations (`ops` Profile):**
   ```powershell
   docker compose --profile ops run --rm -T migrator alembic upgrade head
   docker compose --profile ops run --rm -T migrator alembic current
   ```
   Confirm the migration head is `0016_phase15_ai_redteam (head)`.
4. **Start Control Plane Services:**
   ```powershell
   docker compose up -d api frontend orchestrator update-controller
   ```
5. **Verify Liveness, Readiness & Runtime Identity:**
   ```powershell
   Invoke-RestMethod -Uri "http://127.0.0.1:8000/health"
   Invoke-RestMethod -Uri "http://127.0.0.1:8000/ready"
   Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/meta"
   ```

---

## 4. Controlled Upgrade & Rollback Procedure

### 4.1 Pre-Upgrade Backup & Verification
Always run a non-destructive backup and restore-list check before applying any platform or schema upgrade:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/dr/backup_and_verify.ps1
```
Additionally, create a tenant-scoped encrypted DR backup manifest and execute a restore drill via `/api/v1/organizations/{org_id}/hardening/dr/backups` and `/dr/restore-drills`.

### 4.2 Four-Stream, 10-Channel Scanner / Rule / Feed Updates (Zero-Rebuild)
Scanner images (`opengrep`, `gitleaks`, `syft`, `grype`, `checkov`, `zap`, `nuclei`, `nmap`, `testssl`), vulnerability databases (`grype-db`, `trivy-db`), threat-intelligence feeds (`cisa-kev`, `epss`, `nvd-cve`, `osv`, `exploit-db`), rule packs, and AI skills are updated through the **Phase 10 Update Lifecycle (`candidate -> validated -> approved -> canary -> stable`)** without rebuilding the Control Plane:
1. Register candidate version (`@sha256` digest mandatory for images; SHA-256 archive hash mandatory for feeds).
2. Run validation gates (`POST /api/v1/organizations/{org_id}/updates/{update_id}/validate`).
3. Approve (`POST .../approve` — Segregation of Duties enforced).
4. Promote to `canary` (`POST .../promote-canary`) and then `stable` (`POST .../promote-stable`).
5. **Instant Rollback:** If a promoted scanner or feed causes regressions, invoke `POST /api/v1/organizations/{org_id}/updates/{update_id}/rollback` (or `POST .../feeds/{snapshot_id}/rollback`) to atomically restore the previous stable `@sha256` pin without rebuilding containers or mutating historical scan records.

### 4.3 Control-Plane Application Rollback
If a Control Plane code upgrade must be rolled back:
1. Stop `orchestrator` and `update-controller` to quiesce background workers:
   ```powershell
   docker compose stop orchestrator update-controller
   ```
2. If the upgrade included a schema migration that must be reverted, run the isolated `migrator` downgrade to the target revision:
   ```powershell
   docker compose --profile ops run --rm -T migrator alembic downgrade <target_revision>
   ```
3. Checkout the previous verified Git commit/tag and rebuild `api`, `frontend`, `migrator`, `orchestrator`, and `update-controller`.
4. Re-run `scripts/dr/backup_and_verify.ps1` and the phase smoke suite (`tests/smoke/phase15_smoke.ps1`) to confirm full system health.

---

## 5. Multi-VM Portainer Business Edition GitOps Deployment

For split Control Plane and Execution Plane deployments across two Linux hosts managed via Portainer Business Edition:

- **VM-1 (Control Plane — `docker-compose.portainer-vm1.yml`):**
  - Self-bootstraps OPA Rego policies, Keycloak realm configuration, Runner Gateway mTLS certificates, least-privilege PostgreSQL roles (`vforge_migrator`, `vforge_app`), RabbitMQ vhost permissions, and Alembic migrations (`0001` through `0018_clean_ai_model_catalog`) via `control-plane-init`.
- **VM-2 (Execution Plane via Portainer Agent — `docker-compose.portainer-vm2.yml`):**
  - Uses pre-built container images (`docker:27-cli` and `python:3.13-slim`) with runtime source synchronization in `runner-init` so deployment over Portainer Agent (`:9001`) succeeds without requiring Docker BuildKit HTTP/2 gRPC streaming through the agent proxy.

