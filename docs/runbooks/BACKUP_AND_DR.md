# VForge Backup, Disaster Recovery & Incident Response Runbook (Phase 14 & Final Audit Close-Out)

> **Critical Safety Rule:** Never delete `vforge_*` persistent volumes (`vforge_postgres_data`, `vforge_rabbitmq_data`, `vforge_valkey_data`, `vforge_artifacts`, `vforge_grype_db`) and **never** run `docker compose down -v`.

---

## 1. Encryption & Key Separation Policy (§26.2)

- **Artifact Envelope KEK (`ARTIFACT_ENCRYPTION_KEY_B64` / `ARTIFACT_ENCRYPTION_KEYRING_JSON`):** Wraps per-artifact AES-256-GCM data encryption keys (`DEK`). Never stored inside PostgreSQL, Git, `.env.example`, or scanner containers.
- **Backup Envelope KEK (`BACKUP_ENCRYPTION_KEY_B64`):** Dedicated key-encryption key used to encrypt tenant DR snapshot bundles (`AES-256-GCM` with canonical AAD binding `vf:dr-backup-v1|<org_id>|<manifest_id>|<plaintext_sha256>`).
- **Cryptographic Honesty & PQC Readiness (§26.3 / §26.4):**
  - Classical baseline active: `AES-256-GCM`, `Ed25519` (scope/pack signatures), `ECDSA P-256` (runner mTLS), `Argon2id` (password fallback where applicable), `TLS 1.3`.
  - PQC agility metadata targets FIPS 203 (`ML-KEM`), FIPS 204 (`ML-DSA`), and FIPS 205 (`SLH-DSA`), disabled cleanly (`pqc_live_enabled: false`) until interoperable vetted TLS/crypto libraries are deployed.
  - **No FIPS claim** is made from algorithm choice alone without a validated cryptographic module.

---

## 2. Per-Service Backup, Restore, Retention, RPO & RTO Matrix

VForge persists state across 5 Docker volumes (`vforge_postgres_data`, `vforge_rabbitmq_data`, `vforge_valkey_data`, `vforge_artifacts`, `vforge_grype_db`) plus external secret/KMS material (`OpenBao` / `.secrets/`). Full-platform recovery requires restoring or re-hydrating each stateful component according to its role:

| Service / Volume | Authoritative Data Stored | Backup Procedure | Restore Procedure | Independent Restore Verification Status | Target RPO | Target RTO | Backup Retention Policy |
|---|---|---|---|---|---|---|---|
| **PostgreSQL 18.6 (`vforge_postgres_data`)** | All 81 tables (tenant domain, RBAC, signed `scope_snapshots`, `scan_runs`, `outbox_events`, `findings`, `artifacts` metadata + inline ciphertexts, audit logs, catalogs) | `pg_dump -U vforge -d vforge -Fc -f <path>.dump` + continuous WAL archiving in production | Pre-create `vforge_migrator` & `vforge_app` roles, `CREATE DATABASE ... OWNER vforge_migrator`, `pg_restore --exit-on-error` | **INDEPENDENTLY RESTORED & VERIFIED** in isolated container (`vforge_dr_verify_pg_*`) via `scripts/dr/backup_and_verify.ps1` | **<= 15 min** (continuous WAL) / **<= 24h** (daily dump) | **<= 30 min** | **35 days** daily snapshots + **1 year** monthly compliance archives |
| **Application Tenant DR Bundles (`dr_backup_manifests`)** | Envelope-encrypted (`AES-256-GCM`) per-tenant configuration, findings summary, and governance state | `POST /api/v1/organizations/{org_id}/hardening/backups` | `POST /api/v1/organizations/{org_id}/hardening/drills` (decrypts via `BACKUP_ENCRYPTION_KEY_B64`, verifies SHA-256 & AAD) | **INDEPENDENTLY RESTORED & VERIFIED** in API integration suite (`test_phase14_hardening_dr.py`) | **<= 24h** (or on-demand pre-change) | **<= 15 min** | **90 days** online in `dr_backup_manifests` + off-site export |
| **RabbitMQ 4.2 (`vforge_rabbitmq_data`)** | Broker topology/definitions (`vforge` vhost, `vforge_admin` & `vforge_app` users, scoped regex permissions, exchanges, queues, DLX policies). Transient unacked AMQP messages are recoverable from PostgreSQL `outbox_events` and expired job lease sweeps. | `rabbitmqctl export_definitions /tmp/vf_rmq_defs.json` | Boot fresh RabbitMQ node, run `rabbitmqctl import_definitions <defs.json>`, allow `orchestrator` to replay pending `outbox_events` from PostgreSQL | **INDEPENDENTLY RESTORED & VERIFIED** (broker definitions, vhost `vforge`, and user permissions restored into isolated container `vforge_dr_verify_rmq_*` via `scripts/dr/backup_and_verify.ps1`; Mnesia transient queue messages re-driven from PostgreSQL `outbox_events`) | **0 data loss** for durable scan state (backed by PostgreSQL `outbox_events`) | **<= 10 min** | **35 days** versioned broker definition exports |
| **Valkey 9.1 (`vforge_valkey_data` + `.secrets/valkey/users.acl`)** | AOF/RDB persistence (`/data/dump.rdb`, `/data/appendonlydir`) for sliding-window rate limits (`vf:rl:*`) and session revocation cache (`vf:session:revoked:*`), plus ACL rules (`users.acl`). Authoritative session revocation timestamps (`auth_sessions.revoked_at`) are stored in PostgreSQL. | `tar -czf <path>.tar.gz -C /data .` + versioned backup of `users.acl` | Extract `/data` archive into fresh volume/tmpfs, mount `/etc/valkey/users.acl:ro`, start `valkey-server --appendonly yes --aclfile /etc/valkey/users.acl` | **INDEPENDENTLY RESTORED & VERIFIED** (`/data` archive + `users.acl` restored into isolated container `vforge_dr_verify_valkey_*` with `default off` `NOAUTH` enforcement verified via `scripts/dr/backup_and_verify.ps1`) | **<= 5 min** (AOF `everysec`; authoritative session revocations in PostgreSQL have PostgreSQL RPO) | **<= 10 min** | **14 days** daily `/data` snapshots + versioned ACL templates |
| **Encrypted Artifacts Volume (`vforge_artifacts`)** | File-backed AES-256-GCM encrypted raw scanner outputs, source archives, SBOMs, and reports under `/var/lib/vforge/artifacts` (wrapped DEKs & SHA-256 digests stored in PostgreSQL `artifacts`) | Read-only volume archive (`tar -czf <path>.tar.gz -C /var/lib/vforge/artifacts .`) + SHA-256 file manifest | Extract archive into `/var/lib/vforge/artifacts` and verify file count and SHA-256 digests against PostgreSQL `artifacts.sha256` | **INDEPENDENTLY RESTORED & VERIFIED** (volume archive extracted into isolated container mount with file-count parity verified via `scripts/dr/backup_and_verify.ps1`, plus AES-256-GCM ciphertext decryption verified in `test_phase4_runner_isolation.py` & `test_phase14_hardening_dr.py`) | **<= 15 min** (object-storage replication) / **<= 24h** (daily volume archive) | **<= 30 min** | **90 days** hot retention + **1 year** cold archive aligned with PostgreSQL backups |
| **Grype Offline Vulnerability DB (`vforge_grype_db`)** | Unpacked SQLite offline vulnerability feed (`/var/lib/vforge/grype-db/6/vulnerability.db`, ~3.2 GB, `import.json`, `last_update_check`) used by `GrypeAdapter` in `--network=none` containers | Export provenance manifest (`import.json` SHA-256, upstream `.tar.zst` checksum, SQLite header & byte size) + mirror pinned upstream `vulnerability-db_*.tar.zst` archive | Re-import pinned offline archive (`grype db import <bundle.tar.zst>`) into `vforge_grype_db` and verify digest against `vulnerability_db_snapshots.db_sha256` / `import.json` | **PROVENANCE & SQLITE INTEGRITY VERIFIED; REPRODUCIBLE RE-HYDRATION** (`scripts/dr/backup_and_verify.ps1` exports and verifies `import.json` SHA-256 + 3.2 GB `SQLite format 3` header; full 3.2 GB SQLite copy is skipped during routine local smoke runs in favor of deterministic offline feed re-import) | **0 data loss** (reproducible from pinned offline feed archive tracked in `vulnerability_db_snapshots`) | **<= 15 min** | Retain current **`stable`** and prior **`rolled_back`** offline `.tar.zst` feed bundles (**90 days**) |
| **Cryptographic Keys & Secrets (`OpenBao` / `.secrets/`)** | `ARTIFACT_ENCRYPTION_KEYRING_JSON`, `BACKUP_ENCRYPTION_KEY_B64`, `SCOPE_SIGNING_PRIVATE_KEY_PEM`, Runner mTLS CA (`ca.crt`/`ca.key`), DB/broker passwords | Encrypted OpenBao Raft snapshot (`bao operator raft snapshot save`) or offline HSM-wrapped key escrow | Restore OpenBao snapshot / unseal KMS before starting Control Plane containers (`api`, `orchestrator`, `runner-gateway`) | **LOCAL KEYRING & mTLS CA ROTATION VERIFIED** (`test_phase14_hardening_dr.py`); live external HA OpenBao cluster snapshot restore is an **External Production Prerequisite (`NOT VERIFIABLE` locally)** | **0 data loss** (synchronous Raft replication + offline escrow on every key epoch rotation) | **<= 15 min** | Retain all historical key epochs in `verify_only` / decrypt-only keyring until all dependent archives expire (**>= 1 year**) |

---

## 3. Automated Non-Destructive Backup & Isolated-Container Restore Verification Drill

1. **Multi-Service Backup + Isolated-Container Restore Drill (Windows/PowerShell):**
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/dr/backup_and_verify.ps1
   ```
   This script executes 8 non-destructive steps without modifying any `vforge_*` persistent volume:
   - `[1/8]` Verifies all 5 persistent volumes (`vforge_postgres_data`, `vforge_rabbitmq_data`, `vforge_valkey_data`, `vforge_artifacts`, `vforge_grype_db`) remain intact.
   - `[2/8]` Creates a fresh custom-format PostgreSQL dump (`pg_dump -Fc`) from `postgres` in a restricted outside-repository directory (`icacls /inheritance:r`) and verifies `pg_restore --list` structure + SHA-256 checksum.
   - `[3/8]` Exports RabbitMQ broker definitions (`rabbitmqctl export_definitions`), archives Valkey `/data`, archives `vforge_artifacts` (read-only), and exports the `vforge_grype_db` provenance manifest (`import.json` SHA-256 + `SQLite format 3` verification).
   - `[4/8]` Launches an isolated disposable PostgreSQL 18.6 container (`vforge_dr_verify_pg_*`) on an `--internal` Docker network (`vforge_dr_verify_net_*`) with ephemeral `--tmpfs` storage.
   - `[5/8]` Restores the PostgreSQL archive via `pg_restore --exit-on-error` and verifies Alembic head `0016_phase15_ai_redteam`, all `81` tables, `63` forced-RLS tenant tables, `172` foreign keys, `35` triggers, seeded catalogs, and `vforge_app` (`NOBYPASSRLS`) runtime read isolation.
   - `[6/8]` Launches an isolated disposable RabbitMQ container (`vforge_dr_verify_rmq_*`) on the `--internal` network, runs `rabbitmqctl import_definitions`, and verifies restoration of vhost `vforge` and scoped user permissions (`vforge_admin`, `vforge_app`).
   - `[7/8]` Launches an isolated disposable Valkey container (`vforge_dr_verify_valkey_*`) on the `--internal` network, restores `/data` + `/etc/valkey/users.acl`, verifies `default off` `NOAUTH` ACL enforcement, and extracts the `vforge_artifacts` archive into an isolated `--tmpfs` mount to verify file-count parity and Grype SQLite provenance.
   - `[8/8]` Cleans up all disposable containers (`vforge_dr_verify_pg_*`, `vforge_dr_verify_rmq_*`, `vforge_dr_verify_valkey_*`) and the isolated network (`vforge_dr_verify_net_*`).

2. **Disposable-Database Full Migration Chain Verification (`0001..0016`):**
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/db/verify_migrations_disposable.ps1
   ```
   Verifies `alembic upgrade head` (`base -> 0016`), `alembic downgrade base` (`0016 -> base`), and `alembic upgrade head` (`base -> 0016`) on a fresh disposable database without downgrading the persistent `vforge` database.

3. **Application Encrypted DR Manifest & Restore Drill:**
   - Via UI (`Security Ops & DR` -> **Create Encrypted Backup** -> **Run Restore Drill**) or API:
     - `POST /api/v1/organizations/{org_id}/hardening/backups`
     - `POST /api/v1/organizations/{org_id}/hardening/drills`
   - Decrypts ciphertext via `resolve_keyring`, confirms SHA-256 digests and AAD match, records observed RTO seconds, and appends an immutable `dr_restore_drills` row (`BEFORE UPDATE OR DELETE` trigger enforced).

---

## 4. Incident Response Playbooks

### A. Credential or KEK Compromise
1. Provision new `ARTIFACT_ENCRYPTION_KEY_B64` (and `BACKUP_ENCRYPTION_KEY_B64`) in secret manager (`OpenBao` / Docker Secrets), retaining compromised KEK strictly in `ARTIFACT_ENCRYPTION_KEYRING_JSON` temporarily while rotating DEKs.
2. Register the rotated key epoch via `POST /hardening/keys` (automatically shifts prior active key to `verify_only`), execute `POST /hardening/keys/rewrap-drill`, and re-wrap mutable `dr_backup_manifests` DEKs online via `POST /hardening/keys/rewrap-persisted` (append-only `artifacts` / `source_snapshots` remain readable via `ARTIFACT_ENCRYPTION_KEYRING_JSON` until retention expiry or offline `vforge_migrator` maintenance).
3. Remove old KEK from keyring once no referenced backup manifests/artifacts remain; revoke the old epoch and rotate DB (`vforge_app`, `vforge_migrator`), RabbitMQ, and Valkey credentials via `infrastructure/postgres/` / OpenBao dynamic leases.

### B. Compromised Runner mTLS Certificate
1. Immediately revoke the runner (`POST /api/v1/organizations/{org_id}/runners/{runner_id}/revoke`) so gateway handshakes & claim/heartbeat APIs fail closed.
2. Monitor expiry/revocation posture via `GET /api/v1/organizations/{org_id}/hardening/certs/posture`.
3. If the Runner CA private key is suspected compromised, generate a new Runner CA via `generate_runner_ca()`, update `RUNNER_MTLS_CA_CERT_PATH`, and re-enroll runners with fresh leaf certs.
