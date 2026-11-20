# VForge Secret Management, Credential Separation & OpenBao Readiness

> **Scope:** Security Preflight (pre-Phase 3), local vs. production configuration separation, database/broker/cache least-privilege identities, OpenBao integration architecture, and safe credential rotation/rollback procedures.

---

## 1. Local vs. Production Configuration Separation

| Aspect | Local Development (`development` / `test`) | Production / Staging (`production` / `staging`) |
|---|---|---|
| Secret source | Gitignored `.env` + `.secrets/valkey/users.acl` | `OpenBaoProvider` / `DockerSecretProvider` (`/run/secrets/*`) — **no `.env` file** (`Settings.settings_customise_sources` skips `DotEnvSettingsSource`) |
| Committed templates | `.env.example`, `infrastructure/valkey/users.acl.example`, `infrastructure/postgres/01-role-separation.sql.example` | Same non-sensitive templates and pinned image digests (`lifecycle/image-lock/`) |
| URL construction | Single-source component credentials assembled via `sqlalchemy.engine.URL.create` (`build_postgres_url`) and `urllib.parse.quote` (`build_amqp_url`, `build_valkey_url`) | Same typed URL builders from resolved `SecretProvider` values |
| Startup enforcement | `Settings.validate_startup_configuration()` fails closed if required runtime credentials are missing or if migration credentials leak into runtime API env | Same, plus rejects `SECRET_PROVIDER=local_dev`, rejects static `BAO_TOKEN`/`VAULT_TOKEN`, and requires `SCOPE_SIGNING_PRIVATE_KEY_PATH` |

---

## 2. Service Identity & Privilege Separation

### 2.1 PostgreSQL Role Separation

VForge enforces three strictly separated PostgreSQL identities:

1. **Bootstrap / Administrative (`vforge`)**: Initial cluster/database superuser created during volume bootstrap. Used solely for DBA operations, backups, and initial role provisioning. Never exposed to `api`, workers, or `alembic`.
2. **Migration / Schema Owner (`vforge_migrator`)**: `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`. Owns database `vforge`, schema `public`, all tables, sequences, and trigger functions (`prevent_audit_events_mutation`, `prevent_scope_snapshots_mutation`). Used exclusively by the dedicated `migrator` profile/job (`MIGRATION_DATABASE_URL` / `POSTGRES_MIGRATOR_PASSWORD`), never passed to runtime `api` containers.
3. **Runtime Application (`vforge_app`)**: `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`. Owns zero tables, holds minimal DML grants (`SELECT, INSERT, UPDATE, DELETE` on operational tables; `SELECT, INSERT` only on `audit_events` and `scope_snapshots`; `SELECT` only on `alembic_version` and `platform_metadata`), and cannot `SET ROLE` into `vforge` or `vforge_migrator`.

- The legacy `SET LOCAL ROLE vforge_app` fallback in `apps/api` has been **removed**.
- `verify_runtime_db_identity()` executes at API `lifespan` startup and fails closed if the connected role has `SUPERUSER`, `BYPASSRLS`, `CREATEROLE`, `CREATEDB`, or owns any table in `public`.

### 2.2 RabbitMQ Identity & Vhost Hardening

- **Management / Admin (`vforge_admin`)**: `administrator` tag for broker administration and future OpenBao RabbitMQ engine configuration. Never used by `api` or runtime workers.
- **Runtime Application (`vforge_app`)**: Zero management tags (`[]`), restricted exclusively to the dedicated `/vforge` virtual host (zero access to `/`), with regex permissions scoped to `^(vforge\..*|amq\.gen-.*)$` (configure) and `^(vforge\..*|amq\.default|amq\.gen-.*)$` (write/read).
- Default `guest` and compromised single-user `vforge` accounts are disabled/retired.

### 2.3 Valkey 9.1.3 ACL Hardening

- External ACL file (`.secrets/valkey/users.acl`, mounted read-only at `/etc/valkey/users.acl`) replaces CLI `--requirepass` flags and uses SHA-256 password hashes only.
- `user default off` disables unauthenticated/default access completely.
- `vforge_admin`: full administrative ACL (never exposed to `api`).
- `vforge_health`: `resetkeys -@all +ping +client|setinfo +quit` used exclusively by the container healthcheck via `REDISCLI_AUTH` + `--user vforge_health`.
- `vforge_app`: `~vf:* resetchannels -@all +ping +select +hello +client|setinfo +quit +incr +incrby +expire +ttl` restricting runtime access strictly to `vf:*` keys and required rate-limit/readiness commands.

---

## 3. Centralized `SecretProvider` Architecture & OpenBao Readiness

`apps/api/src/vforge/secrets/provider.py` defines an extensible `SecretProvider` interface:

```text
SecretProvider
 ├── LocalDevelopmentProvider   (dev/test only; forbidden in prod/staging)
 ├── DockerSecretProvider       (/run/secrets/<key> with traversal guards)
 ├── OpenBaoProvider            (KV v2 + Database + RabbitMQ engines; workload auth)
 └── FutureExternalSecretProvider (aws-sm / gcp-sm / azure-kv / k8s-secret hook)
```

### Verified OpenBao Integration Capabilities (Official `openbao.org` Docs)

1. **Authentication & Identity**: Containers authenticate via short-lived workload identity (`AppRole`, `Kubernetes`, or `JWT/OIDC`). Static root/admin tokens (`VAULT_TOKEN` / `BAO_TOKEN`) inside application containers are explicitly forbidden and rejected by `OpenBaoProvider` and `validate_startup_configuration()`.
2. **Static Application Secrets**: OpenBao **KV v2** secrets engine (`kv_mount`, e.g., OIDC client secrets, external feed API keys, signing key references).
3. **PostgreSQL Dynamic Credentials**: OpenBao **Database Secrets Engine** (`postgresql-database-plugin`) natively supports dynamic role creation (`CREATE ROLE ... VALID UNTIL ...`), static role rotation, root credential rotation, and lease revocation.
4. **Valkey Dynamic Credentials**: OpenBao **Database Secrets Engine** (`valkey-database-plugin`) natively supports dynamic ACL roles (`creation_statements` with Valkey ACL rules), static roles, and root credential rotation (`username` customization is not supported on dynamic Valkey roles).
5. **RabbitMQ Dynamic Credentials**: OpenBao uses its standalone **RabbitMQ Secrets Engine** (`rabbitmq`, NOT the database plugin), connecting to the RabbitMQ Management HTTP API (`:15672`) with `vforge_admin` to mint short-lived vhost-scoped RabbitMQ users and revoke them automatically when leases expire.

Full OpenBao server deployment, automatic lease renewal loops, and KMS envelope encryption remain scoped to Phase 14.

---

## 4. Credential Rotation & Rollback Procedure

### Safe Rotation Sequence

1. **Back up persistent data outside the Git repository** with restricted OS permissions (`icacls /inheritance:r` on Windows):
   - PostgreSQL: `pg_dumpall --globals-only` and binary custom `pg_dump -Fc`.
   - RabbitMQ: `rabbitmqctl export_definitions`.
   - Valkey: `valkey-cli SAVE` + copy `/data/dump.rdb` and `/data/appendonlydir`.
   - Pre-rotation `.env` snapshot.
2. **Generate independent CSPRNG secrets** (`>= 32` random bytes each) without printing values to terminal output or logs.
3. **Rotate services without removing volumes (`never docker compose down -v`)**:
   - PostgreSQL via client-hashed SCRAM-SHA-256 verifiers or `\password` over `stdin`.
   - RabbitMQ via `rabbitmqctl add_user ... --pre-hashed-password` on dedicated vhost; retire old user only after runtime validation succeeds.
   - Valkey via hashed `.secrets/valkey/users.acl` and container recreate (`up -d --force-recreate valkey`).
4. **Recreate `api`**, verify `/ready`, runtime DB identity (`vforge_app`), RLS isolation, RabbitMQ publish/consume, and Valkey ACL enforcement.

### Rollback Procedure for Partial Failures

- **PostgreSQL failure**: Restore pre-rotation `.env` from the ACL-protected backup; if role ownership or passwords need reverting, connect via local container `psql -U postgres`/`vforge` or restore `pg_vforge.dump` (`pg_restore`) without touching Docker volumes.
- **RabbitMQ failure**: Run `rabbitmqctl import_definitions` with the backed-up `rabbitmq_definitions.json` (which restores prior users/vhosts/permissions cleanly on the existing `rabbitmq_data` volume) and restore pre-rotation `.env`.
- **Valkey failure**: Restore pre-rotation `.env` and revert `docker-compose.yml` Valkey command/healthcheck, then `docker compose up -d --force-recreate valkey` (preserving `valkey_data` AOF/RDB files).
