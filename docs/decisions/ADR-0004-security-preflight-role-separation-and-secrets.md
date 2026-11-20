# ADR-0004: Pre-Phase 3 Role Separation, `SecretProvider` Abstraction, Broker/Cache ACLs & Supply-Chain Registry

- **Status:** Accepted
- **Date:** 2026-11-12
- **Phase:** Security Preflight (Pre-Phase 3)
- **Related ADRs:** [`ADR-0001-platform-boundaries.md`](ADR-0001-platform-boundaries.md), [`ADR-0002-phase1-identity-rls-rbac.md`](ADR-0002-phase1-identity-rls-rbac.md)

## Context

Phase 1 originally ran `SET LOCAL ROLE vforge_app` on connections initialized with database owner credentials (`vforge`) and kept migration/runtime configuration closely coupled (`DATABASE_URL` fallback). Furthermore, Valkey relied on `--requirepass` in CLI flags using a shared `default` user, RabbitMQ used a shared `vforge` user on `/` without fixed Mnesia node identity, and no extensible `SecretProvider` existed for future OpenBao integration.

## Decisions

1. **Three-Way PostgreSQL Role Separation & Removal of `SET LOCAL ROLE`:**
   - Separate bootstrap superuser (`vforge`), non-superuser schema owner (`vforge_migrator`), and least-privilege runtime role (`vforge_app`, owning zero tables).
   - Remove `SET LOCAL ROLE vforge_app` escalation patterns from `apps/api`; run Alembic strictly inside a dedicated `--profile ops` `migrator` service (`MIGRATION_DATABASE_URL` / `POSTGRES_MIGRATOR_PASSWORD`) and fail closed at API startup (`verify_runtime_db_identity()`) if a privileged role connects.
2. **RabbitMQ Node Persistence & Least-Privilege Vhost Identity:**
   - Pin `hostname: rabbitmq` and `RABBITMQ_NODENAME: rabbit@rabbitmq` so Mnesia preserves users, virtual hosts, and permissions across container recreations.
   - Separate `vforge_admin` (`administrator`) from tagless runtime user `vforge_app` scoped exclusively to vhost `/vforge` with regex resource restrictions, and remove `guest` / legacy `vforge`.
3. **Valkey 9.1.3 External SHA-256 ACL File:**
   - Replace `--requirepass` with read-only mounted `.secrets/valkey/users.acl`, disable `user default off`, dedicate `vforge_health` to Docker healthchecks, and restrict `vforge_app` to `~vf:*` and minimal required commands (`+ping +select +hello +client|setinfo +quit +incr +incrby +expire +ttl`).
4. **Centralized `SecretProvider` & Production `.env` Prohibition:**
   - Introduce `SecretProvider` (`LocalDevelopmentProvider`, `DockerSecretProvider`, `OpenBaoProvider`, `FutureExternalSecretProvider`), URL-escaping connection builders, startup validation rejecting `.env`/`local_dev`/`VAULT_TOKEN` in production/staging, and 10-channel `lifecycle/image-lock/phase2-images.json` + Renovate tracking.

## Consequences

- Runtime `api` and future Phase 3 workers cannot escalate to `vforge_migrator` or bypass RLS, and leaked credentials affect only the single isolated component.
- Future OpenBao integration (Phase 14) plugs cleanly into `OpenBaoProvider` using documented KV v2, `postgresql-database-plugin`, `valkey-database-plugin`, and standalone `rabbitmq` engines without rewriting application services.
