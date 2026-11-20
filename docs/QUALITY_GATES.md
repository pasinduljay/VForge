# VForge Phase Quality Gates

No phase may be committed or marked complete until **every applicable gate** passes cleanly after the final edit.

## 1. Architecture & Code Quality Gates
- Implementation matches [`docs/DEVELOPMENT_ROADMAP.md`](docs/DEVELOPMENT_ROADMAP.md) and [`DEVELOPMENT_ROADMAP.md`](DEVELOPMENT_ROADMAP.md); any deviation or new subsystem design is recorded in `docs/decisions/ADR-XXXX-*.md`.
- Python (`apps/api`, `packages/*`, `services/*`, `runner/*`): `ruff check`, `ruff format --check`, and strict `mypy` pass with zero errors.
- Frontend (`apps/web`): `npm run typecheck`, `npm run lint`, and `npm run build` pass with zero errors.
- Database changes use additive reversible Alembic migrations under `vforge_migrator`; existing persistent rows are preserved.

## 2. Security Review Gates
- Tenant isolation (`FORCE ROW LEVEL SECURITY` + `vforge_app` + composite FKs + cross-tenant tests) verified on all new tenant tables.
- RBAC + OPA policy tests (`opa test /policies -v`) cover positive and default-deny negative paths.
- Input validation (`extra="forbid"`), SSRF/scope enforcement, CSRF/session protections, secret-redaction checks, and non-root/no-socket container checks verified.
- Full `git diff` scanned to ensure zero secrets, `.env` values, or private keys exist anywhere in tracked/untracked candidate files.

## 3. Functional & Regression Verification Gates
- Unit tests, negative failure-mode tests, integration tests against live Postgres/RabbitMQ/Valkey/OPA, and prior-phase smoke scripts pass after final code changes.
- `/api/v1/meta` honestly reports current phase capabilities and keeps unimplemented planes (`scanners_enabled`, `runner_connected`, etc.) truthfully marked until implemented.

## 4. Continuity & Documentation Gates
- Updated `docs/IMPLEMENTATION_STATUS.md`, `docs/TRACEABILITY_MATRIX.md`, `docs/RISK_REGISTER.md`, and `docs/IMPLEMENTATION_STATUS.md`.
- Phase changes committed on the phase feature branch cleanly before branching `feature/phase-(N+1)-...`.
