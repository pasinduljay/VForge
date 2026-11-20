# ADR-0001: Control/Execution Boundaries and Phase 0 Technical Baseline

- **Status:** Accepted
- **Date:** 2026-11-12
- **Deciders:** VForge Architecture & Platform Engineering
- **Supersedes:** None

## Context

`docs/DEVELOPMENT_ROADMAP.md` and `docs/DEVELOPMENT_ROADMAP.md` define a multi-plane enterprise security assessment platform. During the Phase 0 discovery pass, we verified the architecture against current official documentation (PostgreSQL 18, RabbitMQ 4, Valkey 9, OPA v1.22.3, FastAPI/SQLAlchemy 2.1/Alembic/Psycopg 3, Next.js 16, Docker Compose v5) and inspected the local development environment.

We identified several items requiring explicit architectural decisions before writing Phase 0 code:
1. Reconciling the 11-phase roadmap in Architecture §17 (`Phase 0..10`) with the 16-phase delivery sequence in Master Prompt §3 (`Phase 0..15`).
2. Scoping the Phase 0 Docker Compose stack cleanly without creating fake/stub worker services.
3. Enforcing strict trust boundaries between the Control Plane and future Execution Plane.
4. Resolving upstream Docker/runtime changes discovered in official documentation.

## Decisions

### 1. Authoritative Phased Sequence
We adopt the **16-phase sequence (`Phase 0..15`)** from `docs/DEVELOPMENT_ROADMAP.md` §3 as the authoritative implementation roadmap, mapped to Architecture v1.2 §17 milestones in `docs/IMPLEMENTATION_PLAN.md`. Each phase is delivered as an independently testable vertical slice gated by explicit acceptance tests.

### 2. Strict Control/Execution Separation & Zero Docker Socket Access
- The Control Plane (`frontend`, `api`, `postgres`, `rabbitmq`, `valkey`, `opa`) **must never** mount `/var/run/docker.sock` or run with `privileged: true`.
- Scanner execution belongs exclusively to the Phase 4+ dedicated Linux Runner Agent in an isolated execution boundary.
- In Phase 0, no scanner images or execution endpoints exist; `/api/v1/meta` explicitly reports `scanners_enabled: false`.

### 3. Minimal Honest Phase 0 Compose Stack
- `docker-compose.yml` in Phase 0 includes only `frontend`, `api`, `postgres`, `rabbitmq`, `valkey`, and `opa`.
- Future-phase workers (`orchestrator`, `dispatcher`, `workflow-worker`, `report-worker`, `update-controller`) are omitted from Phase 0 `docker-compose.yml` rather than shipping fake stub processes that report healthy without doing real work.
- All Compose services use modern `deploy.resources.limits.memory` instead of deprecated `mem_limit`.
- Only `frontend` (`127.0.0.1:3000:3000`) and `api` (`127.0.0.1:8000:8000`) expose ports, strictly bound to loopback. `postgres`, `rabbitmq`, `valkey`, and `opa` reside on the `internal: true` `control` network with zero published host ports.

### 4. Upstream Documentation Alignments
- **PostgreSQL 18:** Persist `postgres_data:/var/lib/postgresql` (required by Postgres 18's versioned `PGDATA=/var/lib/postgresql/18/docker` layout).
- **OPA v1.22.3:** Use `import rego.v1` in all Rego files (`policies/rego/`). Because the official OPA image is scratch/distroless without `sh`, `curl`, or `wget`, OPA health is verified by `api`'s `/ready` HTTP check (`http://opa:8181/health`) and by `opa test /policies` rather than an in-container shell `healthcheck`.
- **Valkey 9:** Pass `REDISCLI_AUTH` via environment inside the healthcheck rather than `valkey-cli -a <password>` on the command line to avoid argv exposure and stderr warnings (verified against Valkey 9.1.3 `valkey-cli`).
- **Next.js 16 Standalone + `read_only: true`:** Mount `tmpfs` on `/app/.next/cache` (UID/GID `1001`) alongside `/tmp` so Next.js standalone mode operates cleanly under a read-only root filesystem as non-root user `nextjs`.
- **All Images Pinned by Digest:** Store reviewed tags and SHA-256 digests in `lifecycle/image-lock/phase0-images.json` and `.env.example`.

## Consequences

- **Positive:** Phase 0 delivers a fast, verifiable, hardened control-plane foundation with zero fake functionality, zero host socket exposure, and verified compatibility with current 2026 upstream images.
- **Trade-off:** Developers must use `docker compose` (or WSL2 `.venv` + Windows `npm.cmd`) for running tests locally because host Windows lacks Python; documented in `README.md` and `docs/IMPLEMENTATION_STATUS.md`.
- **Follow-up:** Phase 1 will add domain tables via Alembic migrations on top of the Phase 0 baseline migration (`0001_phase0_foundation`).
