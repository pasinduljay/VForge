# VForge Implementation Plan (Phase 0 Discovery Pass)

> **Baseline:** `docs/DEVELOPMENT_ROADMAP.md` & `docs/DEVELOPMENT_ROADMAP.md`  
> **Discovery Date:** 2026-11-12  
> **Active Phase:** Phase 0 — Repository and Local Foundation

---

## 1. Architecture Verification Findings (Contradictions & Prerequisites)

During the Phase 0 discovery pass against official upstream documentation and the local environment, the following contradictions, upstream updates, and prerequisites were identified and resolved:

| ID | Finding | Source / Evidence | Resolution |
|---|---|---|---|
| DISC-01 | **Phase numbering mismatch** | Architecture v1.2 Section 17 defines 11 phases (`Phase 0..10`), while the Master Build Prompt Section 3 defines 16 phases (`Phase 0..15`). | Adopt Master Build Prompt `Phase 0..15` as the authoritative engineering sequence and map each phase back to Architecture v1.2 Section 17 below. Recorded in `ADR-0001`. |
| DISC-02 | **Unimplemented Compose services in Phase 0** | Architecture Section 8.2 includes `orchestrator`, `dispatcher`, `workflow-worker`, `report-worker`, and `update-controller`, which depend on modules from Phases 3, 8, and 10. | Phase 0 Compose deploys only the core control plane (`frontend`, `api`, `postgres`, `rabbitmq`, `valkey`, `opa`). Unimplemented workers are omitted rather than stubbed with fake success states. |
| DISC-03 | **Deprecated `mem_limit` & `pids_limit` conflict in Compose v5** | Architecture Section 8.2 uses legacy `mem_limit` and `pids_limit`. Compose v5 rejects distinct `pids_limit` alongside `deploy.resources.limits`. | Use `deploy.resources.limits.memory` and `deploy.resources.limits.pids` per Compose v5 specification. |
| DISC-04 | **PostgreSQL 18 volume path** | PostgreSQL 18 official image changed `PGDATA` to `/var/lib/postgresql/18/docker` and `VOLUME` to `/var/lib/postgresql`. | Blueprint Section 8.2 already mounts `/var/lib/postgresql`; keep this exact mount path and pin `postgres:18` by digest. |
| DISC-05 | **OPA v1 syntax & scratch container** | Current OPA is `v1.22.3`, which defaults to `rego.v1` syntax and ships as a minimal scratch/distroless image without `sh`, `wget`, or `curl`. | All `.rego` files use `import rego.v1`. Because the OPA image has no shell/HTTP client for an in-container `HEALTHCHECK`, `api` `/ready` checks `http://opa:8181/health` over the internal `control` network and the Phase 0 smoke script verifies OPA directly. |
| DISC-06 | **Next.js `read_only: true` runtime cache** | Next.js `output: "standalone"` writes runtime cache under `/app/.next/cache`, which fails if only `/tmp` is mounted as `tmpfs`. | Mount `tmpfs` on both `/tmp` and `/app/.next/cache` (owned by UID/GID `1001`) in `docker-compose.yml`. |
| DISC-07 | **Valkey CLI password warning** | `valkey-cli -a $VALKEY_PASSWORD` exposes the password in process `argv` and emits a stderr warning. Valkey 9.1.3 `valkey-cli` reads `REDISCLI_AUTH`, not `VALKEY_CLI_AUTH`. | Pass `REDISCLI_AUTH` in the healthcheck subshell (`REDISCLI_AUTH="$VALKEY_PASSWORD" valkey-cli ping`). |
| DISC-08 | **Developer host environment gaps** | Windows 11 host has Docker 29.8.2, Compose v5.5.1, Git 2.55, and Node 24.21 (`npm.ps1` blocked by PS execution policy; `npm.cmd` works), but no host Python; WSL2 Ubuntu has Python 3.14.4 without `pip` or `node`. Workspace is not yet a Git repository. | Initialize local Git repo cleanly (no global config edits), run Python/API tests inside the `api` container (or WSL2 `.venv`), and run Node checks via `npm.cmd` or container build. |

---

## 2. Reconciled Milestone Roadmap (Phase 0–15)

| Master Prompt Phase | Architecture v1.2 Mapping | Deliverables | Dependencies | Primary Acceptance Gate |
|---|---|---|---|---|
| **Phase 0** — Repository & local foundation | Phase 0 — Architecture foundation | Monorepo skeleton, docs, ADRs, threat model, risk register, `docs/`, Compose control plane (`frontend`, `api`, `postgres`, `rabbitmq`, `valkey`, `opa`), Alembic baseline migration, health/readiness endpoints, smoke tests | None | `docker compose config` passes; all services healthy; Alembic migration applies; `/health` & `/ready` pass; loopback-only ports; zero Docker socket mounts; secrets not in Git |
| **Phase 1** — Domain model & user access | Phase 1 — Core product (part 1) | `organizations`, `app_users`, `memberships`, `projects`, `environments`, `assets`, `authorizations`, `scan_profiles`, `audit_events`; OIDC-ready auth + RBAC; tenant isolation / RLS | Phase 0 | Tenant A cannot read/mutate Tenant B records; RBAC denies unauthorized actions; unauthenticated requests rejected |
| **Phase 2** — Scope & policy enforcement | Phase 1 — Core product (part 2) | OPA integration with typed schemas, exact domain/IP/CIDR/port scope validation, expiry & approval checks, redirect/DNS/SSRF/metadata protections | Phase 1 | Out-of-scope targets, expired authorizations, disallowed ports, unauthorized roles, and unsafe redirects denied server-side |
| **Phase 3** — Queue, orchestrator & state machine | Phase 2 — Orchestration & runner (part 1) | RabbitMQ integration, `outbox_events` dispatcher, `scan_runs` / `scan_stages` / `runner_jobs` / `scan_target_leases`, idempotency, heartbeats, abandoned-job reconciliation | Phase 2 | Dummy job survives API restart and duplicate delivery without double-execution |
| **Phase 4** — Runner Agent & ephemeral executor | Phase 2 — Orchestration & runner (part 2) | Dedicated Linux Runner Agent, mTLS registration/claim/upload, signed job manifests, ephemeral container hardening (`cap_drop: ALL`, `read_only`, seccomp, limits), scoped egress gateway | Phase 3 | Dummy container runs, returns SHA-256 verified artifact, and cleans up; runner revocation works; API has no Docker socket |
| **Phase 5** — First scanner vertical slice | Phase 3 — Static & supply chain (part 1) | `ScannerAdapter` SDK, OpenGrep & Gitleaks manifests/adapters, pinned digests, read-only source snapshot, SARIF/JSON normalization, secret redaction | Phase 4 | Same commit rescanned reproducibly; vulnerable/clean fixtures pass; secrets redacted |
| **Phase 6** — Supply-chain & IaC scanners | Phase 3 — Static & supply chain (part 2) | Syft SBOM, Grype SCA on immutable SBOM with DB snapshot metadata, Checkov IaC with signed custom-policy support | Phase 5 | Findings trace to PURL/version and exact Grype DB snapshot; IaC evidence includes source location |
| **Phase 7** — Web/API DAST | Phase 4 — Web/API DAST | ZAP Automation Framework + OpenAPI import (passive first), auth profiles (secret refs), Nuclei pinned template snapshots, target leases & safety health monitor | Phase 6 | Local lab scan completes; scope escape tests fail safely; target abort & failure reporting work |
| **Phase 8** — Findings, correlation & reports | Phase 5 — Finding lifecycle & reporting | Canonical `findings`, `finding_occurrences`, conservative fingerprinting, triage/retest workflow, `report-worker` (HTML, PDF, JSON, SARIF) with coverage & limitations | Phase 7 | Multiple scanner observations correlate without deleting raw evidence; role-gated report exports validate |
| **Phase 9** — Threat-intelligence connectors | Architecture Section 24 | Provenance-aware connectors (NVD 2.0, CVE v5, KEV, EPSS, OSV, GHSA, CWE, NIST CSF; gated Shodan/Pulsedive/VT; local SearchSploit) | Phase 8 | Snapshot replay works; provider outage surfaces stale warning; no default source/binary upload |
| **Phase 10** — Tool & intelligence update management | Phase 7 — Tool & Intelligence Lifecycle | `update-controller`, Renovate integration, digest lock updates, feed/template snapshots, canary/promotion/rollback workflow | Phase 9 | Simulated update detected, tested, approved, promoted, and rolled back; historical scans retain original versions |
| **Phase 11** — Rule & Skill Studio | Phase 6 — Rule & Skill Studio | Rule-pack & skill schemas/registries, positive/negative/near-miss fixture harness, signing, candidate/stable channels | Phase 8, Phase 12 (or stubbed) | AI cannot self-approve/self-sign; unreviewed packs blocked; regression failures block promotion |
| **Phase 12** — AI provider gateway & workflows | Architecture Section 25 | Provider adapters (`managed_zdr`, `managed_retained`, OpenAI, OpenAI-compatible, local), model catalog, data classification/retention gates (`enterprise-30d-v1` 30-day rule), RAG, prompt-injection tests | Phase 8 | Provider fallback works; tenant context isolated; policy engine gates all proposed tool actions |
| **Phase 13** — Learning lab & safe validation | Architecture Section 27 | Isolated lab network with pinned OWASP Juice Shop, crAPI, WebGoat; resettable state; guided tracks; VForge self-scan | Phase 7, Phase 8 | Lab targets not public; egress denied by default; reset restores clean state |
| **Phase 14** — Security hardening & release candidate | Phase 10 — Enterprise hardening | Envelope encryption (AES-256-GCM), key rotation, mTLS cert rotation, backup/restore DR, fuzzing, SSRF/authz/tenant suites, observability (`compose.observability.yaml`), Section 32 release audit | Phases 0–13 | All Section 32 release gates pass with evidence; zero unresolved critical/high platform findings |
| **Phase 15** — Optional AI-assisted red teaming | Phase 9 — Optional AI red teaming | Isolated Strix/PentAGI sandbox, tool/network allowlists, human session approval, hypothesis vs confirmed separation | Phase 14 | AI agent cannot alter scope/policy, reach unapproved nets, or persist past cleanup |

---

## 3. Phase 0 Acceptance Criteria & Tests

1. `docker compose config --quiet` succeeds with zero errors.
2. All exposed host ports in `docker-compose.yml` bind exclusively to `127.0.0.1`; `postgres`, `rabbitmq`, `valkey`, and `opa` expose no host ports.
3. No service in `docker-compose.yml` mounts `/var/run/docker.sock` or enables `privileged: true`.
4. `postgres`, `rabbitmq`, `valkey`, `api`, `frontend`, and `opa` start cleanly; healthchecks pass.
5. `alembic upgrade head` applies cleanly against PostgreSQL 18 and `alembic current` reports `head`.
6. `GET http://127.0.0.1:8000/health` returns `200 OK`; `GET http://127.0.0.1:8000/ready` returns `200 OK` verifying PostgreSQL, RabbitMQ, Valkey, and OPA.
7. `GET http://127.0.0.1:3000/api/health` and `GET http://127.0.0.1:3000/` return `200 OK` without fake scanner status.
8. `opa test /policies` passes all Rego v1 baseline tests (default deny verified).
9. Python unit/negative tests (`pytest`), Ruff lint/format, Mypy typecheck, and Next.js lint/typecheck/build pass.
10. `.env` and secrets are excluded by `.gitignore` and absent from Git history.

---

## 4. Phase 1 Acceptance Criteria & Tests

1. Alembic migration `0002_phase1_domain_rls` upgrades cleanly from `0001_phase0_foundation` and from a fresh empty PostgreSQL 18 database, supports `alembic downgrade 0001_phase0_foundation`, and provisions non-owner `NOBYPASSRLS` role `vforge_app`.
2. PostgreSQL `ENABLE` + `FORCE ROW LEVEL SECURITY` enforces tenant isolation under connection pooling (`pool_reset_on_return="rollback"`) and composite foreign keys prevent cross-tenant parent linkages.
3. All 10 domain entities (`organizations`, `app_users`, `memberships`, `projects`, `environments`, `assets`, `authorizations`, `auth_profiles`, `scan_profiles`, `audit_events`) enforce separation of duties, secret-manager-reference-only auth profiles, asset normalization, and append-only audit logs.
4. OIDC Authorization Code Flow with PKCE (`S256`), JWT signature/claim/algorithm validation, JWKS rotation, HTTP-only cookie sessions, and CSRF protection pass negative and E2E tests.
5. All 7 RBAC roles (`owner`, `admin`, `security_lead`, `security_analyst`, `developer`, `auditor`, `viewer`) match across PostgreSQL constraints, Python RBAC, and OPA `authz.rego` (`8/8` OPA tests).
6. Next.js frontend routes (`/`, `/login`, `/organizations`, `/organizations/[orgId]`, `members`, `projects`, `projects/[projectId]`, `assets`, `authorizations`, `scan-profiles`, `audit`) pass `tsc`, `eslint`, and `next build`, proxy `/api/v1/*` cleanly, and store zero tokens in `localStorage`.
7. Opt-in local dev Keycloak (`--profile dev-oidc`) isolates `keycloak` on `edge` + `idp` without access to `control` backing services.

---

## 5. Phase 2 Acceptance Criteria & Tests

1. Reusable scope-validation package `packages/scope-validator` (`vforge_scope`) canonicalizes targets across all supported types (FQDN/IDNA, wildcard domain-and-subdomains, exact URL, URL path prefix, IPv4, IPv6, CIDR ranges, network services/ports, REST APIs, source repositories, container image references, and infrastructure paths) and rejects malformed/ambiguous/lookalike inputs.
2. DNS, SSRF, and redirect guards resolve A/AAAA records, detect mixed allowed/disallowed answers, reject cloud metadata/link-local/unapproved loopback/unapproved private IPs, allow explicitly authorized private networks, detect DNS rebinding drift against snapshot bindings, and revalidate redirect chains while blocking HTTPS->HTTP downgrades.
3. Explicit authorization capabilities, separation of duties (`approved_by <> requested_by`), validity window (`valid_from..expires_at`), revocation, and automatic re-approval on scope/capability edits are enforced server-side.
4. OPA Rego v1 scope engine (`policies/rego/vforge/scope.rego`) fails closed and returns `ALLOW`, `DENY`, or `REQUIRES_APPROVAL` with structured reasons across tenant/project/environment/asset ownership, RBAC, expiry, ports, capabilities, intensity, production safeguards, and snapshot freshness.
5. Immutable Ed25519-signed `scope_snapshots` record target assets, pinned DNS bindings, allowed IPs/ports, capabilities, `policy_version`, `asset.version`, timestamp, and SHA-256 hash; DB triggers/permissions block `UPDATE`/`DELETE`; keyring lifecycle supports `active`, `verify_only`, and `revoked` key rotation.
6. Next.js Scope Management & Authorization UI (`/organizations/[orgId]/scope` and `/authorizations`) supports asset viewing, authorization creation/editing, explicit capability/port/domain/IP scope editing, second-person approval, revocation, expired filtering, and structured policy rejection diagnostics without exposing raw scanner CLI arguments.
7. Execution boundary preserved: zero scanner adapters integrated, zero Runner Agent containers introduced, and `/api/v1/meta` honestly reports `phase: 2`, `scanners_enabled: false`, `runner_connected: false`, `docker_socket_mounted: false`. Network-level isolation remains pending Phase 4 Runner Agent and egress gateway enforcement.
