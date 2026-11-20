# VForge Threat Model

> **Scope:** Enterprise platform architecture with detailed Phase 0 control-plane analysis  
> **Methodology:** Trust-boundary decomposition + STRIDE  
> **Baseline:** `docs/DEVELOPMENT_ROADMAP.md` §2, §7, §8, §19, §26

---

## 1. System Assets & Security Objectives

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| Platform credentials, DB/broker passwords, API/AI keys | Critical | Critical | High |
| Target scope definitions & signed authorization records | High | Critical | High |
| Scanner raw evidence, artifacts, secrets findings | Critical | Critical | Medium |
| Rule packs, skills, OPA policies, scanner image digests | Medium | Critical | High |
| Control-plane state (PostgreSQL, RabbitMQ, Valkey) | High | Critical | High |
| Target applications & isolated lab environments | Medium | Critical | High |

## 2. Trust Boundaries

| Boundary ID | Boundary | Untrusted Side | Trusted Side | Enforcement Controls |
|---|---|---|---|---|
| **TB-1** | Host / Developer Workstation ↔ `vf-edge` | Browser / localhost caller | `frontend` (`127.0.0.1:3000`), `api` (`127.0.0.1:8000`) | Loopback-only binding in dev; security headers + CSP; OIDC PKCE + HTTP-only cookie sessions + CSRF + 7-role RBAC (Ph1); no DB/broker/OPA ports exposed |
| **TB-2** | `vf-edge` ↔ `vf-control` | `frontend`, HTTP request inputs | `api` → `postgres`, `rabbitmq`, `valkey`, `opa` | `control` network marked `internal: true`; strict Pydantic (`extra="forbid"`); parameterized SQL; non-owner `vforge_app` + `FORCE ROW LEVEL SECURITY` (Ph1); non-root containers; `cap_drop: [ALL]` |
| **TB-2b** | `vf-edge` / `idp` ↔ Dev OIDC IdP (`dev-oidc`) | Local browser & Keycloak dev container | `api` (`OIDC_INTERNAL_BASE_URL`) | Keycloak attaches only to `edge` + `idp`; zero access to `control` network; PKCE `S256` mandatory; direct password grants disabled; `iss/aud/exp/nbf/nonce/alg` verified |
| **TB-3** | Control Plane ↔ Execution Plane (Phase 4+) | Runner VM / ephemeral scanner containers | Control API & PostgreSQL | Separate Linux Runner VM; outbound mTLS; signed job envelopes; **zero Docker socket in control-plane or scanners** |
| **TB-4** | Scanner Container ↔ Target / Egress (Phase 4+) | Untrusted target responses / source trees | Runner VM host & internal networks | Scope-aware egress gateway; DNS/IP revalidation; metadata/RFC1918 deny-by-default; read-only source mounts |
| **TB-5** | AI Gateway ↔ External Providers & Untrusted Content (Phase 11–12) | Target source/comments/scanner output; external LLM APIs | Policy engine, rule registry, signing keys | Untrusted data treated strictly as data; data classification & retention checks (e.g., Fable 30-day rule); AI cannot sign rules or change OPA |
| **TB-6** | Supply Chain ↔ Production Channels (Phase 10+) | Upstream registries, templates, advisories, DB feeds | Approved `image-lock` & `rule-packs` | Digest pinning (`@sha256:...`); SBOM + vuln scan; fixture regression; human promotion; rollback retention |

## 3. STRIDE Analysis (Phase 0 & Core Platform)

| ID | Threat (STRIDE) | Vector | Affected Component | Phase 0 Mitigation | Future-Phase Mitigation |
|---|---|---|---|---|---|
| TM-01 | **Elevation of Privilege** | Container escape or lateral host takeover via mounted Docker socket | `api`, `frontend`, workers | No container mounts `/var/run/docker.sock`; verified by automated smoke test `TEST-P0-NOSOCK`; `cap_drop: [ALL]`, `no-new-privileges: true`, non-root users | Dedicated Runner VM with rootless/hardened runtime (Ph4) |
| TM-02 | **Information Disclosure** | Direct host access to DB, RabbitMQ management UI, Valkey, or OPA | `postgres`, `rabbitmq`, `valkey`, `opa` | Zero host ports published; `control` network has `internal: true`; verified by `TEST-P0-PORTS` | mTLS/TLS internal encryption & network policies (Ph14) |
| TM-03 | **Information Disclosure** | Secrets leaked in Git, logs, HTTP `/ready` errors, or container argv | `apps/api`, `.env`, Valkey | `.env` and `.secrets/` gitignored; `.env.example` uses placeholders; structured logger redacts `password`, `token`, `secret`, `authorization`, `client_secret`, `REDISCLI_AUTH`, Bearer/Basic, and URL credentials (including `redis://:pw@`); Valkey uses `--aclfile` (hashed SHA-256) + `vforge_health` via `REDISCLI_AUTH` (no `--requirepass` in argv); `api` runtime excludes migration/admin credentials | Full OpenBao dynamic secrets + envelope encryption (Ph14) |
| TM-04 | **Tampering** | Runtime modification of container binaries or web assets | `api`, `frontend`, `opa` | `read_only: true` root filesystems with bounded `noexec,nosuid` `tmpfs` mounts | Image signing (Cosign) + provenance verification (Ph10, Ph14) |
| TM-05 | **Tampering / Spoofing** | Floating container image tags (`latest`) pulling unreviewed or compromised code | `docker-compose.yml` | All base & service images pinned by reviewed tag + `sha256` digest in `.env.example` & `lifecycle/image-lock/` | Automated digest updates via Renovate + staging canary (Ph10) |
| TM-06 | **Tampering / EoP** | Policy bypass or missing policy defaults allowing unauthorized operations | `opa`, `api` | Default-deny baseline `default allow := false` in `authz.rego`; Phase 2 adds default-deny `scope.rego` (`ALLOW`/`DENY`/`REQUIRES_APPROVAL`), fail-closed `OpaScopeClient`, and Ed25519-signed immutable `scope_snapshots` (`ADR-0003`) | Orchestrator pre-dispatch enforcement (Ph3) & Runner verification (Ph4) |
| TM-07 | **Denial of Service** | Unbounded memory/PID consumption by control-plane containers | `api`, `frontend`, `opa` | `pids_limit` and `deploy.resources.limits.memory` set on application/policy services | Rate limiting (Ph1), target leases & safety monitor (Ph3, Ph7) |
| TM-08 | **SSRF / Scope Escape** *(Ph2+)* | Redirects, DNS rebinding, lookalike domains, path traversal, or private/metadata IPs reaching internal services | `vforge-scope`, OPA, DAST runners | Phase 2 implements canonicalization (IDNA, trailing dot, path traversal/encoding, lookalike rejection), A/AAAA mixed-answer detection, DNS rebinding drift detection against pinned snapshots, cloud metadata blocking, explicit-only private network policy, and redirect revalidation in application control plane | Runner Agent network-level egress gateway, DNS pinning at socket connect, and isolated network namespaces (Ph4, Ph7) — **network-level isolation is NOT complete until Phase 4** |
| TM-09 | **Prompt Injection** *(Ph11–12)* | Malicious instructions in scanned repo comments/READMEs hijacking AI rule author | AI Rule Engineer, Strix | No AI runtime or scanners exist in Phase 0 | Untrusted content isolation, schema validation, OPA tool broker, human signing (Ph11–12) |

## 4. Phase 0 & Phase 1 Abuse Cases & Negative Tests

1. **Docker Socket Exposure Check:** Verify `docker compose config` contains zero references to `docker.sock` and `privileged: true`.
2. **Public/Internal Port Exposure Check:** Verify no published port binds to `0.0.0.0` or `::`, and internal services (`postgres`, `rabbitmq`, `valkey`, `opa`) have zero published ports.
3. **Readiness Failure Honesty Check:** Unit test `/ready` when a dependency probe fails -> must return HTTP `503` (never `200`) and must not include connection-string passwords in the JSON response or logs.
4. **OPA Default-Deny & RBAC Check:** `opa test /policies` verifies unauthenticated/unspecified inputs evaluate `allow == false` and all 7 roles follow the tenant permission matrix (`8/8`).
5. **Cross-Tenant RLS & Connection Pool Bleed Test (`test_rls_isolation.py`):** Non-owner `NOBYPASSRLS` PostgreSQL session reads/mutates across tenants, reuses the exact same pooled connection without context (0 rows leaked), attempts cross-tenant `INSERT` (blocked by RLS `WITH CHECK`), attempts cross-tenant parent FK (`environments.project_id`, blocked by composite FK), and attempts `UPDATE`/`DELETE` on `audit_events` (blocked by `REVOKE` + trigger).
6. **JWT / OIDC Algorithm & Claim Confusion (`test_oidc_jwt.py`):** Rejects `alg=none`, `alg=HS256`, tampered signatures, expired/immature tokens, wrong `iss`/`aud`/`nonce`, and validates JWKS `kid` rotation refresh.
7. **Authorization Separation of Duties & Credential Hygiene (`test_api_phase1_e2e.py`, `test_rbac_matrix.py`):** Requesters receive `403 Forbidden` when approving their own authorization; `auth_profiles` rejects plaintext passwords/tokens/PEM keys; CSRF rejects cookie-auth `POST`/`PATCH`/`DELETE` without `X-CSRF-Token`.
8. **Phase 2 Scope Enforcement, DNS/SSRF/Redirect & Signed Snapshot Integrity (`test_scope_validator.py`, `test_phase2_scope_authz.py`, `scope_test.rego`):** Verified lookalike domain rejection (`example.com` vs `notexample.com`), unauthorized subdomain/CIDR/port rejection, cloud metadata (`169.254.169.254`) and unapproved localhost (`127.0.0.1`) blocking, explicitly authorized private network (`10.20.30.0/24`), mixed DNS answer rejection, DNS rebinding drift rejection, unsafe redirect blocking, expired/revoked authorization denial, self-approval denial, cross-tenant `404` / RLS isolation, and Ed25519 snapshot tampering/stale-policy/asset-mutation/revoked-key rejection.
