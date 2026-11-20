# VForge Security Baseline

> **Baseline:** `docs/DEVELOPMENT_ROADMAP.md` §1.3, §7, §26 & Master Prompt §1.11  
> **Scope:** Mandatory controls for Phase 0 and target controls for Phases 1–15

## 1. Container & Runtime Hardening (Enforced in Phase 0)

- **Non-root execution:** Application services (`api`, `frontend`, `opa`) run as explicit non-root UIDs/GIDs (`10001` for `api`, `1001` for `frontend`, `1000` for `opa`).
- **Read-only root filesystems:** `api`, `frontend`, and `opa` run with `read_only: true` and bounded `noexec,nosuid` `tmpfs` mounts (`/tmp`, plus `/app/.next/cache` for Next.js).
- **Capability dropping:** `cap_drop: [ALL]` and `security_opt: [no-new-privileges:true]` on application and policy containers.
- **Resource bounds:** Explicit `deploy.resources.limits.pids` and `deploy.resources.limits.memory` on application services.
- **No Docker socket:** `/var/run/docker.sock` must never be mounted into any control-plane service (`frontend`, `api`, `postgres`, `rabbitmq`, `valkey`, `opa`, workers) or scanner container.
- **Network separation:**
  - `edge`: `frontend` and `api` only, bound exclusively to `127.0.0.1` in local dev.
  - `control`: `internal: true` bridge network for `api` ↔ `postgres`, `rabbitmq`, `valkey`, `opa`. Zero host ports published for backing services.

## 2. Secrets & Credential Hygiene

- Never commit `.env`, `.secrets/`, private keys, tokens, or passwords to Git.
- Structured application logs and exception summaries (`sanitize_exception_message`) must redact keys matching `password`, `secret`, `token`, `authorization`, `cookie`, `api_key`, `client_secret`, `rediscli_auth`, `pgpassword`, Bearer/Basic headers, and credentials embedded in URLs (including empty-username `redis://:secret@host`).
- Valkey 9.1.3 runs with an external SHA-256-hashed ACL file (`/etc/valkey/users.acl`), `user default off`, a dedicated healthcheck user (`vforge_health` via `REDISCLI_AUTH`), and a key-pattern-restricted runtime user (`vforge_app` limited to `vf:*`), eliminating `--requirepass` from container CLI arguments.
- PostgreSQL separates bootstrap superuser (`vforge`), non-superuser schema/migration owner (`vforge_migrator`), and least-privilege runtime login (`vforge_app`: `NOSUPERUSER`, `NOBYPASSRLS`, `NOCREATEROLE`, `NOINHERIT`, owns zero tables). `SET LOCAL ROLE` escalation workarounds are eliminated and `verify_runtime_db_identity()` fails closed at API startup if a privileged role is detected. Migration credentials are never passed to runtime `api` containers.
- RabbitMQ separates management administrator (`vforge_admin`) from runtime identity (`vforge_app` with zero tags and permissions restricted to vhost `vforge`).
- Centralized `SecretProvider` (`LocalDevelopmentProvider`, `DockerSecretProvider`, `OpenBaoProvider`, `FutureExternalSecretProvider`) manages secret resolution (`docs/SECRET_MANAGEMENT_AND_OPENBAO.md`). Production/staging environments reject `.env` files, `local_dev` providers, and static OpenBao root tokens.
- Phase 1+ scanner/intelligence/AI credentials will be stored strictly as secret-manager references (`auth_profiles`, `intelligence_credentials`, `ai_provider_configs`).

## 3. Cryptography & Identity Baseline (Phases 1, 4, 14)

- **Transport:** TLS 1.3 preferred (TLS 1.2 only where required); mTLS with unique short-lived certificates for Runner Agent ↔ Control Plane (Phase 4).
- **Data at rest:** AES-256-GCM envelope encryption using vetted libraries (`cryptography`) and KMS-wrapped DEKs (Phase 14). Never implement custom cryptographic primitives.
- **Authentication (Enforced in Phase 1):** OIDC Authorization Code Flow with PKCE (`S256`), asymmetric JWT signature allowlist (`RS256`, `ES256`, `EdDSA`), strict `iss`/`aud`/`exp`/`nbf`/`nonce` validation, JWKS key rotation refresh, HTTP-only `SameSite=Lax` cookie sessions (`vf_session` hashed with SHA-256), and double-submit CSRF protection (`X-CSRF-Token`). Tokens are never stored in browser `localStorage`.
- **Local Dev IdP Boundary (`--profile dev-oidc`):** Pinned Keycloak `26.4.0` joins only `edge` + `idp`, never `control`; uses `infrastructure/keycloak/realm-vforge.json` strictly for local development and never in production.
- **Supply-chain signing:** Image digest pinning (`@sha256:...`) from Phase 0; Cosign/Sigstore image signing and signed rule-pack manifests in Phases 10–11, 14.
- **Post-quantum readiness:** Design crypto-agility abstractions; track NIST FIPS 203 (ML-KEM), 204 (ML-DSA), and 205 (SLH-DSA) without inventing custom hybrid protocols.
- **Honest claims:** Do not claim FIPS compliance merely because AES-256 is configured.

## 4. Application Security Controls (Phase 1–2 Enforced; Phase 3+ Planned)

- Server-side authorization via FastAPI 7-role RBAC + OPA (`default allow := false` in `authz.rego`; `default outcome := "DENY"` in `scope.rego`) + PostgreSQL `FORCE ROW LEVEL SECURITY` using non-owner `NOBYPASSRLS` role `vforge_app` and transaction-scoped `set_config(..., true)` (enforced in Phase 1–2).
- Append-only `audit_events` and immutable `scope_snapshots` protected by PostgreSQL triggers (`trg_audit_events_append_only`, `trg_scope_snapshots_immutable`) and revoked `UPDATE`/`DELETE` grants (Phase 1–2).
- **Phase 2 Scope & Snapshot Cryptography:** Target scope canonicalization (IDNA, trailing DNS dot removal, URL authority/path-traversal guards, IPv4/IPv6/CIDR normalization, explicit-only private network & loopback gates), A/AAAA DNS safety checks, DNS rebinding detection against snapshot bindings, redirect revalidation, fail-closed OPA HTTP evaluation, and Ed25519 + SHA-256 signed `scope_snapshots` with key-rotation states (`active`, `verify_only`, `revoked`). Network-level enforcement awaits the Phase 4 Runner Agent & egress gateway.
- HTTP security headers on Next.js (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, CSP with `connect-src 'self'`).
- All timestamps stored and processed in UTC (`TIMESTAMPTZ`).
