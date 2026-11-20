# ADR-0002: Phase 1 Identity, Row-Level Security, RBAC, and Local IdP Strategy

- **Status:** Accepted
- **Date:** 2026-11-12
- **Phase:** Phase 1 — Domain Model, Authentication, RBAC and Multi-Tenant Isolation
- **Related ADRs:** [ADR-0001-platform-boundaries.md](ADR-0001-platform-boundaries.md)

## Context

Phase 1 introduces multi-tenant organizations, users, memberships, projects, environments, target assets, authorization governance, authentication profile secret references, versioned scan profiles, and immutable security audit logs. Several security-critical design decisions are required to reconcile the architecture specification (`docs/DEVELOPMENT_ROADMAP.md`) with the authoritative delivery roadmap (`docs/IMPLEMENTATION_PLAN.md`) and Phase 1 controls:

1. **Identity anchoring & browser session model:** Email addresses can be reassigned or duplicated across IdPs and must not be trusted alone as a global user identifier. Browser sessions must never store OIDC access or refresh tokens in `localStorage`.
2. **Database-level tenant isolation:** Application-layer `WHERE organization_id = ...` filters alone are insufficient against developer bugs or connection-pool state bleed.
3. **Role taxonomy reconciliation:** Architecture v1.2 §10.3 illustrated 5 roles (`owner`, `admin`, `analyst`, `developer`, `viewer`), whereas the Phase 1 enterprise RBAC model requires 7 distinct roles including `security_lead`, `security_analyst`, and `auditor`.
4. **Local development OIDC IdP boundaries:** Local OIDC testing requires an actual OIDC provider without exposing internal control-plane backing stores (`postgres`, `rabbitmq`, `valkey`, `opa`) or altering production authentication standards.

## Decisions

### 1. External Identity Key `(oidc_issuer, oidc_subject)` & Cookie + CSRF Session Architecture

- `app_users` uses `UNIQUE (oidc_issuer, oidc_subject)` as the canonical external identity anchor.
- OIDC authentication uses Authorization Code Flow with mandatory PKCE (`S256`), validated `state`, `nonce`, signature, `iss`, `aud`, `exp`, `nbf`, algorithm allowlist (`RS256`, `ES256`, `EdDSA`; explicitly rejecting `none` and symmetric `HS*` algorithms), and JWKS key rotation refresh on unknown `kid`.
- The backend exchanges the authorization code and validates the ID Token server-side, creating an opaque SHA-256 hashed session record (`auth_sessions`) with a separate CSRF token.
- Browser clients authenticate via first-party HTTP-only `SameSite=Lax` cookie (`vf_session`) and send `X-CSRF-Token` from the readable `vf_csrf` cookie on state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`). The Next.js frontend proxies `/api/v1/*` to `INTERNAL_API_BASE_URL` so session cookies remain strictly same-origin.
- No tokens or secrets are stored in `localStorage` or `sessionStorage`.

### 2. PostgreSQL Row-Level Security (RLS) & Role Separation

- Migration `0002_phase1_domain_rls` provisions a dedicated non-superuser, `NOBYPASSRLS` application role (`vforge_app`), distinct from the migration/table owner role (`vforge`).
- Every HTTP request transaction in `apps/api` executes `SET LOCAL ROLE vforge_app` and sets transaction-scoped GUCs via parameterized `SELECT set_config(..., true)` (`app.current_org_id`, `app.current_user_id`, `app.auth_issuer`, `app.auth_subject`).
- SQLAlchemy uses `pool_reset_on_return="rollback"` so pooled connections always clear transaction-local `SET LOCAL ROLE` and `set_config(..., true)` context before reuse.
- `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` are enabled across `organizations`, `app_users`, `memberships`, `projects`, `environments`, `assets`, `authorizations`, `auth_profiles`, `scan_profiles`, and `audit_events`.
- Composite foreign keys (`(organization_id, project_id)`, `(organization_id, environment_id)`, `(organization_id, asset_id)`) enforce tenant consistency in the database schema itself, preventing cross-tenant child linkage even before RLS policies run.
- `audit_events` is protected by both `REVOKE UPDATE, DELETE ON audit_events FROM vforge_app` and an append-only PostgreSQL trigger (`trg_audit_events_append_only`) across all roles.

### 3. Seven-Role RBAC Matrix (Reconciling Architecture v1.2 §10.3)

The authoritative Phase 1 role set is **7 roles** enforced identically across PostgreSQL `CHECK` constraints, Python RBAC (`vforge.auth.rbac`), and OPA Rego policies (`policies/rego/vforge/authz.rego`):

- `owner`: full organization control including owner role assignment and org deletion/archival.
- `admin`: organization, project, environment, asset, non-owner member, and audit administration.
- `security_lead`: authorization approval/rejection/revocation, scan-profile and asset governance, and audit read access.
- `security_analyst`: project/asset/auth-profile read, authorization request & revocation, scan-profile management, and audit read access (cannot self-approve authorizations).
- `developer`: project/environment/asset/scan-profile read and assessment request (`authorization:request`), project creation/updates, cannot approve authorizations or manage org memberships.
- `auditor`: organization/project/asset/authorization/scan-profile and audit-log read-only access.
- `viewer`: restricted read-only access to organization, projects, environments, and assets (no auth-profile refs, no scan profiles, no audit logs).

### 4. Separation of Duties & Credential Reference Boundary

- Authorization approvals enforce `requested_by != approved_by` in both the service layer (`403 Forbidden`) and database `CHECK (approved_by IS NULL OR approved_by <> requested_by)`.
- Registering an asset does not authorize testing; an explicit `approved` Authorization within `[valid_from, expires_at)` is required.
- `auth_profiles` stores only secret-manager URI references (e.g., `vault://...`, `secrets://...`) and strictly rejects plaintext passwords, bearer tokens, private keys, or inline credentials.

### 5. Local Development Identity Provider (`--profile dev-oidc`)

- Keycloak `26.4.0` pinned by immutable digest (`quay.io/keycloak/keycloak:26.4.0@sha256:5f3fb534cde6bf006d79f5912473e5d2c828c707cdfc52e16972803aca9d43dd`) is provided as an opt-in Docker Compose profile (`--profile dev-oidc`).
- **Network boundary:** Keycloak attaches only to `edge` (loopback `127.0.0.1:8080` for browser OIDC redirects) and `idp` (shared exclusively with `api` for server-side discovery/JWKS/token requests via `OIDC_INTERNAL_BASE_URL=http://keycloak:8080/realms/vforge`). Keycloak is never attached to `control` and cannot reach PostgreSQL, RabbitMQ, Valkey, or OPA.
- **Credential & lifecycle boundary:** Realm fixture `infrastructure/keycloak/realm-vforge.json` is strictly for local developer evaluation (`start-dev --import-realm`, PKCE `S256` enforced, direct password grants disabled). Production deployments must disable `dev-oidc` and point `OIDC_ISSUER` to a hardened enterprise IdP over TLS.

## Consequences

- Cross-tenant enumeration or mutation is blocked simultaneously at three independent layers: API tenancy dependencies, SQLAlchemy/PostgreSQL RLS with non-owner `vforge_app`, and composite tenant foreign keys.
- Upgrading from Phase 0 uses additive migration `0002_phase1_domain_rls` without altering `0001_phase0_foundation`.
- Phase 2 (OPA scope enforcement, DNS/SSRF/redirect protections) builds directly on `assets`, `authorizations`, and `authz.rego` established here.
