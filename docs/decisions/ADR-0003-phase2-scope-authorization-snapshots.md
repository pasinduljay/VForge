# ADR-0003: Phase 2 Centralized Scope Enforcement, OPA Policy Engine, and Signed Scope Snapshots

- **Status:** Accepted
- **Date:** 2026-11-12
- **Phase:** Phase 2 — Scope Enforcement and Authorization Engine

## Context

VForge must guarantee that no target address, hostname, IP range, repository, container image, or infrastructure artifact can be tested solely because a user supplied or edited a locator string. Phase 1 established tenant identity, OIDC PKCE sessions, 7-role RBAC, separation of duties for authorization approval, and PostgreSQL Row-Level Security (`vforge_app`). Phase 2 adds mandatory target-scope canonicalization, network/DNS/redirect SSRF defenses, fail-closed Open Policy Agent (OPA) evaluation, and cryptographically signed immutable scope snapshots prior to introducing any Phase 3 orchestration or Phase 4 execution components.

## Decisions

1. **Reusable Zero-Database Validation Package (`packages/scope-validator`):**
   - Implement `vforge-scope` (`vforge_scope`) as an independent Python package installed by the control-plane API (`apps/api`) and designed to be embedded directly into future Phase 4 Runner Agents and Egress Gateways.
   - Canonicalize FQDNs (IDNA Punycode, lowercase, trailing DNS dots stripped, control-char rejection), URLs (scheme allowlist `http`/`https`, embedded credential rejection, POSIX path normalization preventing dot-segment traversal bypasses), IPv4/IPv6 (including IPv4-mapped IPv6 unwrapping), CIDRs, network ports, REST APIs, source repositories, container image references, and infrastructure paths.
   - Enforce label-boundary matching (`example.com` vs `notexample.com`, exact domain vs explicit `domain_and_subdomains` opt-in, exact URL vs canonical `url_path_prefix`).

2. **DNS, Redirect, and Network Destination Security:**
   - Resolve A and AAAA records via an injectable `DnsResolver` interface (`SystemDnsResolver` in runtime, `StaticDnsResolver` in deterministic security tests) and inspect **every** returned IP address.
   - Unconditionally block cloud metadata ranges (`169.254.169.254`, `169.254.0.0/16`, `fd00:ec2::254`, `fe80::/10`), multicast/unspecified/reserved ranges, loopback (`127.0.0.0/8`, `::1`, `localhost`) unless explicitly permitted for isolated testing, and RFC1918/ULA private ranges unless `allow_private_networks=True` is explicitly registered and approved on the authorization.
   - Reject mixed allowed/disallowed DNS answer sets (`dns_mixed_response`), detect DNS changes against pinned snapshot bindings (`dns_rebinding_detected`), and re-validate every HTTP redirect destination before following.

3. **Default-Deny OPA Policy Engine (`vforge.scope` + `vforge.authz`):**
   - Expand `policies/rego/vforge/authz.rego` with Phase 2 permissions (`scope:evaluate`, `snapshot:read`, `snapshot:create`, `snapshot:verify`).
   - Add `policies/rego/vforge/scope.rego` returning `{outcome, allowed, requires_approval, reasons, policy_version}` with outcomes strictly in `{"ALLOW", "DENY", "REQUIRES_APPROVAL"}`.
   - `vforge.security.opa_client.OpaScopeClient` fails closed with `DENY` if OPA is unreachable, returns non-200 HTTP, times out, or emits invalid JSON.
   - Permanently forbid destructive/DoS capabilities (`dos_testing`, `denial_of_service`, `destructive_testing`, `unrestricted_exploitation`, etc.) and production `approved_exploit_validation` / `high` intensity.

4. **Immutable Ed25519-Signed Scope Snapshots & Key Rotation:**
   - Upon second-person approval (`POST /api/v1/organizations/{org_id}/authorizations/{id}/approve`) or explicit snapshot issuance, freeze target scope, asset version (`assets.version`), authorization window, resolved/pinned DNS IPs, permitted capabilities, permitted intensity, and `policy_version` into `scope_snapshots`.
   - Protect `scope_snapshots` in PostgreSQL (`0003_phase2_scope_snapshots.py`) with `FORCE ROW LEVEL SECURITY`, `REVOKE UPDATE, DELETE ... FROM vforge_app`, and `BEFORE UPDATE OR DELETE` trigger `trg_scope_snapshots_immutable`.
   - Sign canonical SHA-256 payload digests using Ed25519 via `vforge.security.signing.SnapshotSigner`, keeping private keys outside PostgreSQL, Git, and ordinary `.env` (mounted key files required outside `development`/`test`). Support zero-downtime key rotation via keyring statuses (`active`, `verify_only`, `revoked`).
   - Modifying an asset increments `assets.version`; modifying an approved authorization (`PATCH /authorizations/{id}`) resets its status to `pending` and clears approval fields; stale `policy_version` or `asset_version` fails snapshot verification and triggers `DENY`.

## Consequences & Boundaries

- **No Scanner Execution Yet:** Phase 2 intentionally contains zero scanner integrations and zero Runner Agents (`/api/v1/meta` continues reporting `scanners_enabled: false`, `runner_connected: false`, `docker_socket_mounted: false`).
- **Deferred Control Boundary:** Application-layer DNS/IP/redirect validation in Phase 2 is strong defense-in-depth, **not** network isolation. Network-level enforcement (`nftables`/egress proxy/re-resolved socket IP pinning at connect time) will be enforced in Phase 4 inside the isolated Linux Runner Agent and scope-aware egress gateway before any Phase 5–7 scanner executes against external or internal targets.
