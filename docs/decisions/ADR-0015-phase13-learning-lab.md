# ADR-0015: Phase 13 — Isolated Learning Lab & Self-Scan Verification

- **Status:** Accepted
- **Date:** 2026-11-13
- **Deciders:** VForge Architecture & Security Engineering
- **Supersedes / Extends:** [ADR-0001](ADR-0001-platform-boundaries.md), [ADR-0002](ADR-0002-phase1-identity-rls-rbac.md), [ADR-0012](ADR-0012-phase10-release-update-lifecycle.md), [ADR-0013](ADR-0013-phase11-rule-skill-studio.md)

## Context

VForge requires a safe, repeatable learning laboratory covering beginner-to-expert security skills alongside self-assessment capabilities against VForge control-plane artifacts, without exposing production/internet hosts, linking vulnerable targets into control-plane networks or databases, or storing user progress without explicit organization consent.

## Decision

1. **Separate Opt-In Egress-Denied Lab Compose Topology (`infrastructure/lab/compose.lab.yaml`):**
   - Isolate vulnerable applications (`bkimminich/juice-shop:v17.1.1`, `webgoat/webgoat:v2023.8`, `crapi/crapi-web:develop`, `crapi/crapi-identity:develop`, disposable `postgres:18`) under an independent Compose project (`vforge-lab`) using `--profile lab`.
   - Attach all lab containers strictly to `lab_internal` (`driver: bridge`, `internal: true`), bind host ports strictly to `127.0.0.1` (`3100..3102`), drop capabilities (`cap_drop: [ALL]`, only minimal PostgreSQL init caps on disposable `crapi-db`), enforce `no-new-privileges:true`, store container state in disposable `tmpfs`, forbid `/var/run/docker.sock` and `privileged: true`, and pin immutable `@sha256:` digests (`lifecycle/image-lock/phase13-images.json`).

2. **Schema, Tenant RLS & Append-Only Auditability (`0014_phase13_learning_lab.py`):**
   - Seed 4 guided tracks (`beginner`, `intermediate`, `advanced`, `expert_practice`) in `lab_challenges`.
   - Add 5 tenant-scoped tables (`lab_workspaces`, `lab_challenge_progress`, `lab_validation_runs`, `lab_self_scans`, `lab_audit_events`) owned by `vforge_migrator` with `ENABLE` + `FORCE ROW LEVEL SECURITY` (`app.current_org_id`), composite `(organization_id, workspace_id)` foreign keys, DB safety `CHECK` constraints (`egress_denied IS TRUE`, `public_exposure_blocked IS TRUE`, `consent_granted IS TRUE`, `safety_boundary_verified IS TRUE`), and append-only immutability triggers (`REVOKE UPDATE, DELETE` from `vforge_app`) on `lab_validation_runs`, `lab_self_scans`, and `lab_audit_events`.

3. **Fail-Closed Exploitation Boundaries, Consent Gates & Honest Self-Scans (`vforge/lab/`, `authz.rego`):**
   - Restrict lab validation targets strictly to loopback lab ports (`3100`, `3101`, `3102`, `8090`) or `.lab.vforge.local` service names; block external IPs, IMDS/cloud metadata, control-plane services/ports, userinfo, and query-string credentials (`validate_lab_target_url`).
   - Enforce positive allowlisting of safe `LabValidationAction` modes in both Python (`safety.py`) and OPA (`authz.rego` `lab_practice_action_allowed` + `lab_forbidden_boundary`), failing closed if OPA is unreachable or returns malformed responses, and enforcing OPA across `lab:manage` and `lab:practice` operations.
   - Require epoch-scoped disposable identities (`@disposable.lab.vforge.local`), pre-storage secret/PII redaction (`classify_and_redact_payload`), non-empty real observation evidence (`>= 12 chars`), consent-gated `LabChallengeProgress` persistence (revoking consent resets & suppresses progress rows cleanly), and workspace epoch resets.
   - Perform honest `run_vforge_self_scan` checks across mounted Compose manifests (`docker-compose.yml`, `compose.lab.yaml`, `docker-compose.runner.yml`), `policies/rego/vforge/authz.rego`, and raw JSON lockfiles without failing open on missing artifacts or crashing with 422 on unpinned lock entries.

4. **Control-Plane API & UI (`/api/v1/organizations/{org_id}/lab/*`, `/organizations/[orgId]/lab`):**
   - Expose 7-role RBAC endpoints (`lab:read`, `lab:practice`, `lab:manage`), update `/api/v1/meta` (`phase: 13`, `learning_lab_enabled: true`), and deliver a Next.js Learning Lab workspace displaying Compose isolation verification, disposable identities, guided tracks, remediation/retest loop, and self-scan history.

## Consequences

- Operators run `docker compose -f infrastructure/lab/compose.lab.yaml --profile lab up -d` only when intentionally practicing; default control-plane Compose startups never launch vulnerable containers.
- Control-plane DB connections and networks remain completely isolated from lab applications, and all Phase 13 tenant tables uphold existing PostgreSQL RLS and immutability invariants.
