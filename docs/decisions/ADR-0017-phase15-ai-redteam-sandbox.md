# ADR-0017: Phase 15 Optional Isolated AI Red-Team Sandbox (Strix / PentAGI), Per-Session Human Approval, Hypothesis Review & Benchmark Harness

- **Status:** Accepted
- **Date:** 2026-11-14
- **Phase:** 15 (Optional Isolated AI-Assisted Advanced Assessment & Final Release Readiness)
- **Author:** VForge Autonomous Architecture & Security Engineering

---

## 1. Context & Problem Statement

Section 21 (`Phase 15 — Optional AI-Assisted Advanced Assessment`) and Section 32 (`Release Acceptance Criteria`) of `docs/DEVELOPMENT_ROADMAP.md` define the final capability of the platform: an **opt-in, strictly isolated AI Red-Team Sandbox** for evaluating advanced agentic security frameworks (`Strix` / `PentAGI`) against isolated Learning Lab targets without endangering the Control Plane, tenant data, or external networks.

Key architectural risks that must be prevented by design:
1. **Unbounded Tool or Network Execution:** Autonomous red-team agents must never execute arbitrary shell commands (`shell:exec`), access the Docker socket (`docker.sock`), modify scope/OPA policies (`scope:modify`, `opa:modify`), sign/promote rules (`rule:sign`, `rule:promote`), or reach external internet/control-plane endpoints.
2. **Self-Approval or Unsupervised Launch:** No AI agent or single operator may self-approve an assessment session. Every session requires explicit per-session human approval by a different reviewer (`approved_by <> requested_by`) with an expiration window (`approval_expires_at`).
3. **Hallucinated / Unverified Findings Polluting Confirmed Reports:** AI red-team observations must never be auto-confirmed or silently merged into confirmed vulnerability findings. Every AI-generated observation must be recorded as `hypothesis` and can transition to `confirmed` or `rejected` only through an independent human reviewer (`reviewed_by <> recorded_by`) with a substantive review note.
4. **Unbounded Resource Consumption or Lingering Sandbox State:** Every session must enforce hard wall-clock duration (`max_duration_seconds`), tool-call (`max_tool_calls`), and token (`max_tokens`) budgets, and cannot transition to `completed` or `terminated` without explicit ephemeral cleanup attestation (`cleanup_attested = true`).
5. **Objective Evaluation Against Established Scanners:** Operators need an immutable benchmark harness comparing AI red-team detection recall against OWASP ZAP and ProjectDiscovery Nuclei on known Learning Lab ground-truth challenges (`ai_redteam_benchmarks`).

---

## 2. Decision

### 2.1 Opt-In Isolated Sandbox Compose (`infrastructure/redteam/compose.redteam.yaml`)
- Declared under the opt-in `redteam` Docker Compose profile (`profiles: ["redteam"]`) so normal platform startup never launches an AI red-team container.
- Attached **exclusively** to the external `vforge-lab_lab_internal` network (`internal: true`), with zero internet egress, zero control-plane network connectivity, zero published ports, zero volume mounts (`tmpfs` only on `/tmp` and `/home/agent`), `read_only: true`, non-root `user: "10001:10001"`, `cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true"]`, `restart: "no"`, CPU/memory/PIDs limits, no secret environment variables, and a mandatory `@sha256` digest-pinned image reference (`${REDTEAM_AGENT_IMAGE:?...}`).
- Continuously verified at runtime before session creation and session start via `verify_redteam_compose_isolation()` and `verify_lab_compose_isolation()`.

### 2.2 Per-Session Human Approval, Freeze Triggers & Budget Enforcement (`0016_phase15_ai_redteam`)
- Created four RLS-enforced (`ENABLE` + `FORCE ROW LEVEL SECURITY`) tables in migration `0016_phase15_ai_redteam`:
  - `ai_redteam_sessions`: Enforces `ck_rts_approver_not_requester` (`approved_by IS NULL OR approved_by <> requested_by`), `ck_rts_approval_required`, and `guard_phase15_session_update()` trigger that freezes `engine`, `tool_allowlist`, `target_urls`, `max_duration_seconds`, `max_tool_calls`, `max_tokens`, and `requested_by` after creation, enforces monotonic usage counters within budget, and blocks updates after terminal states (`completed`, `terminated`, `expired`, `rejected`).
  - `ai_redteam_observations`: Enforces `ck_rto_confirmed_requires_independent_review` (`classification <> 'confirmed' OR (reviewed_by IS NOT NULL AND reviewed_by <> recorded_by AND char_length(review_note) >= 12)`) and `guard_phase15_observation_update()` trigger that freezes `title`, `category`, `severity`, `evidence_summary`, `evidence_sha256`, `source`, and `recorded_by` and permits only a single `hypothesis -> confirmed/rejected` transition.
  - `ai_redteam_events`: Append-only audit log guarded by `prevent_phase15_immutable_mutation()` (and no `UPDATE`/`DELETE` grants for `vforge_app`), recording every allowed and denied session/tool/observation/benchmark action.
  - `ai_redteam_benchmarks`: Append-only benchmark record comparing AI red-team recall, unique true positives, and out-of-ground-truth claims against OWASP ZAP and ProjectDiscovery Nuclei.

### 2.3 Defense-in-Depth Policy Enforcement (Python + OPA `authz.rego` + PostgreSQL)
- Fixed safe tool catalog (`ALLOWED_TOOL_CATALOG`: `http_probe`, `browser_navigate`, `dom_inspect`, `template_lookup`, `note_hypothesis`) and explicit permanent `FORBIDDEN_TOOLS` (`shell_exec`, `shell:exec`, `docker`, `raw_docker_socket`, `scope:modify`, `opa:modify`, `rule:sign`, `rule:promote`, `finding:auto_confirm`, `network:expand_scope`, etc.).
- Every session target URL is validated via `validate_session_targets()` (delegating to Phase 13 `validate_lab_target_url()`), and every targeted tool call is checked against the session's frozen `target_urls` via `assert_url_within_session_targets()`.
- OPA `policies/rego/vforge/authz.rego` enforces `redteam:read`, `redteam:request`, `redteam:approve`, `redteam:execute`, and `redteam:review` permissions alongside `redteam_policy_forbidden` rules blocking non-human approvals/reviews, self-approval/self-review (SoD), forbidden tools, external network requests, and auto-confirmation.

---

## 3. Alternatives Considered

1. **Allowing AI Red-Team Agents on the Runner Execution Network:** Rejected. Even the scoped Runner network can reach approved staging/production scan targets during active DAST runs. Confining Phase 15 strictly to `vforge-lab_lab_internal` guarantees that experimental autonomous agents can only ever interact with disposable Learning Lab containers.
2. **Auto-Promoting High-Confidence AI Observations to Canonical Findings:** Rejected. Autonomous agents are prone to hallucination and over-claiming. Requiring observations to start as `hypothesis` in `ai_redteam_observations` and requiring an independent human reviewer (`reviewed_by <> recorded_by`) to confirm or reject them preserves the integrity of canonical findings and executive reports.

---

## 4. Consequences

- **Positive:** Fulfils all Phase 15 and §32 requirements with defense-in-depth across Docker Compose network isolation, OPA policy rules, Python service validation, and PostgreSQL `FORCE ROW LEVEL SECURITY` + immutability/SoD triggers.
- **Trade-offs:** Every AI red-team session requires two distinct human operators (one to request/execute, another with `redteam:approve` / `redteam:review` to approve the session and confirm hypotheses), which intentionally prioritizes safety and auditability over unattended automation.
