# ADR-0014: Phase 12 — AI Provider Governance & Controlled Multi-Agent Workflows

**Status:** Accepted  
**Date:** 2026-11-13  
**Phase:** Phase 12 (`feature/phase-12-ai-governance`)

---

## Context

VForge Phase 12 introduces a governed, provider-agnostic runtime AI Gateway supporting multiple hosted and local models (including `managed-fast-v1`, `managed-reasoning-v2`, `enterprise-30d-v1`, `gpt-5-codex`, OpenAI-compatible endpoints, and `ollama/qwen3-coder`), replacing the Phase 11 stub `RuleAuthor` gateway (`GovernedRuleAuthorGateway`) and adding tenant-isolated curated RAG memory, multi-agent roles, OPA tool proposal brokering, human approval workflows, de-identified feedback labeling, and offline model evaluation tracking.

Without strict technical enforcement, AI integrations introduce acute risks:
1. Secret/PII leakage to external model APIs and third-party logs.
2. Violation of vendor data-retention policies (specifically 30-day server-side retention on hosted models such as `enterprise-30d-v1` when confidential/restricted security telemetry is transmitted without explicit org-admin consent and operator acknowledgment).
3. Prompt-injection payloads in untrusted source snippets or retrieved RAG documents tricking agents into calling privileged actions (`opa:modify`, `scope:modify`, `rule:promote_stable`, `tenant:export`, `system:exec`, `runner:exec`).
4. Cross-tenant secret reference theft (`POSTGRES_APP_PASSWORD`, cross-org env/path prefixes) or SSRF against cloud IMDS (`169.254.169.254`, `[::ffff:169.254.169.254]`) or internal control-plane services (`opa`, `postgres`, `rabbitmq`, `valkey`).
5. Cost runaway / concurrent monthly budget races and silent cross-tenant AI learning leakage.

---

## Decision

1. **Additive Tenant Schema, RLS & Immutable Audit Controls (`0013_phase12_ai_governance.py`):**
   - Seed `ai_model_catalog` with active platform models and explicit `retention_days` / `requires_retention_consent` metadata (marking `enterprise-30d-v1` with 30-day retention and `requires_retention_consent=true`).
   - Add 9 tenant-scoped tables owned by `vforge_migrator` with `ENABLE` + `FORCE ROW LEVEL SECURITY` (`NULLIF(current_setting('app.current_org_id', true), '')::uuid`), composite tenant FKs (`ondelete="RESTRICT"` on provider configs), and database `CHECK` constraints blocking raw API keys (`ck_apc_secret_ref_not_raw_key` requiring `VF_AI_%` or `ai/orgs/%`):
     - `ai_provider_configs`, `ai_task_requests`, `ai_runs`, `ai_tool_proposals`, `knowledge_documents`, `knowledge_chunks`, `ai_feedback_labels` (`ck_afl_no_cross_tenant` forcing `cross_tenant_sharing_enabled = false`), `model_evaluation_runs`, and `ai_audit_events`.
   - Protect `ai_audit_events`, `ai_task_requests`, and `ai_runs` against in-place mutation (`prevent_phase12_audit_mutation` trigger on `ai_audit_events` + `REVOKE UPDATE, DELETE` from `vforge_app`).

2. **Pre-Egress Classification, Redaction & Prompt-Injection Quarantine (`ai_gateway/classification.py`):**
   - Classify payloads deterministically (`public`, `internal`, `confidential`, `restricted`) with monotonic caller escalation only.
   - Redact tokens/credentials (`sk-*`, `AIza*`, `ghp_*`, `github_pat_*`, `hf_*`, `npm_*`, `whsec_*`, `eyJ*` JWTs, `PGP` private keys, `Bearer`/`Basic` auth headers, URL query/URI credentials, password/secret assignments), PII (`EMAIL`, `SSN`), and host indicators (`PRIVATE_IP`) prior to persistence and egress.
   - Detect prompt-injection patterns and quarantine untrusted inputs and retrieved RAG chunks inside entity-escaped (`html.escape`) `<untrusted_data>` and `<untrusted_rag_context>` boundaries, fixing summary slicing (`rule_author.py`) so wrapper closing tags cannot be truncated.

3. **Provider Registry, Tenant-Namespaced Secrets & SSRF Protection (`ai_gateway/providers.py`):**
   - Enforce tenant-namespaced `secret_ref` prefixes (`VF_AI_<ORG_HEX>_*` or `ai/orgs/<org_id>/*`) and block raw secret prefixes and platform credential names.
   - Pin hosted official vendor hosts (`api.managed-zdr.example.com`, `api.managed-retained.example.com`, `api.openai.com`), reject URL credentials/fragments, reject cloud metadata (`169.254.169.254`, `fd00:ec2::/32`, IPv4-mapped IPv6 bypasses), internal Docker hostnames, loopback/RFC1918 addresses (unless `local_inference`), validate DNS resolution targets, and disable HTTP redirects (`follow_redirects=False`).
   - Run offline deterministic responses safely unless an explicit endpoint is configured (`ai_execution_mode: offline_deterministic_unless_endpoint_configured` surfaced honestly on `/api/v1/meta`).

4. **Retention Consent Gates, Budget Locking & Fail-Closed OPA Tool Broker (`ai_gateway/service.py`, `authz.rego`):**
   - Gate external model egress of confidential/restricted payloads or 30-day retained models on BOTH persistent admin consent (`retention_consent_approved`) AND per-request operator acknowledgment (`consent_acknowledged`), plus org-wide `local_only_mode` overrides.
   - Serialize budget accounting via `SELECT ... FOR UPDATE` on `AiProviderConfig` rows using worst-case `max_tokens` output pricing, enforce `require_independent_model` against `prior_model_slug`, and isolate primary policy blocks from failover bypasses.
   - Broker all proposed agent tools fail-closed through OPA (`authz.rego`), denying normalized (`lower(trim_space(...))`) forbidden privileged actions and enforcing Separation of Duties (`decided_by != task_req.requested_by`) in both Python and OPA (`ai:manage` rule).
   - Persist `TASK_BLOCKED` audit events and task records in an independent session transaction inside `/api/v1/organizations/{org_id}/ai/tasks/execute` even when HTTP 403/422 rolls back the primary request transaction.

5. **Tenant-Isolated Curated RAG & Control Console (`rag.py`, `api/routers/ai_gateway.py`, `ai-governance/page.tsx`):**
   - Enforce `curated://` and `https://` URI schemes, approved source types (`owasp_asvs`, `cwe_catalog`, `internal_runbook`, `remediation_guide`, `approved_framework`), pre-storage redaction, and `ConflictError` on duplicate slugs.
   - Expose Next.js `/organizations/[orgId]/ai-governance` workspace with provider allowlist/consent management, governed task runner, RAG knowledge ingestion/search, SoD-gated tool proposal approval, de-identified feedback, and benchmark evaluation recording.

---

## Consequences

- **Security:** Confidential and restricted vulnerability data cannot leave the tenant boundary without dual consent and mandatory secret/PII redaction; external providers cannot be abused for SSRF or secret exfiltration; multi-agent tool proposals remain strictly bounded by OPA deny-by-default rules and human SoD approval.
- **Honesty:** When hosted external endpoints/keys are absent in air-gapped or local dev environments, VForge operates deterministically offline and reports `ai_execution_mode: "offline_deterministic_unless_endpoint_configured"` on `/api/v1/meta`.
- **Compatibility:** Phase 11 `RuleStudio` transparently delegates drafting through `GovernedRuleAuthorGateway`, inheriting pre-egress redaction and injection quarantine with zero breaking API changes.

---

## Verification

- `0013_phase12_ai_governance` verified downgrade/upgrade reversibility via `--profile ops` `migrator`.
- `opa test /policies -v`: **32/32 PASS**.
- `apps/api`: `ruff check` clean, `ruff format --check` (`125 files`), `mypy src` (`0 issues in 93 source files`), `pytest` full suite **95 passed, 2 skipped** (including `tests/test_phase12_ai_governance.py`).
- `apps/web`: `tsc --noEmit`, `eslint`, and `next build` clean (including `/organizations/[orgId]/ai-governance`).
- `tests/smoke/phase12_smoke.ps1`: All 7 gates PASS (exit `0`).
