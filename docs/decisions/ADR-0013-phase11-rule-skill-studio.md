# ADR-0013: Phase 11 Rule & Skill Studio — Native Validators, Fixture Regression Harness, Segregation of Duties, Ed25519 Signing, and Quarantine Rollback

**Status:** Accepted  
**Date:** 2026-11-13  
**Deciders:** VForge Principal Architect & Security Engineering Team  
**Scope:** Phase 11 — Rule & Skill Studio (`rule_packs`, `rule_pack_versions`, `rules`, `rule_fixture_runs`, `assessment_skills`, `skill_versions`, `studio_audit_events`), Native Engine Validators, Fixture Corpus Harness, SoD & OPA Policy Guards, Ed25519 Signed Promotion, Canary/Stable Channels, and Instant Quarantine Rollback

---

## Context

Enterprise application security teams need to author organization-specific detection rules across VForge's supported scanners (`opengrep`, `nuclei`, `checkov`, `gitleaks`, `zap`, `nmap`) and bounded AI assessment playbooks (`AssessmentSkill`), optionally accelerated with AI-assisted drafting stubs. Allowing custom rules or AI playbooks into production scans without strict guardrails creates severe risks:

1. **Engine Code Execution & YAML/Regex DoS:** Raw custom Checkov Python checks, Nmap Lua scripts, Nuclei templates, or ZAP automation plans can embed shell directives, YAML alias amplification, ReDoS regexes, or active exploitation primitives.
2. **Untested / Noisy Rules ("Alert Fatigue"):** Rules promoted without mandatory positive, negative, and near-miss fixture regression can flood teams with false positives or silently miss true vulnerabilities.
3. **Self-Approval & AI Privilege Escalation:** If an author or AI agent can self-approve, cryptographically sign, promote to `stable`, or reference privileged actions (`modify_opa`, `bypass_scope`, `sign_pack`), tenant governance and segregation of duties (SoD) collapse.
4. **Post-Signing Tampering & Scan Replay Drift:** If a signed `RulePackVersion` or its child `StudioRule` rows can be mutated after Ed25519 signing, or if quarantined/superseded versions can be re-promoted or resolved at scan time, scan provenance cannot be trusted.

---

## Decision

### 1. Tenant-Isolated Schema, Constraints, and Post-Sign Immutability (`0012_phase11_rule_skill_studio.py`)
- Added seven tenant-scoped tables owned by `vforge_migrator` with `ENABLE` + `FORCE ROW LEVEL SECURITY` (`app.current_org_id` using `NULLIF(current_setting('app.current_org_id', true), '')::uuid`) and composite tenant foreign keys: `rule_packs`, `rule_pack_versions`, `rules`, `rule_fixture_runs`, `assessment_skills`, `skill_versions`, and `studio_audit_events`.
- Enforced single active channel pointers per pack/skill via partial unique indexes (`uq_rpv_active_canary`, `uq_rpv_active_stable`, `uq_sv_active_canary`, `uq_sv_active_stable`).
- Enforced database-level SoD and integrity `CHECK` constraints (`ck_rpv_signer_not_author`, `ck_rpv_regression_zero_errors`, `ck_rpv_channel_active_consistency`, `ck_sv_signer_not_author`, `ck_sv_channel_active_consistency`) alongside PostgreSQL triggers blocking mutations/deletes on `rule_fixture_runs`, `studio_audit_events`, and signed `rule_pack_versions`, `skill_versions`, and child `rules` (`SQLSTATE 55000`).

### 2. Fail-Closed Native Engine Validators & Bounded Fixture Harness (`apps/api/src/vforge/studio/`)
- **Native Validators (`validators.py`):**
  - `_NoAliasSafeLoader` blocks YAML anchors/aliases and enforces max nesting depth (`32`) across YAML-based engines (`opengrep`, `nuclei`, `checkov`, `zap`), plus recursive forbidden execution key blocking and bounded regex safety (`_compile_safe_regex`).
  - Validates all items across OpenGrep `rules[]`, Nuclei protocol step lists (blocking `headless`, `javascript`, `file`, `websocket`, `workflows`, `self-contained`, `code` blocks), allowlisted ZAP `jobs[]`, and Gitleaks `rules[]`/allowlists.
  - Checkov `python` enforces strict AST allowlisting (`checkov`/`typing` imports, no dunder attributes, no `getattr`/`globals`/dynamic builtins, no executable top-level statements, required `*Check` class), while `harness.py` refuses synthetic inline pass on Checkov Python checks (requiring offline runner execution).
  - Nmap `lua` strips Lua comments before validating every `categories` declaration (`safe`/`version`/`discovery`/`default` only) and blocks dynamic obfuscation primitives (`os[`, `io[`, `ffi`, `require`, `load*`, `_g`, `stdnse.exec`, `nmap.new_socket`).
- **Mandatory Fixture Corpus & Known Limitations:** Every rule must declare non-empty `positive`, `negative`, and `near_miss` fixtures, CWE reference, `rationale`, `known_limitations`, and pass 0-FP / 0-FN fixture evaluation (`evaluate_pack_version_fixtures`).
- **Bounded Skills:** `AssessmentSkill` / `SkillVersion` validate `playbook_steps` structure, block wildcard or privileged capabilities (`FORBIDDEN_SKILL_CAPABILITIES`), and inject mandatory `forbidden_actions` guardrails.

### 3. Segregation of Duties, Ed25519 Manifest Signing, Scan Gate & Rollback
- **State Machine & SoD (`service.py`, `authz.rego`, `api/routers/studio.py`):**
  - AI authoring (`Phase12StubRuleAuthorGateway`) sanitizes untrusted code snippets, persists `creation_method = 'ai_assisted'` and `author_actor_type = 'ai_agent'`, and produces `draft` candidates only.
  - Peer review strictly requires transition through `PENDING_REVIEW` (`submit-review` -> `review`), enforces `reviewer_id != author_id` and `signer_id != author_id` across service, OPA `authz.rego`, and PostgreSQL constraints, and rejects AI actors and header spoofing (`_resolve_actor_type` rejects `"system"` or unknown headers with `ForbiddenError` and binds server-side AI user identity).
  - Mutating Studio endpoints enforce `enforce_sensitive_rate_limit`.
- **Cryptographic Signing & Live Scan Gate:**
  - `sign_rule_pack_version` and `sign_skill_version` build deterministic canonical manifest payloads (`vforge.rulepack.v1`, `vforge.skill.v1`) and sign via Ed25519 `SnapshotSigner`.
  - `_verify_pack_signature` / `_verify_skill_signature` recompute every child rule's SHA-256 and live manifest payload before matching the Ed25519 signature; scan dispatch (`resolve_and_verify_rule_packs_for_scan` via `orchestration/service.py`) fails closed on inactive packs, unpromoted/rolled-back/quarantined versions, regression errors, or signature tampering.
  - Promoting a new `canary` or `stable` version cleanly demotes any superseded active channel version to `rolled_back`. Instant rollback (`rollback_rule_pack`, `rollback_skill`) supports immediate `quarantine=True` (permanently blocking re-promotion) and restores only compatible prior versions on the target channel after verifying their Ed25519 signature.

---

## Consequences

### Positive
- Custom rules and bounded AI skills undergo uniform static safety validation, near-miss false-positive testing, independent human peer review, and immutable Ed25519 verification before scan execution.
- Compromised or noisy rules can be instantaneously quarantined and rolled back without database corruption or scan replay loss.

### Negative / Trade-offs
- Checkov Python checks require offline runner execution rather than inline API fixture simulation.
- Post-signing immutability triggers require authors to publish a new SemVer candidate version rather than editing a signed pack in place.
