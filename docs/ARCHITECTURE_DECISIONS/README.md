# VForge Architecture Decision Records (ADRs)

All Architecture Decision Records are stored canonically under [`../decisions/`](../decisions/) and indexed here.

Any change to plane boundaries, storage schemas, cryptography, authentication, orchestration semantics, runner isolation, scanner contracts, intelligence provenance, update workflows, or AI governance **must** be documented in a numbered ADR (`docs/decisions/ADR-XXXX-<slug>.md`) before or alongside implementation.

## Index

| ADR | Date | Status | Scope | Document |
|---|---|---|---|---|
| **ADR-0001** | 2026-11-12 | Accepted | Control/Execution Boundaries & Phase 0 Technical Baseline | [`ADR-0001-platform-boundaries.md`](../decisions/ADR-0001-platform-boundaries.md) |
| **ADR-0002** | 2026-11-12 | Accepted | Phase 1 Identity, PostgreSQL RLS, 7-Role RBAC & Local Dev IdP | [`ADR-0002-phase1-identity-rls-rbac.md`](../decisions/ADR-0002-phase1-identity-rls-rbac.md) |
| **ADR-0003** | 2026-11-12 | Accepted | Phase 2 Centralized Scope Validation, OPA Engine & Signed Snapshots | [`ADR-0003-phase2-scope-authorization-snapshots.md`](../decisions/ADR-0003-phase2-scope-authorization-snapshots.md) |
| **ADR-0004** | 2026-11-12 | Accepted | Pre-Phase 3 Role Separation, SecretProvider Abstraction, Broker/Cache ACLs & Update Registry | [`ADR-0004-security-preflight-role-separation-and-secrets.md`](../decisions/ADR-0004-security-preflight-role-separation-and-secrets.md) |
| **ADR-0005** | 2026-11-12 | Accepted | Phase 3 Orchestration — Trigger-Synced Wakeup Index, Transactional Outbox & Target Leases | [`ADR-0005-phase3-orchestration-outbox-leases.md`](../decisions/ADR-0005-phase3-orchestration-outbox-leases.md) |
| **ADR-0006** | 2026-11-12 | Accepted | Phase 4 Dedicated Runner Agent, mTLS Gateway, Signed Manifests & Scoped Egress Isolation | [`ADR-0006-phase4-runner-agent-mtls-isolation.md`](../decisions/ADR-0006-phase4-runner-agent-mtls-isolation.md) |
| **ADR-0007** | 2026-11-12 | Accepted | Phase 5 Scanner Adapter SDK, Language Coverage & OpenGrep/Gitleaks Vertical Slice | [`ADR-0007-phase5-scanner-adapter-sast-secrets.md`](../decisions/ADR-0007-phase5-scanner-adapter-sast-secrets.md) |
| **ADR-0008** | 2026-11-12 | Accepted | Phase 6 Supply Chain SBOM, Air-Gapped SCA & Declarative IaC Execution | [`ADR-0008-phase6-supply-chain-sbom-sca-iac.md`](../decisions/ADR-0008-phase6-supply-chain-sbom-sca-iac.md) |
| **ADR-0009** | 2026-11-12 | Accepted | Phase 7 Web/API DAST, Pinned Engines, Target Leases & Active Safety Auto-Abort | [`ADR-0009-phase7-dast-target-leases-health-abort.md`](../decisions/ADR-0009-phase7-dast-target-leases-health-abort.md) |
| **ADR-0010** | 2026-11-13 | Accepted | Phase 8 Canonical Findings Correlation, Triage/Retest Lifecycle, SLA Tracking, and Multi-Format Reporting | [`ADR-0010-phase8-findings-correlation-triage-reporting.md`](../decisions/ADR-0010-phase8-findings-correlation-triage-reporting.md) |
| **ADR-0011** | 2026-11-13 | Accepted | Phase 9 Provenance-Aware Threat Intelligence Connectors, Offline Sync & Gated Enrichment | [`ADR-0011-phase9-threat-intelligence-connectors.md`](../decisions/ADR-0011-phase9-threat-intelligence-connectors.md) |
| **ADR-0012** | 2026-11-13 | Accepted | Phase 10 Four-Stream Release & Update Lifecycle, Canary Promotion & Zero-Rebuild Rollback | [`ADR-0012-phase10-release-update-lifecycle.md`](../decisions/ADR-0012-phase10-release-update-lifecycle.md) |
| **ADR-0013** | 2026-11-13 | Accepted | Phase 11 Rule & Skill Studio — Native Validators, Fixture Harness, SoD, Ed25519 Signing & Quarantine Rollback | [`ADR-0013-phase11-rule-skill-studio.md`](../decisions/ADR-0013-phase11-rule-skill-studio.md) |
| **ADR-0014** | 2026-11-13 | Accepted | Phase 12 AI Provider Governance — Pre-Egress Redaction, Consent Gates, Failover & OPA Tool Broker | [`ADR-0014-phase12-ai-governance.md`](../decisions/ADR-0014-phase12-ai-governance.md) |
| **ADR-0015** | 2026-11-13 | Accepted | Phase 13 Isolated Learning Lab — Egress-Denied Compose, Consent-Gated Tracks & Self-Scan Verification | [`ADR-0015-phase13-learning-lab.md`](../decisions/ADR-0015-phase13-learning-lab.md) |
| **ADR-0016** | 2026-11-13 | Accepted | Phase 14 Hardening, Multi-KEK Rotation, Encrypted DR & Observability | [`ADR-0016-phase14-hardening-dr-observability.md`](../decisions/ADR-0016-phase14-hardening-dr-observability.md) |
| **ADR-0017** | 2026-11-14 | Accepted | Phase 15 Optional Isolated AI Red-Team Sandbox, Per-Session Human Approval, Hypothesis Review & Benchmark Harness | [`ADR-0017-phase15-ai-redteam-sandbox.md`](../decisions/ADR-0017-phase15-ai-redteam-sandbox.md) |
