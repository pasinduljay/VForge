# ADR-0007: Phase 5 Scanner Adapter SDK, Language Coverage & OpenGrep/Gitleaks Vertical Slice

- **Status:** Accepted
- **Date:** 2026-11-12
- **Phase:** Phase 5 — Scanner Adapter SDK, Polyglot Coverage Registry & SAST/Secrets Vertical Slice
- **Owners:** Platform Architecture & AppSec Engineering

---

## Context

Phase 4 established the isolated Linux Runner Agent, TLS 1.3 mTLS gateway, signed `ExecutionManifest` envelopes, ephemeral hardened containers (`--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, seccomp allowlist, non-root `uid=10001`), and AES-256-GCM envelope encryption for artifacts. However, the runner had only executed a minimal dummy container (`scanners_enabled: false`) and had no real source intake, scanner contract SDK, language coverage honesty model, or canonical finding persistence.

Per VForge Architecture §3, §9.3, and the Phase 5 acceptance gates:
- The platform must define a reusable `ScannerAdapter` contract shared across scanners and the control/execution planes without importing control-plane DB/broker dependencies into scanner packages.
- Untrusted source archives must be sanitized deterministically (`tar.gz` / `zip`) to block path traversal, symlinks/hardlinks, special device nodes, and decompression bombs before envelope encryption or runner execution.
- Language and ecosystem detection must honestly distinguish full support vs. partial/unsupported languages (`assessment_coverage_status`) rather than masking unsupported code behind a clean pass.
- OpenGrep (SAST) and Gitleaks (Secrets) must execute strictly inside hardened `--network=none` ephemeral containers pinned by immutable `@sha256:` image digests.
- Secret values detected by Gitleaks (or echoed into stdout/stderr/snippets) must never be persisted raw in PostgreSQL, logs, or API responses; findings must redact secrets before storage and deduplicate deterministically across rescans of identical commits.

---

## Decisions

1. **Shared Standalone Contract Package (`packages/scanner-contracts/`, `vforge_scanners`)**
   - Placed SDK abstractions (`ScannerAdapter`, `ScannerMetadata`, `ToolContext`, `ExecutionSpec`, `ExecutionResult`, `NormalizedFinding`), polyglot language/manifest/ecosystem detection (`languages.py`), capability registry & honest coverage evaluation (`registry.py`), canonical archive sanitizer (`archive.py`), regex+token secret redaction (`redaction.py`), and `OpenGrepAdapter` + `GitleaksAdapter` inside `packages/scanner-contracts/` so both `apps/api` (Control Plane) and `runner/` (Execution Plane) share one strictly typed contract with zero database/broker leakage.

2. **Safe Source Snapshot Intake & Envelope Encryption (`source_snapshots`, Migration `0006_phase5_scanners`)**
   - `SourceSnapshotCreate` validates uploaded `archive_tar_gz` / `archive_zip` payloads through `canonicalize_source_archive()`, rejecting `..` traversal, absolute paths, symlinks, hardlinks, device nodes, oversized member counts, and zip-bomb uncompressed expansion ratios.
   - Canonicalized tarballs are envelope-encrypted at rest using AES-256-GCM (`vforge.security.envelope` per-snapshot DEK + wrapped DEK + nonce + AAD bound to `org_id|project_id|asset_id|archive_sha256`), persisted under `ARTIFACT_ROOT`, and streamed strictly over TLS 1.3 mTLS via `GET /api/v1/runner/jobs/{job_id}/source-snapshot` ONLY while the claiming runner holds the active `RUNNING` lease.
   - `RunnerAgent` re-verifies the archive SHA-256 against `ExecutionManifest.inputs.sourceSnapshotSha256` before safe read-only extraction into `/work/in/source:ro`.

3. **Honest Polyglot Coverage Model & Deterministic Planning**
   - `evaluate_coverage()` inspects detected languages, manifests, and ecosystems against `CAPABILITY_REGISTRY` and explicitly populates `supported_languages`, `partial_languages`, `unsupported_languages`, and `assessment_coverage_status` (`complete`, `partial`, `unsupported`, `not_applicable`) on both `source_snapshots.coverage_report` and `scan_runs.coverage_status`/`coverage_summary`.
   - When non-passive or unsupported languages exist in an archive, the scan run preserves `"partial"` coverage even when selected scanners return zero findings or exit 0.
   - `planner.py` maps `"sast"` -> `opengrep` and `"secrets"` -> `gitleaks` pinned stages executing offline with `--network=none`.

4. **Hardened Pinned OpenGrep & Gitleaks Images (`lifecycle/image-lock/phase5-images.json`)**
   - Built minimal Debian-based `vforge-opengrep:1.33.1` (`runner/images/opengrep/Dockerfile`) with non-root `uid=10001`, bundled baseline rules (`/opt/opengrep/rules/vforge-baseline.yaml`), and pre-warmed `XDG_CACHE_HOME=/opt/opengrep/cache` so OpenGrep succeeds with `--read-only` root filesystem and bounded `--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m`.
   - Pinned `zricethezav/gitleaks@sha256:2bcceac45179b3a91bff11a824d0fb952585b429e54fc928728b1d4d5c3e5176` (`v8.24.0`), invoked strictly with `--redact=100 --exit-code=10` so Gitleaks exit code 10 indicates redacted leaks found (accepted by `allowed_exit_codes=(0, 10)`) rather than a crash.

5. **Canonical Findings & Append-Only Occurrences with Pre-Persistence Redaction (`0006_phase5_scanners`)**
   - Added tenant-scoped `findings` (unique by `(organization_id, project_id, scanner_tool_id, fingerprint)`) and append-only `finding_occurrences` (`REVOKE UPDATE, DELETE` + `trg_finding_occurrences_append_only`) enforced with `ENABLE` + `FORCE ROW LEVEL SECURITY` for `vforge_app`.
   - Added `SOURCE_SNAPSHOT_READ`, `SOURCE_SNAPSHOT_CREATE`, and `FINDING_READ` permissions across Python RBAC and OPA `policies/rego/vforge/authz.rego`.
   - All finding descriptions, code snippets, metadata, and captured container stdout/stderr (`execution_log`) pass through `redact_text_secrets()` (and raw secret match scrubbing) before persistence in PostgreSQL or upload to encrypted artifacts.

---

## Consequences

- Real SAST (`opengrep-sast`) and Secrets (`gitleaks-secrets`) scanning is now enabled (`phase: 5`, `scanners_enabled: true`) while DAST/SCA/IaC/Reporting remain marked honestly unavailable (`scanners` Phase 6–8).
- Control Plane containers (`frontend`, `api`, `orchestrator`, `postgres`, `rabbitmq`, `valkey`, `opa`) continue running with zero Docker socket mounts and least-privilege `vforge_app` DB identity.
- Upload canonicalization and `--redact=100` + pre-persistence scrubbing ensure rescans of an identical snapshot produce identical canonical findings with incrementing append-only occurrences and zero raw secret storage.
