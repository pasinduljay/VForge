# ADR-0008: Phase 6 Supply Chain SBOM, Air-Gapped SCA & Declarative IaC Execution

- **Status:** Accepted
- **Date:** 2026-11-12
- **Phase:** 6 — Supply Chain & IaC (`Syft` SBOM, `Grype` Offline SCA, `Checkov` IaC)

## Context

Phase 6 introduces software supply-chain visibility and infrastructure-as-code security analysis inside the isolated Execution Plane:

1. **Deterministic SBOM Generation:** Produce both CycloneDX JSON and SPDX JSON from canonicalized immutable source snapshots (`SourceSnapshot`).
2. **Air-Gapped SCA:** Scan dependencies strictly from the persisted CycloneDX SBOM against a pre-hydrated offline vulnerability database volume (`vforge_grype_db`), recording cryptographic DB snapshot provenance (`schema_version`, `built_at`, archive SHA-256) on every finding without allowing runtime internet downloads inside scanner containers.
3. **IaC & Custom Policy Analysis:** Execute static IaC analysis (Terraform, Dockerfile, Kubernetes, cloud manifests) offline with declarative YAML custom rules (`runner/images/checkov/policies/`) — never executing arbitrary Python policy modules mounted from user repos.

## Decision

1. **Image Pinning & Grype Engine Upgrade (`v0.93.0` -> `v0.121.3`):**
   Live verification revealed that `anchore/grype:v0.93.0` fails hydrating live v6 vulnerability DB schemas (`UNIQUE constraint failed: operating_systems...`). We pinned **`anchore/grype:v0.121.3@sha256:13113eeceab017260370cf540e1d25442c59665fd07d1b09b66d63bb0c282887`** paired with **`anchore/syft:v1.57.1@sha256:03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060`** and **`bridgecrew/checkov:3.2.435@sha256:ccead19bd9201d43872ceb7e78bb5868eabfc0d3960d3756fc75f4896067372a`** in `lifecycle/image-lock/phase6-images.json`.
2. **Artifact Storage Reuse vs New Blob Table:**
   To preserve `ck_artifacts_type` and reuse existing AES-256-GCM envelope encryption, `sbom_documents` metadata rows store references (`artifact_id`, `bom_sha256`, bounded `components_summary`) while raw CycloneDX and SPDX JSON bytes remain encrypted in `artifacts` with `artifact_type='raw_output'` and MIME-disambiguated `content_type` (`application/vnd.cyclonedx+json`, `application/spdx+json`).
3. **Automatic Upstream SBOM Stage Ordering:**
   When a scan profile schedules `sca` without an explicit `sbom` stage, `build_declarative_scan_plan()` prepends an upstream `sbom` (`syft`) stage automatically so `grype` always receives an immutable CycloneDX document over the runner mTLS `/api/v1/runner/jobs/{job_id}/sbom-input` endpoint and links every SCA finding to `sbom_document_id` and `vulnerability_db_snapshot_id`.
4. **Hardened Container Execution Adjustments:**
   - Scanner containers receive `--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777` so UID `10001:10001` tools can maintain ephemeral non-executable `/tmp` caches on read-only root filesystems.
   - `extra_ro_mounts` validates read-only `/work/*:ro` bindings exclusively for `vforge_grype_db:/work/db:ro` and validated declarative YAML policies (`/work/policies:ro`), explicitly forbidding `docker.sock`, path traversal, or non-`/work/` targets.

## Consequences

- `GRYPE_DB_AUTO_UPDATE=false`, `GRYPE_CHECK_FOR_APP_UPDATE=false`, `SYFT_CHECK_FOR_APP_UPDATE=false`, and `--skip-download` are enforced alongside `--network=none`; missing `vforge_grype_db` causes fail-closed `runner_execution_error` rather than attempting online DB fallback.
- Cross-tenant isolation is preserved via PostgreSQL `ENABLE` + `FORCE ROW LEVEL SECURITY`, composite tenant foreign keys, `vforge_app` non-bypass privileges, and append-only immutability on `sbom_documents`.
