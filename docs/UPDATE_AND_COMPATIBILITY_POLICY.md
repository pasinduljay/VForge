# VForge Update and Compatibility Policy

> **Baseline:** `docs/DEVELOPMENT_ROADMAP.md` §5, §16, §28 & Master Prompt §1.10

## 1. Four Independent Update Streams

VForge separates updates into independent, versioned streams so a content/database update never silently alters engine behavior or historical scan provenance:

1. **Scanner engine images & runtime base images:** e.g., `postgres`, `rabbitmq`, `valkey`, `opa`, `python`, `node` (Phase 0); OpenGrep, Gitleaks, Syft, Grype, Checkov, ZAP, Nuclei, Nmap, testssl.sh (Phases 5–8).
2. **Rules, templates, policies, and add-ons:** OpenGrep rules, Nuclei template snapshots, Checkov custom policies, ZAP add-ons/plans, curated Nmap NSE scripts.
3. **Vulnerability & threat-intelligence databases:** Grype DB, NVD, CVE v5, CISA KEV, FIRST EPSS, OSV, GHSA, CWE, SearchSploit.
4. **VForge adapters, schemas, and AI prompts/skills:** Adapter contracts, normalizers, API schemas, signed VForge rule packs and assessment skills.

## 2. Digest Pinning & Version Locks

- All container images in `docker-compose.yml`, Dockerfiles, and future runner manifests **must** be pinned by reviewed version tag and immutable `sha256` digest (`tag@sha256:...`).
- `lifecycle/image-lock/phase2-images.json` (validated against `lifecycle/image-lock/schema.json`) records `toolName`, `toolVersion`, `updateChannel`, `repository`, `tag`, `digest`, `reference`, `architecture`, `sourceRepository`, `releaseSource`, `signatureProvenance`, `sbomReference`, `approvalState`, and `lastVerifiedAt` for all active images across the 10 platform update channels (`phase0-images.json` and `phase1-images.json` are preserved as historical phase records).
- Floating `:latest` tags are prohibited in Compose files, lock registries, and scanner manifests.

## 3. Change Classification & Promotion Rules

| Change Type | Handling | Promotion Gate |
|---|---|---|
| Critical security fix | Urgent update PR / candidate | Expedited compatibility + safety checks + human approval; never skip safety gates |
| Patch release | Automated update PR (Renovate) | Contract + fixture regression tests; human review (`automerge: false`) |
| Minor release | Automated update PR | Full compatibility + regression corpus + config diff review |
| Major release | Separate migration PR | Manual architecture review, compatibility matrix update, staging soak |
| Rule / template / DB update | Immutable content snapshot | Schema validation, positive/negative/near-miss fixtures, FP/FN diff check |

## 4. Immutability & Rollback

- Never update a scanner engine, template snapshot, or vulnerability database mid-scan.
- Every `scan_run` and `tool_execution` (Phase 3+) records immutable references to engine digest, adapter version, rule-pack hash, template snapshot hash, and feed snapshot ID.
- Retain the last-known-good stable digest/snapshot in the image lock and `tool_versions` table so rollback requires no rebuild.
- `renovate.json` configures `docker:pinDigests` with `automerge: false` for controlled update PRs.
