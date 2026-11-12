# VForge — Enterprise Cloud & Application Security Control Plane

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.13+](https://img.shields.io/badge/Python-3.13%2B-3776AB.svg)](apps/api/pyproject.toml)
[![Next.js 16](https://img.shields.io/badge/Next.js-16.4-000000.svg)](apps/web/package.json)
[![PostgreSQL 18 RLS](https://img.shields.io/badge/PostgreSQL_18-FORCE_RLS-336791.svg)](infrastructure/postgres/01-role-separation.sql.example)
[![OPA Rego v1](https://img.shields.io/badge/Policy-OPA_Rego_v1-7D9199.svg)](policies/rego/vforge)

**VForge** is an open-source, self-hosted Application Security Posture Management (ASPM), VAPT orchestration, and Threat Intelligence Control Plane. It is engineered around strict **Control Plane / Execution Plane separation**, cryptographic target scope governance (`Ed25519`), database-enforced multi-tenant isolation (`ENABLE` + `FORCE ROW LEVEL SECURITY`), and isolated ephemeral scanner containers communicating over **TLS 1.3 mutual TLS (mTLS)**.

---

## Architecture Overview

```mermaid
flowchart LR
    subgraph Operator["Security Engineer / Operator"]
      Browser["Web Browser (Dark / Light / System UI)"]
    end

    subgraph ControlPlane["VM-1: VForge Control Plane (No Docker Socket)"]
      UI["Next.js 16 Workspace UI (:3000)"]
      API["FastAPI Control Plane (:8000)"]
      Orch["Orchestrator & Outbox Worker"]
      Upd["4-Stream Update Controller"]
      GW["TLS 1.3 mTLS Runner Gateway (:8443)"]
      OPA["Open Policy Agent (Rego v1)"]
      PG[("PostgreSQL 18 (FORCE RLS)")]
      RMQ[("RabbitMQ 4")]
      VK[("Valkey 9 ACL")]
      IdP["OIDC Identity Provider (:8080)"]
    end

    subgraph ExecutionPlane["VM-2: Isolated Execution Plane (Dedicated Runner Host)"]
      Agent["vforge-runner Agent (ECDSA P-256 mTLS)"]
      Egress["Scoped Egress Proxy & DNS Pinning"]
      Scanners["Ephemeral Scanners (OpenGrep, Gitleaks, Syft, Grype, Checkov, ZAP, Nuclei, Nmap, testssl.sh)"]
    end

    Browser -->|HTTPS / OIDC PKCE| UI
    UI --> API
    API --> PG
    API --> RMQ
    API --> VK
    API --> OPA
    API --> IdP
    Orch --> PG
    Orch --> RMQ
    Upd --> PG
    GW --> PG
    Agent <-->|TLS 1.3 mTLS + Ed25519 Signed Manifests| GW
    Agent --> Scanners
    Scanners --> Egress
```

---

## Key Capabilities

| Domain | Capabilities Implemented |
|---|---|
| **Multi-Tenant Identity & Zero-Trust DB** | OIDC Authorization Code Flow with PKCE (`S256`), RP-Initiated Logout, HTTP-only session cookies, CSRF tokens, and PostgreSQL 18 `ENABLE` + `FORCE ROW LEVEL SECURITY` across 63 tenant tables under least-privilege runtime role `vforge_app` (`NOSUPERUSER NOBYPASSRLS`). |
| **Target Scope & Policy Engine** | Canonical domain/IP/CIDR/URL scope validation (`vforge_scope`), SSRF/IMDS/rebinding blocks (`169.254.169.254`, link-local, RFC1918 gates), Open Policy Agent (`policies/rego/vforge/`), and `Ed25519`-signed immutable `scope_snapshots`. |
| **Isolated mTLS Runner & Scanners** | Control Plane never mounts `/var/run/docker.sock`. Dedicated `vforge-runner` authenticates via `ECDSA P-256` SPIFFE client certificates (`spiffe://vforge/org/<id>/runner/<id>`), verifies signed job manifests, and executes `@sha256` digest-pinned containers (`OpenGrep`, `Gitleaks`, `Syft`, `Grype`, `Checkov`, `OWASP ZAP`, `Nuclei`, `Nmap`, `testssl.sh`) with `read_only: true`, `cap_drop: [ALL]`, and `no-new-privileges:true`. |
| **Findings, Triage & Reporting** | Multi-scanner finding correlation preserving raw evidence occurrences, SLA breach tracking, 4-eyes Segregation of Duties (SoD) risk exceptions, `AES-256-GCM` envelope-encrypted artifacts, and multi-format report exports (`HTML`, `PDF`, `JSON`, `SARIF 2.1.0`). |
| **Threat Intel & OSINT Correlation** | Offline-capable **CISA KEV**, **FIRST EPSS**, **NVD CVE 2.0**, **OSV**, and **Exploit-DB** feeds with stale-data degradation, plus multi-source OSINT compromise lookups (**Hudson Rock Cavalier v2**, **XposedOrNot**, **ProxyNova COMB** with in-memory secret redaction, **Shodan InternetDB**, **crt.sh**, **HackerTarget**, **AlienVault OTX**, **URLScan.io**, **Wayback CDX**). |
| **Release Lifecycle & Rule Studio** | 4-stream, 10-channel digest-pinned update pipeline (`candidate -> validated -> approved -> canary -> stable`) with instant rollback, plus a 6-engine Rule & Skill Studio with mandatory `positive`/`negative`/`near_miss` fixture verification and `Ed25519` manifest signing. |
| **Governed AI Gateway & Labs** | Provider-agnostic runtime AI gateway with pre-egress secret/PII redaction, `<untrusted_data>` quarantine, dual retention consent gates, OPA-brokered read-only tools, and opt-in isolated OWASP Learning Lab (`compose.lab.yaml`) & Red-Team Sandbox (`compose.redteam.yaml`). |

---

## Repository Layout

```text
vforge/
├── apps/
│   ├── api/                             # FastAPI control-plane API, workers & 18 Alembic migrations
│   └── web/                             # Next.js 16 App Router UI (self-hosted Inter & JetBrains Mono)
├── docs/                                # Architecture Decision Records (ADR-0001..0017), threat model & runbooks
├── infrastructure/
│   ├── keycloak/                        # OIDC realm fixture (realm-vforge.json)
│   ├── lab/                             # Opt-in isolated OWASP learning lab Compose stack
│   ├── monitoring/                      # Opt-in Prometheus & Grafana observability stack
│   ├── portainer/                       # Self-bootstrapping DB role, migration & mTLS initializers
│   ├── postgres/                        # PostgreSQL role-separation SQL reference
│   ├── redteam/                         # Opt-in isolated red-team sandbox Compose stack
│   └── valkey/                          # Valkey 9 ACL template
├── lifecycle/image-lock/                # Digest-pinned container image lockfiles
├── packages/
│   ├── scanner-contracts/               # vforge_scanners adapter SDK, parsers & secret redaction
│   └── scope-validator/                 # vforge_scope target canonicalization & SSRF guardrails
├── policies/rego/vforge/                # OPA Rego v1 authorization & scope policies + unit tests
├── rule-packs/                          # Baseline signed detection rule packs
├── runner/                              # Dedicated Execution Plane (vforge_runner) & egress gateway
├── scripts/                             # Disposable migration verifier & isolated DR backup/restore drill
├── tests/smoke/                         # End-to-end phase smoke test suites
├── docker-compose.yml                   # Local development Control Plane Compose stack
├── docker-compose.portainer-vm1.yml     # Self-bootstrapping Portainer Git stack for VM-1 (Control Plane)
├── docker-compose.portainer-vm2.yml     # Self-bootstrapping Portainer Git stack for VM-2 (Execution Runner)
├── .env.example                         # Environment template
└── LICENSE                              # Apache-2.0 License
```

---

## Deployment Option 1: Multi-VM Portainer GitOps Deployment (Proxmox / Linux VMs)

VForge includes two self-bootstrapping Compose stacks at the repository root so you can deploy the **Control Plane (VM-1)** and **Execution Plane (VM-2)** directly from the **Portainer UI (`Stacks -> + Add stack -> Repository`)** with zero manual terminal scripts:

1. **On VM-1 (`Control Plane` environment in Portainer):**
   - **Repository URL:** `https://github.com/pasinduljay/VForge`
   - **Repository reference:** `refs/heads/main` (or `refs/heads/dev`)
   - **Compose path:** `docker-compose.portainer-vm1.yml`
   - Automatically initializes PostgreSQL roles (`vforge_migrator`, `vforge_app`), RabbitMQ `vforge` vhost, Valkey SHA-256 ACLs, all 18 Alembic migrations, Runner Gateway ECDSA P-256 mTLS certificates, and starts the Control Plane (`:3000` UI, `:8000` API, `:8080` Keycloak, `:8443` mTLS Runner Gateway).
2. **On VM-2 (`Execution Runner` environment in Portainer):**
   - **Repository URL:** `https://github.com/pasinduljay/VForge`
   - **Repository reference:** `refs/heads/main` (or `refs/heads/dev`)
   - **Compose path:** `docker-compose.portainer-vm2.yml`
   - Automatically derives the matching ECDSA P-256 client certificate (`spiffe://vforge/...`) and connects `vforge-runner` to VM-1 (`https://<VM1_IP>:8443`) over TLS 1.3 mTLS.

---

## Deployment Option 2: Local Workstation Quickstart

1. **Create `.env` from template** and populate independent random secrets for all `CHANGE_ME_*` variables:
   ```bash
   cp .env.example .env
   ```
2. **Start the Control Plane with local OIDC (`dev-oidc` profile):**
   ```bash
   docker compose --profile dev-oidc up -d --build
   ```
3. **Run database schema migrations via the isolated `migrator` profile:**
   ```bash
   docker compose --profile ops run --rm migrator alembic upgrade head
   ```
4. **Access the Web UI:**
   - Open `http://localhost:3000`
   - Sign in with OIDC (`dev-owner@vforge.local` / `VForge-Dev-Local-Only!`).

---

## Documentation & Runbooks

- [Development Roadmap & Architecture Baseline](docs/DEVELOPMENT_ROADMAP.md)
- [Security Baseline & Invariants](docs/SECURITY_BASELINE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Production Readiness Assessment](docs/PRODUCTION_READINESS_ASSESSMENT.md)
- [Deployment & Upgrade Runbook](docs/runbooks/DEPLOYMENT_AND_UPGRADE.md)
- [Backup & Disaster Recovery Runbook](docs/runbooks/BACKUP_AND_DR.md)
- [Architecture Decision Records (ADRs)](docs/ARCHITECTURE_DECISIONS/README.md)

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
