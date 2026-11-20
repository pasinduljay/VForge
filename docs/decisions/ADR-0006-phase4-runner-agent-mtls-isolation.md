# ADR-0006: Phase 4 Dedicated Runner Agent, mTLS Gateway, Signed Manifests & Scoped Egress Isolation

- **Status:** Accepted
- **Date:** 2026-11-12
- **Phase:** Phase 4 — Runner Agent and Ephemeral Container Executor
- **Owners:** Platform Architecture & Security Engineering

---

## Context

Phases 1–3 established tenant RLS isolation, centralized scope/OPA/Ed25519 snapshot verification, and reliable Postgres-outbox + RabbitMQ orchestration with exclusive target leases. However, scan jobs still lacked a segregated execution boundary capable of running untrusted scanner workloads inside ephemeral hardened containers while keeping Docker control, execution secrets, and network egress physically and logically isolated from the Control Plane (`frontend`, `api`, `orchestrator`, `postgres`, `rabbitmq`, `valkey`, `opa`).

Per VForge Architecture §7 and §9:
- No Control Plane container may mount `/var/run/docker.sock` or accept arbitrary runtime CLI arguments from users or the API.
- All runner-to-control-plane communication must authenticate via unique mutual TLS (mTLS) identities and support immediate runner revocation.
- Each job runs in a single ephemeral hardened container (`read_only`, `cap_drop: ALL`, `no-new-privileges`, seccomp, non-root, CPU/memory/PID/timeout/output limits) from an immutable `@sha256:` image digest validated against an Ed25519-signed `ExecutionManifest`.
- Network-capable jobs must pass through a scoped egress gateway performing allowlist checks, independent DNS resolution, metadata/RFC1918 blocking, socket-connect IP pinning, and HTTP redirect revalidation.
- Collected artifacts must be SHA-256 verified and envelope-encrypted at rest (`AES-256-GCM`).

---

## Decisions

1. **Tenant-Scoped Runner Pools & Runners (`0005_phase4_runner_isolation`)**
   - `runner_pools`, `runners`, `runner_heartbeats`, `runner_events`, `tool_executions`, and `artifacts` are strictly tenant-scoped (`org_id` + composite foreign keys + `ENABLE`/`FORCE ROW LEVEL SECURITY` scoped to `vforge_app`).
   - `runner_events` is append-only (`REVOKE UPDATE/DELETE` + `trg_runner_events_append_only` trigger) and explicitly captures security events (`cleanup_failed`, `egress_blocked`, `runner_revoked`, `manifest_rejected`).

2. **Dedicated mTLS Runner Gateway (`vforge.runner_gateway`, Port `8443`)**
   - All runner endpoints (`/api/v1/runner/*`) live exclusively on a separate FastAPI application (`vforge.runner_gateway`) served over TLS 1.3 with `ssl.CERT_REQUIRED` client CA verification using `MtlsH11Protocol` (which injects OpenSSL-verified `peercert` DER bytes directly into `scope["extensions"]["vforge.mtls_peer_der"]`).
   - The main public Control Plane API (`vforge.main`, port `8000`) does not mount `/api/v1/runner/*` and ignores HTTP certificate forwarding headers.
   - Each runner certificate embeds a CA-signed SPIFFE SAN URI (`spiffe://vforge/org/<org_id>/runner/<runner_id>`). The gateway binds the PostgreSQL session context to that CA-authenticated `org_id`, verifies exact `cert_sha256`, certificate validity dates, and `runner.status == 'active'`. Revoked or draining runners cannot claim jobs, heartbeat, or upload artifacts.

3. **Ed25519-Signed `ExecutionManifest` & Allowlisted Immutable Digests**
   - Before a job with `execution_mode = "runner"` becomes claimable (`LEASED`), the orchestrator constructs and signs a canonical `ExecutionManifest` (`apiVersion: vforge.io/v1`, `kind: RunnerJob`, `expiresAt`, pinned `image@sha256:...`, resource limits, security posture flags, and network scope allowlist) using the Control Plane's Ed25519 signing key.
   - Both Control Plane dispatch and the Runner Agent independently verify the Ed25519 signature, expiration timestamp, and `image@sha256:` digest allowlist before any container starts. User/API payloads can never supply host paths, Docker options, capabilities, or arbitrary images.

4. **Ephemeral Hardened Container Executor (`runner/executor/`)**
   - Implemented as a clean standalone Python package under `runner/` (`vforge-runner`) holding zero Control Plane DB, RabbitMQ, or Valkey credentials.
   - Creates per-job temporary input/output directories with bounded quotas and launches containers enforcing:
     - `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, seccomp allowlist (`runner/network-policy/seccomp-scanner.json`), non-root `--user 10001:10001`, PID/memory/CPU/tmpfs limits, and strict wall-clock timeouts.
     - Read-only input mount (`/work/in:ro`) and bounded output mount (`/work/out:rw`).
     - Mandatory container + temporary workspace destruction on success, failure, timeout, and operator cancellation; any cleanup failure emits a `security` event (`cleanup_failed`).

5. **Network-Layer Scoped Egress Gateway (`runner/network-policy/`)**
   - Offline/static jobs run with `--network=none`.
   - Network-capable jobs run on an internal bridge network with zero direct default route and traverse `ScopedEgressGateway`, which resolves DNS independently, blocks cloud metadata IPs (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`, etc.), unapproved loopback/link-local/RFC1918/ULA/IPv4-mapped ranges, mixed DNS answers, and DNS-rebinding against pinned snapshot IPs, connects directly by validated pinned IP (`sock.connect((pinned_ip, port))`), and revalidates HTTP redirects + rejects HTTPS->HTTP downgrades.

6. **AES-256-GCM Envelope Encryption for Uploaded Artifacts (`apps/api/src/vforge/security/envelope.py`)**
   - Uploaded artifacts are hashed (`sha256`) before encryption and verified against runner-supplied manifests, wrapped with a per-artifact 256-bit DEK encrypted by an authenticated AES-256-GCM KEK (using canonical AAD `org_id|scan_run_id|job_id|sha256`) and stored atomically under `ARTIFACT_ROOT`, keeping the crypto boundary ready for OpenBao Transit KMS in Phase 14.

---

## Consequences

- Control Plane containers (`frontend`, `api`, `orchestrator`, `postgres`, `rabbitmq`, `valkey`, `opa`) keep `docker_socket_mounted: false`, zero host privileges, and zero container runtime access.
- Real scanners (`OpenGrep`, `Gitleaks`, `Syft`, `Grype`, `Checkov`, `ZAP`, `Nuclei`) remain disabled (`scanners_enabled: false`) until Phases 5–7; Phase 4 exercises a pinned minimal dummy container image (`runner/images/dummy-scanner/`) and protocol runtime tests to validate full isolation, cancellation, revocation, egress blocking, and SHA-256 artifact roundtrips.
- For local WSL2/Docker Desktop development, the optional `--profile runner` Compose configuration is explicitly labeled **development-only** (`ADR-0006` / Architecture §7.1); production deployments run `runner/` on an isolated Linux execution VM with host firewall egress enforcement.
