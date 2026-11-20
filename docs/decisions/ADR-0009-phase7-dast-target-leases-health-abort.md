# ADR-0009: Phase 7 Web/API DAST, Pinned Engines, Target Leases & Active Safety Auto-Abort

- **Status:** Accepted
- **Date:** 2026-11-12
- **Phase:** 7 — Web/API DAST & Active Target Testing (`OWASP ZAP`, `Nuclei`, `Nmap`, `testssl.sh`)

## Context

Phase 7 activates live HTTP/API and network target scanning inside the isolated Execution Plane (`runner/`). Unlike Phase 5 and Phase 6 static analysis (which inspects immutable source archives and SBOMs under `--network=none`), DAST tools interact directly with live targets across network boundaries.

Active target interaction introduces critical operational and security failure modes:
1. **Target Disruption & Cascading 5xx Outages:** Active fuzzing or high-concurrency vulnerability scanning can overwhelm test targets or trigger state corruption.
2. **SSRF & Scope Escape:** Scanning tools can follow HTTP redirects into internal cloud metadata services (`169.254.169.254`) or unapproved private infrastructure.
3. **Target Scanning Collisions:** Multiple active scanners testing the same target simultaneously can cause race conditions or false alerts.
4. **Credential Leakage:** Authenticated scanning requires target credentials that must never be committed to source, logged in plaintext, or persisted unencrypted in manifests or databases.
5. **Dishonest Reporting:** If a scanner crashes, times out, or trips an emergency safety abort, the platform must never return a clean pass or synthetic findings.

## Decision

1. **Pinned Image Registry:**
   - **OWASP ZAP 2.16.0:** `ghcr.io/zaproxy/zaproxy@sha256:391f66efa53b30de40d4a1c6e28146477263552fc828bc7613c9cd11a2949908`. Executed in Automation Framework mode (`zap.sh -cmd -dir /tmp/.ZAP -autorun /work/in/zap.yaml`) with `-dir /tmp/.ZAP` and `--tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777` ensuring read-only root compliance and passive-first / active-second workflows with OpenAPI spec ingestion.
   - **ProjectDiscovery Nuclei v3.11.1:** `projectdiscovery/nuclei@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb`. Executed with pinned, reviewed templates, `-duc` (disable update check), `-ni` (disable interactsh OAST), and strict rate-limit (`-rl 2`) and concurrency (`-c 1` or `-c 2`) flags.
   - **Instrumentisto Nmap 7.98:** `instrumentisto/nmap@sha256:96f6ed194519b62421a1a1c57809e65a7f94d2aa1c8c25676f247e5e148c0827`. Executed non-root UID 10001 with TCP connect scan (`-sT -Pn -p <ports> -oX /work/out/nmap.xml`), ensuring zero `CAP_NET_RAW` requirement.
   - **drwetter/testssl.sh 3.2.5:** `drwetter/testssl.sh@sha256:e42cb1ba9445ea861e8b6eec96b97f6f293ce4e5908eebc75c28bdd96d66108e`. Executed with `--quiet --warnings batch --jsonfile-pretty /work/out/testssl.json` for TLS/cipher suite verification.

2. **Scoped Egress Enforcement & Scope Escape Prevention:**
   - All Phase 7 jobs execute with `network_profile="scoped-http-egress"`.
   - The Runner Agent spawns an ephemeral `ScopedEgressGateway` HTTP/CONNECT forward proxy binding loopback. The scanner container is injected with `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`.
   - The gateway enforces independent DNS resolution, pre-connect and post-DNS destination validation against the signed `ExecutionManifest` scope, blocks cloud metadata (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`), unapproved loopback/RFC1918/ULA ranges, socket-connects exclusively by validated pinned IP, and terminates/re-validates HTTP 301/302 redirects.
   - Any attempt to reach unapproved assets raises `EgressBlockedError` and triggers an `egress_blocked` security audit event.

3. **PostgreSQL Target Leases for Mutual Exclusion:**
   - Active DAST stages (`dast_active`) require an exclusive `active_http` lease from `scan_target_leases`.
   - Network scans (`network_scan`, `port_scan`, `tls_assessment`) require a `network_scan` lease.
   - The PostgreSQL partial unique index `uq_active_target_lease` on `(asset_id, lease_risk_class)` where `status = 'active'` prevents concurrent active scans against the same target.

4. **Target Health Monitor & Emergency Safety Auto-Abort:**
   - Active scan jobs execute a background target health monitor that periodically sends lightweight GET/HEAD requests to an authorized target baseline URL.
   - **Tripwire Criteria:**
     - 3 consecutive 5xx server responses, OR
     - Target latency exceeds `latency_threshold_ms` (default 5000ms), OR
     - Repeated connection timeouts / network unreachability, OR
     - Scope violation detected at egress gateway (`egress_blocked`).
   - When tripped, the monitor immediately signals cancellation to the running container runtime (`proc.terminate()` + `docker kill`), records the probe tripwire in `target_health_probes`, transitions the runner job to `failed` with `error_code="target_health_tripwire_aborted"`, and sets the scan run to `failed` (never synthetic clean pass).

5. **Target Authentication Profile (`auth_profiles`) Ephemeral Delivery:**
   - Target authentication uses `auth_profiles` rows storing `secret_manager_ref` (`secret://...`, `env://...`).
   - The API resolves credentials on demand via `SecretProvider` and delivers them over mTLS to the runner via `GET /api/v1/runner/jobs/{job_id}/target-auth`.
   - The runner injects credentials into the scanner configuration in memory (or temporary restricted `/work/in/` files), never persists them in database tables or logs, and passes all container logs through `redact_text_secrets(...)`.

6. **Database Schema Additions (`0008_phase7_dast`):**
   - New table `target_health_probes`: tracks baseline, periodic, and tripwire health checks (`organization_id`, `scan_run_id`, `runner_job_id`, `asset_id`, `probe_type`, `target_url`, `status_code`, `latency_ms`, `healthy`, `error_message`, `created_at`).
   - Composite foreign keys, `ENABLE` + `FORCE ROW LEVEL SECURITY`, tenant isolation under `vforge_app`.
   - `scan_runs.auth_profile_id` foreign key referencing `auth_profiles`.

## Consequences

- Active DAST scans cannot saturate target applications without tripping the safety guard and halting.
- Out-of-scope requests (including redirect hops) are blocked at the socket layer before reaching the network.
- Concurrent active scans against the same asset are blocked by database constraints.
- Scanner failures, aborts, and timeouts surface truthfully as `failed` runs.
