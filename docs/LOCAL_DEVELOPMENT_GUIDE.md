# VForge Local Development Guide

This guide covers running, authenticating against, and troubleshooting the local VForge Control Plane stack (`frontend` + `api` + backing services).

## 1. Local Service Endpoints & Architecture

| Service | Host URL | Internal Container URL | Notes |
| --- | --- | --- | --- |
| Next.js Web UI (`frontend`) | `http://127.0.0.1:3000` / `http://localhost:3000` | `http://frontend:3000` | Binds loopback `127.0.0.1:3000`. Proxies `/api/v1/*` server-side to `INTERNAL_API_BASE_URL`. |
| FastAPI Control Plane (`api`) | `http://127.0.0.1:8000` | `http://api:8000` | Runs as unprivileged DB role `vforge_app` (`NOBYPASSRLS`). |
| Dev OIDC IdP (`keycloak`, opt-in) | `http://127.0.0.1:8080` | `http://keycloak:8080/realms/vforge` | Started only with `--profile dev-oidc`. |
| PostgreSQL / RabbitMQ / Valkey / OPA | Internal only (`control` network) | `postgres:5432`, `rabbitmq:5672`, `valkey:6379`, `opa:8181` | No host ports published. |

## 2. Starting the Control Plane

1. **Configure `.env` (never commit `.env` or `.secrets/`):**
   ```powershell
   Copy-Item .env.example .env
   ```
   Replace all `CHANGE_ME_*` placeholders in `.env` with unique CSPRNG secrets.

2. **Start core Control Plane containers (preserving persistent volumes):**
   ```powershell
   docker compose up -d --build
   ```

3. **Run PostgreSQL migrations via the dedicated `ops` `migrator` profile (`vforge_migrator`):**
   ```powershell
   docker compose --profile ops run --rm migrator alembic upgrade head
   ```
   > **Note:** Never run Alembic directly inside the `api` container; `api` runs with least-privilege `vforge_app` credentials and intentionally lacks migration credentials.

4. **Check service health:**
   - Web proxy health: `GET http://localhost:3000/api/health` -> `200 OK`
   - Control-plane API metadata: `GET http://localhost:3000/api/v1/meta` -> `200 OK`
   - Direct API health: `GET http://127.0.0.1:8000/health` -> `200 OK`

## 3. Authentication & Organization Management (`/organizations`)

All `/api/v1/organizations` and `/api/v1/auth/me` endpoints require authentication (`401 Unauthorized` when no session cookie or valid Bearer JWT is present).

### Default Mode (`OIDC_ENABLED=false`)
- By default in `.env.example`, `OIDC_ENABLED=false` and the local Keycloak container is not started.
- Visiting `/organizations` without an active session displays an **Authentication Required (`HTTP 401`)** state with **Sign In**, **Retry**, and **Back to Home** actions.
- `/login` queries `/api/v1/meta` (`oidc_enabled: false`) and displays instructions for enabling local Keycloak OIDC.

### Enabling Local OIDC Sign-In (`--profile dev-oidc`)
1. In `.env`, configure:
   - `OIDC_ENABLED=true`
   - `OIDC_ISSUER=http://127.0.0.1:8080/realms/vforge`
   - `OIDC_INTERNAL_BASE_URL=http://keycloak:8080/realms/vforge`
   - `OIDC_REDIRECT_URI=http://localhost:3000/api/v1/auth/oidc/callback`
   - `FRONTEND_BASE_URL=http://localhost:3000`
2. Start Keycloak alongside the Control Plane:
   ```powershell
   docker compose --profile dev-oidc up -d
   ```
3. Recreate `api` so it picks up the updated `.env` values:
   ```powershell
   docker compose up -d api
   ```
4. Open **`http://localhost:3000/login`** (use the exact host—`localhost` or `127.0.0.1`—matching `OIDC_REDIRECT_URI` / `FRONTEND_BASE_URL` so the `HttpOnly` `vf_session` cookie stays bound to the exact origin) and sign in with a pre-configured Keycloak dev user from `infrastructure/keycloak/realm-vforge.json`:
   - `dev-owner` (`dev-owner@vforge.local`)
   - `dev-analyst` (`dev-analyst@vforge.local`)
   *(Check `infrastructure/keycloak/realm-vforge.json` locally for dev-only realm passwords.)*
5. Once signed in, `/organizations` loads your organization memberships (or an empty state prompting you to create your first organization, where the creator automatically receives the `owner` membership).

## 4. Enterprise Workspace UI Architecture

- **Navigation & Context (`apps/web/src/components/OrgShell.tsx` + `apps/web/src/lib/navigation.ts`):** Collapsible RBAC-filtered sidebar organized into `Workspace`, `Security Testing`, `Intelligence`, `Platform`, and `Administration`, paired with a sticky top bar containing breadcrumbs, organization switcher, project filter, posture alerts, and user session controls.
- **Core & New Workspace Routes under `/organizations/[orgId]`:**
  - `/` (`[orgId]/page.tsx`): Security Posture Dashboard (authorized targets, active scans, open/critical+high findings, severity bars, remediation state, KEV/EPSS intel, observation timeline, recent scans & audit stream).
  - `/findings`: Canonical findings triage (`finding:triage`), SLA breach evaluation, and **Risk Exceptions Queue** (`risk_exception:request` / `risk_exception:approve` with SoD self-approval prevention).
  - `/evidence`: Consolidated encrypted scanner artifacts, Ed25519-signed scope snapshots, and generated reports.
  - `/integrations`: Live threat-intelligence and governed AI provider connectors alongside clearly labeled planned ticketing/SIEM/ChatOps/PR integrations.
  - `/system-health`: Control-plane metadata (`/api/v1/meta`), Docker socket isolation posture, mTLS runner certificates, and threat feed freshness (noting `/metrics` operator bearer auth).
  - `/settings`: Organization profile editing (`org:update`), session token rotation, effective RBAC permissions, and planned policy defaults.

## 5. Content Security Policy (CSP) & Request Timeouts

- HTML pages rendered by Next.js use a **per-request cryptographic nonce CSP** generated in `apps/web/src/proxy.ts` (`script-src 'self' 'nonce-...' 'strict-dynamic'`) paired with dynamic rendering in `apps/web/src/app/layout.tsx` (`await connection()`).
- Never set a static `Content-Security-Policy` on HTML routes that omits `'nonce-...'`, or Next.js inline hydration/RSC scripts will be blocked and client pages (such as `/organizations`) will stay stuck in their initial `"Loading..."` markup without firing API requests.
- Server-side proxy requests in `apps/web/src/app/api/v1/[...path]/route.ts` enforce a 15-second upstream timeout (`HTTP 504 gateway_timeout` on timeout, `HTTP 502 bad_gateway` when `api` is unreachable), and `/organizations` explicitly renders **Authentication Required (401)**, **Permission Denied (403)**, **API Unavailable (502/503/504/network/timeout)**, **Unexpected Error**, **Empty**, and **Loaded** states with a **Retry** button.

## 6. Verification Commands

```powershell
# Frontend checks
npm.cmd --prefix apps/web run typecheck
npm.cmd --prefix apps/web run lint
npm.cmd --prefix apps/web run build

# Rebuild & restart frontend container safely (never use `down -v`)
docker compose up -d --build frontend
```
