param(
  [switch]$TestDowngrade = $false
)

$ErrorActionPreference = "Stop"

Write-Host "[1/9] Validating Docker Compose config (default & dev-oidc profile)..."
docker compose config --quiet
if ($LASTEXITCODE -ne 0) { throw "FAIL: docker compose config failed" }
docker compose --profile dev-oidc config --quiet
if ($LASTEXITCODE -ne 0) { throw "FAIL: docker compose --profile dev-oidc config failed" }

$rendered = docker compose --profile dev-oidc config --no-interpolate | Out-String
if ($rendered -match "docker\.sock") { throw "FAIL: docker.sock reference found in Compose config" }
if ($rendered -match "privileged:\s*true") { throw "FAIL: privileged container found in Compose config" }
if ($rendered -match "host_ip:\s*0\.0\.0\.0" -or $rendered -match '"0\.0\.0\.0:') {
  throw "FAIL: non-loopback 0.0.0.0 port binding found"
}

Write-Host "[2/9] Checking .env is not tracked by Git..."
$trackedEnv = git ls-files .env
if ($trackedEnv) { throw "FAIL: .env is tracked by Git" }

Write-Host "[3/9] Running OPA policy unit tests..."
docker compose run --rm --no-deps opa test /policies -v
if ($LASTEXITCODE -ne 0) { throw "FAIL: OPA policy tests failed" }

Write-Host "[4/9] Verifying Alembic migrations via migrator role..."
docker compose --profile ops run --rm migrator alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic upgrade head failed" }
docker compose --profile ops run --rm migrator alembic current
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic current failed" }
if ($TestDowngrade) {
  Write-Host "Running opt-in destructive downgrade/re-upgrade check..."
  docker compose --profile ops run --rm migrator alembic downgrade 0001_phase0_foundation
  if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic downgrade 0001_phase0_foundation failed" }
  docker compose --profile ops run --rm migrator alembic upgrade head
  if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic re-upgrade head failed" }
}

Write-Host "[5/9] Checking API code quality, types, and Phase 1 test suite (unit, RLS, RBAC, E2E)..."
docker compose exec -T api ruff check src tests alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: ruff check failed" }
docker compose exec -T api ruff format --check src tests alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: ruff format check failed" }
docker compose exec -T api mypy src
if ($LASTEXITCODE -ne 0) { throw "FAIL: mypy failed" }
docker compose exec -T api pytest -v
if ($LASTEXITCODE -ne 0) { throw "FAIL: pytest failed" }

Write-Host "[6/9] Running Next.js typecheck, lint, and production build..."
npm.cmd --prefix apps/web run typecheck
if ($LASTEXITCODE -ne 0) { throw "FAIL: web typecheck failed" }
npm.cmd --prefix apps/web run lint
if ($LASTEXITCODE -ne 0) { throw "FAIL: web lint failed" }
npm.cmd --prefix apps/web run build
if ($LASTEXITCODE -ne 0) { throw "FAIL: web build failed" }

Write-Host "[7/9] Verifying live API, Auth Enforcement (401), and Frontend endpoints..."
$health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health"
if ($health.status -ne "ok") { throw "FAIL: /health did not return ok" }

$ready = Invoke-RestMethod -Uri "http://127.0.0.1:8000/ready"
if ($ready.status -ne "ready") { throw "FAIL: /ready did not return ready" }

$meta = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/meta"
if ($meta.phase -lt 1 -or ($meta.phase -lt 5 -and $meta.scanners_enabled -ne $false) -or $meta.docker_socket_mounted -ne $false) {
  throw "FAIL: /api/v1/meta Phase 1+ boundary check failed"
}

try {
  Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/v1/organizations" -UseBasicParsing | Out-Null
  throw "FAIL: unauthenticated GET /api/v1/organizations succeeded unexpectedly"
} catch {
  $statusCode = $_.Exception.Response.StatusCode.value__
  if ($statusCode -ne 401) {
    throw "FAIL: expected 401 on unauthenticated GET /api/v1/organizations, got $statusCode"
  }
}

$webHealth = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/health"
if ($webHealth.status -ne "ok" -or $webHealth.phase -lt 1) {
  throw "FAIL: web /api/health did not return phase >= 1 ok"
}

$proxyMeta = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/v1/meta"
if ($proxyMeta.phase -lt 1 -or $proxyMeta.platform -ne "VForge" -or ($proxyMeta.phase -lt 5 -and $proxyMeta.scanners_enabled -ne $false)) {
  throw "FAIL: web /api/v1/meta proxy check failed"
}

foreach ($route in @("/", "/login", "/organizations")) {
  $resp = Invoke-WebRequest -Uri "http://127.0.0.1:3000$route" -UseBasicParsing
  if ($resp.StatusCode -ne 200) {
    throw "FAIL: web $route returned $($resp.StatusCode)"
  }
}

Write-Host "[8/9] Auditing running container hardening & loopback bindings..."
foreach ($svc in @("vforge-api-1", "vforge-frontend-1", "vforge-opa-1")) {
  $ro = docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' $svc
  if ($ro -ne "true") { throw "FAIL: $svc ReadonlyRootfs is $ro" }
  $capDrop = docker inspect --format '{{json .HostConfig.CapDrop}}' $svc
  if ($capDrop -notmatch "ALL") { throw "FAIL: $svc CapDrop missing ALL: $capDrop" }
}
foreach ($svc in @("vforge-api-1", "vforge-frontend-1", "vforge-opa-1", "vforge-postgres-1", "vforge-rabbitmq-1", "vforge-valkey-1")) {
  $priv = docker inspect --format '{{.HostConfig.Privileged}}' $svc
  if ($priv -ne "false") { throw "FAIL: $svc Privileged is $priv" }
  $mounts = docker inspect --format '{{json .Mounts}}' $svc
  if ($mounts -match "docker\.sock") { throw "FAIL: $svc mounts docker.sock" }
}

Write-Host "[9/9] Phase 1 smoke & acceptance checks PASSED."
