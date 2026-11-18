$ErrorActionPreference = "Stop"

Write-Host "=== VForge Phase 3 Acceptance Smoke Check ===" -ForegroundColor Cyan

Write-Host "[1/7] Checking Docker Compose configuration & security posture..."
docker compose config --quiet
if ($LASTEXITCODE -ne 0) { throw "FAIL: docker compose config failed" }
$rendered = docker compose config --no-interpolate | Out-String
if ($rendered -match "docker\.sock") { throw "FAIL: docker.sock reference found in Compose config" }
if ($rendered -match "privileged:\s*true") { throw "FAIL: privileged container found in Compose config" }

Write-Host "[2/7] Running Alembic migration upgrade via dedicated migrator role..."
docker compose --profile ops run --rm migrator alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic upgrade head failed" }

Write-Host "[3/7] Running OPA policy tests (RBAC + Scope)..."
docker compose run --rm --no-deps opa test /policies -v
if ($LASTEXITCODE -ne 0) { throw "FAIL: OPA tests failed" }

Write-Host "[4/7] Running API quality gates & full pytest suite..."
docker compose exec -T api ruff check src tests alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: ruff check failed" }
docker compose exec -T api ruff format --check src tests alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: ruff format check failed" }
docker compose exec -T api mypy src
if ($LASTEXITCODE -ne 0) { throw "FAIL: mypy failed" }
docker compose exec -T api pytest -v tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: API pytest suite failed" }

Write-Host "[5/7] Checking /api/v1/meta and web /api/health Phase 3 boundaries..."
$meta = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/meta"
if (
  $meta.phase -lt 3 -or
  ($meta.phase -lt 5 -and $meta.scanners_enabled -ne $false) -or
  ($meta.phase -lt 4 -and $meta.runner_connected -ne $false) -or
  $meta.docker_socket_mounted -ne $false -or
  ($meta.implemented_capabilities -notcontains "orchestration-outbox-leases")
) {
  throw "FAIL: /api/v1/meta Phase 3 boundary check failed"
}

$webHealth = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/health"
if ($webHealth.status -ne "ok" -or $webHealth.phase -lt 3) {
  throw "FAIL: web /api/health did not return phase >= 3 ok"
}

Write-Host "[6/7] Auditing orchestrator container hardening & no Docker socket..."
foreach ($svc in @("vforge-api-1", "vforge-orchestrator-1", "vforge-frontend-1", "vforge-opa-1")) {
  $ro = docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' $svc
  if ($ro -ne "true") { throw "FAIL: $svc ReadonlyRootfs is $ro" }
  $capDrop = docker inspect --format '{{json .HostConfig.CapDrop}}' $svc
  if ($capDrop -notmatch "ALL") { throw "FAIL: $svc CapDrop missing ALL: $capDrop" }
  $priv = docker inspect --format '{{.HostConfig.Privileged}}' $svc
  if ($priv -ne "false") { throw "FAIL: $svc Privileged is $priv" }
  $mounts = docker inspect --format '{{json .Mounts}}' $svc
  if ($mounts -match "docker\.sock") { throw "FAIL: $svc mounts docker.sock" }
}

Write-Host "[7/7] Phase 3 smoke & acceptance checks PASSED." -ForegroundColor Green
