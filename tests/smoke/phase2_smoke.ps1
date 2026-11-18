$ErrorActionPreference = "Stop"

Write-Host "=== VForge Phase 2 Acceptance Smoke Check ===" -ForegroundColor Cyan

Write-Host "[1/6] Checking docker-compose configuration & service health..."
docker compose config --quiet
if ($LASTEXITCODE -ne 0) { throw "FAIL: docker compose config failed" }

Write-Host "[2/6] Running Alembic migration upgrade check via dedicated migrator role..."
docker compose --profile ops run --rm migrator alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic upgrade head failed" }

Write-Host "[3/6] Running OPA Rego policy & Phase 2 scope tests..."
docker compose run --rm --no-deps opa test /policies -v
if ($LASTEXITCODE -ne 0) { throw "FAIL: OPA tests failed" }

Write-Host "[4/6] Running vforge-scope unit & property-based tests..."
docker compose exec -T api pytest -v -o cache_dir=/tmp/.pytest_cache /opt/packages/scope-validator/tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: vforge-scope tests failed" }

Write-Host "[5/6] Running API Phase 0/1/2 test suites & verifying /api/v1/meta boundary..."
docker compose exec -T api pytest -v tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: API Phase 2 pytest suite failed" }

$meta = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/meta"
if (
  $meta.phase -lt 2 -or
  ($meta.phase -lt 5 -and $meta.scanners_enabled -ne $false) -or
  ($meta.phase -lt 4 -and $meta.runner_connected -ne $false) -or
  $meta.docker_socket_mounted -ne $false
) {
  throw "FAIL: /api/v1/meta Phase 2+ execution-boundary check failed"
}

$webHealth = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/health"
if ($webHealth.status -ne "ok" -or $webHealth.phase -lt 2) {
  throw "FAIL: web /api/health did not return phase >= 2 ok"
}

Write-Host "[6/6] Auditing unauthenticated enforcement on Phase 2 scope endpoint..."
$orgProbe = [guid]::NewGuid().ToString()
try {
  Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/v1/organizations/$orgProbe/snapshots" -UseBasicParsing | Out-Null
  throw "FAIL: unauthenticated GET snapshots succeeded unexpectedly"
} catch {
  $statusCode = $_.Exception.Response.StatusCode.value__
  if ($statusCode -ne 401) {
    throw "FAIL: expected 401 on unauthenticated GET snapshots, got $statusCode"
  }
}

Write-Host "PASS: All Phase 2 smoke assertions succeeded." -ForegroundColor Green
