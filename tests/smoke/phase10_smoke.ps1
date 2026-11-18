$ErrorActionPreference = "Stop"

Write-Host "=== VForge Phase 10 Release & Update Lifecycle Smoke Check ===" -ForegroundColor Cyan

Write-Host "[1/8] Checking Phase 10 migration (0011_phase10_update_lifecycle)..."
docker compose --profile ops run --rm migrator alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic upgrade head failed" }
$rev = docker compose --profile ops run --rm migrator alembic current | Out-String
if ($rev -notmatch "001[1-9]_") {
  throw "FAIL: expected >= 0011_phase10_update_lifecycle, got: $rev"
}

Write-Host "[2/8] Running OPA policy tests (RBAC + Scope + Supply Chain + Phase 8..10)..."
docker compose run --rm --no-deps opa test /policies -v
if ($LASTEXITCODE -ne 0) { throw "FAIL: OPA tests failed" }

Write-Host "[3/8] Running vforge-scanners contracts & adapter tests..."
docker compose run --rm -v "${PWD}/packages/scanner-contracts:/opt/packages/scanner-contracts" api pytest -v -o cache_dir=/tmp/.pytest_cache /opt/packages/scanner-contracts/tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: vforge-scanners tests failed" }

Write-Host "[4/8] Running API lint, mypy & full pytest suite (including Phase 10 Lifecycle)..."
docker compose stop orchestrator update-controller | Out-Null
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api ruff check --no-cache /app/src /app/tests /app/alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: API ruff check failed" }
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api ruff format --check /app/src /app/tests /app/alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: API ruff format check failed" }
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api mypy --cache-dir /tmp/.mypy_cache /app/src
if ($LASTEXITCODE -ne 0) { throw "FAIL: API mypy failed" }
docker compose run --rm -e "PYTHONPATH=/app/src" -v "${PWD}/apps/api/src:/app/src:ro" -v "${PWD}/apps/api/tests:/app/tests:ro" api pytest -v -o cache_dir=/tmp/.pytest_cache tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: API pytest suite failed" }

Write-Host "[5/8] Running Runner Agent lint, mypy & pytest..."
docker compose -f runner/docker-compose.runner.yml --profile runner run --rm --no-deps -v "${PWD}/runner:/opt/runner" -v "${PWD}/packages/scanner-contracts/src/vforge_scanners:/usr/local/lib/python3.13/site-packages/vforge_scanners" -v "${PWD}/runner/vforge_runner:/usr/local/lib/python3.13/site-packages/vforge_runner" --entrypoint sh vforge-runner -c "ruff check --no-cache vforge_runner tests && ruff format --check vforge_runner tests && mypy --cache-dir /tmp/.mypy_cache vforge_runner && pytest -v -o cache_dir=/tmp/.pytest_cache tests"
if ($LASTEXITCODE -ne 0) { throw "FAIL: runner quality gates / pytest failed" }

Write-Host "[6/8] Verifying Control Plane update-controller (--once) & active digest pins..."
docker compose run --rm update-controller python -m vforge.lifecycle.update_controller --once
if ($LASTEXITCODE -ne 0) { throw "FAIL: update-controller single cycle failed" }

Write-Host "[7/8] Checking Next.js typecheck, lint & build..."
npm.cmd --prefix apps/web run typecheck
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js typecheck failed" }
npm.cmd --prefix apps/web run lint
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js lint failed" }
npm.cmd --prefix apps/web run build
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js build failed" }

Write-Host "[8/8] Verifying live /api/v1/meta, web /api/health & unauthenticated updates denial..."
$meta = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/meta" -Method Get
if ($meta.phase -lt 10 -or -not $meta.updates_enabled -or -not ($meta.implemented_capabilities -contains "four-stream-update-lifecycle") -or -not ($meta.implemented_capabilities -contains "zero-rebuild-rollback") -or -not ($meta.implemented_capabilities -contains "immutable-scan-tool-pins")) {
  throw "FAIL: /api/v1/meta did not report Phase 10 capabilities: $($meta | ConvertTo-Json -Compress)"
}
if ($meta.docker_socket_mounted) { throw "FAIL: Control-plane API reports docker.sock mounted!" }

$webHealth = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/health"
if ($webHealth.status -ne "ok" -or $webHealth.phase -lt 10) {
  throw "FAIL: web /api/health did not return phase >= 10 ok: $($webHealth | ConvertTo-Json -Compress)"
}

$orgProbe = [guid]::NewGuid().ToString()
try {
  Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/v1/organizations/$orgProbe/updates/overview" -UseBasicParsing | Out-Null
  throw "FAIL: unauthenticated GET updates overview succeeded unexpectedly"
} catch {
  $statusCode = $_.Exception.Response.StatusCode.value__
  if ($statusCode -ne 401) {
    throw "FAIL: expected 401 on unauthenticated GET updates overview, got $statusCode"
  }
}

docker compose up -d orchestrator update-controller | Out-Null

Write-Host "Phase 10 Release & Update Lifecycle smoke verification PASSED cleanly." -ForegroundColor Green
