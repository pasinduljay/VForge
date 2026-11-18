$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Write-Host "=== VForge Phase 12 AI Provider Governance Smoke Check ===" -ForegroundColor Cyan

Write-Host "[1/7] Checking Phase 12 migration (0013_phase12_ai_governance)..." -ForegroundColor Yellow
docker compose --profile ops run --rm -T migrator alembic upgrade head | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic upgrade head failed" }
$migHead = docker compose --profile ops run --rm -T migrator alembic current
if ($LASTEXITCODE -ne 0 -or ($migHead -notmatch "001[3-9]_")) {
    throw "FAIL: expected >= 0013_phase12_ai_governance at head, got: $migHead"
}

Write-Host "[2/7] Running OPA policy tests (RBAC + Scope + Supply Chain + Phase 8..12)..." -ForegroundColor Yellow
docker compose run --rm --no-deps -T opa test /policies -v | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: OPA tests failed" }

Write-Host "[3/7] Running vforge-scanners contracts & adapter tests..." -ForegroundColor Yellow
docker compose run --rm -v "${PWD}/packages/scanner-contracts:/opt/packages/scanner-contracts" api pytest -v -o cache_dir=/tmp/.pytest_cache /opt/packages/scanner-contracts/tests | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: scanner-contracts pytest failed" }

Write-Host "[4/7] Running API lint, mypy & full pytest suite (including Phase 12 AI Governance)..." -ForegroundColor Yellow
docker compose stop orchestrator update-controller | Out-Host
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api ruff check --no-cache /app/src /app/tests /app/alembic | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: ruff check failed" }
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api ruff format --check /app/src /app/tests /app/alembic | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: ruff format --check failed" }
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api mypy --cache-dir /tmp/.mypy_cache /app/src | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: mypy failed" }
docker compose run --rm -e "PYTHONPATH=/app/src" -v "${PWD}/apps/api/src:/app/src:ro" -v "${PWD}/apps/api/tests:/app/tests:ro" api pytest -v -o cache_dir=/tmp/.pytest_cache tests | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: API pytest suite failed" }

Write-Host "[5/7] Running Runner Agent lint, mypy & pytest..." -ForegroundColor Yellow
docker compose -f runner/docker-compose.runner.yml --profile runner run --rm --no-deps -v "${PWD}/runner:/opt/runner" -v "${PWD}/packages/scanner-contracts/src/vforge_scanners:/usr/local/lib/python3.13/site-packages/vforge_scanners" -v "${PWD}/runner/vforge_runner:/usr/local/lib/python3.13/site-packages/vforge_runner" --entrypoint sh vforge-runner -c "ruff check --no-cache vforge_runner tests && ruff format --check vforge_runner tests && mypy --cache-dir /tmp/.mypy_cache vforge_runner && pytest -v -o cache_dir=/tmp/.pytest_cache tests" | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: Runner verification failed" }

Write-Host "[6/7] Checking Next.js typecheck, lint & build (including /ai-governance)..." -ForegroundColor Yellow
npm.cmd --prefix apps/web run typecheck
if ($LASTEXITCODE -ne 0) { throw "FAIL: web typecheck failed" }
npm.cmd --prefix apps/web run lint
if ($LASTEXITCODE -ne 0) { throw "FAIL: web lint failed" }
npm.cmd --prefix apps/web run build
if ($LASTEXITCODE -ne 0) { throw "FAIL: web build failed" }

Write-Host "[7/7] Verifying live /api/v1/meta, web /api/health & unauthenticated AI gateway denial..." -ForegroundColor Yellow
$meta = Invoke-RestMethod -UseBasicParsing -Uri "http://127.0.0.1:8000/api/v1/meta"
if ($meta.phase -lt 12 -or -not $meta.ai_gateway_enabled) {
    throw "FAIL: /api/v1/meta did not report Phase 12 ai_gateway_enabled"
}
$webHealth = Invoke-RestMethod -UseBasicParsing -Uri "http://127.0.0.1:3000/api/health"
if ($webHealth.status -ne "ok" -or $webHealth.phase -lt 12) {
    throw "FAIL: web /api/health did not report Phase 12"
}

$orgProbe = [guid]::NewGuid().ToString()
$denied = $false
try {
    Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8000/api/v1/organizations/$orgProbe/ai/overview" | Out-Null
}
catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 401) {
        $denied = $true
    }
}
if (-not $denied) { throw "FAIL: unauthenticated AI overview did not return 401" }

docker compose up -d orchestrator update-controller | Out-Host
Write-Host "Phase 12 AI Provider Governance smoke verification PASSED cleanly." -ForegroundColor Green
