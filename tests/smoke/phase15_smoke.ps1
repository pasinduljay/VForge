$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Write-Host "=== VForge Phase 15 AI Red-Team Sandbox & Final Release Smoke Check ===" -ForegroundColor Cyan

Write-Host "[1/8] Checking Phase 15 migration (0016_phase15_ai_redteam), disposable-DB full migration chain & Red-Team Sandbox Compose..." -ForegroundColor Yellow
docker compose --profile ops run --rm -T migrator alembic upgrade head | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic upgrade head failed" }
$migHead = docker compose --profile ops run --rm -T migrator alembic current
if ($LASTEXITCODE -ne 0 -or ($migHead -notmatch "0016_phase15_ai_redteam")) {
    throw "FAIL: expected 0016_phase15_ai_redteam at head, got: $migHead"
}
powershell -ExecutionPolicy Bypass -File scripts/db/verify_migrations_disposable.ps1 | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: disposable-DB full migration chain verification failed" }
$env:REDTEAM_AGENT_IMAGE = "ghcr.io/vforge/redteam-sandbox@sha256:0000000000000000000000000000000000000000000000000000000000000000"
docker compose -f infrastructure/redteam/compose.redteam.yaml --profile redteam config -q
$rtCode = $LASTEXITCODE
Remove-Item Env:REDTEAM_AGENT_IMAGE -ErrorAction SilentlyContinue
if ($rtCode -ne 0) { throw "FAIL: infrastructure/redteam/compose.redteam.yaml validation failed" }

Write-Host "[2/8] Running multi-service isolated-container DR backup & restore verification drill..." -ForegroundColor Yellow
powershell -ExecutionPolicy Bypass -File scripts/dr/backup_and_verify.ps1 | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: DR backup_and_verify script failed" }

Write-Host "[3/8] Running OPA policy tests (RBAC + Scope + Phase 8..15)..." -ForegroundColor Yellow
docker compose run --rm --no-deps -T opa test /policies -v | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: OPA tests failed" }

Write-Host "[4/8] Running vforge-scanners contracts & adapter tests..." -ForegroundColor Yellow
docker compose run --rm -v "${PWD}/packages/scanner-contracts:/opt/packages/scanner-contracts" api pytest -v -o cache_dir=/tmp/.pytest_cache /opt/packages/scanner-contracts/tests | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: scanner-contracts pytest failed" }

Write-Host "[5/8] Running API lint, mypy & full pytest suite (Phases 0..15 + migrator role ownership check)..." -ForegroundColor Yellow
docker compose stop orchestrator update-controller | Out-Host
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api ruff check --no-cache /app/src /app/tests /app/alembic | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: ruff check failed" }
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api ruff format --check /app/src /app/tests /app/alembic | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: ruff format --check failed" }
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api mypy --cache-dir /tmp/.mypy_cache /app/src | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: mypy failed" }
docker compose run --rm -e "PYTHONPATH=/app/src" -v "${PWD}:/workspace:ro" -v "${PWD}/apps/api/src:/app/src:ro" -v "${PWD}/apps/api/tests:/app/tests:ro" api pytest -v -o cache_dir=/tmp/.pytest_cache tests | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: API pytest suite failed" }
docker compose --profile ops run --rm -v "${PWD}/apps/api/tests:/app/tests:ro" migrator pytest -v -o cache_dir=/tmp/.pytest_cache tests/test_rls_isolation.py -k "test_postgresql_migrator_role_separation_when_configured" | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: migrator schema ownership test failed" }

Write-Host "[6/8] Running Runner Agent lint, mypy, non-root unit pytest & live-Docker scanner container pytest..." -ForegroundColor Yellow
docker compose -f runner/docker-compose.runner.yml --profile runner run --rm --no-deps -v "${PWD}/runner:/opt/runner" -v "${PWD}/packages/scanner-contracts/src/vforge_scanners:/usr/local/lib/python3.13/site-packages/vforge_scanners" -v "${PWD}/runner/vforge_runner:/usr/local/lib/python3.13/site-packages/vforge_runner" --entrypoint sh vforge-runner -c "ruff check --no-cache vforge_runner tests && ruff format --check vforge_runner tests && mypy --cache-dir /tmp/.mypy_cache vforge_runner && pytest -v -o cache_dir=/tmp/.pytest_cache tests" | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: Runner verification failed" }
docker run --rm --user 0:0 -v /var/run/docker.sock:/var/run/docker.sock -v /tmp:/tmp -v "${PWD}/runner/images:/opt/runner/images:ro" -v "${PWD}/runner/network-policy/seccomp-scanner.json:/opt/runner/network-policy/seccomp-scanner.json:ro" runner-vforge-runner:latest pytest -v -o cache_dir=/tmp/.pytest_cache tests/test_runner_isolation.py -k "test_live_docker" | Out-Host
if ($LASTEXITCODE -ne 0) { throw "FAIL: Runner live-Docker scanner container tests failed" }

Write-Host "[7/8] Checking Next.js typecheck, lint & build (including /redteam)..." -ForegroundColor Yellow
npm.cmd --prefix apps/web run typecheck
if ($LASTEXITCODE -ne 0) { throw "FAIL: web typecheck failed" }
npm.cmd --prefix apps/web run lint
if ($LASTEXITCODE -ne 0) { throw "FAIL: web lint failed" }
npm.cmd --prefix apps/web run build
if ($LASTEXITCODE -ne 0) { throw "FAIL: web build failed" }

Write-Host "[8/8] Verifying live /api/v1/meta, /metrics, web /api/health & unauthenticated denial..." -ForegroundColor Yellow
$meta = Invoke-RestMethod -UseBasicParsing -Uri "http://127.0.0.1:8000/api/v1/meta"
if ($meta.phase -lt 15 -or -not $meta.ai_redteam_governance_enabled -or $meta.ai_redteam_sandbox_enabled -ne $false) {
    throw "FAIL: /api/v1/meta did not report honest Phase 15 redteam governance/sandbox status"
}
$metricsText = (Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8000/metrics").Content
if ($metricsText -notmatch "vforge_build_info") {
    throw "FAIL: /metrics did not expose vforge_build_info"
}
$webHealth = Invoke-RestMethod -UseBasicParsing -Uri "http://127.0.0.1:3000/api/health"
if ($webHealth.status -ne "ok" -or $webHealth.phase -lt 15) {
    throw "FAIL: web /api/health did not report Phase 15"
}

$orgProbe = [guid]::NewGuid().ToString()
$denied = $false
try {
    Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8000/api/v1/organizations/$orgProbe/redteam/overview" | Out-Null
}
catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 401) {
        $denied = $true
    }
}
if (-not $denied) { throw "FAIL: unauthenticated redteam overview did not return 401" }

docker compose up -d orchestrator update-controller | Out-Host
Write-Host "Phase 15 AI Red-Team Sandbox & Final Release smoke verification PASSED cleanly." -ForegroundColor Green
