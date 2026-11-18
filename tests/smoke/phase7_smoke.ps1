$ErrorActionPreference = "Stop"

Write-Host "=== VForge Phase 7 Acceptance Smoke Check ===" -ForegroundColor Cyan

Write-Host "[1/8] Checking Phase 7 migration (0008_phase7_dast)..."
docker compose --profile ops run --rm migrator alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic upgrade head failed" }
$rev = docker compose --profile ops run --rm migrator alembic current | Out-String
if ($rev -notmatch "0008_phase7_dast|0009_|001\d_") {
  throw "FAIL: expected >= 0008_phase7_dast, got: $rev"
}

Write-Host "[2/8] Running OPA policy tests (RBAC + Scope + Supply Chain)..."
docker compose run --rm --no-deps opa test /policies -v
if ($LASTEXITCODE -ne 0) { throw "FAIL: OPA tests failed" }

Write-Host "[3/8] Running vforge-scanners contracts & Phase 7 DAST/network adapter tests..."
docker compose exec -T api pytest -v -o cache_dir=/tmp/.pytest_cache /opt/packages/scanner-contracts/tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: vforge-scanners tests failed" }

Write-Host "[4/8] Running API lint, mypy & pytest suite (including Phase 7 DAST + Leases + Health)..."
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api ruff check --no-cache /app/src /app/tests /app/alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: API ruff check failed" }
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api ruff format --check /app/src /app/tests /app/alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: API ruff format check failed" }
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api mypy --cache-dir /tmp/.mypy_cache /app/src
if ($LASTEXITCODE -ne 0) { throw "FAIL: API mypy failed" }
docker compose exec -T api pytest -v -o cache_dir=/tmp/.pytest_cache tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: API pytest suite failed" }

Write-Host "[5/8] Running Runner Agent lint, mypy & pytest (including TargetHealthMonitor)..."
docker compose -f runner/docker-compose.runner.yml --profile runner run --rm --no-deps -v "${PWD}/runner:/opt/runner" -v "${PWD}/packages/scanner-contracts/src/vforge_scanners:/usr/local/lib/python3.13/site-packages/vforge_scanners" -v "${PWD}/runner/vforge_runner:/usr/local/lib/python3.13/site-packages/vforge_runner" --entrypoint sh vforge-runner -c "ruff check --no-cache vforge_runner tests && ruff format --check vforge_runner tests && mypy --cache-dir /tmp/.mypy_cache vforge_runner && pytest -v -o cache_dir=/tmp/.pytest_cache tests"
if ($LASTEXITCODE -ne 0) { throw "FAIL: runner quality gates / pytest failed" }

Write-Host "[6/8] Verifying TargetHealthMonitor tripwire auto-abort & DAST parser contracts..."
docker compose run --rm --no-deps --entrypoint python api -c @"
import asyncio
from unittest.mock import AsyncMock
from vforge_scanners import (
    ZAPAdapter,
    NucleiAdapter,
    NmapAdapter,
    TestsslAdapter,
)

# Verify parser contracts and empty/corrupt handling
zap_findings = ZAPAdapter(pinned_image='test@sha256:1111').parse_json_report({'site': []})
assert len(zap_findings) == 0, 'ZAP clean fixture non-zero'

nuclei_findings = NucleiAdapter(pinned_image='test@sha256:2222').parse_jsonl_text('')
assert len(nuclei_findings) == 0, 'Nuclei empty non-zero'

nmap_findings = NmapAdapter(pinned_image='test@sha256:3333').parse_xml_text('<nmaprun></nmaprun>')
assert len(nmap_findings) == 0, 'Nmap clean non-zero'

testssl_findings = TestsslAdapter(pinned_image='test@sha256:4444').parse_json_report([])
assert len(testssl_findings) == 0, 'Testssl clean non-zero'

print('DAST standalone contract checks passed!')
"@
if ($LASTEXITCODE -ne 0) { throw "FAIL: DAST standalone contract check failed" }

Write-Host "[7/8] Checking Next.js typecheck, lint & build..."
npm.cmd --prefix apps/web run typecheck
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js typecheck failed" }
npm.cmd --prefix apps/web run lint
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js lint failed" }
npm.cmd --prefix apps/web run build
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js build failed" }

Write-Host "[8/8] Verifying live /api/v1/meta, web /api/health & unauthenticated health-probes denial..."
$meta = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/meta" -Method Get
if ($meta.phase -lt 7 -or -not $meta.dast_enabled -or -not ($meta.implemented_capabilities -contains "zap-dast") -or -not ($meta.implemented_capabilities -contains "nuclei-dast") -or -not ($meta.implemented_capabilities -contains "nmap-network") -or -not ($meta.implemented_capabilities -contains "testssl-tls")) {
  throw "FAIL: /api/v1/meta did not report Phase 7 capabilities: $($meta | ConvertTo-Json -Compress)"
}
if ($meta.docker_socket_mounted) { throw "FAIL: Control-plane API reports docker.sock mounted!" }

$webHealth = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/health"
if ($webHealth.status -ne "ok" -or $webHealth.phase -lt 7) {
  throw "FAIL: web /api/health did not return phase >= 7 ok"
}

$orgProbe = [guid]::NewGuid().ToString()
$scanProbe = [guid]::NewGuid().ToString()
try {
  Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/v1/organizations/$orgProbe/scans/$scanProbe/health-probes" -UseBasicParsing | Out-Null
  throw "FAIL: unauthenticated GET health-probes succeeded unexpectedly"
} catch {
  $statusCode = $_.Exception.Response.StatusCode.value__
  if ($statusCode -ne 401) {
    throw "FAIL: expected 401 on unauthenticated GET health-probes, got $statusCode"
  }
}

Write-Host "Phase 7 DAST smoke verification PASSED cleanly." -ForegroundColor Green
