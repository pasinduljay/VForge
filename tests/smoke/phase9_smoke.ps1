$ErrorActionPreference = "Stop"

Write-Host "=== VForge Phase 9 Acceptance Smoke Check ===" -ForegroundColor Cyan

Write-Host "[1/8] Checking Phase 9 migration (0010_phase9_threat_intel)..."
docker compose --profile ops run --rm migrator alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic upgrade head failed" }
$rev = docker compose --profile ops run --rm migrator alembic current | Out-String
if ($rev -notmatch "001\d_") {
  throw "FAIL: expected >= 0010_phase9_threat_intel, got: $rev"
}

Write-Host "[2/8] Running OPA policy tests (RBAC + Scope + Supply Chain + Phase 8 + Phase 9)..."
docker compose run --rm --no-deps opa test /policies -v
if ($LASTEXITCODE -ne 0) { throw "FAIL: OPA tests failed" }

Write-Host "[3/8] Running vforge-scanners contracts & adapter tests..."
docker compose run --rm -v "${PWD}/packages/scanner-contracts:/opt/packages/scanner-contracts" api pytest -v -o cache_dir=/tmp/.pytest_cache /opt/packages/scanner-contracts/tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: vforge-scanners tests failed" }

Write-Host "[4/8] Running API lint, mypy & pytest suite (including Phase 9 Threat Intelligence)..."
docker compose stop orchestrator | Out-Null
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

Write-Host "[6/8] Verifying Threat Intelligence Connectors, Privacy Gates & Enrichment..."
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" -e "PYTHONPATH=/app/src" --entrypoint python api -c @"
import json
import uuid
from datetime import datetime, UTC
from vforge.intel.connectors.cisa_kev import CisaKevConnector
from vforge.intel.connectors.first_epss import FirstEpssConnector
from vforge.intel.connectors.exploit_db import ExploitDbConnector
from vforge.intel.connectors.gated import VirusTotalGatedConnector, ShodanGatedConnector
from vforge.intel.connector import FeedBatch

# 1. Verify CISA KEV connector
kev = CisaKevConnector()
kev_batch = FeedBatch(
    cursor_before=None,
    cursor_after='2026.11',
    raw_payload={'title': 'CISA', 'catalogVersion': '2026.11', 'vulnerabilities': [{'cveID': 'CVE-2021-44228', 'vendorProject': 'Apache', 'product': 'Log4j', 'vulnerabilityName': 'RCE', 'dateAdded': '2021-12-10', 'shortDescription': 'RCE', 'requiredAction': 'Patch', 'dueDate': '2021-12-24', 'knownRansomwareCampaignUse': 'Known'}]},
    raw_hash='abc',
    retrieved_at=datetime.now(UTC),
    record_count=1,
)
assert kev.validate(kev_batch).is_valid
kev_records = kev.normalize(kev_batch)
assert len(kev_records) == 1
assert kev_records[0].is_known_exploited is True

# 2. Verify FIRST EPSS connector
epss = FirstEpssConnector()
epss_batch = FeedBatch(
    cursor_before=None,
    cursor_after='1',
    raw_payload={'status': 'OK', 'data': [{'cve': 'CVE-2021-44228', 'epss': '0.9745', 'percentile': '0.9998', 'date': '2026-11-13'}]},
    raw_hash='def',
    retrieved_at=datetime.now(UTC),
    record_count=1,
)
assert epss.validate(epss_batch).is_valid
epss_records = epss.normalize(epss_batch)
assert len(epss_records) == 1
assert epss_records[0].epss_score == 0.9745

# 3. Verify Exploit-DB connector safety
edb = ExploitDbConnector()
edb_batch = FeedBatch(
    cursor_before=None,
    cursor_after='1',
    raw_payload={'exploits': [{'id': '50592', 'file': '50592.py', 'description': 'Log4j RCE', 'date_published': '2021-12-15', 'author': 'test', 'type': 'remote', 'platform': 'multiple', 'port': '80', 'codes': 'CVE-2021-44228'}]},
    raw_hash='ghi',
    retrieved_at=datetime.now(UTC),
    record_count=1,
)
assert edb.validate(edb_batch).is_valid
edb_records = edb.normalize(edb_batch)
assert len(edb_records) == 1
assert 'Automated exploit execution is strictly prohibited' in edb_records[0].description

# 4. Verify Privacy Gates
vt = VirusTotalGatedConnector(allow_binary_upload=False)
try:
    vt.upload_file_binary('test.bin', b'malicious')
    raise AssertionError('Expected PermissionError on VT binary upload')
except PermissionError as e:
    assert 'PRIVACY GATE VIOLATION' in str(e)

shodan = ShodanGatedConnector()
try:
    shodan.query_host('unauthorized.target.com', is_in_scope=False)
    raise AssertionError('Expected PermissionError on Shodan out-of-scope query')
except PermissionError as e:
    assert 'SCOPE GATE VIOLATION' in str(e)

print('Phase 9 Threat Intelligence Connectors & Privacy Gates verified successfully!')
"@
if ($LASTEXITCODE -ne 0) { throw "FAIL: Threat intelligence engine verification failed" }

Write-Host "[7/8] Checking Next.js typecheck, lint & build..."
npm.cmd --prefix apps/web run typecheck
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js typecheck failed" }
npm.cmd --prefix apps/web run lint
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js lint failed" }
npm.cmd --prefix apps/web run build
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js build failed" }

Write-Host "[8/8] Verifying live /api/v1/meta, web /api/health & unauthenticated intel denial..."
$meta = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/meta" -Method Get
if ($meta.phase -lt 9 -or -not $meta.threat_intel_enabled -or -not ($meta.implemented_capabilities -contains "cisa-kev-exploitation-feed") -or -not ($meta.implemented_capabilities -contains "first-epss-probability-scoring") -or -not ($meta.implemented_capabilities -contains "nvd-cve-catalog-2.0") -or -not ($meta.implemented_capabilities -contains "exploit-db-reference-catalog")) {
  throw "FAIL: /api/v1/meta did not report Phase 9 capabilities: $($meta | ConvertTo-Json -Compress)"
}
if ($meta.docker_socket_mounted) { throw "FAIL: Control-plane API reports docker.sock mounted!" }

$webHealth = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/health"
if ($webHealth.status -ne "ok" -or $webHealth.phase -lt 9) {
  throw "FAIL: web /api/health did not return phase >= 9 ok: $($webHealth | ConvertTo-Json -Compress)"
}

$orgProbe = [guid]::NewGuid().ToString()
try {
  Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/v1/organizations/$orgProbe/intel/summary" -UseBasicParsing | Out-Null
  throw "FAIL: unauthenticated GET intel summary succeeded unexpectedly"
} catch {
  $statusCode = $_.Exception.Response.StatusCode.value__
  if ($statusCode -ne 401) {
    throw "FAIL: expected 401 on unauthenticated GET intel summary, got $statusCode"
  }
}

docker compose up -d orchestrator | Out-Null

Write-Host "Phase 9 Threat Intelligence Connectors & Offline Sync smoke verification PASSED cleanly." -ForegroundColor Green
