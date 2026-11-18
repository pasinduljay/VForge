$ErrorActionPreference = "Stop"

Write-Host "=== VForge Phase 8 Acceptance Smoke Check ===" -ForegroundColor Cyan

Write-Host "[1/8] Checking Phase 8 migration (0009_phase8_findings_reporting)..."
docker compose --profile ops run --rm migrator alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic upgrade head failed" }
$rev = docker compose --profile ops run --rm migrator alembic current | Out-String
if ($rev -notmatch "0009_phase8_findings_reporting|001\d_") {
  throw "FAIL: expected >= 0009_phase8_findings_reporting, got: $rev"
}

Write-Host "[2/8] Running OPA policy tests (RBAC + Scope + Supply Chain + Phase 8)..."
docker compose run --rm --no-deps opa test /policies -v
if ($LASTEXITCODE -ne 0) { throw "FAIL: OPA tests failed" }

Write-Host "[3/8] Running vforge-scanners contracts & Phase 8 adapter tests..."
docker compose run --rm -v "${PWD}/packages/scanner-contracts:/opt/packages/scanner-contracts" api pytest -v -o cache_dir=/tmp/.pytest_cache /opt/packages/scanner-contracts/tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: vforge-scanners tests failed" }

Write-Host "[4/8] Running API lint, mypy & pytest suite (including Phase 8 Findings & Reporting)..."
docker compose stop orchestrator | Out-Null
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api ruff check --no-cache /app/src /app/tests /app/alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: API ruff check failed" }
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api ruff format --check /app/src /app/tests /app/alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: API ruff format check failed" }
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" api mypy --cache-dir /tmp/.mypy_cache /app/src
if ($LASTEXITCODE -ne 0) { throw "FAIL: API mypy failed" }
docker compose exec -T api pytest -v -o cache_dir=/tmp/.pytest_cache tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: API pytest suite failed" }

Write-Host "[5/8] Running Runner Agent lint, mypy & pytest..."
docker compose -f runner/docker-compose.runner.yml --profile runner run --rm --no-deps -v "${PWD}/runner:/opt/runner" -v "${PWD}/packages/scanner-contracts/src/vforge_scanners:/usr/local/lib/python3.13/site-packages/vforge_scanners" -v "${PWD}/runner/vforge_runner:/usr/local/lib/python3.13/site-packages/vforge_runner" --entrypoint sh vforge-runner -c "ruff check --no-cache vforge_runner tests && ruff format --check vforge_runner tests && mypy --cache-dir /tmp/.mypy_cache vforge_runner && pytest -v -o cache_dir=/tmp/.pytest_cache tests"
if ($LASTEXITCODE -ne 0) { throw "FAIL: runner quality gates / pytest failed" }

Write-Host "[6/8] Verifying Multi-Format Reporting Generator and Envelope Encryption..."
docker compose run --rm --no-deps -v "${PWD}/apps/api:/app" -e "PYTHONPATH=/app/src" --entrypoint python api -c @"
import json
import base64
import uuid
from datetime import datetime, UTC
from vforge.models.domain import Project
from vforge.models.scanner import Finding
from vforge.services.reporting import (
    _generate_html_report,
    _generate_pdf_report,
    _generate_json_report,
    _generate_sarif_report,
)
from vforge.security.envelope import encrypt_artifact_bytes, decrypt_artifact_bytes

kek_bytes = b'phase8-smoke-kek-32-bytes-exact!'
kek_b64 = base64.urlsafe_b64encode(kek_bytes).decode('ascii')
org_id = uuid.uuid4()
rep_id = uuid.uuid4()

project = Project(
    id=uuid.uuid4(),
    organization_id=org_id,
    name='Smoke Test Project',
    slug='smoke-test',
    criticality='tier_1',
)

finding = Finding(
    id=uuid.uuid4(),
    organization_id=org_id,
    project_id=project.id,
    fingerprint='smoke-fp-123456',
    category='sast',
    scanner_tool_id='opengrep',
    scanner_version='1.0.0',
    rule_id='test-rule',
    title='Sample Finding',
    severity='high',
    business_priority='P1',
    confidence='high',
    validation_status='confirmed',
    status='open',
    retest_status='none',
    sla_breached=False,
    sla_due_at=None,
    file_path='src/app.py',
    start_line=10,
    end_line=12,
    description='Sample description',
    remediation='Fix it',
    remediation_notes=None,
    code_snippet_redacted='foo()',
    secret_redacted=False,
    purl=None,
    fixed_version=None,
    cve_id=None,
    iac_resource=None,
    occurrence_count=1,
    first_seen_at=datetime.now(UTC),
    last_seen_at=datetime.now(UTC),
)

summary = {
    'total_findings': 1,
    'severity_counts': {'high': 1},
    'category_counts': {'sast': 1},
    'sla_breached_count': 0,
}

# Verify HTML generator
html_out = _generate_html_report(
    report_id=rep_id,
    title='Smoke Report',
    report_type='detailed_technical',
    project=project,
    scan_run=None,
    stages=[],
    jobs=[],
    findings=[finding],
    occurrences_by_finding={finding.id: []},
    summary=summary,
)
assert 'VForge' in html_out
assert 'Smoke Report' in html_out
assert 'Sample Finding' in html_out

# Verify PDF generator
pdf_out = _generate_pdf_report(
    report_id=rep_id,
    title='Smoke Report',
    project=project,
    findings=[finding],
    summary=summary,
)
assert pdf_out.startswith(b'%PDF-1.4')
assert b'%%EOF' in pdf_out

# Verify JSON generator
json_out = _generate_json_report(
    report_id=rep_id,
    title='Smoke Report',
    report_type='detailed_technical',
    project=project,
    scan_run=None,
    stages=[],
    jobs=[],
    findings=[finding],
    occurrences_by_finding={finding.id: []},
    summary=summary,
)
parsed_json = json.loads(json_out.decode('utf-8'))
assert parsed_json['title'] == 'Smoke Report'

# Verify SARIF generator
sarif_out = _generate_sarif_report(
    report_id=rep_id,
    findings=[finding],
    occurrences_by_finding={finding.id: []},
)
parsed_sarif = json.loads(sarif_out.decode('utf-8'))
assert parsed_sarif['version'] == '2.1.0'
assert len(parsed_sarif['runs'][0]['results']) == 1

# Verify AES-256-GCM envelope encryption round-trip
aad = b'tenant-smoke-aad'
enc = encrypt_artifact_bytes(
    plaintext=pdf_out,
    kek_id='smoke-key',
    kek_bytes=kek_bytes,
    aad=aad,
)
dec = decrypt_artifact_bytes(
    ciphertext=enc.ciphertext,
    expected_plaintext_sha256=enc.plaintext_sha256,
    expected_ciphertext_sha256=enc.ciphertext_sha256,
    kek_bytes=kek_bytes,
    wrapped_dek_b64=enc.wrapped_dek_b64,
    nonce_b64=enc.nonce_b64,
    aad_b64=enc.aad_b64,
)
assert dec == pdf_out, 'Decrypted PDF does not match original'

print('Phase 8 multi-format report generation and envelope encryption verified successfully!')
"@
if ($LASTEXITCODE -ne 0) { throw "FAIL: Multi-format reporting engine verification failed" }

Write-Host "[7/8] Checking Next.js typecheck, lint & build..."
npm.cmd --prefix apps/web run typecheck
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js typecheck failed" }
npm.cmd --prefix apps/web run lint
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js lint failed" }
npm.cmd --prefix apps/web run build
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js build failed" }

Write-Host "[8/8] Verifying live /api/v1/meta, web /api/health & unauthenticated reports denial..."
$meta = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/meta" -Method Get
if ($meta.phase -lt 8 -or -not $meta.reporting_enabled -or -not ($meta.implemented_capabilities -contains "canonical-finding-correlation") -or -not ($meta.implemented_capabilities -contains "sla-tracking-and-breaches") -or -not ($meta.implemented_capabilities -contains "multi-format-reporting-html")) {
  throw "FAIL: /api/v1/meta did not report Phase 8 capabilities: $($meta | ConvertTo-Json -Compress)"
}
if ($meta.docker_socket_mounted) { throw "FAIL: Control-plane API reports docker.sock mounted!" }

$webHealth = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/health"
if ($webHealth.status -ne "ok" -or $webHealth.phase -lt 8) {
  throw "FAIL: web /api/health did not return phase >= 8 ok: $($webHealth | ConvertTo-Json -Compress)"
}

$orgProbe = [guid]::NewGuid().ToString()
try {
  Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/v1/organizations/$orgProbe/reports" -UseBasicParsing | Out-Null
  throw "FAIL: unauthenticated GET reports succeeded unexpectedly"
} catch {
  $statusCode = $_.Exception.Response.StatusCode.value__
  if ($statusCode -ne 401) {
    throw "FAIL: expected 401 on unauthenticated GET reports, got $statusCode"
  }
}

docker compose up -d orchestrator | Out-Null

Write-Host "Phase 8 Findings & Reporting smoke verification PASSED cleanly." -ForegroundColor Green
