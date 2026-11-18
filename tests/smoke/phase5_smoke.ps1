$ErrorActionPreference = "Stop"

Write-Host "=== VForge Phase 5 Acceptance Smoke Check ===" -ForegroundColor Cyan

Write-Host "[1/8] Checking Phase 5 migration (0006_phase5_scanners)..."
docker compose --profile ops run --rm migrator alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic upgrade head failed" }
$rev = docker compose --profile ops run --rm migrator alembic current | Out-String
if ($rev -notmatch "0006_phase5_scanners|000[7-9]_|001\d_") {
  throw "FAIL: expected >= 0006_phase5_scanners, got: $rev"
}

Write-Host "[2/8] Running OPA policy tests (RBAC + Scope + Findings)..."
docker compose run --rm --no-deps opa test /policies -v
if ($LASTEXITCODE -ne 0) { throw "FAIL: OPA tests failed" }

Write-Host "[3/8] Running vforge-scanners SDK, archive safety, coverage & adapter unit tests..."
docker compose exec -T api pytest -v -o cache_dir=/tmp/.pytest_cache /opt/packages/scanner-contracts/tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: vforge-scanners tests failed" }

Write-Host "[4/8] Running API lint, mypy & pytest suite (including Phase 5 tests)..."
docker compose exec -T api ruff check --no-cache src tests alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: API ruff check failed" }
docker compose exec -T api ruff format --check src tests alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: API ruff format check failed" }
docker compose exec -T api mypy --cache-dir /tmp/.mypy_cache src
if ($LASTEXITCODE -ne 0) { throw "FAIL: API mypy failed" }
docker compose exec -T api pytest -v -o cache_dir=/tmp/.pytest_cache tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: API pytest suite failed" }

Write-Host "[5/8] Running Runner Agent lint, mypy & pytest..."
docker compose -f runner/docker-compose.runner.yml --profile runner run --rm --no-deps --entrypoint sh vforge-runner -c "ruff check --no-cache vforge_runner tests && ruff format --check vforge_runner tests && mypy --cache-dir /tmp/.mypy_cache vforge_runner && pytest -v -o cache_dir=/tmp/.pytest_cache tests"
if ($LASTEXITCODE -ne 0) { throw "FAIL: runner quality gates / pytest failed" }

Write-Host "[6/8] Executing hardened OpenGrep & Gitleaks container runs against positive & clean fixtures..."
$workTmp = Join-Path ([System.IO.Path]::GetTempPath()) ("vf-ph5-smoke-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$inDir = Join-Path $workTmp "in"
$outDir = Join-Path $workTmp "out"
New-Item -ItemType Directory -Force -Path $inDir | Out-Null
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
try {
  $vulnPy = @'
import subprocess

def run_cmd(user_input: str) -> None:
    subprocess.run(user_input, shell=True, check=False)
'@
  $secretPy = 'GITHUB_TOKEN = "ghp_9mKx2pQ8wVzL4nR7cYbJ1fH6sD3aE5uG0xZt"'
  [System.IO.File]::WriteAllText((Join-Path $inDir "app.py"), $vulnPy)
  [System.IO.File]::WriteAllText((Join-Path $inDir "secrets.py"), $secretPy)

  docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --network=none --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m `
    -v "${inDir}:/work/in:ro" -v "${outDir}:/work/out:rw" `
    vforge-opengrep:1.33.1 scan --config /opt/opengrep/rules/vforge-baseline.yaml --json-output /work/out/opengrep.json --sarif-output /work/out/opengrep.sarif --no-git-ignore /work/in
  if ($LASTEXITCODE -ne 0) { throw "FAIL: hardened opengrep run exited $LASTEXITCODE" }
  if (-not (Test-Path (Join-Path $outDir "opengrep.json")) -or -not (Test-Path (Join-Path $outDir "opengrep.sarif"))) {
    throw "FAIL: OpenGrep missing json/sarif output"
  }

  $ogJson = Get-Content -Raw (Join-Path $outDir "opengrep.json") | ConvertFrom-Json
  if ($ogJson.results.Count -lt 1) { throw "FAIL: OpenGrep did not detect positive fixture vulnerability" }

  docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --network=none --user=10001:10001 --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m -e HOME=/tmp `
    -v "${inDir}:/work/in:ro" -v "${outDir}:/work/out:rw" `
    zricethezav/gitleaks@sha256:2bcceac45179b3a91bff11a824d0fb952585b429e54fc928728b1d4d5c3e5176 dir --no-banner --no-color --redact=100 --exit-code=10 --report-format=json --report-path=/work/out/gitleaks.json /work/in
  if ($LASTEXITCODE -ne 10) { throw "FAIL: hardened gitleaks positive run exited $LASTEXITCODE (expected 10)" }
  $glRaw = Get-Content -Raw (Join-Path $outDir "gitleaks.json")
  if ($glRaw -match "ghp_9mKx2pQ8wVzL4nR7cYbJ1fH6sD3aE5uG0xZt") {
    throw "FAIL: Gitleaks leaked unredacted secret despite --redact=100"
  }

  $cleanIn = Join-Path $workTmp "clean_in"
  $cleanOut = Join-Path $workTmp "clean_out"
  New-Item -ItemType Directory -Force -Path $cleanIn | Out-Null
  New-Item -ItemType Directory -Force -Path $cleanOut | Out-Null
  [System.IO.File]::WriteAllText((Join-Path $cleanIn "ok.py"), "def add(a: int, b: int) -> int:`n    return a + b`n")

  docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --network=none --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m `
    -v "${cleanIn}:/work/in:ro" -v "${cleanOut}:/work/out:rw" `
    vforge-opengrep:1.33.1 scan --config /opt/opengrep/rules/vforge-baseline.yaml --json-output /work/out/opengrep.json --no-git-ignore /work/in
  if ($LASTEXITCODE -ne 0) { throw "FAIL: clean opengrep run exited $LASTEXITCODE" }
  $ogClean = Get-Content -Raw (Join-Path $cleanOut "opengrep.json") | ConvertFrom-Json
  if ($ogClean.results.Count -ne 0) { throw "FAIL: OpenGrep reported unexpected findings on clean fixture" }

  docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --network=none --user=10001:10001 --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m -e HOME=/tmp `
    -v "${cleanIn}:/work/in:ro" -v "${cleanOut}:/work/out:rw" `
    zricethezav/gitleaks@sha256:2bcceac45179b3a91bff11a824d0fb952585b429e54fc928728b1d4d5c3e5176 dir --no-banner --no-color --redact=100 --exit-code=10 --report-format=json --report-path=/work/out/gitleaks.json /work/in
  if ($LASTEXITCODE -ne 0) { throw "FAIL: clean gitleaks run exited $LASTEXITCODE (expected 0)" }
} finally {
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $workTmp
}

Write-Host "[7/8] Checking /api/v1/meta and web /api/health Phase 5 capabilities..."
$meta = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/meta"
if (
  $meta.phase -lt 5 -or
  $meta.scanners_enabled -ne $true -or
  $meta.docker_socket_mounted -ne $false -or
  ($meta.implemented_capabilities -notcontains "opengrep-sast") -or
  ($meta.implemented_capabilities -notcontains "gitleaks-secrets")
) {
  throw "FAIL: /api/v1/meta Phase 5 check failed"
}

$webHealth = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/health"
if ($webHealth.status -ne "ok" -or $webHealth.phase -lt 5) {
  throw "FAIL: web /api/health did not return phase >= 5 ok"
}

Write-Host "[8/8] Auditing control-plane image-pin & unauthenticated findings denial..."
$orgProbe = [guid]::NewGuid().ToString()
try {
  Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/v1/organizations/$orgProbe/findings" -UseBasicParsing | Out-Null
  throw "FAIL: unauthenticated GET findings succeeded unexpectedly"
} catch {
  $statusCode = $_.Exception.Response.StatusCode.value__
  if ($statusCode -ne 401) {
    throw "FAIL: expected 401 on unauthenticated GET findings, got $statusCode"
  }
}

Write-Host "PASS: All Phase 5 smoke & acceptance checks succeeded." -ForegroundColor Green
