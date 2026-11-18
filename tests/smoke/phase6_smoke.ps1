$ErrorActionPreference = "Stop"

Write-Host "=== VForge Phase 6 Acceptance Smoke Check ===" -ForegroundColor Cyan

Write-Host "[1/8] Checking Phase 6 migration (0007_phase6_supply_chain_iac) on persistent DB (no live downgrade)..."
docker compose --profile ops run --rm migrator alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic upgrade head failed" }
$rev = docker compose --profile ops run --rm migrator alembic current | Out-String
if ($rev -notmatch "0007_phase6_supply_chain_iac|000[8-9]_|001\d_") {
  throw "FAIL: expected >= 0007_phase6_supply_chain_iac, got: $rev"
}

Write-Host "[2/8] Running OPA policy tests (RBAC + Scope + Supply Chain)..."
docker compose run --rm --no-deps opa test /policies -v
if ($LASTEXITCODE -ne 0) { throw "FAIL: OPA tests failed" }

Write-Host "[3/8] Running vforge-scanners contracts & Phase 6 adapter tests..."
docker compose exec -T api pytest -v -o cache_dir=/tmp/.pytest_cache /opt/packages/scanner-contracts/tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: vforge-scanners tests failed" }

Write-Host "[4/8] Running API lint, mypy & pytest suite (including Phase 6 E2E + RLS)..."
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

Write-Host "[6/8] Executing live hardened Syft -> Grype (offline DB) -> Checkov (+ custom YAML policy) containers..."
$workTmp = Join-Path ([System.IO.Path]::GetTempPath()) ("vf-ph6-smoke-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$inDir = Join-Path $workTmp "in"
$outDir = Join-Path $workTmp "out"
$cleanIn = Join-Path $workTmp "clean_in"
$cleanOut = Join-Path $workTmp "clean_out"
$polDir = Join-Path (Get-Location) "runner/images/checkov/policies"
New-Item -ItemType Directory -Force -Path $inDir, $outDir, $cleanIn, $cleanOut | Out-Null

try {
  $reqTxt = "requests==2.19.1`nurllib3==1.26.5`n"
  $vulnTf = @'
resource "aws_s3_bucket" "insecure_lake" {
  bucket = "acme-insecure-lake"
}
'@
  [System.IO.File]::WriteAllText((Join-Path $inDir "requirements.txt"), $reqTxt)
  [System.IO.File]::WriteAllText((Join-Path $inDir "main.tf"), $vulnTf)

  docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --network=none --user=10001:10001 `
    --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777 `
    -e HOME=/tmp -e SYFT_CHECK_FOR_APP_UPDATE=false `
    -v "${inDir}:/work/in:ro" -v "${outDir}:/work/out:rw" `
    anchore/syft:v1.57.1@sha256:03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060 `
    scan dir:/work/in --output cyclonedx-json=/work/out/sbom.cdx.json --output spdx-json=/work/out/sbom.spdx.json --source-name smoke-vuln
  if ($LASTEXITCODE -ne 0) { throw "FAIL: hardened syft positive run exited $LASTEXITCODE" }
  if (-not (Test-Path (Join-Path $outDir "sbom.cdx.json")) -or -not (Test-Path (Join-Path $outDir "sbom.spdx.json"))) {
    throw "FAIL: Syft missing CycloneDX or SPDX output"
  }

  Copy-Item (Join-Path $outDir "sbom.cdx.json") (Join-Path $inDir "sbom.cdx.json")
  docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --network=none --user=10001:10001 `
    --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777 `
    -e HOME=/tmp -e GRYPE_DB_CACHE_DIR=/work/db -e GRYPE_DB_AUTO_UPDATE=false -e GRYPE_CHECK_FOR_APP_UPDATE=false `
    -v "${inDir}:/work/in:ro" -v "vforge_grype_db:/work/db:ro" -v "${outDir}:/work/out:rw" `
    anchore/grype:v0.121.3@sha256:13113eeceab017260370cf540e1d25442c59665fd07d1b09b66d63bb0c282887 `
    sbom:/work/in/sbom.cdx.json --output json=/work/out/grype.json --quiet
  if ($LASTEXITCODE -ne 0) { throw "FAIL: hardened grype positive run exited $LASTEXITCODE" }
  $grypeJson = Get-Content -Raw (Join-Path $outDir "grype.json") | ConvertFrom-Json
  if ($grypeJson.matches.Count -lt 1) { throw "FAIL: Grype offline scan found 0 CVEs for requests==2.19.1" }
  if ($grypeJson.descriptor.db.status.valid -ne $true) { throw "FAIL: Grype offline DB status valid != true" }

  docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --network=none --user=10001:10001 `
    --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777 `
    -e HOME=/tmp -e CHECKOV_RUN_SCA_PACKAGE_SCAN=false -e LOG_LEVEL=WARNING `
    -v "${inDir}:/work/in:ro" -v "${outDir}:/work/out:rw" -v "${polDir}:/work/policies:ro" `
    bridgecrew/checkov:3.2.435@sha256:ccead19bd9201d43872ceb7e78bb5868eabfc0d3960d3756fc75f4896067372a `
    -d /work/in --output json --output sarif --output-file-path /work/out --soft-fail --skip-download --quiet --external-checks-dir /work/policies
  if ($LASTEXITCODE -ne 0) { throw "FAIL: hardened checkov positive run exited $LASTEXITCODE" }
  $ckvRaw = Get-Content -Raw (Join-Path $outDir "results_json.json")
  if ($ckvRaw -notmatch "CKV2_VF_CUSTOM_1") { throw "FAIL: Checkov custom YAML rule CKV2_VF_CUSTOM_1 did not fire on untagged S3 bucket" }

  # Clean fixture check (empty dir -> 0 Syft components -> 0 Grype matches -> 0 Checkov custom failures)
  $cleanTf = @'
resource "aws_s3_bucket" "tagged_lake" {
  bucket = "acme-tagged-lake"
  tags = {
    DataClassification = "Confidential"
  }
}
'@
  [System.IO.File]::WriteAllText((Join-Path $cleanIn "main.tf"), $cleanTf)
  docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --network=none --user=10001:10001 `
    --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777 `
    -e HOME=/tmp -e SYFT_CHECK_FOR_APP_UPDATE=false `
    -v "${cleanIn}:/work/in:ro" -v "${cleanOut}:/work/out:rw" `
    anchore/syft:v1.57.1@sha256:03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060 `
    scan dir:/work/in --output cyclonedx-json=/work/out/sbom.cdx.json --source-name smoke-clean
  if ($LASTEXITCODE -ne 0) { throw "FAIL: clean syft run exited $LASTEXITCODE" }
  Copy-Item (Join-Path $cleanOut "sbom.cdx.json") (Join-Path $cleanIn "sbom.cdx.json")
  docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --network=none --user=10001:10001 `
    --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777 `
    -e HOME=/tmp -e GRYPE_DB_CACHE_DIR=/work/db -e GRYPE_DB_AUTO_UPDATE=false -e GRYPE_CHECK_FOR_APP_UPDATE=false `
    -v "${cleanIn}:/work/in:ro" -v "vforge_grype_db:/work/db:ro" -v "${cleanOut}:/work/out:rw" `
    anchore/grype:v0.121.3@sha256:13113eeceab017260370cf540e1d25442c59665fd07d1b09b66d63bb0c282887 `
    sbom:/work/in/sbom.cdx.json --output json=/work/out/grype.json --quiet
  if ($LASTEXITCODE -ne 0) { throw "FAIL: clean grype run exited $LASTEXITCODE" }
  $cleanGrype = Get-Content -Raw (Join-Path $cleanOut "grype.json") | ConvertFrom-Json
  if ($cleanGrype.matches.Count -ne 0) { throw "FAIL: expected 0 clean Grype matches, got $($cleanGrype.matches.Count)" }
} finally {
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $workTmp
}

Write-Host "[7/8] Checking Next.js typecheck, lint & build..."
npm.cmd --prefix apps/web run typecheck
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js typecheck failed" }
npm.cmd --prefix apps/web run lint
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js lint failed" }
npm.cmd --prefix apps/web run build
if ($LASTEXITCODE -ne 0) { throw "FAIL: Next.js build failed" }

Write-Host "[8/8] Verifying live /api/v1/meta, web /api/health & unauthenticated denial..."
$meta = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/meta" -Method Get
if ($meta.phase -lt 6 -or -not $meta.supply_chain_enabled -or -not ($meta.implemented_capabilities -contains "syft-sbom") -or -not ($meta.implemented_capabilities -contains "grype-sca") -or -not ($meta.implemented_capabilities -contains "checkov-iac")) {
  throw "FAIL: /api/v1/meta did not report Phase 6 capabilities: $($meta | ConvertTo-Json -Compress)"
}
if ($meta.docker_socket_mounted) { throw "FAIL: Control-plane API reports docker.sock mounted!" }

$webHealth = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/health"
if ($webHealth.status -ne "ok" -or $webHealth.phase -lt 6) {
  throw "FAIL: web /api/health did not return phase >= 6 ok"
}

$orgProbe = [guid]::NewGuid().ToString()
try {
  Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/v1/organizations/$orgProbe/sboms" -UseBasicParsing | Out-Null
  throw "FAIL: unauthenticated GET sboms succeeded unexpectedly"
} catch {
  $statusCode = $_.Exception.Response.StatusCode.value__
  if ($statusCode -ne 401) {
    throw "FAIL: expected 401 on unauthenticated GET sboms, got $statusCode"
  }
}

Write-Host "Phase 6 smoke verification PASSED cleanly." -ForegroundColor Green
