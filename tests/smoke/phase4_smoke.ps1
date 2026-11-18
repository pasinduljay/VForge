$ErrorActionPreference = "Stop"

Write-Host "=== VForge Phase 4 Acceptance Smoke Check ===" -ForegroundColor Cyan

Write-Host "[1/8] Checking control-plane vs execution-plane isolation..."
docker compose --profile runner config --quiet
if ($LASTEXITCODE -ne 0) { throw "FAIL: docker compose config failed" }
$renderedControl = docker compose --profile runner config --no-interpolate | Out-String
if ($renderedControl -match "docker\.sock") { throw "FAIL: docker.sock found in control-plane Compose config" }
if ($renderedControl -match "privileged:\s*true") { throw "FAIL: privileged container found in control-plane Compose" }

$runnerOverlay = Get-Content -Raw "runner/docker-compose.runner.yml"
if ($runnerOverlay -match "POSTGRES_|RABBITMQ_|VALKEY_|OPENBAO_|SCOPE_SIGNING_") {
  throw "FAIL: runner overlay must not receive control-plane credentials"
}

Write-Host "[2/8] Verifying Alembic 0005 migration via isolated migrator..."
docker compose --profile ops run --rm migrator alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic upgrade head failed" }
$rev = docker compose --profile ops run --rm migrator alembic current | Out-String
if ($rev -notmatch "000[5-9]_|001\d_") { throw "FAIL: expected >= 0005 migration head, got: $rev" }

Write-Host "[3/8] Running OPA policy tests..."
docker compose run --rm --no-deps opa test /policies -v
if ($LASTEXITCODE -ne 0) { throw "FAIL: OPA tests failed" }

Write-Host "[4/8] Running Control-Plane API lint, typecheck & pytest..."
docker compose exec -T api ruff check src tests alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: API ruff check failed" }
docker compose exec -T api ruff format --check src tests alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: API ruff format check failed" }
docker compose exec -T api mypy src
if ($LASTEXITCODE -ne 0) { throw "FAIL: API mypy failed" }
docker compose exec -T api pytest -v tests
if ($LASTEXITCODE -ne 0) { throw "FAIL: API pytest failed" }

Write-Host "[5/8] Running Isolated Runner Agent lint, strict mypy & pytest..."
docker compose -f runner/docker-compose.runner.yml --profile runner build vforge-runner
if ($LASTEXITCODE -ne 0) { throw "FAIL: vforge-runner image build failed" }
docker compose -f runner/docker-compose.runner.yml --profile runner run --rm --no-deps --entrypoint sh vforge-runner -c "ruff check vforge_runner tests && ruff format --check vforge_runner tests && mypy vforge_runner && pytest -v tests"
if ($LASTEXITCODE -ne 0) { throw "FAIL: runner quality gates / pytest failed" }

Write-Host "[6/8] Verifying Dummy Scanner image builds & runs non-root..."
docker build -t vforge-dummy-scanner:smoke runner/images/dummy-scanner
if ($LASTEXITCODE -ne 0) { throw "FAIL: dummy-scanner build failed" }
$uid = docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --network=none --entrypoint id vforge-dummy-scanner:smoke -u
if ($LASTEXITCODE -ne 0 -or $uid.Trim() -ne "10001") { throw "FAIL: dummy-scanner UID is $uid (expected 10001)" }

Write-Host "[7/8] Checking /api/v1/meta and web /api/health Phase 4 boundaries..."
$meta = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/meta"
if (
  $meta.phase -lt 4 -or
  ($meta.phase -lt 5 -and $meta.scanners_enabled -ne $false) -or
  $meta.docker_socket_mounted -ne $false -or
  ($meta.implemented_capabilities -notcontains "runner-mtls-gateway")
) {
  throw "FAIL: /api/v1/meta Phase 4 boundary check failed"
}

$webHealth = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/health"
if ($webHealth.status -ne "ok" -or $webHealth.phase -lt 4) {
  throw "FAIL: web /api/health did not return phase >= 4 ok"
}

Write-Host "[8/8] Auditing control-plane container hardening..."
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

Write-Host "Phase 4 smoke & acceptance checks PASSED." -ForegroundColor Green
