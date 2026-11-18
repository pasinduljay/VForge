$ErrorActionPreference = "Stop"

Write-Host "[1/7] Validating Docker Compose config..."
docker compose config --quiet
if ($LASTEXITCODE -ne 0) { throw "FAIL: docker compose config failed" }
$rendered = docker compose config --no-interpolate | Out-String

if ($rendered -match "docker\.sock") { throw "FAIL: docker.sock reference found in Compose config" }
if ($rendered -match "privileged:\s*true") { throw "FAIL: privileged container found in Compose config" }
if ($rendered -match "host_ip:\s*0\.0\.0\.0" -or $rendered -match '"0\.0\.0\.0:') {
  throw "FAIL: non-loopback 0.0.0.0 port binding found"
}

Write-Host "[2/7] Checking .env is not tracked by Git..."
$trackedEnv = git ls-files .env
if ($trackedEnv) { throw "FAIL: .env is tracked by Git" }

Write-Host "[3/7] Running OPA policy unit tests..."
docker compose run --rm --no-deps opa test /policies -v
if ($LASTEXITCODE -ne 0) { throw "FAIL: OPA policy tests failed" }

Write-Host "[4/7] Applying Alembic migrations via dedicated migrator role..."
docker compose --profile ops run --rm migrator alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic upgrade head failed" }
docker compose --profile ops run --rm migrator alembic current
if ($LASTEXITCODE -ne 0) { throw "FAIL: alembic current failed" }

Write-Host "[5/7] Checking API quality & unit tests..."
docker compose exec -T api ruff check src tests alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: ruff check failed" }
docker compose exec -T api ruff format --check src tests alembic
if ($LASTEXITCODE -ne 0) { throw "FAIL: ruff format check failed" }
docker compose exec -T api mypy src
if ($LASTEXITCODE -ne 0) { throw "FAIL: mypy failed" }
docker compose exec -T api pytest -v
if ($LASTEXITCODE -ne 0) { throw "FAIL: pytest failed" }

Write-Host "[6/7] Verifying control-plane HTTP health & readiness..."
$health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health"
if ($health.status -ne "ok") { throw "FAIL: /health did not return ok" }

$ready = Invoke-RestMethod -Uri "http://127.0.0.1:8000/ready"
if ($ready.status -ne "ready") { throw "FAIL: /ready did not return ready" }

$meta = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/meta"
if (($meta.phase -lt 5 -and $meta.scanners_enabled -ne $false) -or $meta.docker_socket_mounted -ne $false) {
  throw "FAIL: /api/v1/meta boundary check failed"
}

$webHealth = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/health"
if ($webHealth.status -ne "ok") { throw "FAIL: web /api/health did not return ok" }

$webHtml = (Invoke-WebRequest -Uri "http://127.0.0.1:3000/" -UseBasicParsing).Content
if ($webHtml -notmatch "Control Plane Ready") {
  throw "FAIL: web / did not render Control Plane Ready"
}

Write-Host "[7/8] Auditing running container hardening & loopback bindings..."
foreach ($svc in @("vforge-api-1", "vforge-frontend-1", "vforge-opa-1")) {
  $ro = docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' $svc
  if ($ro -ne "true") { throw "FAIL: $svc ReadonlyRootfs is $ro" }
  $capDrop = docker inspect --format '{{json .HostConfig.CapDrop}}' $svc
  if ($capDrop -notmatch "ALL") { throw "FAIL: $svc CapDrop missing ALL: $capDrop" }
}
foreach ($svc in @("vforge-api-1", "vforge-frontend-1", "vforge-opa-1", "vforge-postgres-1", "vforge-rabbitmq-1", "vforge-valkey-1")) {
  $priv = docker inspect --format '{{.HostConfig.Privileged}}' $svc
  if ($priv -ne "false") { throw "FAIL: $svc Privileged is $priv" }
  $mounts = docker inspect --format '{{json .Mounts}}' $svc
  if ($mounts -match "docker\.sock") { throw "FAIL: $svc mounts docker.sock" }
}

Write-Host "[8/8] Phase 0 smoke checks PASSED."
