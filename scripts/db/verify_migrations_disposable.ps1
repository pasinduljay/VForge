$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Write-Host "=== VForge Disposable-Database Full Migration Chain Verification (0001..0016) ===" -ForegroundColor Cyan

$pgCid = (docker compose ps -q postgres).Trim()
if (-not $pgCid) {
    throw "FAIL: Postgres container is not running"
}

$suffix = [guid]::NewGuid().ToString("N").Substring(0, 8)
$tempDb = "vforge_mig_verify_$suffix"

try {
    Write-Host "[1/5] Creating isolated disposable database '$tempDb'..." -ForegroundColor Yellow
    $initSql = @"
CREATE DATABASE $tempDb OWNER vforge_migrator;
\connect $tempDb
CREATE EXTENSION IF NOT EXISTS pgcrypto;
GRANT ALL ON SCHEMA public TO vforge_migrator;
"@
    $initSql = $initSql.Replace("`r`n", "`n")
    $initSql | docker exec -i $pgCid psql -v ON_ERROR_STOP=1 -U vforge -d postgres | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Could not create disposable database $tempDb"
    }

    Write-Host "[2/5] Running full upgrade chain (base -> 0016_phase15_ai_redteam) on '$tempDb'..." -ForegroundColor Yellow
    docker compose --profile ops run --rm -T -e "POSTGRES_DB=$tempDb" -v "${PWD}/apps/api/alembic:/app/alembic:ro" migrator alembic upgrade head | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Full migration upgrade head (base -> 0016) failed on $tempDb"
    }

    Write-Host "[3/5] Running full downgrade chain (0016_phase15_ai_redteam -> base) on '$tempDb'..." -ForegroundColor Yellow
    docker compose --profile ops run --rm -T -e "POSTGRES_DB=$tempDb" -v "${PWD}/apps/api/alembic:/app/alembic:ro" migrator alembic downgrade base | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Full migration downgrade base (0016 -> base) failed on $tempDb"
    }

    Write-Host "[4/5] Re-running full upgrade chain (base -> 0016_phase15_ai_redteam) on '$tempDb'..." -ForegroundColor Yellow
    docker compose --profile ops run --rm -T -e "POSTGRES_DB=$tempDb" -v "${PWD}/apps/api/alembic:/app/alembic:ro" migrator alembic upgrade head | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Second migration upgrade head failed on $tempDb"
    }

    $curHead = docker compose --profile ops run --rm -T -e "POSTGRES_DB=$tempDb" migrator alembic current
    if ($LASTEXITCODE -ne 0 -or ($curHead -notmatch "0016_phase15_ai_redteam")) {
        throw "FAIL: Expected 0016_phase15_ai_redteam on $tempDb, got: $curHead"
    }
    Write-Host "[5/5] Verified disposable DB '$tempDb' reached head: $($curHead.Trim())" -ForegroundColor Green
}
finally {
    if ($tempDb -match "^vforge_mig_verify_[0-9a-f]{8}$") {
        docker exec $pgCid psql -v ON_ERROR_STOP=1 -U vforge -d postgres -c "DROP DATABASE IF EXISTS $tempDb WITH (FORCE);" | Out-Null
        Write-Host "Cleaned up disposable database '$tempDb' (persistent 'vforge' DB untouched)." -ForegroundColor Green
    }
}

Write-Host "Disposable-database full migration chain (0001..0016 upgrade -> downgrade base -> upgrade head) PASSED." -ForegroundColor Green
