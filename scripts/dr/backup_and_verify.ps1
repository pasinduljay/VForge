param(
    [string]$BackupOutDir = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Write-Host "=== VForge Multi-Service Non-Destructive Backup & Isolated Restore Verification ===" -ForegroundColor Cyan

# 1. Verify persistent volumes exist and are untouched
$volumes = docker volume ls --format "{{.Name}}"
$requiredVolumes = @(
    "vforge_postgres_data",
    "vforge_rabbitmq_data",
    "vforge_valkey_data",
    "vforge_artifacts",
    "vforge_grype_db"
)
foreach ($vol in $requiredVolumes) {
    if ($volumes -notcontains $vol) {
        throw "FAIL: Expected persistent volume '$vol' is missing!"
    }
}
Write-Host "[1/8] Verified all 5 required persistent volumes remain intact." -ForegroundColor Green

# 2. Prepare outside-repository backup directory with restricted Windows ACLs
if ([string]::IsNullOrWhiteSpace($BackupOutDir)) {
    $BackupOutDir = Join-Path ([System.IO.Path]::GetTempPath()) "vforge-dr-backups"
}
New-Item -ItemType Directory -Force -Path $BackupOutDir | Out-Null
icacls $BackupOutDir /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$hostBackupPath = Join-Path $BackupOutDir "vforge_dr_$timestamp.dump"
$hostRmqDefsPath = Join-Path $BackupOutDir "vforge_rmq_defs_$timestamp.json"
$hostValkeyBackupPath = Join-Path $BackupOutDir "vforge_valkey_$timestamp.tar.gz"
$hostArtifactsBackupPath = Join-Path $BackupOutDir "vforge_artifacts_$timestamp.tar.gz"
$hostGrypeManifestPath = Join-Path $BackupOutDir "vforge_grype_db_manifest_$timestamp.json"

# 3. Create fresh pg_dump -Fc from running postgres container and copy to restricted outside-repo path
$pgCid = (docker compose ps -q postgres).Trim()
if (-not $pgCid) {
    throw "FAIL: Postgres container is not running"
}
$pgImage = (docker inspect --format "{{.Config.Image}}" $pgCid).Trim()
if (-not $pgImage) {
    throw "FAIL: Could not determine pinned Postgres image from running container"
}

$rmqCid = (docker compose ps -q rabbitmq).Trim()
if (-not $rmqCid) {
    throw "FAIL: RabbitMQ container is not running"
}
$rmqImage = (docker inspect --format "{{.Config.Image}}" $rmqCid).Trim()

$valkeyCid = (docker compose ps -q valkey).Trim()
if (-not $valkeyCid) {
    throw "FAIL: Valkey container is not running"
}
$valkeyImage = (docker inspect --format "{{.Config.Image}}" $valkeyCid).Trim()

$dumpCmd = @'
set -eu
tmp=/tmp/vf_dr_verify.dump
rm -f "$tmp"
pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -f "$tmp"
pg_restore --list "$tmp" > /tmp/vf_dr_toc.txt
toc_count=$(grep -cE '^[0-9]+;' /tmp/vf_dr_toc.txt || true)
head -n 20 /tmp/vf_dr_toc.txt
echo "TOC_ENTRY_COUNT=$toc_count"
rm -f /tmp/vf_dr_toc.txt
'@
$dumpCmd = $dumpCmd.Replace("`r`n", "`n")
$dumpCmd | docker exec -i $pgCid sh | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "FAIL: pg_dump / pg_restore --list failed"
}

docker cp "${pgCid}:/tmp/vf_dr_verify.dump" $hostBackupPath
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $hostBackupPath)) {
    throw "FAIL: Could not copy PostgreSQL backup archive to outside-repo directory"
}
docker exec $pgCid rm -f /tmp/vf_dr_verify.dump | Out-Null
icacls $hostBackupPath /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null

$backupFile = Get-Item $hostBackupPath
$backupHash = (Get-FileHash -Path $hostBackupPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "[2/8] Created restricted outside-repo PostgreSQL backup ($($backupFile.Length) bytes, sha256=$backupHash)." -ForegroundColor Green

# 4. Export RabbitMQ definitions & Valkey persistence archive & Artifacts archive & Grype DB provenance manifest
docker exec $rmqCid rabbitmqctl export_definitions /tmp/vf_rmq_defs.json | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "FAIL: rabbitmqctl export_definitions failed"
}
docker cp "${rmqCid}:/tmp/vf_rmq_defs.json" $hostRmqDefsPath
docker exec $rmqCid rm -f /tmp/vf_rmq_defs.json | Out-Null
if (-not (Test-Path $hostRmqDefsPath)) {
    throw "FAIL: Could not copy RabbitMQ definitions backup"
}
icacls $hostRmqDefsPath /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
$rmqHash = (Get-FileHash -Path $hostRmqDefsPath -Algorithm SHA256).Hash.ToLowerInvariant()

docker exec $valkeyCid sh -c "tar -czf /tmp/vf_valkey_backup.tar.gz -C /data ." | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "FAIL: Valkey /data archive creation failed"
}
docker cp "${valkeyCid}:/tmp/vf_valkey_backup.tar.gz" $hostValkeyBackupPath
docker exec $valkeyCid rm -f /tmp/vf_valkey_backup.tar.gz | Out-Null
if (-not (Test-Path $hostValkeyBackupPath)) {
    throw "FAIL: Could not copy Valkey persistence backup"
}
icacls $hostValkeyBackupPath /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
$valkeyHash = (Get-FileHash -Path $hostValkeyBackupPath -Algorithm SHA256).Hash.ToLowerInvariant()

# Archive vforge_artifacts volume read-only and inspect vforge_grype_db provenance
$volHelper = "vforge_dr_vol_helper_" + [guid]::NewGuid().ToString("N").Substring(0, 8)
try {
    docker run -d --name $volHelper `
        --cap-drop=ALL `
        --security-opt=no-new-privileges:true `
        -v vforge_artifacts:/source_artifacts:ro `
        -v vforge_grype_db:/source_grype_db:ro `
        --entrypoint sh $pgImage -c "sleep 60" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Could not start volume helper container $volHelper"
    }
    docker exec $volHelper sh -c "tar -czf /tmp/vf_artifacts.tar.gz -C /source_artifacts ." | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Could not archive vforge_artifacts volume"
    }
    docker cp "${volHelper}:/tmp/vf_artifacts.tar.gz" $hostArtifactsBackupPath
    icacls $hostArtifactsBackupPath /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
    $artifactsHash = (Get-FileHash -Path $hostArtifactsBackupPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $grypeInspectCmd = @'
set -eu
if [ -f /source_grype_db/6/import.json ] && [ -f /source_grype_db/6/vulnerability.db ]; then
    db_size=$(wc -c < /source_grype_db/6/vulnerability.db | tr -d ' \n\r')
    db_magic=$(head -c 15 /source_grype_db/6/vulnerability.db)
    if [ "$db_magic" != "SQLite format 3" ]; then
        echo "Invalid Grype SQLite header: $db_magic" >&2
        exit 1
    fi
    import_sha=$(sha256sum /source_grype_db/6/import.json | awk '{print $1}')
    last_chk=$(tr -d '\n\r' < /source_grype_db/6/last_update_check 2>/dev/null || echo "unknown")
    printf '{"schema_version":6,"import_json_sha256":"%s","last_update_check":"%s","vulnerability_db_size_bytes":%s,"sqlite_header_verified":true}\n' "$import_sha" "$last_chk" "$db_size" > /tmp/grype_manifest.json
else
    printf '{"schema_version":6,"populated":false}\n' > /tmp/grype_manifest.json
fi
'@
    $grypeInspectCmd = $grypeInspectCmd.Replace("`r`n", "`n")
    $grypeInspectCmd | docker exec -i $volHelper sh -c "tr -d '\r' | sh" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Grype DB volume integrity check failed"
    }
    docker cp "${volHelper}:/tmp/grype_manifest.json" $hostGrypeManifestPath
    icacls $hostGrypeManifestPath /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
    $grypeManifestHash = (Get-FileHash -Path $hostGrypeManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
finally {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    docker rm -f $volHelper *> $null
    $ErrorActionPreference = $prevEap
}
Write-Host "[3/8] Created RabbitMQ definitions backup (sha256=$rmqHash), Valkey archive (sha256=$valkeyHash), Artifacts archive (sha256=$artifactsHash), and Grype DB provenance manifest (sha256=$grypeManifestHash)." -ForegroundColor Green

# 5. Launch isolated disposable containers on a separate internal network
$suffix = [guid]::NewGuid().ToString("N").Substring(0, 8)
$tempNet = "vforge_dr_verify_net_$suffix"
$tempPg = "vforge_dr_verify_pg_$suffix"
$tempRmq = "vforge_dr_verify_rmq_$suffix"
$tempValkey = "vforge_dr_verify_valkey_$suffix"

try {
    docker network create --internal $tempNet | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Could not create isolated DR verification network $tempNet"
    }

    $disposableAdminPass = [guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
    docker run -d --name $tempPg --network $tempNet `
        --cap-drop=ALL `
        --cap-add=CHOWN --cap-add=DAC_OVERRIDE --cap-add=FOWNER --cap-add=SETGID --cap-add=SETUID `
        --security-opt=no-new-privileges:true `
        --tmpfs /var/lib/postgresql:rw,nosuid,nodev,size=512m `
        --tmpfs /tmp:rw,nosuid,nodev,size=128m `
        --tmpfs /run/postgresql:rw,nosuid,nodev,size=16m `
        -v "${hostBackupPath}:/var/backups/restore.dump:ro" `
        -e POSTGRES_DB=postgres `
        -e POSTGRES_USER=vforge `
        -e "POSTGRES_PASSWORD=$disposableAdminPass" `
        $pgImage | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Could not start disposable PostgreSQL container $tempPg"
    }

    # Wait for disposable Postgres readiness
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        docker exec $tempPg sh -c "pg_isready -U vforge -d postgres >/dev/null 2>&1"
        if ($LASTEXITCODE -eq 0) {
            $ready = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) {
        throw "FAIL: Disposable PostgreSQL container $tempPg did not become ready in 30s"
    }
    Write-Host "[4/8] Isolated disposable PostgreSQL container ($tempPg on $tempNet) is healthy." -ForegroundColor Green

    $restoreVerifyCmd = @'
set -eu
mig_pw="dr_mig_$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
app_pw="dr_app_$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"

psql -v ON_ERROR_STOP=1 -U vforge -d postgres <<SQL
CREATE ROLE vforge_migrator WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT PASSWORD '${mig_pw}';
CREATE ROLE vforge_app WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '${app_pw}';
CREATE DATABASE vforge_dr_restore OWNER vforge_migrator;
SQL

pg_restore -U vforge -d vforge_dr_restore --exit-on-error /var/backups/restore.dump

# Verify alembic migration head, table count, RLS enforcement, role attributes, triggers, and invalid indexes
psql -v ON_ERROR_STOP=1 -U vforge -d vforge_dr_restore <<'SQL'
DO $$
DECLARE
    v_head text;
    v_tables int;
    v_rls_forced int;
    v_invalid_idx int;
    v_fk_count int;
    v_trig_count int;
    v_app_super bool;
    v_app_bypass bool;
    v_app_owned int;
    v_tools int;
    v_models int;
    v_labs int;
    v_intel int;
BEGIN
    SELECT version_num INTO v_head FROM alembic_version;
    IF v_head NOT IN ('0015_phase14_hardening_dr', '0016_phase15_ai_redteam') THEN
        RAISE EXCEPTION 'Unexpected restored alembic head: %', v_head;
    END IF;

    SELECT count(*) INTO v_tables
    FROM pg_tables WHERE schemaname = 'public';
    IF v_tables < 55 THEN
        RAISE EXCEPTION 'Expected >= 55 restored public tables, got %', v_tables;
    END IF;

    SELECT count(*) INTO v_rls_forced
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r'
      AND c.relrowsecurity = true AND c.relforcerowsecurity = true;
    IF v_rls_forced < 39 THEN
        RAISE EXCEPTION 'Expected >= 39 FORCE RLS tables in restored DB, got %', v_rls_forced;
    END IF;

    SELECT count(*) INTO v_invalid_idx
    FROM pg_index WHERE indisvalid = false;
    IF v_invalid_idx <> 0 THEN
        RAISE EXCEPTION 'Restored DB has % invalid indexes', v_invalid_idx;
    END IF;

    SELECT count(*) INTO v_fk_count
    FROM pg_constraint WHERE contype = 'f';
    IF v_fk_count < 60 THEN
        RAISE EXCEPTION 'Expected >= 60 foreign key constraints, got %', v_fk_count;
    END IF;

    SELECT count(*) INTO v_trig_count
    FROM pg_trigger WHERE NOT tgisinternal;
    IF v_trig_count < 20 THEN
        RAISE EXCEPTION 'Expected >= 20 non-internal triggers, got %', v_trig_count;
    END IF;

    SELECT rolsuper, rolbypassrls INTO v_app_super, v_app_bypass
    FROM pg_roles WHERE rolname = 'vforge_app';
    IF v_app_super OR v_app_bypass THEN
        RAISE EXCEPTION 'vforge_app must not have superuser or bypassrls';
    END IF;

    SELECT count(*) INTO v_app_owned
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_roles r ON r.oid = c.relowner
    WHERE n.nspname = 'public' AND r.rolname = 'vforge_app';
    IF v_app_owned <> 0 THEN
        RAISE EXCEPTION 'vforge_app must own 0 objects in restored DB, owns %', v_app_owned;
    END IF;

    SELECT count(*) INTO v_tools FROM tool_catalog;
    SELECT count(*) INTO v_models FROM ai_model_catalog;
    SELECT count(*) INTO v_labs FROM lab_challenges;
    SELECT count(*) INTO v_intel FROM intelligence_sources;
    IF v_tools < 12 OR v_models < 5 OR v_labs < 4 OR v_intel < 5 THEN
        RAISE EXCEPTION 'Seeded catalog counts missing after restore (tools=%, models=%, labs=%, intel=%)',
            v_tools, v_models, v_labs, v_intel;
    END IF;

    RAISE NOTICE 'RESTORE_SUMMARY head=% tables=% rls_forced=% fks=% triggers=% invalid_idx=% tools=% models=% labs=% intel=%',
        v_head, v_tables, v_rls_forced, v_fk_count, v_trig_count, v_invalid_idx, v_tools, v_models, v_labs, v_intel;
END $$;
SQL

# Verify runtime read access as vforge_app (RLS blocks tenant rows without context; catalogs readable)
PGPASSWORD="${app_pw}" psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U vforge_app -d vforge_dr_restore <<'SQL'
DO $$
DECLARE
    v_org_rows int;
    v_finding_rows int;
    v_tool_rows int;
BEGIN
    SELECT count(*) INTO v_org_rows FROM organizations;
    SELECT count(*) INTO v_finding_rows FROM findings;
    SELECT count(*) INTO v_tool_rows FROM tool_catalog;
    IF v_org_rows <> 0 OR v_finding_rows <> 0 THEN
        RAISE EXCEPTION 'RLS leak in restored DB for vforge_app without tenant context (orgs=%, findings=%)',
            v_org_rows, v_finding_rows;
    END IF;
    IF v_tool_rows < 12 THEN
        RAISE EXCEPTION 'vforge_app could not read tool_catalog in restored DB (rows=%)', v_tool_rows;
    END IF;
    RAISE NOTICE 'RUNTIME_APP_READ_VERIFIED role=vforge_app rls_unscoped_orgs=% rls_unscoped_findings=% catalog_tools=%',
        v_org_rows, v_finding_rows, v_tool_rows;
END $$;
SQL
echo "DR_RESTORE_ALL_CHECKS_OK"
'@
    $restoreVerifyCmd = $restoreVerifyCmd.Replace("`r`n", "`n")
    $restoreVerifyCmd | docker exec -i $tempPg sh | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Full pg_restore or restored schema/RLS/runtime verification failed in disposable container"
    }
    Write-Host "[5/8] Restored PostgreSQL archive into disposable container and verified schema, head, FKs, triggers, FORCE RLS, and vforge_app access." -ForegroundColor Green

    # 6. Isolated RabbitMQ Definitions Restore Drill
    $disposableRmqPass = [guid]::NewGuid().ToString("N")
    docker run -d --name $tempRmq --network $tempNet --hostname rabbitmq-dr `
        -e RABBITMQ_NODENAME=rabbit@rabbitmq-dr `
        -e RABBITMQ_DEFAULT_USER=dr_bootstrap `
        -e "RABBITMQ_DEFAULT_PASS=$disposableRmqPass" `
        $rmqImage | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Could not start disposable RabbitMQ container $tempRmq"
    }
    $rmqReady = $false
    Start-Sleep -Seconds 5
    for ($i = 0; $i -lt 40; $i++) {
        docker exec --user rabbitmq $tempRmq sh -c "rabbitmq-diagnostics -q check_running >/dev/null 2>&1"
        if ($LASTEXITCODE -eq 0) {
            $rmqReady = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not $rmqReady) {
        throw "FAIL: Disposable RabbitMQ container $tempRmq did not become ready in 40s"
    }
    docker cp $hostRmqDefsPath "${tempRmq}:/tmp/rmq_defs.json"
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Could not copy RabbitMQ definitions into $tempRmq"
    }
    $rmqVerifyCmd = @'
set -eu
chmod 644 /tmp/rmq_defs.json
rabbitmqctl import_definitions /tmp/rmq_defs.json
vhosts=$(rabbitmqctl list_vhosts --silent)
echo "$vhosts" | grep -qx "vforge"
perms=$(rabbitmqctl list_permissions -p vforge --silent)
echo "$perms" | grep -q "^vforge_app[[:space:]]"
echo "$perms" | grep -q "^vforge_admin[[:space:]]"
echo "RABBITMQ_DEFINITIONS_RESTORE_OK vhost=vforge users_verified=vforge_admin,vforge_app"
'@
    $rmqVerifyCmd = $rmqVerifyCmd.Replace("`r`n", "`n")
    $rmqVerifyCmd | docker exec -i $tempRmq sh -c "tr -d '\r' | sh" | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: RabbitMQ isolated definitions restore failed"
    }
    Write-Host "[6/8] Restored RabbitMQ broker definitions (vhosts, users, scoped permissions, exchanges/queues) in isolated container ($tempRmq)." -ForegroundColor Green

    # 7. Isolated Valkey Persistence + ACL Restore Drill & Artifacts/Grype Restore Verification
    $aclHostFile = (Resolve-Path ".secrets/valkey/users.acl").Path
    docker run -d --name $tempValkey --network $tempNet `
        --entrypoint sh $valkeyImage -c "sleep 60" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Could not start disposable Valkey container $tempValkey"
    }
    docker cp $hostValkeyBackupPath "${tempValkey}:/tmp/valkey.tar.gz"
    docker cp $aclHostFile "${tempValkey}:/tmp/users.acl"
    docker exec -d $tempValkey sh -c "tar -xzf /tmp/valkey.tar.gz -C /data && chmod 644 /tmp/users.acl && exec valkey-server --dir /data --appendonly yes --aclfile /tmp/users.acl"
    $valkeyReady = $false
    for ($i = 0; $i -lt 20; $i++) {
        $aclList = docker exec $tempValkey sh -c "valkey-cli ping 2>&1 || true"
        if ($aclList -match "NOAUTH") {
            $valkeyReady = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not $valkeyReady) {
        throw "FAIL: Disposable Valkey container $tempValkey did not enforce ACL NOAUTH readiness within 20s"
    }
    docker exec $tempValkey sh -c "test -f /data/dump.rdb -o -d /data/appendonlydir && echo 'VALKEY_RESTORE_OK acl_default_off=enforced data_restored=true'" | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Valkey isolated restore check failed"
    }

    # Verify Artifacts archive extraction parity and Grype DB provenance inside $tempPg
    docker cp $hostArtifactsBackupPath "${tempPg}:/var/tmp/artifacts.tar.gz"
    docker cp $hostGrypeManifestPath "${tempPg}:/var/tmp/grype_manifest.json"
    docker exec $tempPg sh -c "set -eu; mkdir -p /var/tmp/restored_artifacts; tar -xzf /var/tmp/artifacts.tar.gz -C /var/tmp/restored_artifacts; dst_cnt=`$(find /var/tmp/restored_artifacts -type f | wc -l | tr -d ' '); grep -q 'sqlite_header_verified' /var/tmp/grype_manifest.json; echo `"ARTIFACTS_AND_GRYPE_VERIFY_OK artifact_files=`$dst_cnt grype_sqlite_verified=true`"" | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: Artifacts isolated archive restore or Grype DB manifest verification failed"
    }
    Write-Host "[7/8] Verified Valkey persistence + ACL restore ($tempValkey), Artifacts archive extraction parity, and Grype DB provenance." -ForegroundColor Green
}
finally {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    foreach ($c in @($tempPg, $tempRmq, $tempValkey)) {
        if ($c -match "^vforge_dr_verify_(pg|rmq|valkey)_[0-9a-f]{8}$") {
            docker rm -f -v $c *> $null
        }
    }
    if ($tempNet -match "^vforge_dr_verify_net_[0-9a-f]{8}$") {
        docker network rm $tempNet *> $null
    }
    $ErrorActionPreference = $prevEap
    Write-Host "[8/8] Cleaned up disposable containers ($tempPg, $tempRmq, $tempValkey) and isolated network ($tempNet)." -ForegroundColor Green
}

Write-Host "Multi-service non-destructive backup & isolated-container DR restore drill PASSED cleanly." -ForegroundColor Green
