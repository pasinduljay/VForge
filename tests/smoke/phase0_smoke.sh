#!/usr/bin/env bash
set -euo pipefail

echo "[1/7] Validating Docker Compose config..."
docker compose config --quiet
rendered="$(docker compose config --no-interpolate)"

if grep -q "docker.sock" <<<"$rendered"; then
  echo "FAIL: docker.sock reference found in Compose config" >&2
  exit 1
fi
if grep -q "privileged: true" <<<"$rendered"; then
  echo "FAIL: privileged container found in Compose config" >&2
  exit 1
fi
if grep -qE 'host_ip:\s*0\.0\.0\.0|"0\.0\.0\.0:' <<<"$rendered"; then
  echo "FAIL: non-loopback 0.0.0.0 port binding found" >&2
  exit 1
fi

echo "[2/7] Checking .env is ignored by Git..."
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git ls-files --error-unmatch .env >/dev/null 2>&1; then
    echo "FAIL: .env is tracked by Git" >&2
    exit 1
  fi
fi

echo "[3/7] Running OPA policy unit tests..."
docker compose run --rm --no-deps opa test /policies -v

echo "[4/7] Applying Alembic migrations via dedicated migrator role..."
docker compose --profile ops run --rm migrator alembic upgrade head
docker compose --profile ops run --rm migrator alembic current

echo "[5/7] Checking API quality & unit tests..."
docker compose exec -T api ruff check src tests alembic
docker compose exec -T api ruff format --check src tests alembic
docker compose exec -T api mypy src
docker compose exec -T api pytest -v

echo "[6/7] Verifying control-plane HTTP health & readiness..."
curl -fsS http://127.0.0.1:8000/health | grep -q '"status":"ok"'
curl -fsS http://127.0.0.1:8000/ready | grep -q '"status":"ready"'
curl -fsS http://127.0.0.1:8000/api/v1/meta | grep -q '"docker_socket_mounted":false'
curl -fsS http://127.0.0.1:3000/api/health | grep -q '"status":"ok"'
curl -fsS http://127.0.0.1:3000/ | grep -q 'Control Plane Ready'

echo "[7/8] Auditing running container hardening & loopback bindings..."
for svc in vforge-api-1 vforge-frontend-1 vforge-opa-1; do
  ro="$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$svc")"
  [ "$ro" = "true" ] || { echo "FAIL: $svc ReadonlyRootfs=$ro" >&2; exit 1; }
  cap="$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$svc")"
  grep -q "ALL" <<<"$cap" || { echo "FAIL: $svc CapDrop=$cap" >&2; exit 1; }
done
for svc in vforge-api-1 vforge-frontend-1 vforge-opa-1 vforge-postgres-1 vforge-rabbitmq-1 vforge-valkey-1; do
  priv="$(docker inspect --format '{{.HostConfig.Privileged}}' "$svc")"
  [ "$priv" = "false" ] || { echo "FAIL: $svc Privileged=$priv" >&2; exit 1; }
  mounts="$(docker inspect --format '{{json .Mounts}}' "$svc")"
  if grep -q "docker.sock" <<<"$mounts"; then
    echo "FAIL: $svc mounts docker.sock" >&2
    exit 1
  fi
done

echo "[8/8] Phase 0 smoke checks PASSED."
