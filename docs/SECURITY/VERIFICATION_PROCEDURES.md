# VForge Security Verification Procedures

Run these non-destructive verification checks before completing any phase commit. **Never** print `.env` values, pass passwords on command lines, or run `docker compose down -v`.

## 1. Secret & Repository Hygiene Audit

```powershell
# Confirm .env and .secrets/ remain untracked and ignored
git ls-files .env .secrets

# Verify Compose manifests without interpolating secrets
docker compose --profile dev-oidc --profile ops config --quiet
$rendered = docker compose --profile dev-oidc --profile ops config --no-interpolate | Out-String
```

Check `$rendered` contains zero `docker.sock`, zero `privileged: true`, and zero `0.0.0.0` bindings.

## 2. Database, Broker & Cache Least-Privilege Verification

```powershell
# PostgreSQL role separation & table ownership (non-secret metadata only)
docker exec vforge-postgres-1 psql -U vforge -d vforge -c "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolinherit, rolcanlogin, rolbypassrls FROM pg_roles WHERE rolname IN ('vforge','vforge_migrator','vforge_app') ORDER BY rolname;"
docker exec vforge-postgres-1 psql -U vforge -d vforge -c "SELECT tableowner, COUNT(*) FROM pg_tables WHERE schemaname='public' GROUP BY tableowner;"

# RabbitMQ users, vhosts, and permissions
docker exec vforge-rabbitmq-1 rabbitmqctl list_users
docker exec vforge-rabbitmq-1 rabbitmqctl list_vhosts
docker exec vforge-rabbitmq-1 rabbitmqctl list_permissions -p vforge
docker exec vforge-rabbitmq-1 rabbitmqctl list_permissions -p /
```

## 3. Automated Security Suites

```powershell
docker compose run --rm --no-deps opa test /policies -v
docker compose --profile ops run --rm migrator pytest -v -o cache_dir=/tmp/.pytest_cache tests/test_rls_isolation.py
docker compose exec -T api pytest -v -o cache_dir=/tmp/.pytest_cache tests/test_security_preflight.py tests/test_logging_redaction.py tests/test_oidc_jwt.py tests/test_rbac_matrix.py tests/test_phase2_scope_authz.py
docker compose exec -T api pytest -v -o cache_dir=/tmp/.pytest_cache /opt/packages/scope-validator/tests
```
