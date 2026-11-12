FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --gid 10001 vforge \
    && useradd --uid 10001 --gid 10001 --shell /sbin/nologin --create-home vforge \
    && mkdir -p /var/lib/vforge/artifacts \
    && chown -R 10001:10001 /var/lib/vforge /app

COPY --chown=10001:10001 packages/scope-validator /opt/packages/scope-validator
COPY --chown=10001:10001 packages/scanner-contracts /opt/packages/scanner-contracts
COPY --chown=10001:10001 apps/api/pyproject.toml ./
COPY --chown=10001:10001 apps/api/src ./src

RUN pip install --no-cache-dir /opt/packages/scope-validator /opt/packages/scanner-contracts ".[dev]"

COPY --chown=10001:10001 apps/api/alembic.ini ./
COPY --chown=10001:10001 apps/api/alembic ./alembic
COPY --chown=10001:10001 apps/api/tests ./tests
COPY --chown=10001:10001 infrastructure/lab /opt/infrastructure/lab
COPY --chown=10001:10001 infrastructure/redteam /opt/infrastructure/redteam
COPY --chown=10001:10001 infrastructure/keycloak /opt/infrastructure/keycloak
COPY --chown=10001:10001 infrastructure/portainer /opt/portainer-init
COPY --chown=10001:10001 docker-compose.yml /opt/infrastructure/docker-compose.yml
COPY --chown=10001:10001 runner/docker-compose.runner.yml /opt/infrastructure/docker-compose.runner.yml
COPY --chown=10001:10001 lifecycle/image-lock /opt/lifecycle/image-lock
COPY --chown=10001:10001 policies /opt/policies

USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "vforge.main:app", "--host", "0.0.0.0", "--port", "8000"]
