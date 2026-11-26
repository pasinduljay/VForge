FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 runner \
    && useradd --uid 10001 --gid 10001 --shell /sbin/nologin --create-home runner \
    && mkdir -p /opt/runner/work /opt/runner/network-policy \
    && chown -R 10001:10001 /opt/runner

WORKDIR /opt/runner

COPY --chown=10001:10001 packages/scope-validator /opt/packages/scope-validator
COPY --chown=10001:10001 packages/scanner-contracts /opt/packages/scanner-contracts
COPY --chown=10001:10001 runner/pyproject.toml ./
COPY --chown=10001:10001 runner/vforge_runner ./vforge_runner
COPY --chown=10001:10001 runner/network-policy ./network-policy
COPY --chown=10001:10001 runner/images/checkov/policies ./checkov-policies
COPY --chown=10001:10001 runner/images/dummy-scanner ./images/dummy-scanner
COPY --chown=10001:10001 runner/tests ./tests
COPY --chown=10001:10001 infrastructure/bootstrap /opt/bootstrap

RUN pip install --no-cache-dir /opt/packages/scope-validator /opt/packages/scanner-contracts ".[dev]"

USER 10001:10001

CMD ["vforge-runner", "--gateway-url", "https://runner-gateway:8443"]
