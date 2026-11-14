FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ARG TARGETARCH
ARG OPENGREP_VERSION=v1.33.1
ARG OPENGREP_SHA256_AMD64=46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808
ARG OPENGREP_SHA256_ARM64=d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    XDG_CACHE_HOME=/opt/opengrep/cache \
    OPENGREP_SEND_METRICS=off

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates; \
    arch="${TARGETARCH:-amd64}"; \
    case "${arch}" in \
      amd64) asset="opengrep_manylinux_x86"; expected_sha="${OPENGREP_SHA256_AMD64}" ;; \
      arm64) asset="opengrep_manylinux_aarch64"; expected_sha="${OPENGREP_SHA256_ARM64}" ;; \
      *) echo "Unsupported architecture: ${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${asset}" -o /usr/local/bin/opengrep; \
    echo "${expected_sha}  /usr/local/bin/opengrep" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/opengrep; \
    apt-get purge -y --auto-remove curl; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --gid 10001 vforge; \
    useradd --uid 10001 --gid 10001 --shell /sbin/nologin --create-home vforge; \
    mkdir -p /opt/opengrep/rules /work/in /work/out; \
    chown -R 10001:10001 /opt/opengrep /work

COPY --chown=10001:10001 rules/ /opt/opengrep/rules/

USER 10001:10001
RUN mkdir -p /opt/opengrep/cache && /usr/local/bin/opengrep --version && /usr/local/bin/opengrep scan --validate --config /opt/opengrep/rules/vforge-baseline.yaml
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/opengrep"]
