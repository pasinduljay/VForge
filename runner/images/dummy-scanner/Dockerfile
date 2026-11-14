FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 scanner \
    && useradd --uid 10001 --gid 10001 --shell /sbin/nologin --create-home scanner \
    && mkdir -p /opt/scanner /work/in /work/out \
    && chown -R 10001:10001 /opt/scanner /work

COPY --chown=10001:10001 entrypoint.py /opt/scanner/entrypoint.py

USER 10001:10001
WORKDIR /work

ENTRYPOINT ["python", "/opt/scanner/entrypoint.py"]
