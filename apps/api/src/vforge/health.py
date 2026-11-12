"""Dependency readiness probes for PostgreSQL, RabbitMQ, Valkey, and OPA."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import aio_pika
import httpx
import valkey.asyncio as valkey_async
from sqlalchemy import text

from vforge.config import Settings
from vforge.db import build_engine

logger = logging.getLogger("vforge.health")

PROBE_TIMEOUT_SECONDS = 2.5


@dataclass(frozen=True)
class DependencyCheck:
    """Outcome of a single control-plane dependency probe."""

    status: str
    detail: str


async def check_postgres(settings: Settings) -> DependencyCheck:
    """Verify PostgreSQL connectivity and applied Alembic revision."""
    db_url = settings.effective_database_url
    if not db_url:
        return DependencyCheck(status="error", detail="not_configured")

    engine = build_engine(db_url)
    try:
        async with asyncio.timeout(PROBE_TIMEOUT_SECONDS):
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
                rev_result = await conn.execute(text("SELECT version_num FROM alembic_version"))
                revision = rev_result.scalar_one_or_none()
                if not revision:
                    return DependencyCheck(status="error", detail="migration_missing")
                return DependencyCheck(status="ok", detail=f"alembic:{revision}")
    except Exception as exc:
        logger.warning("postgres readiness check failed: %s", type(exc).__name__)
        return DependencyCheck(status="error", detail="connection_or_migration_failed")
    finally:
        await engine.dispose()


async def check_rabbitmq(settings: Settings) -> DependencyCheck:
    """Verify RabbitMQ AMQP connectivity and credentials."""
    amqp_url = settings.effective_rabbitmq_url
    if not amqp_url:
        return DependencyCheck(status="error", detail="not_configured")

    connection: aio_pika.abc.AbstractRobustConnection | None = None
    try:
        async with asyncio.timeout(PROBE_TIMEOUT_SECONDS):
            connection = await aio_pika.connect_robust(
                amqp_url,
                timeout=PROBE_TIMEOUT_SECONDS,
            )
            return DependencyCheck(status="ok", detail="amqp_connected")
    except Exception as exc:
        logger.warning("rabbitmq readiness check failed: %s", type(exc).__name__)
        return DependencyCheck(status="error", detail="connection_failed")
    finally:
        if connection is not None:
            await connection.close()


async def check_valkey(settings: Settings) -> DependencyCheck:
    """Verify Valkey connectivity and authentication with PING."""
    valkey_url = settings.effective_cache_url
    if not valkey_url:
        return DependencyCheck(status="error", detail="not_configured")

    client = valkey_async.from_url(  # type: ignore[no-untyped-call]
        valkey_url,
        socket_timeout=PROBE_TIMEOUT_SECONDS,
    )
    try:
        async with asyncio.timeout(PROBE_TIMEOUT_SECONDS):
            pong = await client.ping()
            if pong:
                return DependencyCheck(status="ok", detail="pong")
            return DependencyCheck(status="error", detail="unexpected_ping_response")
    except Exception as exc:
        logger.warning("valkey readiness check failed: %s", type(exc).__name__)
        return DependencyCheck(status="error", detail="connection_failed")
    finally:
        await client.aclose()


async def check_opa(settings: Settings) -> DependencyCheck:
    """Verify Open Policy Agent HTTP health endpoint."""
    if not settings.opa_url:
        return DependencyCheck(status="error", detail="not_configured")

    opa_health_url = f"{settings.opa_url.rstrip('/')}/health?bundles=true"
    try:
        async with httpx.AsyncClient(timeout=PROBE_TIMEOUT_SECONDS) as client:
            response = await client.get(opa_health_url)
            if response.status_code == 200:
                return DependencyCheck(status="ok", detail="healthy")
            return DependencyCheck(status="error", detail=f"http_{response.status_code}")
    except Exception as exc:
        logger.warning("opa readiness check failed: %s", type(exc).__name__)
        return DependencyCheck(status="error", detail="connection_failed")


async def run_readiness_checks(settings: Settings) -> dict[str, DependencyCheck]:
    """Run all control-plane dependency checks concurrently."""
    postgres, rabbitmq, valkey, opa = await asyncio.gather(
        check_postgres(settings),
        check_rabbitmq(settings),
        check_valkey(settings),
        check_opa(settings),
    )
    return {
        "postgres": postgres,
        "rabbitmq": rabbitmq,
        "valkey": valkey,
        "opa": opa,
    }
