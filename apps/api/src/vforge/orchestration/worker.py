"""Phase 3 control-plane orchestration worker entrypoint (no Docker socket, no scanners)."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from vforge.config import Settings, get_settings
from vforge.db import (
    build_engine,
    build_session_factory,
    set_db_context,
    verify_runtime_db_identity,
)
from vforge.logging import configure_logging
from vforge.models.domain import Asset, Authorization
from vforge.models.enums import AuthorizationStatus, RegistrationState
from vforge.models.orchestration import RunnerJob, ScanRun
from vforge.orchestration.broker import RabbitMqOrchestrationBroker
from vforge.orchestration.service import (
    dispatch_pending_outbox_once,
    process_dispatch_message,
    reconcile_orchestration_once,
)

logger = logging.getLogger("vforge.orchestration.worker")


async def run_worker(settings: Settings | None = None) -> None:
    """Run outbox dispatcher, RabbitMQ consumer, and lease reconciler until stopped."""
    cfg = settings or get_settings()
    configure_logging(cfg.log_level)
    cfg.validate_startup_configuration()

    db_url = cfg.effective_database_url
    amqp_url = cfg.effective_rabbitmq_url
    if not db_url or not amqp_url:
        raise RuntimeError("Orchestrator worker requires effective database and RabbitMQ URLs")

    engine = build_engine(db_url)
    identity = await verify_runtime_db_identity(engine)
    logger.info("orchestrator_verified_runtime_db role=%s", identity["role"])
    session_factory = build_session_factory(engine)
    broker = RabbitMqOrchestrationBroker(amqp_url)
    await broker.ensure_topology()

    worker_id = f"orchestrator-{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    stop_event = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop_event.set)

    async def _pre_dispatch_authorization_check(run: ScanRun, _job: RunnerJob) -> bool:
        now = datetime.now(UTC)
        async with session_factory() as check_session:
            await set_db_context(check_session, org_id=run.organization_id)
            auth = (
                await check_session.execute(
                    select(Authorization).where(
                        Authorization.id == run.authorization_id,
                        Authorization.organization_id == run.organization_id,
                    )
                )
            ).scalar_one_or_none()
            if (
                auth is None
                or auth.status != AuthorizationStatus.APPROVED.value
                or auth.valid_from > now
                or auth.expires_at <= now
            ):
                return False
            asset = (
                await check_session.execute(
                    select(Asset).where(
                        Asset.id == auth.asset_id,
                        Asset.organization_id == run.organization_id,
                    )
                )
            ).scalar_one_or_none()
            return (
                asset is not None
                and asset.registration_state != RegistrationState.DECOMMISSIONED.value
            )

    async def _handle_message(payload: dict[str, Any]) -> bool:
        outcome = await process_dispatch_message(
            session_factory,
            payload,
            worker_id=worker_id,
            settings=cfg,
            pre_dispatch_hook=_pre_dispatch_authorization_check,
        )
        logger.info("orchestrator_processed_job outcome=%s", outcome)
        return True

    await broker.consume_dispatch(_handle_message)
    logger.info("orchestrator_worker_started worker_id=%s", worker_id)

    async def _outbox_and_reconcile_loop() -> None:
        while not stop_event.is_set():
            try:
                await reconcile_orchestration_once(session_factory, cfg)
                await dispatch_pending_outbox_once(session_factory, broker, cfg)
            except Exception as exc:  # noqa: BLE001
                logger.error("orchestrator_loop_error type=%s", type(exc).__name__)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=0.5)
            except TimeoutError:
                continue

    loop_task = asyncio.create_task(_outbox_and_reconcile_loop())
    try:
        await stop_event.wait()
    finally:
        loop_task.cancel()
        with suppress(asyncio.CancelledError):
            await loop_task
        await broker.close()
        await engine.dispose()
        logger.info("orchestrator_worker_stopped worker_id=%s", worker_id)


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
