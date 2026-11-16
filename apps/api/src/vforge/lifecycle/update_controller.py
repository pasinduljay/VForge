"""Control Plane Release Monitor & Update Controller worker."""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
from contextlib import suppress

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory, verify_runtime_db_identity
from vforge.lifecycle.monitor import detect_candidates_from_image_locks
from vforge.logging import configure_logging
from vforge.models import ToolCatalog, ToolUpdate

logger = logging.getLogger("vforge.lifecycle.update_controller")


async def run_controller_cycle(
    *,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
    settings: Settings | None = None,
) -> dict[str, int]:
    """Run one release-monitoring and catalog health verification pass."""
    owns_engine = None
    factory = session_factory
    if factory is None:
        cfg = settings or get_settings()
        db_url = cfg.effective_database_url
        if not db_url:
            raise RuntimeError("Update controller requires effective database URL")
        owns_engine = build_engine(db_url)
        factory = build_session_factory(owns_engine)

    try:
        async with factory() as db:
            async with db.begin():
                discovered = await detect_candidates_from_image_locks(db)
                tool_count = (await db.execute(select(func.count(ToolCatalog.id)))).scalar_one()
                pending_updates = (
                    await db.execute(
                        select(func.count(ToolUpdate.id)).where(
                            ToolUpdate.status.in_(
                                ["detected", "validating", "validated", "approved", "canary"]
                            )
                        )
                    )
                ).scalar_one()
        return {
            "catalog_tools": int(tool_count),
            "new_candidates_detected": len(discovered),
            "active_pipeline_updates": int(pending_updates),
        }
    finally:
        if owns_engine is not None:
            await owns_engine.dispose()


async def run_loop(
    *,
    once: bool = False,
    interval_seconds: int = 300,
    settings: Settings | None = None,
) -> None:
    """Start the update-controller polling loop after verifying DB runtime identity."""
    cfg = settings or get_settings()
    configure_logging(cfg.log_level)
    db_url = cfg.effective_database_url
    if not db_url:
        raise RuntimeError("Update controller requires effective database URL")

    engine = build_engine(db_url)
    identity = await verify_runtime_db_identity(engine)
    logger.info(
        "update_controller_started role=%s once=%s interval=%s",
        identity["role"],
        once,
        interval_seconds,
    )
    session_factory = build_session_factory(engine)

    stop_event = asyncio.Event()
    if not once:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with suppress(NotImplementedError):
                loop.add_signal_handler(sig, stop_event.set)

    try:
        while not stop_event.is_set():
            try:
                summary = await run_controller_cycle(session_factory=session_factory, settings=cfg)
                logger.info(
                    "update_controller_cycle catalog=%s detected=%s active=%s",
                    summary["catalog_tools"],
                    summary["new_candidates_detected"],
                    summary["active_pipeline_updates"],
                )
            except Exception as exc:
                logger.warning("update_controller_cycle_error=%s", type(exc).__name__)
            if once:
                break
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
            except TimeoutError:
                continue
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="VForge Phase 10 Update Controller")
    parser.add_argument("--once", action="store_true", help="Run a single check cycle and exit")
    parser.add_argument("--interval", type=int, default=300, help="Polling interval in seconds")
    args = parser.parse_args()
    asyncio.run(run_loop(once=args.once, interval_seconds=args.interval))


if __name__ == "__main__":
    main()
