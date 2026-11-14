"""DAST Target Health Safety Monitor and Emergency Tripwire for Runner Agent."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger("vforge_runner.health_monitor")


@dataclass
class HealthMonitorStats:
    probes_total: int = 0
    probes_healthy: int = 0
    probes_failed: int = 0
    consecutive_5xx: int = 0
    consecutive_errors: int = 0
    high_latency_samples: int = 0
    latencies_ms: list[int] = field(default_factory=list)


class TargetHealthTripwireError(RuntimeError):
    """Raised when target health safety thresholds are breached."""

    def __init__(self, reason: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(f"Target health tripwire aborted: {reason}")
        self.reason = reason
        self.details = details or {}


class TargetHealthMonitor:
    """Probes the scan target through ScopedEgressGateway and aborts on safety tripwires."""

    def __init__(
        self,
        *,
        probe_url: str,
        proxy_url: str | None = None,
        interval_seconds: float = 2.0,
        probe_timeout_seconds: float = 5.0,
        max_consecutive_5xx: int = 3,
        max_consecutive_errors: int = 5,
        max_latency_ms: int = 5000,
        max_high_latency_count: int = 5,
        cancel_event: asyncio.Event | None = None,
        on_probe: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> None:
        self.probe_url = probe_url
        self.proxy_url = proxy_url
        self.interval_seconds = max(0.5, interval_seconds)
        self.probe_timeout_seconds = max(1.0, min(probe_timeout_seconds, 30.0))
        self.max_consecutive_5xx = max_consecutive_5xx
        self.max_consecutive_errors = max_consecutive_errors
        self.max_latency_ms = max_latency_ms
        self.max_high_latency_count = max_high_latency_count
        self.on_probe = on_probe

        self.stats = HealthMonitorStats()
        self.cancel_event = cancel_event if cancel_event is not None else asyncio.Event()
        self._stop_event = asyncio.Event()
        self.tripped = False
        self.tripwire_reason: str | None = None
        self._task: asyncio.Task[None] | None = None

    async def _emit_probe(
        self,
        *,
        probe_type: str,
        status_code: int | None,
        latency_ms: int,
        healthy: bool,
        error_message: str | None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.stats.probes_total += 1
        if healthy:
            self.stats.probes_healthy += 1
        else:
            self.stats.probes_failed += 1
        self.stats.latencies_ms.append(latency_ms)

        probe_payload: dict[str, Any] = {
            "probe_type": probe_type,
            "target_url": self.probe_url,
            "status_code": status_code,
            "latency_ms": max(0, latency_ms),
            "healthy": healthy,
            "error_message": error_message,
            "probe_metadata": {
                **(metadata or {}),
                "consecutive_5xx": self.stats.consecutive_5xx,
                "consecutive_errors": self.stats.consecutive_errors,
            },
        }

        if self.on_probe is not None:
            try:
                await self.on_probe(probe_payload)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to emit health probe to runner gateway: %s", exc)

    async def _execute_single_probe(self, probe_type: str) -> bool:
        start = time.perf_counter()
        status_code: int | None = None
        error_msg: str | None = None
        healthy = False

        transport_args: dict[str, Any] = {
            "timeout": httpx.Timeout(self.probe_timeout_seconds),
            "follow_redirects": True,
            "verify": False,  # Targets may use self-signed certs in test environments
        }
        if self.proxy_url:
            transport_args["proxy"] = self.proxy_url

        try:
            async with httpx.AsyncClient(**transport_args) as client:
                headers = {"User-Agent": "VForge-HealthProbe/1.0"}
                resp = await client.get(self.probe_url, headers=headers)
                status_code = resp.status_code
                latency_ms = int((time.perf_counter() - start) * 1000)

                if status_code >= 500:
                    self.stats.consecutive_5xx += 1
                    healthy = False
                    error_msg = f"HTTP {status_code} server error"
                else:
                    self.stats.consecutive_5xx = 0
                    self.stats.consecutive_errors = 0
                    healthy = True

                if latency_ms >= self.max_latency_ms:
                    self.stats.high_latency_samples += 1
                else:
                    self.stats.high_latency_samples = max(0, self.stats.high_latency_samples - 1)

        except (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.NetworkError,
        ) as exc:
            latency_ms = int((time.perf_counter() - start) * 1000)
            self.stats.consecutive_errors += 1
            healthy = False
            error_msg = f"Target connection failure: {type(exc).__name__}"
        except Exception as exc:  # noqa: BLE001
            latency_ms = int((time.perf_counter() - start) * 1000)
            self.stats.consecutive_errors += 1
            healthy = False
            error_msg = f"Target probe unexpected error: {exc}"

        await self._emit_probe(
            probe_type=probe_type,
            status_code=status_code,
            latency_ms=latency_ms,
            healthy=healthy,
            error_message=error_msg,
        )

        # Check tripwire thresholds
        trip_reason: str | None = None
        if self.stats.consecutive_5xx >= self.max_consecutive_5xx:
            trip_reason = (
                f"Consecutive 5xx server errors ({self.stats.consecutive_5xx}) "
                f"exceeded threshold ({self.max_consecutive_5xx})"
            )
        elif self.stats.consecutive_errors >= self.max_consecutive_errors:
            trip_reason = (
                f"Consecutive connection errors ({self.stats.consecutive_errors}) "
                f"exceeded threshold ({self.max_consecutive_errors})"
            )
        elif self.stats.high_latency_samples >= self.max_high_latency_count:
            trip_reason = (
                f"Target latency sustained above {self.max_latency_ms}ms "
                f"({self.stats.high_latency_samples} samples)"
            )

        if trip_reason:
            self.tripped = True
            self.tripwire_reason = trip_reason
            self.cancel_event.set()
            await self._emit_probe(
                probe_type="tripwire",
                status_code=status_code,
                latency_ms=latency_ms,
                healthy=False,
                error_message=trip_reason,
            )
            return False

        return healthy

    async def _monitor_loop(self) -> None:
        try:
            while not self._stop_event.is_set() and not self.tripped:
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval_seconds)
                    break
                except TimeoutError:
                    pass

                if self._stop_event.is_set() or self.tripped:
                    break

                await self._execute_single_probe(probe_type="periodic")
        except asyncio.CancelledError:
            pass

    async def start(self) -> bool:
        """Run baseline probe and start background monitor task. Return True if healthy."""
        baseline_ok = await self._execute_single_probe(probe_type="baseline")
        if not baseline_ok:
            if not self.tripped:
                self.tripped = True
                self.tripwire_reason = (
                    f"Target baseline probe failed (HTTP {self.stats.consecutive_5xx} 5xx)"
                    if self.stats.consecutive_5xx > 0
                    else "Target baseline probe failed"
                )
                self.cancel_event.set()
                await self._emit_probe(
                    probe_type="tripwire",
                    status_code=None,
                    latency_ms=0,
                    healthy=False,
                    error_message=self.tripwire_reason,
                )
            return False
        self._task = asyncio.create_task(self._monitor_loop())
        return True

    async def stop(self) -> None:
        """Stop background monitoring and emit post-scan probe if not tripped."""
        self._stop_event.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        if not self.tripped:
            await self._execute_single_probe(probe_type="post_scan")
