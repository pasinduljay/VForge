"""Rate limiting for authentication and sensitive control-plane endpoints."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque

import valkey.asyncio as valkey_async

from vforge.config import Settings
from vforge.errors import RateLimitExceededError

logger = logging.getLogger("vforge.security.rate_limit")


class RateLimiter:
    """Valkey-backed fixed/sliding window rate limiter with safe in-memory fallback."""

    def __init__(self) -> None:
        self._memory_windows: dict[str, deque[float]] = defaultdict(deque)

    def reset(self) -> None:
        """Clear in-memory fallback windows (useful for test isolation)."""
        self._memory_windows.clear()

    async def check_limit(
        self,
        *,
        settings: Settings,
        bucket: str,
        key: str,
        limit: int,
        window_seconds: int = 60,
    ) -> None:
        """Enforce `limit` requests per `window_seconds` for `(bucket, key)`."""
        if limit <= 0:
            return

        cache_key = f"vf:rl:{bucket}:{key}"
        valkey_url = settings.effective_cache_url
        if valkey_url:
            client = valkey_async.from_url(  # type: ignore[no-untyped-call]
                valkey_url,
                socket_timeout=1.0,
            )
            try:
                count = await client.incr(cache_key)
                if count == 1:
                    await client.expire(cache_key, window_seconds)
                if int(count) > limit:
                    ttl = await client.ttl(cache_key)
                    retry_after = max(int(ttl) if ttl and int(ttl) > 0 else window_seconds, 1)
                    raise RateLimitExceededError(
                        "Rate limit exceeded. Please retry later.",
                        retry_after=retry_after,
                    )
                return
            except RateLimitExceededError:
                raise
            except Exception as exc:
                logger.warning("valkey rate limit fallback triggered: %s", type(exc).__name__)
            finally:
                await client.aclose()

        # In-memory sliding window fallback (unit tests or transient Valkey outage)
        now = time.monotonic()
        window = self._memory_windows[cache_key]
        cutoff = now - window_seconds
        while window and window[0] <= cutoff:
            window.popleft()
        if len(window) >= limit:
            retry_after = max(int(window[0] + window_seconds - now) + 1, 1)
            raise RateLimitExceededError(
                "Rate limit exceeded. Please retry later.",
                retry_after=retry_after,
            )
        window.append(now)


rate_limiter = RateLimiter()
