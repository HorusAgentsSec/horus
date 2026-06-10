"""
Sliding-window rate limiter with optional Redis backend.

When REDIS_URL is configured, state is shared across all workers/instances (correct
multi-worker limiting). When Redis is unavailable or unconfigured, falls back to the
original per-process in-memory implementation (each worker enforces its own budget).

Login itself is handled by Supabase Auth (GoTrue has its own throttling). This guards
our own endpoints: mass token-probing, scan-trigger abuse, team-invite spamming.

The Starlette middleware that wires it into requests lives in backend/main.py.
"""

import logging
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


# ── Interface ─────────────────────────────────────────────────────────────────

class BaseLimiter(ABC):
    @abstractmethod
    def hit(self, key: str, limit: int, now: float | None = None) -> tuple[bool, float]:
        """
        Records one request for `key` and reports whether it is within `limit`.
        Returns (allowed, retry_after_seconds).
        """


# ── In-memory (per-process) ──────────────────────────────────────────────────

class SlidingWindowLimiter(BaseLimiter):
    """Tracks request timestamps per key within a rolling time window."""

    def __init__(self, window_seconds: float = 60.0):
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def hit(self, key: str, limit: int, now: float | None = None) -> tuple[bool, float]:
        now = time.monotonic() if now is None else now
        dq = self._hits[key]
        cutoff = now - self.window
        while dq and dq[0] <= cutoff:
            dq.popleft()

        if len(dq) >= limit:
            retry_after = dq[0] + self.window - now
            return False, max(0.0, retry_after)

        dq.append(now)
        return True, 0.0

    def cleanup(self) -> None:
        for key in [k for k, dq in self._hits.items() if not dq]:
            del self._hits[key]


# ── Redis-backed (shared across workers) ────────────────────────────────────

_REDIS_SCRIPT = """
-- Atomic sliding-window check via sorted set.
-- KEYS[1] = rate-limit key, ARGV[1]=now(ms), ARGV[2]=window(ms), ARGV[3]=limit, ARGV[4]=uid
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local uid    = ARGV[4]

-- Evict entries older than the window
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
-- Count remaining requests in window
local count = tonumber(redis.call('ZCARD', key))

if count >= limit then
  -- Return oldest entry timestamp so caller can compute retry_after
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local oldest_ts = oldest[2] and tonumber(oldest[2]) or now
  return {0, oldest_ts}
end

-- Add this request and set TTL so the key self-cleans
redis.call('ZADD', key, now, uid)
redis.call('PEXPIRE', key, window)
return {1, 0}
"""


class RedisWindowLimiter(BaseLimiter):
    """
    Sliding-window limiter backed by Redis sorted sets. Atomic via Lua script —
    no race conditions under concurrent workers.
    """

    def __init__(self, redis_client, window_seconds: float = 60.0):
        self._redis = redis_client
        self.window_ms = int(window_seconds * 1000)
        self._script = redis_client.register_script(_REDIS_SCRIPT)

    def hit(self, key: str, limit: int, now: float | None = None) -> tuple[bool, float]:
        now_ms = int((time.time() if now is None else now) * 1000)
        uid = str(uuid.uuid4())
        result = self._script(
            keys=[f"rl:{key}"],
            args=[now_ms, self.window_ms, limit, uid],
        )
        allowed = bool(result[0])
        if allowed:
            return True, 0.0
        oldest_ms = float(result[1])
        retry_after = max(0.0, (oldest_ms + self.window_ms - now_ms) / 1000.0)
        return False, retry_after


# ── Factory ──────────────────────────────────────────────────────────────────

def build_limiter(redis_url: str | None = None, window_seconds: float = 60.0) -> BaseLimiter:
    """
    Returns a Redis-backed limiter when redis_url is set and Redis is reachable,
    otherwise falls back to the in-memory implementation with a warning.
    """
    if redis_url:
        try:
            import redis as redis_lib
            client = redis_lib.from_url(redis_url, socket_connect_timeout=2, decode_responses=False)
            client.ping()
            logger.info("Rate limiter: using Redis at %s", redis_url.split("@")[-1])
            return RedisWindowLimiter(client, window_seconds)
        except Exception as e:
            logger.warning(
                "Rate limiter: Redis unavailable (%s) — falling back to in-memory. "
                "Effective limits are per-worker.",
                e,
            )
    return SlidingWindowLimiter(window_seconds)


# ── Helpers ───────────────────────────────────────────────────────────────────

def client_ip_from(client_host: str | None, forwarded_for: str | None, trust_proxy: bool) -> str:
    """
    Resolves the client IP used as the rate-limit key.

    X-Forwarded-For is honored only when trust_proxy is enabled, because the header is
    client-spoofable when not sitting behind a trusted reverse proxy.
    """
    if trust_proxy and forwarded_for:
        first = forwarded_for.split(",")[0].strip()
        if first:
            return first
    return client_host or "unknown"
