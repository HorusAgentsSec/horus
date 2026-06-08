"""
In-memory sliding-window rate limiter — foundational anti-abuse / anti-brute-force
control for the API.

Login itself is handled client-side by Supabase Auth (GoTrue has its own throttling),
so this guards our own endpoints: mass token-probing against the auth dependency,
scan-trigger abuse, and team-invite spamming.

Kept dependency-free (stdlib only) and self-contained so the algorithm is unit-testable
without the web framework. The Starlette middleware that wires it into requests lives in
backend/main.py.

Limitation: state is per-process and in-memory, like the auth TTL cache. With multiple
workers/instances each holds its own counters, so effective limits are per-worker. That's
an accepted trade-off for a foundational control; a shared store (Redis) is the upgrade path.
"""

import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    """Tracks request timestamps per key within a rolling time window."""

    def __init__(self, window_seconds: float = 60.0):
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def hit(self, key: str, limit: int, now: float | None = None) -> tuple[bool, float]:
        """
        Records one request for `key` and reports whether it is within `limit`.

        Returns (allowed, retry_after_seconds). When not allowed, the request is NOT
        recorded and retry_after is how long until the oldest hit ages out of the window.
        """
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
        """Drops keys whose windows have fully drained, to bound memory growth."""
        for key in [k for k, dq in self._hits.items() if not dq]:
            del self._hits[key]


def client_ip_from(client_host: str | None, forwarded_for: str | None, trust_proxy: bool) -> str:
    """
    Resolves the client IP used as the rate-limit key.

    X-Forwarded-For is honored only when trust_proxy is enabled, because the header is
    client-spoofable when not sitting behind a trusted reverse proxy. Otherwise we use the
    socket peer address.
    """
    if trust_proxy and forwarded_for:
        first = forwarded_for.split(",")[0].strip()
        if first:
            return first
    return client_host or "unknown"
