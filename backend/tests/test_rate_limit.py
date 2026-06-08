"""Tests for the sliding-window rate limiter. Anti-abuse regressions are security-relevant."""

from backend.core.rate_limit import SlidingWindowLimiter, client_ip_from


def test_allows_up_to_limit():
    rl = SlidingWindowLimiter(window_seconds=60)
    now = 1000.0
    for i in range(5):
        allowed, retry = rl.hit("ip", limit=5, now=now + i)
        assert allowed is True
        assert retry == 0.0


def test_blocks_over_limit():
    rl = SlidingWindowLimiter(window_seconds=60)
    now = 1000.0
    for i in range(5):
        rl.hit("ip", limit=5, now=now)
    allowed, retry = rl.hit("ip", limit=5, now=now)
    assert allowed is False
    assert retry > 0


def test_rejected_request_is_not_counted():
    # A blocked hit must not extend the window, or a client could be locked out forever.
    rl = SlidingWindowLimiter(window_seconds=60)
    for _ in range(3):
        rl.hit("ip", limit=3, now=1000.0)
    rl.hit("ip", limit=3, now=1000.0)  # blocked, not recorded
    # After the window passes from the ORIGINAL 3 hits, traffic flows again.
    allowed, _ = rl.hit("ip", limit=3, now=1061.0)
    assert allowed is True


def test_window_slides():
    rl = SlidingWindowLimiter(window_seconds=60)
    for _ in range(5):
        rl.hit("ip", limit=5, now=1000.0)
    assert rl.hit("ip", limit=5, now=1000.0)[0] is False
    # 61s later the original burst has aged out.
    assert rl.hit("ip", limit=5, now=1061.0)[0] is True


def test_keys_are_independent():
    rl = SlidingWindowLimiter(window_seconds=60)
    for _ in range(5):
        rl.hit("ip-a", limit=5, now=1000.0)
    assert rl.hit("ip-a", limit=5, now=1000.0)[0] is False
    assert rl.hit("ip-b", limit=5, now=1000.0)[0] is True


def test_retry_after_shrinks_as_window_drains():
    rl = SlidingWindowLimiter(window_seconds=60)
    rl.hit("ip", limit=1, now=1000.0)
    _, retry_early = rl.hit("ip", limit=1, now=1010.0)
    _, retry_late = rl.hit("ip", limit=1, now=1050.0)
    assert retry_early > retry_late > 0


def test_cleanup_drops_drained_keys():
    rl = SlidingWindowLimiter(window_seconds=60)
    rl.hit("ip", limit=5, now=1000.0)
    # Force the deque to drain by querying past the window, then cleanup.
    rl.hit("ip", limit=5, now=1100.0)  # this prunes old + records one
    rl._hits["stale"]  # touch defaultdict to create an empty deque
    rl.cleanup()
    assert "stale" not in rl._hits


def test_client_ip_ignores_forwarded_when_untrusted():
    ip = client_ip_from("10.0.0.1", "1.2.3.4", trust_proxy=False)
    assert ip == "10.0.0.1"


def test_client_ip_uses_forwarded_when_trusted():
    ip = client_ip_from("10.0.0.1", "1.2.3.4, 5.6.7.8", trust_proxy=True)
    assert ip == "1.2.3.4"


def test_client_ip_falls_back_when_unknown():
    assert client_ip_from(None, None, trust_proxy=True) == "unknown"
