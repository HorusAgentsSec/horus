"""
Maintenance (blackout) windows — when NOT to fire scheduled work.

A cron expression says *when* a scan runs; a blackout window says *when it must not*, regardless of
cron. The case it solves: an hourly scan that has to pause during a change-freeze or business hours,
without rewriting the cron. A scheduled run that lands inside a window is skipped (and recorded as
skipped), not queued for later — the next cron tick outside the window runs normally.

Windows are configured as a comma-separated list of `[DAYS ]HH:MM-HH:MM` specs, e.g.:

    "Mon-Fri 09:00-18:00, Sat,Sun 00:00-23:59, 22:00-02:00"

- DAYS is optional (omit → every day). Day tokens are Mon..Sun; ranges (Mon-Fri) and lists (Sat,Sun)
  both work.
- A window whose end is earlier than its start wraps past midnight (22:00-02:00).

Pure and unit-tested: `in_blackout(now, ...)` takes the time explicitly, so it never reads the clock.
"""

from dataclasses import dataclass
from datetime import datetime, time

_DAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


@dataclass(frozen=True)
class Window:
    days: frozenset[int]  # weekday ints (Mon=0 … Sun=6) the window applies to
    start: time
    end: time

    def covers(self, now: datetime) -> bool:
        if now.weekday() not in self.days:
            return False
        t = now.time()
        if self.start <= self.end:
            return self.start <= t <= self.end
        return t >= self.start or t <= self.end  # wraps past midnight


def _parse_days(token: str) -> frozenset[int]:
    out: set[int] = set()
    for part in token.split(","):
        part = part.strip().lower()
        if not part:
            continue
        if "-" in part:
            lo, hi = (p.strip()[:3] for p in part.split("-", 1))
            a, b = _DAYS[lo], _DAYS[hi]
            rng = range(a, b + 1) if a <= b else list(range(a, 7)) + list(range(0, b + 1))
            out.update(rng)
        else:
            out.add(_DAYS[part[:3]])
    return frozenset(out)


def _parse_time(token: str) -> time:
    h, m = token.strip().split(":")
    return time(int(h), int(m))


def parse_windows(spec: str) -> list[Window]:
    """Parse a comma-separated blackout spec into Windows. Malformed entries are skipped, so a
    bad config can never crash the scheduler (worst case: a window doesn't apply)."""
    windows: list[Window] = []
    if not spec:
        return windows
    # Split on commas that separate windows, but commas also appear inside day lists (Sat,Sun).
    # A new window always starts with a token containing a time range "HH:MM-HH:MM"; we detect that.
    for raw in _split_windows(spec):
        raw = raw.strip()
        if not raw:
            continue
        try:
            parts = raw.rsplit(" ", 1)
            if len(parts) == 2 and ":" in parts[1]:
                days = _parse_days(parts[0])
                start, end = parts[1].split("-", 1)
            else:
                days = frozenset(range(7))  # no day token → every day
                start, end = raw.split("-", 1)
            windows.append(Window(days, _parse_time(start), _parse_time(end)))
        except (ValueError, KeyError):
            continue  # skip malformed window, keep the rest
    return windows


def _split_windows(spec: str) -> list[str]:
    """Split the spec into individual windows. A window boundary is a comma that is NOT inside a
    day list — i.e. the comma is followed by a chunk that eventually contains a time range. We
    split greedily on commas, then re-join chunks until each piece has a 'HH:MM-HH:MM'."""
    chunks = [c.strip() for c in spec.split(",")]
    out: list[str] = []
    buf: list[str] = []
    for c in chunks:
        buf.append(c)
        if "-" in c and ":" in c:  # this chunk closes a time range → window complete
            out.append(", ".join(buf))
            buf = []
    if buf:  # trailing fragment with no time range; keep it so parse_windows can reject it
        out.append(", ".join(buf))
    return out


def in_blackout(now: datetime, windows: list[Window]) -> bool:
    """True if `now` falls inside any blackout window."""
    return any(w.covers(now) for w in windows)
