"""
Auth log tailer — parses /var/log/auth.log and/or journalctl -f -u ssh
to detect authentication events and brute-force patterns.
"""

import logging
import queue
import re
import subprocess
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from iris.config import Config

logger = logging.getLogger(__name__)

AUTH_LOG_PATH = Path("/var/log/auth.log")

# Brute-force detection: more than this many failures from one IP in the window
_BRUTE_FORCE_THRESHOLD = 5
_BRUTE_FORCE_WINDOW_SECS = 60

# ── Regex patterns ────────────────────────────────────────────────────────────

_RE_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive) for (?P<user>\S+) from (?P<ip>\S+)"
)
_RE_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
_RE_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"
)
_RE_SUDO = re.compile(
    r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)"
)
_RE_SU = re.compile(
    r"su:\s+(?:Successful su for|pam_unix.*session opened for user) (?P<user>\S+)"
)


class _BruteForceTracker:
    """Tracks per-IP failure timestamps; returns True when threshold crossed."""

    def __init__(self, threshold: int = _BRUTE_FORCE_THRESHOLD, window: int = _BRUTE_FORCE_WINDOW_SECS) -> None:
        self._threshold = threshold
        self._window = window
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._alerted: dict[str, float] = {}

    def record(self, ip: str) -> bool:
        """Record a failure; return True if brute-force threshold just crossed."""
        now = time.monotonic()
        dq = self._failures[ip]
        dq.append(now)
        # Evict old entries outside the window
        while dq and dq[0] < now - self._window:
            dq.popleft()

        if len(dq) >= self._threshold:
            last_alert = self._alerted.get(ip, 0)
            # Only alert once per 5-minute cooldown to avoid flooding
            if now - last_alert > 300:
                self._alerted[ip] = now
                return True
        return False


def _parse_line(line: str) -> tuple[str, str, dict] | None:
    """
    Parse a log line.
    Returns (event_subtype, severity, payload) or None if no match.
    """
    m = _RE_ACCEPTED.search(line)
    if m:
        return (
            "ssh_login_success",
            "info",
            {"user": m["user"], "source_ip": m["ip"], "method": m["method"], "raw_line": line.strip()},
        )

    m = _RE_FAILED.search(line)
    if m:
        return (
            "ssh_login_failure",
            "medium",
            {"user": m["user"], "source_ip": m["ip"], "method": "password", "raw_line": line.strip()},
        )

    m = _RE_INVALID.search(line)
    if m:
        return (
            "ssh_invalid_user",
            "medium",
            {"user": m["user"], "source_ip": m["ip"], "method": "unknown", "raw_line": line.strip()},
        )

    m = _RE_SUDO.search(line)
    if m:
        return (
            "sudo_command",
            "low",
            {"user": m["user"], "source_ip": None, "command": m["command"].strip(), "raw_line": line.strip()},
        )

    m = _RE_SU.search(line)
    if m:
        return (
            "su_session",
            "low",
            {"user": m["user"], "source_ip": None, "method": "su", "raw_line": line.strip()},
        )

    return None


class AuthLogMonitor:
    """Tails auth.log (file-based) or journalctl (systemd-based)."""

    def __init__(self, config: Config, event_queue: queue.Queue) -> None:
        self._config = config
        self._q = event_queue
        self._brute = _BruteForceTracker()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="iris-auth-monitor", daemon=True
        )
        self._thread.start()
        logger.info("Auth log monitor started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Auth log monitor stopped")

    def _run(self) -> None:
        if AUTH_LOG_PATH.exists():
            self._tail_file()
        else:
            self._tail_journalctl()

    # ── File tail ─────────────────────────────────────────────────────────────

    def _tail_file(self) -> None:
        logger.info("Auth monitor: tailing %s", AUTH_LOG_PATH)
        try:
            with AUTH_LOG_PATH.open("r", errors="replace") as fh:
                # Seek to end so we only see new lines
                fh.seek(0, 2)
                while not self._stop_event.is_set():
                    line = fh.readline()
                    if line:
                        self._handle_line(line)
                    else:
                        time.sleep(0.5)
        except PermissionError:
            logger.warning("Auth monitor: no permission to read %s", AUTH_LOG_PATH)
        except Exception as exc:
            logger.error("Auth monitor file tail error: %s", exc)

    # ── journalctl tail ───────────────────────────────────────────────────────

    def _tail_journalctl(self) -> None:
        logger.info("Auth monitor: /var/log/auth.log not found, trying journalctl")
        try:
            proc = subprocess.Popen(
                ["journalctl", "-f", "-u", "ssh", "--output=short-iso", "--no-pager"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                errors="replace",
            )
        except FileNotFoundError:
            logger.warning("Auth monitor: journalctl not found; auth monitoring disabled")
            return
        except Exception as exc:
            logger.error("Auth monitor: failed to start journalctl: %s", exc)
            return

        try:
            while not self._stop_event.is_set():
                line = proc.stdout.readline()
                if line:
                    self._handle_line(line)
                elif proc.poll() is not None:
                    logger.warning("Auth monitor: journalctl process exited unexpectedly")
                    break
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    # ── Line processing ───────────────────────────────────────────────────────

    def _handle_line(self, line: str) -> None:
        result = _parse_line(line)
        if result is None:
            return

        subtype, severity, payload = result
        source_ip = payload.get("source_ip")

        # Brute-force escalation
        if subtype in ("ssh_login_failure", "ssh_invalid_user") and source_ip:
            if self._brute.record(source_ip):
                self._enqueue({
                    "event_type": "auth_event",
                    "severity": "high",
                    "title": f"Brute-force SSH detected from {source_ip}",
                    "payload": {
                        "user": payload.get("user"),
                        "source_ip": source_ip,
                        "method": "brute_force",
                        "raw_line": line.strip(),
                    },
                })
                return  # Don't also emit the individual failure

        title_map = {
            "ssh_login_success": f"SSH login: {payload.get('user')} from {source_ip}",
            "ssh_login_failure": f"SSH failed login: {payload.get('user')} from {source_ip}",
            "ssh_invalid_user": f"SSH invalid user {payload.get('user')} from {source_ip}",
            "sudo_command": f"sudo by {payload.get('user')}: {payload.get('command', '')}",
            "su_session": f"su session opened for {payload.get('user')}",
        }

        self._enqueue({
            "event_type": "auth_event",
            "severity": severity,
            "title": title_map.get(subtype, f"Auth event: {subtype}"),
            "payload": payload,
        })

    def _enqueue(self, evt: dict) -> None:
        try:
            self._q.put_nowait(evt)
        except queue.Full:
            logger.warning("Auth monitor event queue full, dropping event")
