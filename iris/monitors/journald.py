"""
Journald monitor — streams `journalctl -f -o json` and emits security events.

Replaces: auth_log.py (SSH, sudo, su) + system kernel/service alerts.
Zero polling, zero RAM growth — the kernel streams events as they happen.
"""

import json
import logging
import queue
import re
import subprocess
import threading
import time
from collections import defaultdict, deque

from iris.config import Config

logger = logging.getLogger(__name__)

_BRUTE_FORCE_THRESHOLD = 5
_BRUTE_FORCE_WINDOW_SECS = 60

_SECURITY_IDENTIFIERS = {
    "sshd", "sudo", "su", "su-l", "login", "passwd",
    "useradd", "userdel", "usermod", "groupadd", "chpasswd",
}

_RE_SSH_ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)")
_RE_SSH_FAILED   = re.compile(r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_RE_SSH_INVALID  = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
_RE_SUDO         = re.compile(r"(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)")
_RE_SU           = re.compile(r"(?:Successful su for|session opened for user) (?P<user>\S+)")


class _BruteForce:
    def __init__(self):
        self._failures: dict[str, deque] = defaultdict(deque)
        self._alerted: dict[str, float] = {}

    def record(self, ip: str) -> bool:
        now = time.monotonic()
        dq = self._failures[ip]
        dq.append(now)
        while dq and dq[0] < now - _BRUTE_FORCE_WINDOW_SECS:
            dq.popleft()
        if len(dq) >= _BRUTE_FORCE_THRESHOLD and now - self._alerted.get(ip, 0) > 300:
            self._alerted[ip] = now
            return True
        return False


class JournaldMonitor:
    def __init__(self, config: Config, event_queue: queue.Queue) -> None:
        self._q = event_queue
        self._brute = _BruteForce()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="iris-journald", daemon=True)
        self._thread.start()
        logger.info("Journald monitor started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Journald monitor stopped")

    def _run(self) -> None:
        cmd = ["journalctl", "-f", "-o", "json", "--no-pager",
               "--output-fields=MESSAGE,SYSLOG_IDENTIFIER,_COMM,PRIORITY,_PID,_UID"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, errors="replace")
        except FileNotFoundError:
            logger.warning("journalctl not found — journald monitor disabled")
            return

        try:
            while not self._stop.is_set():
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        logger.warning("journalctl exited unexpectedly")
                        break
                    continue
                try:
                    self._handle(json.loads(line))
                except (json.JSONDecodeError, KeyError):
                    pass
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _handle(self, rec: dict) -> None:
        ident = (rec.get("SYSLOG_IDENTIFIER") or rec.get("_COMM") or "").strip()
        msg   = (rec.get("MESSAGE") or "").strip()
        try:
            priority = int(rec.get("PRIORITY", 6))
        except (ValueError, TypeError):
            priority = 6

        if ident not in _SECURITY_IDENTIFIERS and priority > 3:
            return

        if ident == "sshd":
            m = _RE_SSH_ACCEPTED.search(msg)
            if m:
                return self._emit("auth_event", "low",
                    f"SSH login: {m['user']} from {m['ip']}",
                    {"user": m["user"], "source_ip": m["ip"], "method": m["method"]})

            m = _RE_SSH_FAILED.search(msg)
            if m:
                ip = m["ip"]
                if self._brute.record(ip):
                    return self._emit("auth_event", "high",
                        f"Brute-force SSH from {ip}",
                        {"user": m["user"], "source_ip": ip, "method": "brute_force"})
                return self._emit("auth_event", "medium",
                    f"SSH failed login: {m['user']} from {ip}",
                    {"user": m["user"], "source_ip": ip})

            m = _RE_SSH_INVALID.search(msg)
            if m:
                self._brute.record(m["ip"])
                return self._emit("auth_event", "medium",
                    f"SSH invalid user {m['user']} from {m['ip']}",
                    {"user": m["user"], "source_ip": m["ip"]})

        elif ident == "sudo":
            m = _RE_SUDO.search(msg)
            if m:
                return self._emit("auth_event", "low",
                    f"sudo: {m['user']}: {m['command'].strip()[:120]}",
                    {"user": m["user"], "command": m["command"].strip()})

        elif ident in ("su", "su-l"):
            m = _RE_SU.search(msg)
            if m:
                return self._emit("auth_event", "low",
                    f"su session for {m['user']}",
                    {"user": m["user"]})

        elif ident in ("useradd", "userdel", "usermod", "groupadd", "chpasswd"):
            return self._emit("auth_event", "high",
                f"User/group change: {ident}: {msg[:120]}",
                {"identifier": ident, "message": msg[:200]})

        # Emergency/alert/critical/error from any source
        if priority <= 3:
            return self._emit("system_event", "high" if priority <= 2 else "medium",
                msg[:200],
                {"identifier": ident, "priority": priority, "pid": rec.get("_PID")})

    def _emit(self, event_type: str, severity: str, title: str, payload: dict) -> None:
        try:
            self._q.put_nowait({"event_type": event_type, "severity": severity,
                                "title": title, "payload": payload})
        except queue.Full:
            logger.warning("journald monitor: queue full, dropping event")
