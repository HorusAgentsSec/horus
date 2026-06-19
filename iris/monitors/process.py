"""
Process monitor — polls psutil for new or suspicious processes.

Suspicious criteria:
  - Process name in the blacklist (nc, ncat, netcat, socat, mimikatz, …)
  - Executable or CWD under /tmp or /dev/shm
"""

import logging
import queue
import threading
import time

import psutil

from iris.config import Config

logger = logging.getLogger(__name__)

_BLACKLISTED_NAMES: set[str] = {
    "nc", "ncat", "netcat", "socat",
    "mimikatz", "msfconsole", "msfvenom",
}

# Command substrings that indicate downloading to suspicious paths
_SUSPICIOUS_PATH_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/")


def _is_blacklisted(name: str, cmdline: list[str]) -> bool:
    if name.lower() in _BLACKLISTED_NAMES:
        return True
    if name.lower() in ("wget", "curl"):
        return any(arg.startswith(p) for arg in cmdline for p in _SUSPICIOUS_PATH_PREFIXES)
    return False


def _is_suspicious_path(exe: str | None, cwd: str | None) -> bool:
    return any(c and c.startswith(p) for c in (exe, cwd) for p in _SUSPICIOUS_PATH_PREFIXES)


def _snapshot_pids() -> set[int]:
    try:
        return set(psutil.pids())
    except Exception:
        return set()


_ERR = (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError)


def _process_info(proc: psutil.Process) -> dict:
    def _get(fn, default=None):
        try: return fn()
        except _ERR: return default

    return {
        "pid": proc.pid,
        "name": _get(proc.name, "<unknown>"),
        "cmdline": _get(proc.cmdline, []),
        "username": _get(proc.username, "<unknown>"),
        "cwd": _get(proc.cwd),
        "exe": _get(proc.exe),
        "create_time": _get(proc.create_time),
    }


class ProcessMonitor:
    """Polls psutil every interval_seconds, emits events for new suspicious processes."""

    def __init__(self, config: Config, event_queue: queue.Queue) -> None:
        self._config = config
        self._q = event_queue
        self._known_pids: set[int] = _snapshot_pids()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="iris-process-monitor", daemon=True)
        self._thread.start()
        logger.info("Process monitor started (interval=%ds)", self._config.interval_seconds)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Process monitor stopped")

    def _loop(self) -> None:
        while not self._stop_event.wait(self._config.interval_seconds):
            self._poll()

    def _poll(self) -> None:
        current_pids = _snapshot_pids()
        new_pids = current_pids - self._known_pids
        self._known_pids = current_pids

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                info = _process_info(proc)
            except psutil.NoSuchProcess:
                # Process already exited — probably a very short-lived tool
                continue
            except Exception as exc:
                logger.debug("Failed to inspect PID %d: %s", pid, exc)
                continue

            name = info.get("name", "")
            cmdline = info.get("cmdline") or []
            exe = info.get("exe")
            cwd = info.get("cwd")

            if _is_blacklisted(name, cmdline):
                self._emit("high", f"Blacklisted process detected: {name} (PID {pid})", info)
            elif _is_suspicious_path(exe, cwd):
                self._emit(
                    "medium",
                    f"Process running from suspicious path: {name} (PID {pid})",
                    info,
                )

    def _emit(self, severity: str, title: str, payload: dict) -> None:
        evt = {
            "event_type": "suspicious_process",
            "severity": severity,
            "title": title,
            "payload": payload,
        }
        try:
            self._q.put_nowait(evt)
        except queue.Full:
            logger.warning("Process monitor event queue full, dropping event")
