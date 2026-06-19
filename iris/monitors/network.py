"""
Network monitor — polls psutil.net_connections() for new listeners and
outbound connections on suspicious ports.
"""

from __future__ import annotations

import logging
import queue
import threading

import psutil

from iris.config import Config

logger = logging.getLogger(__name__)

_SUSPICIOUS_OUTBOUND_PORTS: set[int] = {4444, 5555, 1337, 31337, 6666, 9001}

ListenerKey = tuple[str, int]  # (laddr_ip, laddr_port)


def _get_process_name(pid: Optional[int]) -> str:
    if pid is None:
        return "<unknown>"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "<unknown>"


def _snapshot_listeners() -> Set[ListenerKey]:
    """Return set of (ip, port) tuples for all LISTEN sockets."""
    listeners: Set[ListenerKey] = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                listeners.add((conn.laddr.ip, conn.laddr.port))
    except (psutil.AccessDenied, PermissionError):
        logger.debug("Insufficient privileges to list all network connections")
    except Exception as exc:
        logger.warning("net_connections snapshot failed: %s", exc)
    return listeners


class NetworkMonitor:
    """Detects new TCP listeners and outbound connections on suspicious ports."""

    def __init__(self, config: Config, event_queue: queue.Queue) -> None:
        self._config = config
        self._q = event_queue
        self._known_listeners: set[ListenerKey] = _snapshot_listeners()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, name="iris-network-monitor", daemon=True
        )
        self._thread.start()
        logger.info(
            "Network monitor started (interval=%ds, %d initial listeners)",
            self._config.interval_seconds,
            len(self._known_listeners),
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Network monitor stopped")

    def _loop(self) -> None:
        while not self._stop_event.wait(self._config.interval_seconds):
            self._poll()

    def _poll(self) -> None:
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            logger.debug("Insufficient privileges to poll network connections")
            return
        except Exception as exc:
            logger.warning("net_connections poll failed: %s", exc)
            return

        current_listeners: Set[ListenerKey] = set()

        for conn in connections:
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                key: ListenerKey = (conn.laddr.ip, conn.laddr.port)
                current_listeners.add(key)

                if key not in self._known_listeners:
                    process_name = _get_process_name(conn.pid)
                    self._emit_listener(conn, process_name)

            elif conn.status == "ESTABLISHED" and conn.raddr:
                if conn.raddr.port in _SUSPICIOUS_OUTBOUND_PORTS:
                    process_name = _get_process_name(conn.pid)
                    self._emit_outbound(conn, process_name)

        self._known_listeners = current_listeners

    def _emit_listener(self, conn, process_name: str) -> None:
        laddr = conn.laddr
        evt = {
            "event_type": "new_listener",
            "severity": "medium",
            "title": f"New listener on port {laddr.port} ({process_name})",
            "payload": {
                "laddr": {"ip": laddr.ip, "port": laddr.port},
                "raddr": None,
                "status": conn.status,
                "pid": conn.pid,
                "process_name": process_name,
            },
        }
        self._enqueue(evt)

    def _emit_outbound(self, conn, process_name: str) -> None:
        laddr = conn.laddr
        raddr = conn.raddr
        evt = {
            "event_type": "new_connection",
            "severity": "high",
            "title": f"Outbound connection to {raddr.ip}:{raddr.port} from {process_name}",
            "payload": {
                "laddr": {"ip": laddr.ip, "port": laddr.port} if laddr else None,
                "raddr": {"ip": raddr.ip, "port": raddr.port},
                "status": conn.status,
                "pid": conn.pid,
                "process_name": process_name,
            },
        }
        self._enqueue(evt)

    def _enqueue(self, evt: dict) -> None:
        try:
            self._q.put_nowait(evt)
        except queue.Full:
            logger.warning("Network monitor event queue full, dropping event")
