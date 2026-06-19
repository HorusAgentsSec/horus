"""
IrisReporter — HTTP client that POSTs batched events to the Horus server.

If the server is unreachable, events are persisted to a local JSON queue file
and replayed on the next successful connection.
"""

import json
import logging
import socket
import time
from pathlib import Path

import requests

from iris.config import Config

logger = logging.getLogger(__name__)

_QUEUE_DIR = Path("/var/lib/horus/iris")
_QUEUE_FILE = _QUEUE_DIR / "queue.json"
_FALLBACK_QUEUE_FILE = Path.home() / ".horus" / "iris_queue.json"

_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 2  # seconds; doubles each retry


def _get_queue_path() -> Path:
    try:
        _QUEUE_DIR.mkdir(parents=True, exist_ok=True)
        return _QUEUE_FILE
    except PermissionError:
        _FALLBACK_QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)
        return _FALLBACK_QUEUE_FILE


def _get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "0.0.0.0"


class IrisReporter:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._session = requests.Session()
        self._session.headers.update({
            "X-Iris-Key": config.api_key,
            "Content-Type": "application/json",
            "User-Agent": "horus-iris/0.1",
        })
        self._hostname = socket.gethostname()
        self._ip = _get_local_ip()
        self._queue_path = _get_queue_path()

    # ── Public API ────────────────────────────────────────────────────────────

    def send_events(self, events: list[dict]) -> bool:
        """
        POST events to the Horus server.

        Returns True if the server accepted them, False if they were enqueued locally.
        Retries up to _MAX_RETRIES times with exponential backoff before giving up.
        """
        if not events:
            return True

        payload = {
            "agent_id": self._config.agent_id,
            "hostname": self._hostname,
            "ip": self._ip,
            "events": events,
        }
        url = f"{self._config.server_url.rstrip('/')}/api/iris/events"

        for attempt in range(_MAX_RETRIES):
            try:
                resp = self._session.post(url, json=payload, timeout=10)
                if resp.status_code in (200, 201, 202, 204):
                    logger.debug("Sent %d events to %s", len(events), url)
                    return True
                logger.warning(
                    "Server returned HTTP %d for event batch (attempt %d/%d)",
                    resp.status_code, attempt + 1, _MAX_RETRIES,
                )
            except requests.exceptions.ConnectionError:
                logger.warning(
                    "Cannot reach server %s (attempt %d/%d)", url, attempt + 1, _MAX_RETRIES
                )
            except requests.exceptions.Timeout:
                logger.warning(
                    "Request timed out to %s (attempt %d/%d)", url, attempt + 1, _MAX_RETRIES
                )
            except Exception as exc:
                logger.error("Unexpected error sending events: %s", exc)

            if attempt < _MAX_RETRIES - 1:
                delay = _RETRY_BASE_DELAY * (2 ** attempt)
                logger.debug("Retrying in %ds…", delay)
                time.sleep(delay)

        # All retries exhausted — persist to local queue
        self._enqueue_local(events)
        return False

    def flush_queue(self) -> int:
        """
        Attempt to send events previously saved to the local queue.

        Returns the number of events successfully sent.
        """
        queued = self._read_queue()
        if not queued:
            return 0

        logger.info("Flushing %d queued events…", len(queued))
        if self.send_events(queued):
            self._write_queue([])
            logger.info("Flushed %d queued events", len(queued))
            return len(queued)
        return 0

    def test_connection(self) -> bool:
        """Check connectivity and credential validity against the server."""
        url = f"{self._config.server_url.rstrip('/')}/api/iris/ping"
        try:
            resp = self._session.get(url, timeout=5)
            if resp.status_code == 200:
                logger.info("Connection OK: %s", url)
                return True
            logger.error("Server returned HTTP %d at %s", resp.status_code, url)
            return False
        except Exception as exc:
            logger.error("Connection test failed: %s", exc)
            return False

    # ── Local queue helpers ───────────────────────────────────────────────────

    def _enqueue_local(self, events: list[dict]) -> None:
        existing = self._read_queue()
        existing.extend(events)
        self._write_queue(existing)
        logger.info("Enqueued %d events locally (%d total in queue)", len(events), len(existing))

    def _read_queue(self) -> list[dict]:
        if not self._queue_path.exists():
            return []
        try:
            data = json.loads(self._queue_path.read_text())
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to read local queue: %s", exc)
            return []

    def _write_queue(self, events: list[dict]) -> None:
        try:
            self._queue_path.write_text(json.dumps(events))
        except OSError as exc:
            logger.error("Failed to write local queue to %s: %s", self._queue_path, exc)
