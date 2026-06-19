"""
File Integrity Monitor (FIM) using watchdog.

Watches configured paths for CREATE/MODIFY/DELETE/MOVED events and converts
them into Horus Iris event dicts, placed on the shared event queue.
"""

import fnmatch
import logging
import os
import queue
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from iris.config import Config

logger = logging.getLogger(__name__)

# Paths whose changes should be treated as high severity
_HIGH_SEVERITY_PREFIXES = ("/etc/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")
_LOW_SEVERITY_PREFIXES = ("/home/",)


def _severity_for_path(path: str) -> str:
    for prefix in _HIGH_SEVERITY_PREFIXES:
        if path.startswith(prefix):
            return "high"
    for prefix in _LOW_SEVERITY_PREFIXES:
        if path.startswith(prefix):
            return "low"
    return "medium"


class _IrisEventHandler(FileSystemEventHandler):
    def __init__(self, event_queue: queue.Queue, ignore_patterns: list[str]) -> None:
        super().__init__()
        self._q = event_queue
        self._ignore_patterns = ignore_patterns

    def _is_ignored(self, path: str) -> bool:
        name = os.path.basename(path)
        for pattern in self._ignore_patterns:
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(path, pattern):
                return True
        return False

    def _build_event(self, action: str, path: str, is_dir: bool, dest_path: str | None = None) -> dict:
        severity = _severity_for_path(path)
        title = f"File {action}: {path}"
        if dest_path:
            title = f"File {action}: {path} -> {dest_path}"

        payload: dict = {
            "path": path,
            "action": action,
            "is_dir": is_dir,
        }
        if dest_path:
            payload["dest_path"] = dest_path

        # Collect stat info without crashing on race conditions or permission errors
        try:
            stat = os.stat(path)
            payload["size"] = stat.st_size
            payload["mtime"] = stat.st_mtime
        except (OSError, PermissionError):
            pass

        return {
            "event_type": "file_change",
            "severity": severity,
            "title": title,
            "payload": payload,
        }

    def _emit(self, action: str, path: str, is_dir: bool, dest_path: str | None = None) -> None:
        if self._is_ignored(path):
            return
        evt = self._build_event(action, path, is_dir, dest_path)
        try:
            self._q.put_nowait(evt)
        except queue.Full:
            logger.warning("FIM event queue full, dropping event for %s", path)

    def on_created(self, event):
        self._emit("created", event.src_path, event.is_directory)

    def on_modified(self, event):
        self._emit("modified", event.src_path, event.is_directory)

    def on_deleted(self, event):
        self._emit("deleted", event.src_path, event.is_directory)

    def on_moved(self, event):
        self._emit("moved", event.src_path, event.is_directory, event.dest_path)


class FIMMonitor:
    """Wraps watchdog Observer; emits events to the shared queue."""

    def __init__(self, config: Config, event_queue: queue.Queue) -> None:
        self._config = config
        self._q = event_queue
        self._observer: Observer | None = None

    def start(self) -> None:
        handler = _IrisEventHandler(self._q, self._config.ignore_patterns)
        self._observer = Observer()

        for watch_path in self._config.watch_paths:
            p = Path(watch_path)
            if not p.exists():
                logger.warning("FIM: watch path does not exist, skipping: %s", watch_path)
                continue
            try:
                # ponytail: count subdirs — watchdog holds every subdir in RAM
                dir_count = sum(1 for _ in p.rglob("*") if _.is_dir()) if p.is_dir() else 0
                recursive = dir_count <= 5_000
                if not recursive:
                    logger.warning(
                        "FIM: %s has %d subdirs — forcing non-recursive to avoid OOM "
                        "(add specific subdirs to watch_paths instead)",
                        watch_path, dir_count,
                    )
                self._observer.schedule(handler, str(p), recursive=recursive)
                logger.info("FIM: watching %s (recursive=%s, dirs=%d)", watch_path, recursive, dir_count)
            except PermissionError:
                logger.warning("FIM: no permission to watch %s, skipping", watch_path)

        self._observer.start()
        logger.info("FIM monitor started")

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            logger.info("FIM monitor stopped")
