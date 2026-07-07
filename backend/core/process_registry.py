"""Tracks scanner subprocesses so scans can be canceled aggressively."""

import logging
import os
import signal
import subprocess
import threading
from collections import defaultdict

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_processes: dict[str, set[subprocess.Popen]] = defaultdict(set)


def register_process(scan_id: str, process: subprocess.Popen) -> None:
    with _lock:
        _processes[scan_id].add(process)


def unregister_process(scan_id: str, process: subprocess.Popen) -> None:
    with _lock:
        processes = _processes.get(scan_id)
        if not processes:
            return
        processes.discard(process)
        if not processes:
            _processes.pop(scan_id, None)


def cancel_scan_processes(scan_id: str) -> int:
    """Terminates active scanner subprocesses for one scan. Returns count signaled."""
    with _lock:
        processes = list(_processes.get(scan_id, set()))

    count = 0
    for process in processes:
        if process.poll() is not None:
            unregister_process(scan_id, process)
            continue
        count += 1
        _terminate_process_group(process)
    return count


def _terminate_process_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except ProcessLookupError:
        return
    except subprocess.TimeoutExpired:
        logger.warning("Scanner process %s ignored SIGTERM; sending SIGKILL", process.pid)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    except Exception:
        logger.exception("Could not terminate scanner process %s", process.pid)
