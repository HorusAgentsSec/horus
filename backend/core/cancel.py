"""Cooperative cancellation registry keyed by job_id.

Workers poll is_canceled() at natural checkpoints (between LLM iterations,
between pipeline stages, etc.) and exit cleanly when it returns True.
The API sets the flag via request(); job_run() clears it on exit.
"""
import threading

_lock = threading.Lock()
_canceled: set[str] = set()


def request(job_id: str | None) -> None:
    if job_id:
        with _lock:
            _canceled.add(job_id)


def is_canceled(job_id: str | None) -> bool:
    if not job_id:
        return False
    with _lock:
        return job_id in _canceled


def clear(job_id: str | None) -> None:
    if job_id:
        with _lock:
            _canceled.discard(job_id)
