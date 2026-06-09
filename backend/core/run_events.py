"""Thread-safe in-memory event store for streaming adversarial cycle progress."""
import threading
from datetime import datetime, timezone

_lock = threading.Lock()
_runs: dict[str, dict] = {}


def create_run(run_id: str) -> None:
    with _lock:
        _runs[run_id] = {"events": [], "done": False}


def emit(run_id: str | None, event: dict) -> None:
    if not run_id:
        return
    event.setdefault("ts", datetime.now(timezone.utc).isoformat())
    with _lock:
        run = _runs.get(run_id)
        if run is not None:
            run["events"].append(event)


def finish(run_id: str | None) -> None:
    if not run_id:
        return
    with _lock:
        run = _runs.get(run_id)
        if run is not None:
            run["done"] = True


def get_events(run_id: str, after: int = 0) -> tuple[list[dict], bool]:
    with _lock:
        run = _runs.get(run_id)
        if run is None:
            return [], True
        return list(run["events"][after:]), run["done"]


def get_all_events(run_id: str) -> list[dict]:
    with _lock:
        run = _runs.get(run_id)
        return list(run["events"]) if run else []


def run_exists(run_id: str) -> bool:
    with _lock:
        return run_id in _runs
