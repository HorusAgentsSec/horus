"""
Configuration loader for Horus Iris.

Search order:
  1. Explicit --config CLI argument (passed via Config(path=...))
  2. HORUS_IRIS_CONFIG environment variable
  3. /etc/horus/iris.yaml
  4. ~/.horus/iris.yaml
"""

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_SEARCH_PATHS = [
    Path("/etc/horus/iris.yaml"),
    Path.home() / ".horus" / "iris.yaml",
]

_DEFAULT_WATCH_PATHS = ["/etc", "/bin", "/usr/bin", "/sbin", "/usr/sbin", "/root"]
_DEFAULT_IGNORE_PATTERNS = ["*.log", "*.tmp", ".git/*"]


@dataclass
class Config:
    server_url: str = ""
    api_key: str = ""
    agent_id: str = ""
    interval_seconds: int = 30
    watch_paths: list[str] = field(default_factory=lambda: list(_DEFAULT_WATCH_PATHS))
    ignore_patterns: list[str] = field(default_factory=lambda: list(_DEFAULT_IGNORE_PATTERNS))
    log_level: str = "INFO"

    def validate(self) -> None:
        missing = [f for f in ("server_url", "api_key", "agent_id") if not getattr(self, f)]
        if missing:
            raise ValueError(
                f"Config is missing required fields: {', '.join(missing)}. "
                "Edit /etc/horus/iris.yaml to set them."
            )


# ── Loader ─────────────────────────────────────────────────────────────────────


def load_config(explicit_path: str | None = None) -> Config:
    """Load and return a Config, searching in priority order."""
    path: Path | None = None

    if explicit_path:
        path = Path(explicit_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
    elif env := os.environ.get("HORUS_IRIS_CONFIG"):
        path = Path(env)
        if not path.exists():
            raise FileNotFoundError(f"HORUS_IRIS_CONFIG points to missing file: {path}")
    else:
        path = next((p for p in _DEFAULT_SEARCH_PATHS if p.exists()), None)

    if path is None:
        logger.warning(
            "No config file found. Using defaults — daemon will fail validation unless "
            "server_url/api_key/agent_id are set."
        )
        return Config()

    logger.info("Loading config from %s", path)
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:
        raise RuntimeError(f"Failed to parse config file {path}: {exc}") from exc

    return Config(
        server_url=raw.get("server_url", ""),
        api_key=raw.get("api_key", ""),
        agent_id=raw.get("agent_id", ""),
        interval_seconds=int(raw.get("interval_seconds", 30)),
        watch_paths=list(raw.get("watch_paths", _DEFAULT_WATCH_PATHS)),
        ignore_patterns=list(raw.get("ignore_patterns", _DEFAULT_IGNORE_PATTERNS)),
        log_level=str(raw.get("log_level", "INFO")).upper(),
    )
