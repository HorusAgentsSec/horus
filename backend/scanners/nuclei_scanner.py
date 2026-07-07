import json
import logging
import subprocess
import tempfile
from pathlib import Path

from backend.agents.state import RawFinding
from backend.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class NucleiScanner(BaseScanner):
    def scan(self, host: str, port: int | None = None, *, scan_id: str | None = None) -> list[RawFinding]:
        target = f"{host}:{port}" if port else host

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = tmp.name

        cmd = [
            "nuclei",
            "-target", target,
            # JSONL (one object per line). `-json-export` writes a single JSON
            # *array*, which the line-by-line parser below cannot read.
            "-jsonl-export", out_path,
            "-severity", "critical,high,medium,low",
            "-silent",
            "-no-interactsh",
            # Skip the template auto-update on every run; it adds latency and can
            # push slow targets past the timeout.
            "-disable-update-check",
        ]

        process = None
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            if scan_id:
                from backend.core.process_registry import register_process
                register_process(scan_id, process)
            process.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            logger.warning(f"NucleiScanner timed out on {target}")
            if process is not None:
                try:
                    import os
                    os.killpg(process.pid, subprocess.signal.SIGKILL)
                except Exception:
                    pass
                try:
                    process.communicate()  # drain pipes after kill
                except Exception:
                    pass
            return []
        except FileNotFoundError:
            logger.error("nuclei binary not found — skipping Nuclei scan")
            return []
        finally:
            if scan_id and process is not None:
                from backend.core.process_registry import unregister_process
                unregister_process(scan_id, process)

        try:
            with open(out_path) as f:
                content = f.read()
        except FileNotFoundError:
            content = ""
        finally:
            Path(out_path).unlink(missing_ok=True)

        # Be tolerant of both output shapes: a single JSON array (`-json-export`)
        # and JSONL (`-jsonl-export`). Either way we end up with a list of records.
        records: list = []
        stripped = content.strip()
        if stripped:
            try:
                parsed = json.loads(stripped)
                records = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                for line in stripped.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        findings = []
        for data in records:
            if not isinstance(data, dict):
                continue
            info = data.get("info") if isinstance(data.get("info"), dict) else {}
            findings.append(
                RawFinding(
                    tool="nuclei",
                    template_id=data.get("template-id"),
                    name=info.get("name", ""),
                    host=data.get("host", ""),
                    severity=info.get("severity", "info"),
                    raw=data,
                )
            )

        logger.info(f"NucleiScanner: {len(findings)} findings on {target}")
        return findings
