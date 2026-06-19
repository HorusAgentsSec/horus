"""
Auditd monitor — tails /var/log/audit/audit.log, groups records by serial number,
and emits horus events for exec / file-change / network audit keys.

Replaces: fim.py (file changes), process.py (exec), network.py (connections).
Requires auditd rules written by the installer (see install.sh).
Zero inotify watches, zero psutil polling — the kernel audit subsystem does it all.
"""

import logging
import queue
import re
import subprocess
import threading
from pathlib import Path

from iris.config import Config

logger = logging.getLogger(__name__)

AUDIT_LOG = Path("/var/log/audit/audit.log")

_SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 6666, 9001}
_BLACKLISTED_CMDS = {"nc", "ncat", "netcat", "socat", "mimikatz", "msfconsole", "msfvenom"}
_SUSPICIOUS_PATHS = ("/tmp/", "/dev/shm/", "/var/tmp/")

_RE_HEADER = re.compile(r"^type=(\S+) msg=audit\(\d+\.\d+:(\d+)\):")
_RE_FIELD   = re.compile(r'(\w+)=(?:"([^"]*?)"|(\S+))')


def _parse(line: str) -> dict:
    m = _RE_HEADER.match(line)
    if not m:
        return {}
    rec = {"type": m.group(1), "_serial": m.group(2)}
    for k, v_q, v_b in _RE_FIELD.findall(line[m.end():]):
        rec[k] = v_q if v_q != "" else v_b
    return rec


class AuditdMonitor:
    def __init__(self, config: Config, event_queue: queue.Queue) -> None:
        self._q = event_queue
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._groups: dict[str, dict] = {}  # serial → {type: rec}

    def start(self) -> None:
        if not AUDIT_LOG.exists():
            logger.warning("AuditdMonitor: %s not found — auditd not installed or not running", AUDIT_LOG)
            return
        self._thread = threading.Thread(target=self._run, name="iris-auditd", daemon=True)
        self._thread.start()
        logger.info("Auditd monitor started (tailing %s)", AUDIT_LOG)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Auditd monitor stopped")

    def _run(self) -> None:
        try:
            proc = subprocess.Popen(
                ["tail", "-f", "-n", "0", str(AUDIT_LOG)],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, errors="replace",
            )
        except Exception as exc:
            logger.error("AuditdMonitor: failed to tail %s: %s", AUDIT_LOG, exc)
            return

        try:
            while not self._stop.is_set():
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                self._handle_line(line.rstrip())
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _handle_line(self, line: str) -> None:
        rec = _parse(line)
        if not rec:
            return

        serial = rec["_serial"]
        rtype  = rec["type"]

        if rtype == "EOE":
            group = self._groups.pop(serial, None)
            if group:
                self._process(group)
            return

        self._groups.setdefault(serial, {})[rtype] = rec

        # ponytail: bound memory — drop oldest if too many open groups
        if len(self._groups) > 500:
            for old in sorted(self._groups)[:100]:
                self._groups.pop(old, None)

    def _process(self, group: dict) -> None:
        syscall = group.get("SYSCALL", {})
        key     = syscall.get("key", "")

        if not key.startswith("horus_"):
            return
        if syscall.get("success", "yes") != "yes":
            return

        exe  = syscall.get("exe", "").strip('"')
        comm = syscall.get("comm", "").strip('"')
        uid  = syscall.get("uid", "?")

        if key == "horus_exec":
            execve = group.get("EXECVE", {})
            argc   = int(execve.get("argc", 0) or 0)
            args   = [execve.get(f"a{i}", "") for i in range(min(argc, 8))]
            cmdline = " ".join(args)

            if comm.lower() in _BLACKLISTED_CMDS:
                sev = "high"
            elif any(exe.startswith(p) for p in _SUSPICIOUS_PATHS):
                sev = "medium"
            else:
                return  # routine exec — ignore

            self._emit("suspicious_process", sev,
                f"Suspicious exec: {comm or exe}",
                {"exe": exe, "comm": comm, "cmdline": cmdline[:300], "uid": uid})

        elif key == "horus_fim":
            path_rec = group.get("PATH", {})
            path = path_rec.get("name", "").strip('"')
            if not path:
                return
            sev = "high" if path.startswith(("/etc/", "/root/")) else "medium"
            self._emit("file_change", sev,
                f"File modified: {path}",
                {"path": path, "exe": exe, "uid": uid})

        elif key == "horus_net":
            # Port from hex saddr: AF_INET sockaddr = 02 00 PPPP AAAA...
            saddr = syscall.get("saddr", "")
            port  = None
            try:
                if len(saddr) >= 8 and saddr[:4] in ("0200", "0A00"):
                    port = int(saddr[4:8], 16)
            except ValueError:
                pass

            sev = "high" if port in _SUSPICIOUS_PORTS else "low"
            if sev == "low":
                return  # skip routine connections

            self._emit("network_connection", sev,
                f"Connection to suspicious port {port} from {comm or exe}",
                {"exe": exe, "comm": comm, "uid": uid, "dest_port": port})

    def _emit(self, event_type: str, severity: str, title: str, payload: dict) -> None:
        try:
            self._q.put_nowait({"event_type": event_type, "severity": severity,
                                "title": title, "payload": payload})
        except queue.Full:
            logger.warning("auditd monitor: queue full, dropping event")
