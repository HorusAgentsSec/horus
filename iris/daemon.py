"""
IrisDaemon — orchestrates all monitors, collects events, and ships them.

Architecture:
  - Each monitor runs in its own thread and pushes events onto a shared
    thread-safe queue.Queue.
  - The main loop wakes every interval_seconds, drains the queue, and hands
    the batch to IrisReporter.
  - SIGTERM / SIGINT trigger a graceful shutdown: monitors are stopped, the
    final in-flight batch is flushed, and the queue file is replayed.
"""

import logging
import queue
import signal
import time
from types import FrameType

from iris.config import Config
from iris.reporter import IrisReporter
from iris.monitors.journald import JournaldMonitor
from iris.monitors.auditd import AuditdMonitor

logger = logging.getLogger(__name__)

class IrisDaemon:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._event_queue: queue.Queue = queue.Queue(maxsize=10_000)
        self._reporter = IrisReporter(config)
        self._running = False

        self._monitors = [
            JournaldMonitor(config, self._event_queue),
            AuditdMonitor(config, self._event_queue),
        ]

    def start(self) -> None:
        logger.info(
            "Horus Iris starting (agent_id=%s, server=%s, interval=%ds)",
            self._config.agent_id,
            self._config.server_url,
            self._config.interval_seconds,
        )

        self._running = True

        # Register signal handlers so systemd / Ctrl-C trigger clean shutdown
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        # Start all monitors
        for monitor in self._monitors:
            try:
                monitor.start()
            except Exception as exc:
                logger.error("Failed to start monitor %s: %s", type(monitor).__name__, exc)

        # Try to flush any events left over from a previous crashed run
        try:
            flushed = self._reporter.flush_queue()
            if flushed:
                logger.info("Flushed %d events from previous run's queue", flushed)
        except Exception as exc:
            logger.warning("Queue flush on startup failed: %s", exc)

        self._main_loop()

    def stop(self) -> None:
        if not self._running:
            return
        logger.info("Iris daemon shutting down…")
        self._running = False

        for monitor in self._monitors:
            try:
                monitor.stop()
            except Exception as exc:
                logger.warning("Error stopping monitor %s: %s", type(monitor).__name__, exc)

        # Drain and ship whatever is left in the queue
        final_batch = self._drain_queue()
        if final_batch:
            logger.info("Sending %d final events before shutdown", len(final_batch))
            self._reporter.send_events(final_batch)

        logger.info("Horus Iris stopped")

    # ── Internal ───────────────────────────────────────────────────────────────

    def _main_loop(self) -> None:
        while self._running:
            # Sleep in small increments so SIGTERM is responsive
            deadline = time.monotonic() + self._config.interval_seconds
            while self._running and time.monotonic() < deadline:
                time.sleep(0.5)

            if not self._running:
                break

            events = self._drain_queue()
            if events:
                logger.debug("Sending %d events", len(events))
                self._reporter.send_events(events)

            # Opportunistically replay the offline queue whenever we wake up
            try:
                self._reporter.flush_queue()
            except Exception as exc:
                logger.debug("Queue flush failed: %s", exc)

    def _drain_queue(self) -> list[dict]:
        events: list[dict] = []
        while True:
            try:
                events.append(self._event_queue.get_nowait())
            except queue.Empty:
                break
        return events

    def _handle_signal(self, signum: int, frame: FrameType | None) -> None:
        sig_name = signal.Signals(signum).name
        logger.info("Received %s, initiating graceful shutdown", sig_name)
        self.stop()
