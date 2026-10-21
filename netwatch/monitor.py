"""The monitoring loop: snapshot -> detect -> record, over and over.

Runs in its own thread so the dashboard web server stays responsive. Each pass
takes a fresh snapshot, compares it to the known devices via :mod:`detect`, and
hands the new events and updated baseline to the shared :class:`State`.
"""

import threading
import time

from netwatch import detect, scan


class Monitor:
    def __init__(self, state, target=None, interval=60, timeout=0.5,
                 use_ping=True, vendors=None, on_event=None):
        self.state = state
        self.target = target
        self.interval = interval
        self.timeout = timeout
        self.use_ping = use_ping
        self.vendors = vendors or {}
        self.on_event = on_event  # callback(event) for console/alert output
        self._stop = threading.Event()
        self._thread = None

    def run_once(self):
        """Take one snapshot, detect changes, and record them. Returns the events."""
        snap = scan.snapshot(self.target, timeout=self.timeout,
                             use_ping=self.use_ping, vendors=self.vendors)
        events, known = detect.evaluate(self.state.known, snap["devices"])
        meta = {k: snap[k] for k in ("target", "scanned_addresses", "duration_s",
                                     "scanner_ip", "scanner_host", "platform")}
        self.state.apply(known, events, meta)
        if self.on_event:
            for event in events:
                self.on_event(event)
        return events

    # -- background thread -------------------------------------------------
    def start(self):
        self._thread = threading.Thread(target=self._loop, name="netwatch-monitor", daemon=True)
        self._thread.start()
        return self

    def _loop(self):
        while not self._stop.is_set():
            start = time.time()
            try:
                self.run_once()
            except Exception as exc:  # a scan must never kill the monitor
                if self.on_event:
                    self.on_event(detect._event(
                        "info", "scan_error", "", "Scan error", str(exc), time.time()))
            # Sleep the remainder of the interval, waking promptly on stop.
            elapsed = time.time() - start
            self._stop.wait(max(1.0, self.interval - elapsed))

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
