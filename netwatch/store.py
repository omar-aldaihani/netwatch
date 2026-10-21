"""The shared, persisted state of the monitor: known devices and recent events.

One ``State`` object is written by the monitor thread and read by the dashboard,
so every access is guarded by a lock. It saves to a single JSON file so a restart
keeps the device baseline (and therefore does not re-alert on everything).
"""

import json
import os
import threading
import time

MAX_EVENTS = 500  # keep the most recent events; plenty for a dashboard feed


class State:
    def __init__(self, path=None):
        self.path = path
        self._lock = threading.Lock()
        self.known = {}          # {ip: device record}
        self.events = []         # most-recent-first
        self.started = time.time()
        self.last_scan = None    # epoch of the last completed scan
        self.last_duration = None
        self.scans = 0
        self.meta = {}           # target, scanner_ip, platform, ...
        if path and os.path.exists(path):
            self._load()

    # -- updates from the monitor -----------------------------------------
    def apply(self, known, events, meta):
        """Replace the known-device map, prepend new events, update counters."""
        with self._lock:
            self.known = known
            if events:
                self.events = (events[::-1] + self.events)[:MAX_EVENTS]
            self.meta = meta
            self.last_scan = time.time()
            self.last_duration = meta.get("duration_s")
            self.scans += 1
        self.save()

    # -- reads for the dashboard ------------------------------------------
    def snapshot(self):
        """A JSON-friendly copy of everything the dashboard needs."""
        with self._lock:
            devices = sorted(self.known.values(),
                             key=lambda d: [int(x) for x in d["ip"].split(".")])
            counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
            for event in self.events:
                counts[event["severity"]] = counts.get(event["severity"], 0) + 1
            return {
                "meta": self.meta,
                "started": self.started,
                "uptime_s": round(time.time() - self.started),
                "last_scan": self.last_scan,
                "last_duration": self.last_duration,
                "scans": self.scans,
                "devices": devices,
                "online": sum(1 for d in devices if d.get("online")),
                "events": self.events[:200],
                "event_counts": counts,
            }

    # -- persistence ------------------------------------------------------
    def save(self):
        if not self.path:
            return
        with self._lock:
            data = {"known": self.known, "events": self.events,
                    "started": self.started, "scans": self.scans, "meta": self.meta}
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
            os.replace(tmp, self.path)
        except OSError:
            pass  # a monitor should never crash because it could not write state

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return
        self.known = data.get("known", {})
        self.events = data.get("events", [])
        self.scans = data.get("scans", 0)
        self.meta = data.get("meta", {})
        self.started = data.get("started", time.time())
        for dev in self.known.values():
            dev["online"] = False  # nothing is confirmed online until the first scan
