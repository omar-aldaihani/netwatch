"""Command-line interface: start the monitor and the dashboard."""

import argparse
import os
import sys
import time
import webbrowser

from netwatch import __version__, scan
from netwatch.dashboard import serve
from netwatch.monitor import Monitor
from netwatch.store import State

_COLOURS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m"}
_RESET = "\033[0m"


def _default_state_path():
    base = os.path.join(os.path.expanduser("~"), ".netwatch")
    try:
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, "state.json")
    except OSError:
        return "netwatch-state.json"


def _print_event(event, use_colour):
    when = event["time"].split(" ")[1]
    tag = event["severity"].upper().ljust(6)
    if use_colour:
        tag = _COLOURS.get(event["severity"], "") + tag + _RESET
    where = (" " + event["ip"]) if event["ip"] else ""
    print("%s %s %s%s - %s" % (when, tag, event["title"], where, event["detail"]))


def build_parser():
    p = argparse.ArgumentParser(
        prog="netwatch",
        description="Watch a local network and alert on new devices, ARP spoofing and new services.")
    p.add_argument("-t", "--target", help="network to watch, e.g. 192.168.1.0/24 (default: auto-detect)")
    p.add_argument("-i", "--interval", type=int, default=60, help="seconds between scans (default 60)")
    p.add_argument("--timeout", type=float, default=0.5, help="per-port probe timeout (default 0.5s)")
    p.add_argument("--no-ping", action="store_true", help="do not use the system ping during discovery")
    p.add_argument("--oui", help="path to IEEE oui.txt to show device makers")
    p.add_argument("--state", help="state file to persist the device baseline (default ~/.netwatch/state.json)")
    p.add_argument("--host", default="127.0.0.1", help="dashboard bind address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=8787, help="dashboard port (default 8787)")
    p.add_argument("--no-dashboard", action="store_true", help="run headless, no web dashboard")
    p.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    p.add_argument("--once", action="store_true", help="run a single scan, print findings and exit")
    p.add_argument("-q", "--quiet", action="store_true", help="only print medium and high alerts")
    p.add_argument("-V", "--version", action="version", version="NetWatch " + __version__)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    vendors = scan.load_oui_file(args.oui) if args.oui else {}
    use_colour = sys.stdout.isatty() and os.name != "nt"

    def on_event(event):
        if args.quiet and event["severity"] not in ("high", "medium"):
            return
        _print_event(event, use_colour)

    state_path = None if args.once else (args.state or _default_state_path())
    state = State(state_path)
    monitor = Monitor(state, target=args.target, interval=args.interval,
                      timeout=args.timeout, use_ping=not args.no_ping,
                      vendors=vendors, on_event=on_event)

    if args.once:
        print("NetWatch %s - single scan of %s" % (__version__, args.target or "the local network"))
        events = monitor.run_once()
        print("\nScanned in %ss. %d device(s) seen, %d event(s)."
              % (state.meta.get("duration_s"), len(state.known), len(events)))
        return 1 if any(e["severity"] == "high" for e in events) else 0

    print("NetWatch %s starting - watching %s every %ds"
          % (__version__, args.target or "the local network", args.interval))
    monitor.start()

    server = None
    if not args.no_dashboard:
        try:
            server = serve(state, host=args.host, port=args.port)
        except OSError as exc:
            print("Could not start the dashboard on %s:%d (%s). Running headless."
                  % (args.host, args.port, exc))
        else:
            url = "http://%s:%d" % (args.host, args.port)
            print("Dashboard: %s   (press Ctrl+C to stop)" % url)
            if args.open:
                webbrowser.open(url)

    try:
        if server:
            server.serve_forever()
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping NetWatch.")
    finally:
        monitor.stop()
        if server:
            server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
