"""Tests for NetWatch. Pure detection logic needs no network; the scanner and
dashboard tests use real sockets on 127.0.0.1 so they run anywhere, including CI.
"""

import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.request

from netwatch import detect, scan
from netwatch.dashboard import serve
from netwatch.store import State


def dev(ip, mac="", ports=None, gateway=False, hostname="", vendor=""):
    return {"ip": ip, "mac": mac, "open_ports": ports or [], "is_gateway": gateway,
            "hostname": hostname, "vendor": vendor, "is_this_computer": False}


class DetectTests(unittest.TestCase):
    def test_new_device_is_flagged_and_remembered(self):
        events, known = detect.evaluate({}, {"192.168.1.5": dev("192.168.1.5", "aa:bb:cc:dd:ee:ff")})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["kind"], "new_device")
        self.assertEqual(events[0]["severity"], "medium")
        self.assertIn("192.168.1.5", known)
        self.assertTrue(known["192.168.1.5"]["online"])

    def test_new_device_with_risky_port_is_high(self):
        events, _ = detect.evaluate({}, {"10.0.0.9": dev("10.0.0.9", ports=[23])})
        self.assertEqual(events[0]["severity"], "high")
        self.assertIn("Telnet", events[0]["detail"])

    def test_no_change_no_events(self):
        known = {"192.168.1.5": detect._record(dev("192.168.1.5", "aa:bb:cc:dd:ee:01", [80]), time.time(), time.time())}
        events, _ = detect.evaluate(known, {"192.168.1.5": dev("192.168.1.5", "aa:bb:cc:dd:ee:01", [80])})
        self.assertEqual(events, [])

    def test_mac_change_on_normal_device_is_high(self):
        known = {"192.168.1.5": detect._record(dev("192.168.1.5", "aa:aa:aa:aa:aa:aa"), time.time(), time.time())}
        events, _ = detect.evaluate(known, {"192.168.1.5": dev("192.168.1.5", "bb:bb:bb:bb:bb:bb")})
        kinds = [e["kind"] for e in events]
        self.assertIn("mac_changed", kinds)
        self.assertEqual([e for e in events if e["kind"] == "mac_changed"][0]["severity"], "high")

    def test_mac_change_on_gateway_is_arp_spoofing(self):
        known = {"192.168.1.1": detect._record(dev("192.168.1.1", "aa:aa:aa:aa:aa:aa", gateway=True), time.time(), time.time())}
        events, _ = detect.evaluate(known, {"192.168.1.1": dev("192.168.1.1", "bb:bb:bb:bb:bb:bb", gateway=True)})
        self.assertEqual(events[0]["kind"], "arp_spoofing")
        self.assertEqual(events[0]["severity"], "high")
        self.assertIn("man-in-the-middle", events[0]["detail"])

    def test_new_risky_port_vs_benign_port(self):
        known = {"10.0.0.2": detect._record(dev("10.0.0.2", "aa:aa:aa:aa:aa:aa", [80]), time.time(), time.time())}
        events, _ = detect.evaluate(known, {"10.0.0.2": dev("10.0.0.2", "aa:aa:aa:aa:aa:aa", [80, 3389])})
        rdp = [e for e in events if e["kind"] == "new_port"][0]
        self.assertEqual(rdp["severity"], "high")  # RDP is risky

        known2 = {"10.0.0.2": detect._record(dev("10.0.0.2", "aa:aa:aa:aa:aa:aa", [80]), time.time(), time.time())}
        events2, _ = detect.evaluate(known2, {"10.0.0.2": dev("10.0.0.2", "aa:aa:aa:aa:aa:aa", [80, 8080])})
        self.assertEqual([e for e in events2 if e["kind"] == "new_port"][0]["severity"], "low")

    def test_closed_port_is_info(self):
        known = {"10.0.0.2": detect._record(dev("10.0.0.2", "aa:aa:aa:aa:aa:aa", [80, 22]), time.time(), time.time())}
        events, _ = detect.evaluate(known, {"10.0.0.2": dev("10.0.0.2", "aa:aa:aa:aa:aa:aa", [80])})
        self.assertEqual([e for e in events if e["kind"] == "closed_port"][0]["severity"], "info")

    def test_offline_then_back_online(self):
        known = {"10.0.0.2": detect._record(dev("10.0.0.2", "aa:aa:aa:aa:aa:aa"), time.time(), time.time())}
        events, known = detect.evaluate(known, {})  # nothing present now
        self.assertEqual(events[0]["kind"], "device_offline")
        self.assertFalse(known["10.0.0.2"]["online"])
        events2, known2 = detect.evaluate(known, {"10.0.0.2": dev("10.0.0.2", "aa:aa:aa:aa:aa:aa")})
        self.assertEqual(events2[0]["kind"], "device_online")
        self.assertTrue(known2["10.0.0.2"]["online"])

    def test_evaluate_does_not_mutate_caller_known(self):
        known = {"10.0.0.2": detect._record(dev("10.0.0.2", "aa:aa:aa:aa:aa:aa", [80]), time.time(), time.time())}
        before = json.dumps(known, sort_keys=True)
        detect.evaluate(known, {"10.0.0.2": dev("10.0.0.2", "bb:bb:bb:bb:bb:bb", [80, 23])})
        self.assertEqual(before, json.dumps(known, sort_keys=True))


class ArpParsingTests(unittest.TestCase):
    def test_windows(self):
        out = "Interface: 192.168.1.10 --- 0x3\n  192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic\n"
        self.assertEqual(scan.parse_arp_output(out), {"192.168.1.1": "aa:bb:cc:dd:ee:ff"})

    def test_unix(self):
        out = "gateway (192.168.1.1) at a1:b2:c3:d4:e5:f6 on en0 ifscope [ethernet]\n"
        self.assertEqual(scan.parse_arp_output(out), {"192.168.1.1": "a1:b2:c3:d4:e5:f6"})

    def test_skips_broadcast(self):
        out = "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0\n"
        self.assertEqual(scan.parse_arp_output(out), {})


class TargetTests(unittest.TestCase):
    def test_rejects_public_ip(self):
        with self.assertRaises(ValueError):
            scan.parse_target("8.8.8.0/24")

    def test_accepts_private_range(self):
        hosts = scan.parse_target("192.168.1.10-12")
        self.assertEqual(hosts, ["192.168.1.10", "192.168.1.11", "192.168.1.12"])

    def test_rejects_oversized_range(self):
        with self.assertRaises(ValueError):
            scan.parse_target("10.0.0.0/20")


class PortScanTests(unittest.TestCase):
    def setUp(self):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(5)
        self.port = self.srv.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self.stop:
            try:
                conn, _ = self.srv.accept()
                conn.close()
            except OSError:
                break

    def tearDown(self):
        self.stop = True
        self.srv.close()

    def test_detects_open_port(self):
        self.assertEqual(scan.tcp_probe("127.0.0.1", self.port, timeout=1), "open")
        self.assertIn(self.port, scan.scan_ports("127.0.0.1", [self.port], timeout=1))

    def test_closed_port_not_reported(self):
        self.assertEqual(scan.scan_ports("127.0.0.1", [1], timeout=0.3), [])


class StoreTests(unittest.TestCase):
    def test_apply_and_snapshot_counts(self):
        state = State()
        ev = detect._event("high", "new_device", "10.0.0.5", "New device", "x", time.time())
        state.apply({"10.0.0.5": detect._record(dev("10.0.0.5"), time.time(), time.time())}, [ev],
                    {"target": "10.0.0.0/24", "duration_s": 1.0})
        snap = state.snapshot()
        self.assertEqual(snap["event_counts"]["high"], 1)
        self.assertEqual(len(snap["devices"]), 1)
        self.assertEqual(snap["scans"], 1)

    def test_persistence_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.json")
            s1 = State(path)
            s1.apply({"10.0.0.5": detect._record(dev("10.0.0.5", "aa:aa:aa:aa:aa:aa"), time.time(), time.time())},
                     [detect._event("info", "x", "10.0.0.5", "t", "d", time.time())],
                     {"target": "10.0.0.0/24"})
            self.assertTrue(os.path.exists(path))
            s2 = State(path)  # reload
            self.assertIn("10.0.0.5", s2.known)
            self.assertFalse(s2.known["10.0.0.5"]["online"])  # unconfirmed until next scan
            self.assertEqual(len(s2.events), 1)


class DashboardTests(unittest.TestCase):
    def test_serves_page_and_api(self):
        state = State()
        state.apply({"10.0.0.5": detect._record(dev("10.0.0.5", "aa:aa:aa:aa:aa:aa", [80]), time.time(), time.time())},
                    [detect._event("high", "new_device", "10.0.0.5", "New device", "detail here", time.time())],
                    {"target": "10.0.0.0/24", "duration_s": 1.0})
        server = serve(state, host="127.0.0.1", port=0)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            page = urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=3).read().decode()
            self.assertIn("NetWatch", page)
            api = json.loads(urllib.request.urlopen("http://127.0.0.1:%d/api/state" % port, timeout=3).read())
            self.assertEqual(api["event_counts"]["high"], 1)
            self.assertEqual(len(api["devices"]), 1)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
