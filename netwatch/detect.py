"""Turn a fresh snapshot into security events by comparing it to what we knew.

This is the brain of NetWatch, and it is deliberately pure data-in / data-out so
every rule can be unit-tested without touching the network:

    events, known = evaluate(known, present, now)

* ``known``   - every device we have ever seen (persisted between runs), each
                carrying its last MAC, open ports and whether it was online.
* ``present`` - the devices in the latest snapshot (currently reachable only).

It returns the new security ``events`` and the updated ``known`` map to store.
"""

import time

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# When a *new* service appears on a known device it can mean a misconfiguration
# or, worse, a compromised machine. Weight the alert by how dangerous the port is.
PORT_RISK = {
    23: ("high", "Telnet (sends passwords in clear text)"),
    21: ("high", "FTP (sends passwords in clear text)"),
    3389: ("high", "Remote Desktop (RDP) - a top ransomware target"),
    5900: ("high", "VNC remote control"),
    445: ("medium", "Windows file sharing (SMB)"),
    139: ("medium", "NetBIOS"),
    135: ("medium", "Windows RPC"),
    161: ("medium", "SNMP"),
    1433: ("high", "SQL Server database exposed"),
    3306: ("high", "MySQL/MariaDB database exposed"),
    5432: ("high", "PostgreSQL database exposed"),
    1883: ("medium", "unencrypted MQTT"),
}


def _event(severity, kind, ip, title, detail, now):
    return {
        "ts": now,
        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        "severity": severity,
        "kind": kind,
        "ip": ip,
        "title": title,
        "detail": detail,
    }


def _label(device):
    """A friendly name for a device in alert text."""
    name = device.get("hostname") or device.get("vendor") or ""
    return "%s (%s)" % (device["ip"], name) if name else device["ip"]


def evaluate(known, present, now=None):
    """Compare the stored ``known`` devices with the ``present`` snapshot.

    Returns ``(events, known)`` - the list of new security events (most serious
    first) and the updated ``known`` map to persist for next time. ``known`` is
    not mutated; a new dict is returned.
    """
    now = time.time() if now is None else now
    known = {ip: dict(dev) for ip, dev in known.items()}  # shallow copy, don't mutate caller
    events = []

    for ip, dev in present.items():
        prev = known.get(ip)
        if prev is None:
            events.append(_new_device_event(dev, now))
            known[ip] = _record(dev, now, first_seen=now)
            continue

        if not prev.get("online", False):
            events.append(_event("info", "device_online", ip,
                                  "Device back online", "%s is reachable again." % _label(dev), now))

        events += _mac_events(prev, dev, now)
        events += _port_events(prev, dev, now)

        known[ip] = _record(dev, now, first_seen=prev.get("first_seen", now),
                             keep_mac=prev.get("mac", ""))

    for ip, prev in list(known.items()):
        if ip not in present and prev.get("online", False):
            prev["online"] = False
            events.append(_event("info", "device_offline", ip, "Device went offline",
                                  "%s is no longer answering on the network." % _label(prev), now))

    events.sort(key=lambda e: (SEVERITY_ORDER[e["severity"]], e["ip"]))
    return events, known


def _new_device_event(dev, now):
    risky = [p for p in dev.get("open_ports", []) if PORT_RISK.get(p, ("low",))[0] in ("high", "medium")]
    extra = ""
    severity = "medium"
    if risky:
        severity = "high"
        extra = " It is already exposing: %s." % ", ".join(
            "%d %s" % (p, PORT_RISK[p][1]) for p in risky)
    mac = (" [%s]" % dev["mac"]) if dev.get("mac") else ""
    return _event(severity, "new_device", dev["ip"], "New device joined the network",
                  "A device not seen before appeared at %s%s.%s Confirm you recognise it; "
                  "an unknown device may be an intruder on your Wi-Fi."
                  % (_label(dev), mac, extra), now)


def _mac_events(prev, dev, now):
    old_mac, new_mac = prev.get("mac", ""), dev.get("mac", "")
    if old_mac and new_mac and old_mac != new_mac:
        if dev.get("is_gateway"):
            return [_event("high", "arp_spoofing", dev["ip"],
                           "Possible ARP spoofing on the gateway",
                           "The router/gateway at %s changed hardware address from %s to %s. "
                           "On the gateway this is a classic sign of a man-in-the-middle attack "
                           "intercepting your traffic. Investigate immediately."
                           % (dev["ip"], old_mac, new_mac), now)]
        return [_event("high", "mac_changed", dev["ip"],
                       "Device hardware address changed",
                       "%s changed hardware (MAC) address from %s to %s. This can mean a different "
                       "device took the address (spoofing) or two devices share it."
                       % (dev["ip"], old_mac, new_mac), now)]
    return []


def _port_events(prev, dev, now):
    old_ports = set(prev.get("open_ports", []))
    new_ports = set(dev.get("open_ports", []))
    events = []
    for port in sorted(new_ports - old_ports):
        severity, why = PORT_RISK.get(port, ("low", "a network service"))
        events.append(_event(severity, "new_port", dev["ip"],
                             "New service opened on a device",
                             "%s started listening on port %d (%s). A service appearing on a device "
                             "that did not have it before can be normal - or a sign the machine was "
                             "changed or compromised." % (_label(dev), port, why), now))
    for port in sorted(old_ports - new_ports):
        events.append(_event("info", "closed_port", dev["ip"], "Service stopped on a device",
                             "%s stopped listening on port %d." % (_label(dev), port), now))
    return events


def _record(dev, now, first_seen, keep_mac="", online=True):
    """Build the stored record for a device from its latest snapshot."""
    return {
        "ip": dev["ip"],
        "mac": dev.get("mac") or keep_mac,
        "hostname": dev.get("hostname", ""),
        "vendor": dev.get("vendor", ""),
        "open_ports": sorted(dev.get("open_ports", [])),
        "is_gateway": dev.get("is_gateway", False),
        "is_this_computer": dev.get("is_this_computer", False),
        "online": online,
        "first_seen": first_seen,
        "last_seen": now,
    }
