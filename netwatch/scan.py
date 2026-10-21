"""Take a point-in-time snapshot of the local network.

Standard library only, no administrator rights. Hosts are found with ordinary
TCP connections (plus an optional system ping); MAC addresses are read from the
operating system's ARP cache. A *snapshot* is a plain dict mapping each live IP
to what we currently know about it, which the detector then compares over time.
"""

import concurrent.futures
import ipaddress
import os
import platform
import re
import socket
import subprocess
import time

# Ports worth checking on a home / small-business network, with a short name.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp",
    443: "https", 445: "smb", 515: "lpd", 554: "rtsp", 631: "ipp",
    1433: "mssql", 1883: "mqtt", 3306: "mysql", 3389: "rdp", 5000: "upnp/web",
    5432: "postgres", 5900: "vnc", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 9100: "jetdirect",
}

# A quick set used only to decide whether a host is up.
DISCOVERY_PORTS = (80, 443, 445, 139, 22, 135, 3389, 53, 9100, 554, 8080, 515, 631, 23)

MAX_HOSTS = 1024  # never sweep anything bigger than a /22 by accident

_MAC_RE = re.compile(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", re.I)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


# --------------------------------------------------------------------------
# Choosing what to watch
# --------------------------------------------------------------------------

def local_ip():
    """This computer's main IPv4 address (no packets are actually sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def default_network(ip=None):
    """The /24 around this computer's address, e.g. 192.168.1.0/24."""
    ip = ip or local_ip()
    if not ip or ip.startswith("127."):
        raise ValueError("Could not find a local network address. Pass one with --target.")
    return ipaddress.ip_network(ip + "/24", strict=False)


def parse_target(target):
    """Turn '192.168.1.0/24' or '192.168.1.10-40' into a list of host strings.

    Only private, link-local and loopback ranges are allowed, so the monitor can
    never be pointed at the public internet by mistake.
    """
    target = target.strip()
    if "-" in target and "/" not in target:
        start_text, end_text = target.split("-", 1)
        start = ipaddress.ip_address(start_text.strip())
        end_text = end_text.strip()
        if "." not in end_text:
            end_text = start_text.rsplit(".", 1)[0] + "." + end_text
        end = ipaddress.ip_address(end_text)
        if int(end) < int(start):
            raise ValueError("Range end is before range start.")
        hosts = [ipaddress.ip_address(n) for n in range(int(start), int(end) + 1)]
    else:
        network = ipaddress.ip_network(target, strict=False)
        hosts = list(network.hosts()) if network.num_addresses > 2 else list(network)
    if not hosts:
        raise ValueError("No addresses to watch.")
    if len(hosts) > MAX_HOSTS:
        raise ValueError("That is %d addresses; the limit is %d." % (len(hosts), MAX_HOSTS))
    for host in hosts:
        if not (host.is_private or host.is_loopback or host.is_link_local):
            raise ValueError(
                "%s is a public internet address. NetWatch only watches local networks "
                "you own or manage." % host)
    return [str(h) for h in hosts]


# --------------------------------------------------------------------------
# Probing
# --------------------------------------------------------------------------

def tcp_probe(ip, port, timeout=0.5):
    """'open', 'closed' (host sent a reset) or None (no answer)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return None


def ping(ip, timeout_ms=600):
    """True if the host answers an ICMP ping (via the system ping command)."""
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), ip]
    try:
        done = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout_ms / 1000 + 2, creationflags=_NO_WINDOW)
        return done.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def is_alive(ip, timeout=0.5, use_ping=True):
    """Up if the host answers a ping or any TCP port (open or reset)."""
    for port in DISCOVERY_PORTS:
        if tcp_probe(ip, port, timeout) is not None:
            return True
    return use_ping and ping(ip, int(timeout * 1000) + 300)


def discover(hosts, timeout=0.5, workers=128, use_ping=True):
    """The hosts that are up, in address order."""
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(is_alive, ip, timeout, use_ping): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                alive.append(futures[future])
    return sorted(alive, key=lambda ip: ipaddress.ip_address(ip))


def scan_ports(ip, ports=None, timeout=0.6, workers=32):
    """Open ports on one host, sorted."""
    ports = sorted(ports or COMMON_PORTS)
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for port, state in pool.map(lambda p: (p, tcp_probe(ip, p, timeout)), ports):
            if state == "open":
                found.append(port)
    return found


def reverse_dns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
        return "" if name == ip else name
    except (OSError, UnicodeError):
        return ""


# --------------------------------------------------------------------------
# MAC addresses from the ARP cache
# --------------------------------------------------------------------------

def read_arp_table():
    """{ip: mac} from the operating system's ARP cache (best effort)."""
    table = {}
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp") as handle:
                for line in handle.read().splitlines()[1:]:
                    fields = line.split()
                    if len(fields) >= 4 and fields[3] != "00:00:00:00:00:00":
                        table[fields[0]] = fields[3].lower()
            if table:
                return table
        except OSError:
            pass
    try:
        done = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10,
                              creationflags=_NO_WINDOW)
        return parse_arp_output(done.stdout)
    except (OSError, subprocess.SubprocessError):
        return table


def parse_arp_output(text):
    """Parse `arp -a` output from Windows, macOS or Linux into {ip: mac}."""
    table = {}
    for line in text.splitlines():
        mac = _MAC_RE.search(line)
        ip = _IP_RE.search(line)
        if mac and ip:
            value = mac.group(0).lower().replace("-", ":")
            if value not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                table[ip.group(1)] = value
    return table


def load_oui_file(path):
    """Read an IEEE 'oui.txt' into {prefix: vendor} for naming device makers."""
    vendors = {}
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = re.match(r"^\s*([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$", line)
            if match:
                vendors[match.group(1).replace("-", ":").lower()] = match.group(2).strip()
    return vendors


def vendor_for(mac, vendors):
    if not mac or not vendors:
        return ""
    return vendors.get(mac.lower()[:8], "")


# --------------------------------------------------------------------------
# A whole snapshot
# --------------------------------------------------------------------------

def snapshot(target=None, ports=None, timeout=0.5, use_ping=True, vendors=None):
    """Scan the network once and return {ip: device} plus a little metadata.

    Each device is a plain dict: ip, mac, hostname, vendor, open_ports (sorted
    list), is_gateway (the .1 of the network), is_this_computer. This is the unit
    the monitor stores and the detector compares between runs.
    """
    vendors = vendors or {}
    if target:
        hosts = parse_target(target)
        label = target
    else:
        network = default_network()
        hosts = parse_target(str(network))
        label = str(network)

    started = time.time()
    alive = set(discover(hosts, timeout=timeout, use_ping=use_ping))
    arp = read_arp_table()
    # A device that answered ARP but blocked every probe is still present.
    alive |= {ip for ip in arp if ip in set(hosts)}
    alive = sorted(alive, key=lambda ip: ipaddress.ip_address(ip))

    me = local_ip()
    gateway = _gateway_of(hosts)
    devices = {}
    for ip in alive:
        open_ports = scan_ports(ip, ports, timeout=timeout + 0.2)
        mac = arp.get(ip, "")
        devices[ip] = {
            "ip": ip,
            "mac": mac,
            "hostname": reverse_dns(ip),
            "vendor": vendor_for(mac, vendors),
            "open_ports": open_ports,
            "is_gateway": ip == gateway,
            "is_this_computer": ip == me,
        }
    return {
        "target": label,
        "scanned_addresses": len(hosts),
        "duration_s": round(time.time() - started, 1),
        "scanner_ip": me,
        "scanner_host": socket.gethostname(),
        "platform": platform.platform(),
        "devices": devices,
    }


def _gateway_of(hosts):
    """The .1 address of the scanned range, if present (the usual gateway)."""
    for ip in hosts:
        if ip.endswith(".1"):
            return ip
    return None
