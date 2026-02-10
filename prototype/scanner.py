"""
Network scanner module.
Uses nmap when available, falls back to mock data for demos.
"""

import shutil
import os
import sys
import json
from datetime import datetime

# Add common nmap install locations to PATH
nmap_paths = [
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Nmap",
]
for p in nmap_paths:
    if os.path.isdir(p) and p not in os.environ.get("PATH", ""):
        os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")

# Try to import nmap
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# Check if nmap binary is installed
NMAP_BINARY = shutil.which("nmap") is not None


def is_nmap_ready():
    """Check if nmap is fully available (library + binary)."""
    return NMAP_AVAILABLE and NMAP_BINARY


def scan_network(target):
    """
    Scan a network/host and return discovered devices.
    Falls back to mock data if nmap is not available.
    """
    if is_nmap_ready():
        return _real_scan(target)
    else:
        return _mock_scan(target)


def _real_scan(target):
    """Run a real nmap scan."""
    nm = nmap.PortScanner()

    # Quick service version scan on common + IoT ports
    # -Pn: skip host discovery (treat all hosts as up) - needed without admin
    # -sT: TCP connect scan (works without admin on Windows)
    # -sV: detect service versions
    # -T4: aggressive timing
    ports = "22,23,53,80,443,554,1883,5353,7000,8080,8443,49152"
    nm.scan(hosts=target, ports=ports, arguments="-Pn -sT -sV -T4")

    devices = []
    for host in nm.all_hosts():
        device = {
            "ip": host,
            "hostname": nm[host].hostname() or "Unknown",
            "state": nm[host].state(),
            "mac": "",
            "vendor": "",
            "os": "",
            "services": [],
            "risk": "low",
            "scan_time": datetime.now().isoformat(),
        }

        # Try to get MAC and vendor from nmap
        if "addresses" in nm[host]:
            if "mac" in nm[host]["addresses"]:
                device["mac"] = nm[host]["addresses"]["mac"]
        if "vendor" in nm[host]:
            for mac, vendor in nm[host]["vendor"].items():
                device["vendor"] = vendor
                device["mac"] = mac

        # OS detection if available
        if "osmatch" in nm[host] and nm[host]["osmatch"]:
            device["os"] = nm[host]["osmatch"][0]["name"]

        # Services -- include open and open|filtered
        has_open = False
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                port_info = nm[host][proto][port]
                if port_info["state"] in ("open", "open|filtered"):
                    has_open = True
                    service = {
                        "port": port,
                        "protocol": proto,
                        "service": port_info["name"],
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                    }
                    device["services"].append(service)

        # Only include devices that have at least one open port
        if has_open:
            device["risk"] = _assess_risk(device)
            devices.append(device)

    # If nmap found hosts but no open ports, it's likely a permissions issue
    if not devices and len(nm.all_hosts()) > 0:
        return {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "device_count": 0,
            "devices": [],
            "mode": "live",
            "warning": (
                f"Nmap detected {len(nm.all_hosts())} host(s) but all ports showed as filtered. "
                "This usually means you need to run as Administrator on Windows. "
                "Falling back to demo data."
            ),
            "needs_admin": True,
        }

    return {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "device_count": len(devices),
        "devices": devices,
        "mode": "live",
    }


def _assess_risk(device):
    """Simple risk assessment based on open services."""
    high_risk_ports = {23, 21, 445, 135, 139}  # telnet, ftp, smb
    medium_risk_ports = {22, 554, 1883, 8080}  # ssh, rtsp, mqtt, alt-http
    
    risk = "low"
    for svc in device["services"]:
        if svc["port"] in high_risk_ports:
            return "high"
        if svc["port"] in medium_risk_ports:
            risk = "medium"
    return risk


def _mock_scan(target):
    """Return mock data for demo purposes."""
    devices = [
        {
            "ip": "192.168.0.1",
            "hostname": "router.local",
            "state": "up",
            "mac": "B0:4E:26:A1:B2:C3",
            "vendor": "TP-Link",
            "os": "Linux 3.x",
            "risk": "medium",
            "scan_time": datetime.now().isoformat(),
            "services": [
                {"port": 80, "protocol": "tcp", "service": "http", "product": "TP-Link httpd", "version": "1.0"},
                {"port": 443, "protocol": "tcp", "service": "https", "product": "TP-Link httpd", "version": "1.0"},
                {"port": 22, "protocol": "tcp", "service": "ssh", "product": "Dropbear", "version": "2020.81"},
            ],
        },
        {
            "ip": "192.168.0.42",
            "hostname": "living-room-tv.local",
            "state": "up",
            "mac": "68:37:E9:D4:E5:F6",
            "vendor": "Samsung",
            "os": "Tizen OS",
            "risk": "high",
            "scan_time": datetime.now().isoformat(),
            "services": [
                {"port": 8080, "protocol": "tcp", "service": "http", "product": "Samsung Smart TV", "version": "2.0"},
                {"port": 8443, "protocol": "tcp", "service": "https", "product": "Samsung Smart TV", "version": "2.0"},
                {"port": 23, "protocol": "tcp", "service": "telnet", "product": "", "version": ""},
            ],
        },
        {
            "ip": "192.168.0.78",
            "hostname": "ring-doorbell.local",
            "state": "up",
            "mac": "44:65:0D:G7:H8:I9",
            "vendor": "Amazon (Ring)",
            "os": "Linux embedded",
            "risk": "medium",
            "scan_time": datetime.now().isoformat(),
            "services": [
                {"port": 443, "protocol": "tcp", "service": "https", "product": "Ring Doorbell API", "version": "3.1"},
                {"port": 554, "protocol": "tcp", "service": "rtsp", "product": "Ring RTSP", "version": "1.0"},
            ],
        },
        {
            "ip": "192.168.0.103",
            "hostname": "echo-dot.local",
            "state": "up",
            "mac": "AC:BC:32:J0:K1:L2",
            "vendor": "Amazon",
            "os": "Fire OS",
            "risk": "low",
            "scan_time": datetime.now().isoformat(),
            "services": [
                {"port": 443, "protocol": "tcp", "service": "https", "product": "Amazon Echo", "version": ""},
                {"port": 8443, "protocol": "tcp", "service": "https", "product": "Amazon Echo", "version": ""},
            ],
        },
        {
            "ip": "192.168.0.115",
            "hostname": "philips-hue-bridge.local",
            "state": "up",
            "mac": "00:17:88:M3:N4:O5",
            "vendor": "Philips Hue (Signify)",
            "os": "Linux embedded",
            "risk": "low",
            "scan_time": datetime.now().isoformat(),
            "services": [
                {"port": 80, "protocol": "tcp", "service": "http", "product": "Philips Hue Bridge", "version": "1.55"},
                {"port": 443, "protocol": "tcp", "service": "https", "product": "Philips Hue Bridge", "version": "1.55"},
            ],
        },
        {
            "ip": "192.168.0.150",
            "hostname": "nest-thermostat.local",
            "state": "up",
            "mac": "18:B4:30:P6:Q7:R8",
            "vendor": "Google (Nest)",
            "os": "ThreadX RTOS",
            "risk": "low",
            "scan_time": datetime.now().isoformat(),
            "services": [
                {"port": 443, "protocol": "tcp", "service": "https", "product": "Nest API", "version": "5.0"},
            ],
        },
    ]

    return {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "device_count": len(devices),
        "devices": devices,
        "mode": "demo",
    }
