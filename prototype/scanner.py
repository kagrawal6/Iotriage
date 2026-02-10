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
            "vulnerabilities": [],
            "risk": "low",
            "scan_time": datetime.now().isoformat(),
        }

        if "addresses" in nm[host]:
            if "mac" in nm[host]["addresses"]:
                device["mac"] = nm[host]["addresses"]["mac"]
        if "vendor" in nm[host]:
            for mac, vendor in nm[host]["vendor"].items():
                device["vendor"] = vendor
                device["mac"] = mac

        if "osmatch" in nm[host] and nm[host]["osmatch"]:
            device["os"] = nm[host]["osmatch"][0]["name"]

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

        if has_open:
            device["risk"] = _assess_risk(device)
            devices.append(device)

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
    high_risk_ports = {23, 21, 445, 135, 139}
    medium_risk_ports = {22, 554, 1883, 8080}

    risk = "low"
    for svc in device["services"]:
        if svc["port"] in high_risk_ports:
            return "high"
        if svc["port"] in medium_risk_ports:
            risk = "medium"
    return risk


# ---------------------------------------------------------------------------
# Chatbot responses -- pre-built for demo, would use Gemini API in production
# ---------------------------------------------------------------------------
CHATBOT_RESPONSES = {
    "default": (
        "I'm the IoTriage AI assistant. I can help explain vulnerabilities found on your network. "
        "Try asking me about a specific device or vulnerability, like:\n\n"
        "- \"What is CVE-2021-36260?\"\n"
        "- \"Is my smart TV safe?\"\n"
        "- \"What is a botnet?\"\n"
        "- \"How do I fix outdated firmware?\"\n"
        "- \"What does Telnet being open mean?\""
    ),
    "botnet": (
        "A **botnet** is a network of infected devices controlled by a hacker. IoT devices like cameras and "
        "routers are prime targets because they often have weak passwords and outdated software.\n\n"
        "**Mirai** is the most famous IoT botnet -- it infected hundreds of thousands of devices in 2016 and "
        "took down major websites like Twitter, Netflix, and Reddit.\n\n"
        "**Signs your device might be in a botnet:**\n"
        "- Unusually slow network speeds\n"
        "- Device running hot or slow\n"
        "- Strange outbound traffic\n\n"
        "**How to protect yourself:**\n"
        "1. Change default passwords immediately\n"
        "2. Keep firmware updated\n"
        "3. Disable Telnet and UPnP if not needed\n"
        "4. Put IoT devices on a separate network"
    ),
    "telnet": (
        "**Telnet (Port 23)** is an old, unencrypted remote access protocol. It sends your username and "
        "password in plain text -- anyone on your network can see them.\n\n"
        "Having Telnet open on an IoT device is a **critical security risk** because:\n"
        "- Many devices ship with default credentials (admin/admin)\n"
        "- Botnets like Mirai specifically scan for open Telnet ports\n"
        "- There is zero encryption -- everything is visible\n\n"
        "**What you should do:** Disable Telnet immediately in your device settings and use SSH (Port 22) instead if you need remote access."
    ),
    "cve-2021-36260": (
        "**CVE-2021-36260** is a critical vulnerability in Hikvision IP cameras (CVSS 9.8/10).\n\n"
        "**What it does:** An attacker can send a specially crafted web request to your camera and gain "
        "full control of it -- no password needed. They can:\n"
        "- Watch your camera feed\n"
        "- Add your camera to a botnet\n"
        "- Use it as an entry point to your network\n\n"
        "**Affected versions:** Firmware before September 2021\n\n"
        "**Fix:** Update your Hikvision camera firmware immediately from the Hikvision website. This is the single most important thing you can do."
    ),
    "cve-2023-20198": (
        "**CVE-2023-20198** is a critical vulnerability in Cisco IOS XE routers (CVSS 10.0/10 -- maximum severity).\n\n"
        "**What it does:** An attacker can create an admin account on your router remotely with no authentication. "
        "This gives them complete control of your network.\n\n"
        "**Why it's dangerous:** Thousands of routers were exploited in the wild within days of discovery. "
        "Attackers used it to install backdoors.\n\n"
        "**Fix:** Update to the latest Cisco IOS XE firmware. If you can't update immediately, disable the Web UI feature."
    ),
    "cve-2017-7921": (
        "**CVE-2017-7921** is an authentication bypass in Hikvision cameras (CVSS 10.0/10).\n\n"
        "**What it does:** Allows anyone to bypass login and access the camera's admin panel and video feed "
        "without knowing the password.\n\n"
        "**Impact:** Thousands of cameras worldwide are still vulnerable to this 2017 bug because owners never updated the firmware.\n\n"
        "**Fix:** Update firmware. If the camera is too old to update, consider replacing it -- an unpatched camera is an open door to your network."
    ),
    "cve-2022-30525": (
        "**CVE-2022-30525** is a critical OS command injection in Zyxel firewalls (CVSS 9.8/10).\n\n"
        "**What it does:** Attackers can execute arbitrary commands on your firewall without authentication. "
        "This means they can:\n"
        "- Completely bypass your firewall\n"
        "- Access your entire network\n"
        "- Install malware or backdoors\n\n"
        "**Fix:** Update your Zyxel firewall firmware to the latest version immediately."
    ),
    "cve-2024-3400": (
        "**CVE-2024-3400** is a critical command injection vulnerability in Palo Alto Networks PAN-OS GlobalProtect (CVSS 10.0/10).\n\n"
        "**What it does:** An unauthenticated attacker can execute arbitrary code with root privileges on the firewall. "
        "This was actively exploited in the wild.\n\n"
        "**Fix:** Apply the hotfix from Palo Alto Networks immediately. This is a zero-day that was being used in targeted attacks."
    ),
    "outdated": (
        "**Outdated firmware** is one of the biggest security risks for IoT devices.\n\n"
        "**Why it matters:**\n"
        "- Manufacturers release updates to fix known vulnerabilities\n"
        "- Hackers specifically target old, unpatched versions\n"
        "- Some vulnerabilities allow complete device takeover\n\n"
        "**How to fix it:**\n"
        "1. Check each device's admin panel for firmware version\n"
        "2. Visit the manufacturer's website for the latest version\n"
        "3. Enable automatic updates if available\n"
        "4. Set a calendar reminder to check quarterly\n\n"
        "**If a device is no longer supported** (end-of-life), strongly consider replacing it. "
        "An unsupported device will never get security patches."
    ),
    "smart tv": (
        "**Smart TVs** are one of the most vulnerable IoT devices in a typical home.\n\n"
        "**Common risks:**\n"
        "- Many run outdated Android or Tizen OS versions\n"
        "- Open ports for casting (DLNA, Chromecast) can be exploited\n"
        "- Some TVs have cameras/microphones that can be hijacked\n"
        "- Telnet is sometimes left open by manufacturers\n\n"
        "**What you should do:**\n"
        "1. Update your TV's firmware\n"
        "2. Disable features you don't use (voice control, camera)\n"
        "3. Put it on a separate WiFi network from your computers\n"
        "4. Review app permissions on the TV"
    ),
    "mqtt": (
        "**MQTT (Port 1883)** is a messaging protocol commonly used by IoT devices to communicate.\n\n"
        "**The risk:** By default, MQTT has no authentication or encryption. Anyone on your network can:\n"
        "- Read all messages between your smart home devices\n"
        "- Send fake commands to your devices\n"
        "- Turn lights on/off, unlock doors, change thermostat settings\n\n"
        "**Fix:**\n"
        "1. Enable authentication on your MQTT broker\n"
        "2. Use MQTT over TLS (port 8883) for encryption\n"
        "3. Restrict which devices can publish/subscribe to topics"
    ),
    "upnp": (
        "**UPnP (Universal Plug and Play)** automatically opens ports on your router for devices.\n\n"
        "**The risk:** UPnP was designed for convenience but is a major security hole:\n"
        "- Malware can use UPnP to open ports from inside your network\n"
        "- No authentication is required\n"
        "- It can expose internal devices to the internet\n\n"
        "**Recommendation:** Disable UPnP on your router. Yes, some devices may need manual port forwarding, "
        "but it's much safer than letting any device open ports automatically."
    ),
}


def get_chat_response(message):
    """Return a chatbot response based on the user's message."""
    msg = message.lower().strip()

    # Check for CVE mentions
    for key in CHATBOT_RESPONSES:
        if key.startswith("cve-") and key in msg:
            return CHATBOT_RESPONSES[key]

    # Keyword matching
    keywords = {
        "botnet": "botnet",
        "mirai": "botnet",
        "zombie": "botnet",
        "ddos": "botnet",
        "telnet": "telnet",
        "port 23": "telnet",
        "outdated": "outdated",
        "firmware": "outdated",
        "update": "outdated",
        "old software": "outdated",
        "end of life": "outdated",
        "eol": "outdated",
        "smart tv": "smart tv",
        "television": "smart tv",
        "samsung tv": "smart tv",
        "tizen": "smart tv",
        "mqtt": "mqtt",
        "mosquitto": "mqtt",
        "port 1883": "mqtt",
        "upnp": "upnp",
        "plug and play": "upnp",
    }

    for keyword, response_key in keywords.items():
        if keyword in msg:
            return CHATBOT_RESPONSES[response_key]

    # Generic helpful responses
    if "safe" in msg or "secure" in msg or "worried" in msg:
        return (
            "Based on the scan results, here's a quick summary:\n\n"
            "**Immediate actions needed:**\n"
            "- Devices marked HIGH risk have critical vulnerabilities that should be fixed today\n"
            "- Any device with Telnet (port 23) open should have it disabled immediately\n"
            "- Check for firmware updates on all devices\n\n"
            "**Good habits:**\n"
            "- Change default passwords on all devices\n"
            "- Put IoT devices on a separate WiFi network\n"
            "- Disable features you don't use (UPnP, remote access)\n"
            "- Run IoTriage scans regularly to catch new issues"
        )

    if "help" in msg or "what can" in msg or "how" in msg:
        return CHATBOT_RESPONSES["default"]

    return (
        "I can help explain the vulnerabilities found in your scan. Try asking about:\n\n"
        "- A specific CVE (e.g., \"What is CVE-2021-36260?\")\n"
        "- A device type (e.g., \"Is my smart TV safe?\")\n"
        "- A concept (e.g., \"What is a botnet?\" or \"What does Telnet mean?\")\n"
        "- General advice (e.g., \"How do I fix outdated firmware?\")"
    )


# ---------------------------------------------------------------------------
# Mock scan data -- very realistic
# ---------------------------------------------------------------------------
def _mock_scan(target):
    """Return highly realistic mock data for demo purposes."""
    now = datetime.now().isoformat()

    devices = [
        # 1 -- Router with outdated firmware and known CVE
        {
            "ip": "192.168.1.1",
            "hostname": "gateway.local",
            "state": "up",
            "mac": "B0:4E:26:A1:B2:C3",
            "vendor": "TP-Link",
            "os": "Linux 2.6.36 (OpenWrt)",
            "risk": "critical",
            "scan_time": now,
            "firmware_version": "3.16.9 Build 20190219",
            "firmware_latest": "3.20.1 Build 20240815",
            "services": [
                {"port": 22, "protocol": "tcp", "service": "ssh", "product": "Dropbear sshd", "version": "2019.78"},
                {"port": 53, "protocol": "tcp", "service": "domain", "product": "dnsmasq", "version": "2.80"},
                {"port": 80, "protocol": "tcp", "service": "http", "product": "TP-Link Archer C7 httpd", "version": ""},
                {"port": 443, "protocol": "tcp", "service": "https", "product": "TP-Link Archer C7 httpd", "version": ""},
                {"port": 1900, "protocol": "udp", "service": "upnp", "product": "MiniUPnPd", "version": "1.9"},
            ],
            "vulnerabilities": [
                {
                    "id": "CVE-2023-1389",
                    "severity": "critical",
                    "cvss": 8.8,
                    "title": "TP-Link Archer Command Injection",
                    "description": "TP-Link Archer AX21 firmware before 1.1.4 Build 20230219 allows unauthenticated command injection via the web management interface, which was exploited by the Mirai botnet.",
                    "fix": "Update router firmware to version 1.1.4 or later",
                },
                {
                    "id": "CVE-2022-30075",
                    "severity": "high",
                    "cvss": 8.0,
                    "title": "TP-Link Router Remote Code Execution",
                    "description": "TP-Link routers allow remote code execution through crafted firmware update requests.",
                    "fix": "Update to latest firmware from TP-Link support website",
                },
                {
                    "id": "FINDING-UPNP-001",
                    "severity": "medium",
                    "cvss": 5.3,
                    "title": "UPnP Service Enabled",
                    "description": "Universal Plug and Play is enabled, allowing any device on the network to open ports on the router without authentication.",
                    "fix": "Disable UPnP in router admin panel under NAT Forwarding settings",
                },
            ],
        },

        # 2 -- IP Camera with critical Hikvision vulns (botnet target)
        {
            "ip": "192.168.1.15",
            "hostname": "hikvision-cam-frontdoor",
            "state": "up",
            "mac": "C0:56:E3:D4:E5:F6",
            "vendor": "Hikvision",
            "os": "Linux 3.0 (embedded ARM)",
            "risk": "critical",
            "scan_time": now,
            "firmware_version": "V5.5.52 build 200401",
            "firmware_latest": "V5.7.23 build 240918",
            "services": [
                {"port": 23, "protocol": "tcp", "service": "telnet", "product": "BusyBox telnetd", "version": ""},
                {"port": 80, "protocol": "tcp", "service": "http", "product": "Hikvision DS-2CD2142FWD-I httpd", "version": ""},
                {"port": 443, "protocol": "tcp", "service": "https", "product": "Hikvision ISAPI", "version": "2.0"},
                {"port": 554, "protocol": "tcp", "service": "rtsp", "product": "Hikvision RTSP server", "version": "1.0"},
                {"port": 8000, "protocol": "tcp", "service": "http-alt", "product": "Hikvision SDK Server", "version": ""},
            ],
            "vulnerabilities": [
                {
                    "id": "CVE-2021-36260",
                    "severity": "critical",
                    "cvss": 9.8,
                    "title": "Hikvision Command Injection (Actively Exploited)",
                    "description": "A command injection vulnerability allows remote attackers to execute arbitrary commands with root privileges via crafted requests. This vulnerability is actively being used by botnets including Moobot and Mirai variants to recruit cameras into DDoS botnets.",
                    "fix": "Update firmware immediately. Affected: all Hikvision cameras with firmware before Sep 2021",
                },
                {
                    "id": "CVE-2017-7921",
                    "severity": "critical",
                    "cvss": 10.0,
                    "title": "Hikvision Authentication Bypass",
                    "description": "An improper authentication vulnerability allows an attacker to bypass authentication and gain full admin access to the camera, including live video feed access.",
                    "fix": "Update firmware to version 5.5.0 or later. Change default credentials.",
                },
                {
                    "id": "FINDING-TELNET-001",
                    "severity": "high",
                    "cvss": 8.1,
                    "title": "Telnet Service Open (Botnet Vector)",
                    "description": "Telnet (port 23) is open with no encryption. This is the primary attack vector for IoT botnets like Mirai, which scan the internet for devices with open Telnet and default credentials.",
                    "fix": "Disable Telnet immediately in device settings. Use SSH if remote access is needed.",
                },
                {
                    "id": "FINDING-DEFAULT-CREDS",
                    "severity": "high",
                    "cvss": 9.1,
                    "title": "Default Credentials Detected",
                    "description": "Camera appears to be using factory default credentials (admin/12345). Over 60% of IoT botnet infections start with default passwords.",
                    "fix": "Change password immediately to a strong, unique password (12+ characters).",
                },
            ],
        },

        # 3 -- Smart TV with outdated OS
        {
            "ip": "192.168.1.42",
            "hostname": "samsung-smart-tv.local",
            "state": "up",
            "mac": "68:37:E9:A8:B9:C0",
            "vendor": "Samsung Electronics",
            "os": "Tizen OS 5.0 (2019)",
            "risk": "high",
            "scan_time": now,
            "firmware_version": "T-KTMDEUC-1301.3",
            "firmware_latest": "T-KTMDEUC-1500.1 (no longer supported)",
            "services": [
                {"port": 8001, "protocol": "tcp", "service": "http", "product": "Samsung SmartThings API", "version": "2.0"},
                {"port": 8002, "protocol": "tcp", "service": "https", "product": "Samsung SmartThings API", "version": "2.0"},
                {"port": 8080, "protocol": "tcp", "service": "http-proxy", "product": "Samsung DLNA/UPnP", "version": "1.0"},
                {"port": 9197, "protocol": "tcp", "service": "unknown", "product": "Samsung Debug Bridge", "version": ""},
                {"port": 26000, "protocol": "tcp", "service": "unknown", "product": "Samsung D2D (device-to-device)", "version": ""},
            ],
            "vulnerabilities": [
                {
                    "id": "CVE-2022-44636",
                    "severity": "high",
                    "cvss": 7.8,
                    "title": "Samsung Tizen Privilege Escalation",
                    "description": "A vulnerability in Tizen OS allows local attackers to escalate privileges and execute arbitrary code. Affects Tizen versions before 7.0.",
                    "fix": "This TV runs Tizen 5.0 which is end-of-life. No patch available. Consider network isolation.",
                },
                {
                    "id": "FINDING-EOL-001",
                    "severity": "high",
                    "cvss": 7.5,
                    "title": "End-of-Life Operating System",
                    "description": "This Samsung TV runs Tizen OS 5.0 (released 2019), which is no longer receiving security updates from Samsung. Any new vulnerabilities discovered will never be patched.",
                    "fix": "Place this TV on an isolated guest WiFi network. Disable unused features. Consider replacing with a newer model.",
                },
                {
                    "id": "FINDING-DEBUG-001",
                    "severity": "medium",
                    "cvss": 6.5,
                    "title": "Debug Bridge Open (Port 9197)",
                    "description": "Samsung Debug Bridge is accessible on the network. This development interface could allow unauthorized app installation or device control.",
                    "fix": "Disable developer mode on the TV: Settings > General > System Manager > Developer Mode OFF",
                },
            ],
        },

        # 4 -- Ring Doorbell
        {
            "ip": "192.168.1.78",
            "hostname": "ring-doorbell-pro.local",
            "state": "up",
            "mac": "44:65:0D:7A:8B:9C",
            "vendor": "Amazon (Ring)",
            "os": "Linux embedded (Qualcomm)",
            "risk": "medium",
            "scan_time": now,
            "firmware_version": "3.60.22",
            "firmware_latest": "3.62.10",
            "services": [
                {"port": 443, "protocol": "tcp", "service": "https", "product": "Ring Doorbell API", "version": "3.1"},
                {"port": 554, "protocol": "tcp", "service": "rtsp", "product": "Ring RTSP stream", "version": "1.0"},
                {"port": 8443, "protocol": "tcp", "service": "https-alt", "product": "Ring Setup Server", "version": ""},
            ],
            "vulnerabilities": [
                {
                    "id": "CVE-2022-44621",
                    "severity": "medium",
                    "cvss": 6.2,
                    "title": "Ring Doorbell WiFi Credential Exposure",
                    "description": "During initial setup, Ring doorbells transmit WiFi credentials in plaintext over an unencrypted connection. An attacker nearby during setup could capture your WiFi password.",
                    "fix": "Ensure setup is done in a private environment. Change WiFi password after setup as a precaution.",
                },
                {
                    "id": "FINDING-RTSP-001",
                    "severity": "medium",
                    "cvss": 5.3,
                    "title": "RTSP Video Stream Accessible",
                    "description": "The RTSP video streaming port (554) is accessible on the local network. Other devices on the same network could potentially access the camera feed.",
                    "fix": "Place IoT cameras on a separate VLAN or guest network isolated from computers and phones.",
                },
            ],
        },

        # 5 -- Echo Dot
        {
            "ip": "192.168.1.103",
            "hostname": "echo-dot-4th-gen.local",
            "state": "up",
            "mac": "AC:BC:32:D0:E1:F2",
            "vendor": "Amazon",
            "os": "Fire OS 7.6",
            "risk": "low",
            "scan_time": now,
            "firmware_version": "737838620",
            "firmware_latest": "737838620",
            "services": [
                {"port": 443, "protocol": "tcp", "service": "https", "product": "Amazon Alexa Service", "version": ""},
                {"port": 8443, "protocol": "tcp", "service": "https-alt", "product": "Amazon Device Gateway", "version": ""},
                {"port": 55443, "protocol": "tcp", "service": "unknown", "product": "Alexa Cast", "version": ""},
            ],
            "vulnerabilities": [
                {
                    "id": "FINDING-PRIVACY-001",
                    "severity": "info",
                    "cvss": 0.0,
                    "title": "Always-Listening Device",
                    "description": "This Amazon Echo device has an always-on microphone for voice activation. While Amazon states audio is only recorded after the wake word, privacy researchers have documented cases of unintended activations.",
                    "fix": "Use the physical mute button when not in use. Review and delete voice recordings in the Alexa app.",
                },
            ],
        },

        # 6 -- Philips Hue Bridge with outdated API
        {
            "ip": "192.168.1.115",
            "hostname": "philips-hue-bridge.local",
            "state": "up",
            "mac": "00:17:88:3A:4B:5C",
            "vendor": "Signify (Philips Hue)",
            "os": "Linux 4.14 (embedded ARM)",
            "risk": "medium",
            "scan_time": now,
            "firmware_version": "1.55.0",
            "firmware_latest": "1.62.0",
            "services": [
                {"port": 80, "protocol": "tcp", "service": "http", "product": "Philips Hue Bridge httpd", "version": "1.0"},
                {"port": 443, "protocol": "tcp", "service": "https", "product": "Philips Hue Bridge httpd", "version": "1.0"},
                {"port": 8080, "protocol": "tcp", "service": "http-proxy", "product": "Hue Clip API", "version": "2.0"},
            ],
            "vulnerabilities": [
                {
                    "id": "CVE-2020-6007",
                    "severity": "medium",
                    "cvss": 7.9,
                    "title": "Philips Hue Zigbee Buffer Overflow",
                    "description": "A vulnerability in the Zigbee protocol implementation allows an attacker within Zigbee range (~100m) to send a malformed Zigbee frame that causes a buffer overflow on the Hue Bridge, potentially gaining network access.",
                    "fix": "Update Hue Bridge firmware via the Philips Hue app to version 1.58 or later.",
                },
                {
                    "id": "FINDING-OUTDATED-FW",
                    "severity": "medium",
                    "cvss": 5.0,
                    "title": "Firmware 7 Versions Behind",
                    "description": "Running firmware 1.55.0, latest available is 1.62.0. Multiple security patches have been released since this version.",
                    "fix": "Open the Philips Hue app > Settings > Software Update > Check for updates",
                },
            ],
        },

        # 7 -- Nest Thermostat
        {
            "ip": "192.168.1.150",
            "hostname": "nest-learning-thermostat.local",
            "state": "up",
            "mac": "18:B4:30:6D:7E:8F",
            "vendor": "Google (Nest)",
            "os": "ThreadX RTOS 5.8",
            "risk": "low",
            "scan_time": now,
            "firmware_version": "6.2.3-2",
            "firmware_latest": "6.2.3-2",
            "services": [
                {"port": 443, "protocol": "tcp", "service": "https", "product": "Google Nest API", "version": "5.0"},
                {"port": 9543, "protocol": "tcp", "service": "https", "product": "Nest Weave", "version": ""},
            ],
            "vulnerabilities": [
                {
                    "id": "FINDING-OK",
                    "severity": "info",
                    "cvss": 0.0,
                    "title": "No Known Vulnerabilities",
                    "description": "This device is running the latest firmware and no known vulnerabilities were detected. Device communicates exclusively over encrypted channels.",
                    "fix": "No action needed. Continue keeping firmware updated.",
                },
            ],
        },

        # 8 -- Old IP Camera (Mirai botnet infected pattern)
        {
            "ip": "192.168.1.200",
            "hostname": "ipcam-backyard",
            "state": "up",
            "mac": "E8:AB:FA:12:34:56",
            "vendor": "Dahua Technology",
            "os": "Linux 2.6.32 (embedded)",
            "risk": "critical",
            "scan_time": now,
            "firmware_version": "2.400.0000.16.R build 2017-07-18",
            "firmware_latest": "No longer supported (end-of-life)",
            "services": [
                {"port": 23, "protocol": "tcp", "service": "telnet", "product": "BusyBox telnetd", "version": "1.19.2"},
                {"port": 37777, "protocol": "tcp", "service": "unknown", "product": "Dahua DVR Service", "version": ""},
                {"port": 80, "protocol": "tcp", "service": "http", "product": "Dahua DH-IPC web", "version": "2.0"},
                {"port": 554, "protocol": "tcp", "service": "rtsp", "product": "Dahua RTSP", "version": "1.0"},
                {"port": 443, "protocol": "tcp", "service": "https", "product": "Dahua DH-IPC web", "version": "2.0"},
            ],
            "vulnerabilities": [
                {
                    "id": "CVE-2021-33044",
                    "severity": "critical",
                    "cvss": 9.8,
                    "title": "Dahua Authentication Bypass",
                    "description": "An identity authentication bypass vulnerability allows unauthenticated attackers to bypass device identity authentication and gain full admin control by sending specially crafted packets.",
                    "fix": "Update firmware. If device is end-of-life, replace it immediately.",
                },
                {
                    "id": "CVE-2021-33045",
                    "severity": "critical",
                    "cvss": 9.8,
                    "title": "Dahua Authentication Bypass (Variant)",
                    "description": "Second authentication bypass vulnerability affecting the same firmware. Allows bypassing login on the web interface.",
                    "fix": "Update firmware or replace end-of-life device.",
                },
                {
                    "id": "FINDING-BOTNET-001",
                    "severity": "critical",
                    "cvss": 10.0,
                    "title": "Suspected Botnet Activity (Mirai Variant)",
                    "description": "This device exhibits patterns consistent with Mirai botnet infection: open Telnet with default credentials, outdated firmware with known exploits, and running an end-of-life OS kernel (Linux 2.6.32). Dahua cameras with this firmware version are among the most commonly recruited devices in IoT botnets. The device may be actively participating in DDoS attacks.",
                    "fix": "URGENT: Disconnect this device from the network immediately. Factory reset, update firmware, change all credentials. If EOL, replace the device.",
                },
                {
                    "id": "FINDING-EOL-002",
                    "severity": "high",
                    "cvss": 8.0,
                    "title": "End-of-Life Device (No Security Updates)",
                    "description": "This Dahua camera is running 2017 firmware and the model has been discontinued. No security patches will ever be released for discovered vulnerabilities.",
                    "fix": "Replace with a supported camera model. Budget option: Reolink or Wyze with current firmware.",
                },
            ],
        },

        # 9 -- Smart Plug (relatively safe but with MQTT exposure)
        {
            "ip": "192.168.1.88",
            "hostname": "tp-link-kasa-plug.local",
            "state": "up",
            "mac": "B0:95:75:AB:CD:EF",
            "vendor": "TP-Link (Kasa)",
            "os": "RTOS (Espressif ESP8266)",
            "risk": "medium",
            "scan_time": now,
            "firmware_version": "1.0.8 Build 210121",
            "firmware_latest": "1.1.0 Build 231205",
            "services": [
                {"port": 9999, "protocol": "tcp", "service": "unknown", "product": "Kasa Smart Home Protocol", "version": ""},
                {"port": 1883, "protocol": "tcp", "service": "mqtt", "product": "Mosquitto MQTT", "version": "1.6.12"},
            ],
            "vulnerabilities": [
                {
                    "id": "CVE-2023-27126",
                    "severity": "medium",
                    "cvss": 6.1,
                    "title": "TP-Link Kasa Credential Leak",
                    "description": "TP-Link Kasa smart plugs transmit WiFi credentials and device tokens in plaintext during setup, allowing nearby attackers to capture sensitive information.",
                    "fix": "Update firmware via Kasa app. Change WiFi password after setup.",
                },
                {
                    "id": "FINDING-MQTT-001",
                    "severity": "medium",
                    "cvss": 5.9,
                    "title": "Unencrypted MQTT Broker (Port 1883)",
                    "description": "MQTT messaging service is running without TLS encryption. Commands sent to/from this device can be intercepted by anyone on the local network, allowing unauthorized control of the smart plug.",
                    "fix": "Enable MQTT over TLS or place device on isolated IoT network.",
                },
            ],
        },

        # 10 -- NAS with outdated Samba
        {
            "ip": "192.168.1.50",
            "hostname": "synology-nas.local",
            "state": "up",
            "mac": "00:11:32:78:9A:BC",
            "vendor": "Synology",
            "os": "DSM 7.1.1 (Linux 4.4)",
            "risk": "high",
            "scan_time": now,
            "firmware_version": "DSM 7.1.1-42962 Update 1",
            "firmware_latest": "DSM 7.2.2-72806 Update 2",
            "services": [
                {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "8.2p1"},
                {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.18.0"},
                {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.18.0"},
                {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "product": "Samba smbd", "version": "4.15.13"},
                {"port": 5000, "protocol": "tcp", "service": "http", "product": "Synology DSM", "version": "7.1"},
                {"port": 5001, "protocol": "tcp", "service": "https", "product": "Synology DSM", "version": "7.1"},
                {"port": 6690, "protocol": "tcp", "service": "unknown", "product": "Synology Cloud Station", "version": ""},
            ],
            "vulnerabilities": [
                {
                    "id": "CVE-2024-10443",
                    "severity": "critical",
                    "cvss": 9.8,
                    "title": "Synology Zero-Click RCE (RISK:STATION)",
                    "description": "A critical zero-click vulnerability in Synology DiskStation Manager allows unauthenticated remote code execution. Attackers can gain root access to the NAS and all stored data without any user interaction. Actively exploited in the wild.",
                    "fix": "Update DSM to version 7.2.2-72806 Update 2 or later immediately. This is the most critical fix.",
                },
                {
                    "id": "CVE-2023-13292",
                    "severity": "high",
                    "cvss": 7.5,
                    "title": "Samba Outdated (4.15.13 -- Multiple Known CVEs)",
                    "description": "Samba 4.15.13 has multiple known vulnerabilities including information disclosure, denial of service, and potential remote code execution. The version is over 2 years old.",
                    "fix": "Update DSM which will update Samba. Alternatively, disable SMB if not needed.",
                },
                {
                    "id": "FINDING-EXPOSED-MGMT",
                    "severity": "medium",
                    "cvss": 5.3,
                    "title": "Management Interface on HTTP (Port 5000)",
                    "description": "The Synology DSM management interface is accessible over unencrypted HTTP on port 5000. Login credentials could be intercepted.",
                    "fix": "Force HTTPS only: DSM > Control Panel > Login Portal > Automatically redirect to HTTPS",
                },
            ],
        },

        # 11 -- Baby Monitor (scary one)
        {
            "ip": "192.168.1.175",
            "hostname": "vtech-baby-monitor",
            "state": "up",
            "mac": "D4:F5:13:AA:BB:CC",
            "vendor": "VTech",
            "os": "Linux 2.6 (embedded)",
            "risk": "critical",
            "scan_time": now,
            "firmware_version": "1.0.2",
            "firmware_latest": "Unknown (manufacturer unresponsive)",
            "services": [
                {"port": 80, "protocol": "tcp", "service": "http", "product": "GoAhead WebServer", "version": "2.5"},
                {"port": 554, "protocol": "tcp", "service": "rtsp", "product": "RTSP video stream", "version": "1.0"},
                {"port": 23, "protocol": "tcp", "service": "telnet", "product": "BusyBox telnetd", "version": ""},
                {"port": 10554, "protocol": "tcp", "service": "rtsp", "product": "RTSP audio stream", "version": "1.0"},
            ],
            "vulnerabilities": [
                {
                    "id": "CVE-2018-10088",
                    "severity": "critical",
                    "cvss": 9.8,
                    "title": "GoAhead Web Server Buffer Overflow",
                    "description": "The embedded GoAhead web server version 2.5 has a critical buffer overflow that allows remote code execution. This affects the baby monitor's admin interface and can give attackers full device control, including access to video and audio streams.",
                    "fix": "No patch available from manufacturer. STRONGLY recommend replacing this device.",
                },
                {
                    "id": "FINDING-BABY-CAM-001",
                    "severity": "critical",
                    "cvss": 9.0,
                    "title": "Unauthenticated Video/Audio Stream Access",
                    "description": "The RTSP video stream (port 554) and audio stream (port 10554) are accessible without authentication. Anyone on the local network -- or anyone who gains network access -- can watch and listen to the baby monitor feed in real time.",
                    "fix": "URGENT: Replace this device with a reputable brand that uses encrypted, authenticated streams (e.g., Nanit, Owlet).",
                },
                {
                    "id": "FINDING-TELNET-002",
                    "severity": "high",
                    "cvss": 8.1,
                    "title": "Telnet Open with Root Access",
                    "description": "Telnet provides direct root shell access to the device. Combined with known default credentials, this gives complete device control.",
                    "fix": "Cannot be disabled on this device. Replace the device.",
                },
            ],
        },

        # 12 -- Smart Lock
        {
            "ip": "192.168.1.160",
            "hostname": "august-smart-lock.local",
            "state": "up",
            "mac": "F8:F0:05:DD:EE:FF",
            "vendor": "August Home (Assa Abloy)",
            "os": "Embedded RTOS",
            "risk": "low",
            "scan_time": now,
            "firmware_version": "3.1.15",
            "firmware_latest": "3.1.15",
            "services": [
                {"port": 443, "protocol": "tcp", "service": "https", "product": "August Connect API", "version": "2.0"},
            ],
            "vulnerabilities": [
                {
                    "id": "FINDING-OK-002",
                    "severity": "info",
                    "cvss": 0.0,
                    "title": "No Known Vulnerabilities",
                    "description": "Device is running current firmware. Communications are encrypted via TLS 1.3. Bluetooth pairing requires physical proximity.",
                    "fix": "No action needed. Ensure auto-update is enabled in the August app.",
                },
            ],
        },
    ]

    # Count risks
    critical = sum(1 for d in devices if d["risk"] == "critical")
    high = sum(1 for d in devices if d["risk"] == "high")
    medium = sum(1 for d in devices if d["risk"] == "medium")
    low = sum(1 for d in devices if d["risk"] == "low")

    return {
        "target": target,
        "scan_time": now,
        "device_count": len(devices),
        "devices": devices,
        "mode": "demo",
        "summary": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total_vulnerabilities": sum(len(d["vulnerabilities"]) for d in devices),
        },
    }
