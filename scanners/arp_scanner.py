"""
ARP Scanner - Fast local network device discovery.

Requirements:
    - pip install scapy
    - On Windows: install Npcap (https://npcap.com/)
    - Admin/root privileges required

Capabilities:
    - Discover all devices on the local network
    - Get MAC addresses for manufacturer identification
    - Very fast and reliable

Tradeoffs:
    - Only works on local network (same Layer 2 broadcast domain)
    - No port scanning or service detection
    - IPv4 only
    - But: extremely reliable, devices MUST respond to ARP

This scanner also includes MAC address OUI (manufacturer) lookup,
which is critical for IoTriage -- knowing the manufacturer helps
identify what type of IoT device we're dealing with.

Best used as:
    - First step in scanning workflow
    - Quick "what's on my network" discovery
    - Getting MAC addresses for manufacturer lookup
"""

import sys
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import ARP, Ether, srp, conf, get_if_addr
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from mac_vendor_lookup import MacLookup, VendorNotFoundError
    MAC_LOOKUP_AVAILABLE = True
except ImportError:
    MAC_LOOKUP_AVAILABLE = False

# Fallback: Common OUI prefixes for IoT manufacturers
# This is used when mac_vendor_lookup is not installed
COMMON_OUI = {
    "00:17:88": "Philips Hue (Signify)",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "28:6D:CD": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "AC:BC:32": "Amazon (Echo, Fire)",
    "F0:F0:A4": "Amazon (Echo)",
    "74:C2:46": "Amazon (Echo, Ring)",
    "44:07:0B": "Google (Nest)",
    "54:60:09": "Google (Chromecast)",
    "F4:F5:D8": "Google (Home)",
    "30:FD:38": "Google (Nest)",
    "18:B4:30": "Nest Labs",
    "64:16:66": "Samsung SmartThings",
    "68:37:E9": "Samsung (SmartTV)",
    "B4:79:A7": "Samsung",
    "78:02:F8": "Xiaomi",
    "7C:49:EB": "Xiaomi",
    "50:EC:50": "TP-Link (Kasa)",
    "B0:4E:26": "TP-Link",
    "60:32:B1": "TP-Link",
    "14:91:82": "Belkin (WeMo)",
    "EC:1A:59": "Belkin",
    "B0:C5:54": "D-Link",
    "C8:D7:19": "D-Link",
    "00:1E:42": "Telsey (routers)",
    "44:65:0D": "Amazon (Ring)",
    "90:E2:02": "Apple (HomePod)",
    "F0:B3:EC": "Apple",
    "7C:D1:C3": "Apple",
    "78:4F:43": "Apple",
    "A4:CF:12": "Espressif (ESP8266/ESP32 IoT)",
    "30:AE:A4": "Espressif",
    "24:0A:C4": "Espressif",
    "EC:FA:BC": "Espressif",
    "84:CC:A8": "Espressif",
    "BC:DD:C2": "Espressif",
    "B4:E6:2D": "Espressif",
    "C4:4F:33": "Espressif",
    "08:3A:F2": "Espressif",
    "24:62:AB": "Espressif",
    "3C:71:BF": "Espressif",
    "AC:67:B2": "Espressif",
    "CC:50:E3": "Espressif",
    "FC:F5:C4": "Espressif",
    "80:7D:3A": "Espressif",
    "40:F5:20": "Espressif",
    "E8:DB:84": "Espressif",
    "70:03:9F": "Espressif",
}


def check_dependencies():
    """Check if required dependencies are installed."""
    ok = True
    
    if SCAPY_AVAILABLE:
        print("[OK] Scapy is installed.")
    else:
        print("[ERROR] Scapy is not installed: pip install scapy")
        ok = False
    
    if MAC_LOOKUP_AVAILABLE:
        print("[OK] mac-vendor-lookup is installed.")
    else:
        print("[WARNING] mac-vendor-lookup not installed.")
        print("          Using built-in OUI database (limited).")
        print("          Install for full manufacturer lookup: pip install mac-vendor-lookup")
    
    return ok


def lookup_manufacturer(mac_address):
    """
    Look up the manufacturer from a MAC address.
    
    The first 3 bytes (6 hex chars) of a MAC address identify the
    manufacturer (called OUI - Organizationally Unique Identifier).
    
    This is crucial for IoTriage -- knowing the manufacturer helps
    identify what kind of device it is and what vulnerabilities to look for.
    
    Args:
        mac_address: MAC address string (e.g. "AA:BB:CC:DD:EE:FF").
    
    Returns:
        Manufacturer name string, or "Unknown" if not found.
    """
    # Try mac-vendor-lookup library first
    if MAC_LOOKUP_AVAILABLE:
        try:
            mac_lookup = MacLookup()
            return mac_lookup.lookup(mac_address)
        except VendorNotFoundError:
            pass
        except Exception:
            pass
    
    # Fallback to built-in OUI database
    oui = mac_address[:8].upper()
    if oui in COMMON_OUI:
        return COMMON_OUI[oui]
    
    return "Unknown"


def classify_device(manufacturer, mac_address):
    """
    Try to classify a device type based on its manufacturer.
    
    This is a rough heuristic. For better classification,
    you'd need service detection (nmap) or device fingerprinting.
    
    Args:
        manufacturer: Manufacturer name from OUI lookup.
        mac_address: MAC address of the device.
    
    Returns:
        Likely device category string.
    """
    manufacturer_lower = manufacturer.lower()
    
    # Smart home / IoT
    if any(x in manufacturer_lower for x in [
        "philips", "hue", "signify", "nest", "ring",
        "wemo", "belkin", "kasa", "tuya", "smartthings",
        "espressif", "esp8266", "esp32"
    ]):
        return "Smart Home / IoT Device"
    
    # Voice assistants
    if any(x in manufacturer_lower for x in ["amazon", "echo", "alexa"]):
        return "Voice Assistant / Smart Speaker"
    
    if any(x in manufacturer_lower for x in ["google", "home"]):
        return "Smart Speaker / Streaming"
    
    if any(x in manufacturer_lower for x in ["apple", "homepod"]):
        return "Apple Device"
    
    # Networking
    if any(x in manufacturer_lower for x in [
        "tp-link", "d-link", "netgear", "linksys", "asus",
        "cisco", "ubiquiti", "aruba", "mikrotik"
    ]):
        return "Network Equipment (Router/Switch/AP)"
    
    # Computers / phones
    if any(x in manufacturer_lower for x in ["samsung", "xiaomi", "huawei", "oneplus"]):
        return "Phone / Tablet"
    
    if any(x in manufacturer_lower for x in ["dell", "lenovo", "hp", "intel"]):
        return "Computer / Laptop"
    
    # Raspberry Pi
    if "raspberry" in manufacturer_lower:
        return "Raspberry Pi (DIY IoT)"
    
    # Smart TVs
    if any(x in manufacturer_lower for x in ["lg", "sony", "vizio", "roku", "chromecast"]):
        return "Smart TV / Streaming Device"
    
    # Cameras
    if any(x in manufacturer_lower for x in ["hikvision", "dahua", "wyze", "arlo"]):
        return "IP Camera / Security Camera"
    
    return "Unknown Device Type"


def full_arp_scan(network="192.168.1.0/24", timeout=3):
    """
    Complete ARP scan with manufacturer lookup and device classification.
    
    This is the main function -- it discovers devices, looks up their
    manufacturers, and tries to classify what type of device they are.
    
    Args:
        network: CIDR notation of network to scan.
        timeout: Seconds to wait for ARP responses.
    
    Returns:
        List of dicts with ip, mac, manufacturer, and device_type.
    """
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy not available.")
        return []
    
    print(f"\n--- ARP Scan with Manufacturer Lookup: {network} ---")
    
    # Build and send ARP request
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    
    print(f"  Broadcasting ARP requests to {network}...")
    answered, _ = srp(packet, timeout=timeout, verbose=0)
    
    devices = []
    for sent, received in answered:
        mac = received.hwsrc
        ip = received.psrc
        
        manufacturer = lookup_manufacturer(mac)
        device_type = classify_device(manufacturer, mac)
        
        device = {
            "ip": ip,
            "mac": mac,
            "manufacturer": manufacturer,
            "device_type": device_type,
        }
        devices.append(device)
    
    # Sort by IP address
    devices.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    
    # Pretty print results
    print(f"\n  {'IP Address':<18} {'MAC Address':<20} {'Manufacturer':<30} {'Type'}")
    print(f"  {'-'*18} {'-'*20} {'-'*30} {'-'*25}")
    
    for device in devices:
        print(f"  {device['ip']:<18} {device['mac']:<20} "
              f"{device['manufacturer']:<30} {device['device_type']}")
    
    print(f"\n  Total devices found: {len(devices)}")
    
    # Summary by type
    types = {}
    for d in devices:
        t = d["device_type"]
        types[t] = types.get(t, 0) + 1
    
    if types:
        print(f"\n  Device type summary:")
        for device_type, count in sorted(types.items(), key=lambda x: -x[1]):
            print(f"    {device_type}: {count}")
    
    return devices


def get_local_network():
    """
    Auto-detect the local network CIDR based on the default interface.
    
    Returns:
        Network CIDR string (e.g. "192.168.1.0/24"), or None if detection fails.
    """
    if not SCAPY_AVAILABLE:
        return None
    
    try:
        local_ip = get_if_addr(str(conf.iface))
        if local_ip and local_ip != "0.0.0.0":
            # Assume /24 subnet (most home networks)
            parts = local_ip.split(".")
            network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            print(f"  Auto-detected network: {network} (from local IP {local_ip})")
            return network
    except Exception:
        pass
    
    return None


if __name__ == "__main__":
    if not check_dependencies():
        print("\nInstall missing dependencies and try again.")
        sys.exit(1)
    
    # Try to auto-detect network, or use argument/default
    if len(sys.argv) > 1:
        network = sys.argv[1]
    else:
        network = get_local_network() or "192.168.1.0/24"
    
    print(f"\nTarget network: {network}")
    print("=" * 60)
    print("NOTE: ARP scanning requires admin/root privileges.")
    print("=" * 60)
    
    # Run full scan with manufacturer lookup
    devices = full_arp_scan(network)
    
    print("\n" + "=" * 60)
    print("ARP scan complete.")
