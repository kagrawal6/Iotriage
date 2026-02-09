"""
Zeroconf/mDNS Scanner - Passive service discovery.

Requirements:
    - pip install zeroconf

Capabilities:
    - Discover devices advertising services via mDNS/DNS-SD
    - Find smart home devices, printers, media players, etc.
    - Completely passive (just listens, sends no scan traffic)
    - Identify device names, types, and service details

Tradeoffs vs Active Scanning (nmap/masscan):
    - Completely passive and non-intrusive
    - Devices self-identify (more accurate names)
    - But only finds devices that advertise via mDNS
    - Many IoT devices DON'T use mDNS
    - No port scanning or vulnerability info
    
Common mDNS service types:
    - _http._tcp         Web servers / device web interfaces
    - _airplay._tcp      Apple AirPlay (Apple TV, speakers)
    - _raop._tcp         AirPlay audio (speakers, receivers)
    - _googlecast._tcp   Google Chromecast / Google Home
    - _hap._tcp          HomeKit Accessory Protocol (Apple HomeKit)
    - _ipp._tcp          Internet Printing Protocol (printers)
    - _printer._tcp      Printers
    - _smb._tcp          Windows file sharing
    - _ssh._tcp          SSH servers
    - _sftp-ssh._tcp     SFTP servers
    - _mqtt._tcp         MQTT brokers (IoT messaging)
    - _coap._udp         CoAP (IoT protocol)
    - _workstation._tcp  macOS / Linux workstations
    - _companion-link._tcp  Apple device pairing
    - _sleep-proxy._udp  Apple Sleep Proxy
    - _spotify-connect._tcp  Spotify Connect devices
    - _daap._tcp         iTunes / DAAP media sharing
    - _hue._tcp          Philips Hue bridges

Best used as:
    - Supplement to active scanning
    - Discovering smart home devices
    - Finding devices that block ping/port scans
"""

import sys
import time
import socket
from datetime import datetime

try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener, ServiceInfo
    ZEROCONF_AVAILABLE = True
except ImportError:
    ZEROCONF_AVAILABLE = False


def check_zeroconf_installed():
    """Verify that zeroconf library is installed."""
    if ZEROCONF_AVAILABLE:
        print("[OK] Zeroconf is installed.")
        return True
    else:
        print("[ERROR] Zeroconf is not installed.")
        print("        pip install zeroconf")
        return False


# Service types to scan for -- focused on IoT and smart home devices
IOT_SERVICE_TYPES = [
    "_http._tcp.local.",              # Web interfaces
    "_https._tcp.local.",             # Secure web interfaces
    "_hap._tcp.local.",               # Apple HomeKit
    "_airplay._tcp.local.",           # Apple AirPlay
    "_raop._tcp.local.",              # AirPlay Audio
    "_googlecast._tcp.local.",        # Google Chromecast / Home
    "_spotify-connect._tcp.local.",   # Spotify Connect
    "_printer._tcp.local.",           # Printers
    "_ipp._tcp.local.",               # Printers (IPP)
    "_smb._tcp.local.",               # File sharing
    "_ssh._tcp.local.",               # SSH servers
    "_mqtt._tcp.local.",              # MQTT (IoT)
    "_coap._udp.local.",              # CoAP (IoT)
    "_hue._tcp.local.",               # Philips Hue
    "_workstation._tcp.local.",       # Workstations
    "_companion-link._tcp.local.",    # Apple pairing
    "_daap._tcp.local.",              # Media sharing
    "_sonos._tcp.local.",             # Sonos speakers
    "_esphomelib._tcp.local.",        # ESPHome IoT devices
    "_arduino._tcp.local.",           # Arduino devices
]


class IoTServiceListener(ServiceListener):
    """
    Listener that collects discovered mDNS services.
    
    This is called by the Zeroconf library whenever a new service
    is discovered on the network.
    """
    
    def __init__(self):
        self.services = []
        self.devices = {}  # Keyed by IP for deduplication
    
    def add_service(self, zc: Zeroconf, service_type: str, name: str):
        """Called when a new service is discovered."""
        try:
            info = zc.get_service_info(service_type, name)
            if info:
                self._process_service(info, service_type, name)
        except Exception as e:
            print(f"  [WARNING] Error getting info for {name}: {e}")
    
    def update_service(self, zc: Zeroconf, service_type: str, name: str):
        """Called when a service is updated."""
        pass  # We don't need to handle updates for scanning
    
    def remove_service(self, zc: Zeroconf, service_type: str, name: str):
        """Called when a service is removed."""
        pass  # We don't need to handle removals for scanning
    
    def _process_service(self, info: ServiceInfo, service_type: str, name: str):
        """Extract useful information from a discovered service."""
        # Get IP addresses
        addresses = []
        if info.addresses:
            for addr in info.addresses:
                try:
                    ip = socket.inet_ntoa(addr)
                    addresses.append(ip)
                except Exception:
                    pass
        
        if not addresses:
            return
        
        # Parse properties
        properties = {}
        if info.properties:
            for key, value in info.properties.items():
                try:
                    if isinstance(key, bytes):
                        key = key.decode("utf-8", errors="replace")
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", errors="replace")
                    properties[key] = value
                except Exception:
                    pass
        
        # Clean up service type for display
        service_type_clean = service_type.replace("._tcp.local.", "").replace("._udp.local.", "")
        
        service_data = {
            "name": name,
            "service_type": service_type_clean,
            "ip_addresses": addresses,
            "port": info.port,
            "server": info.server,
            "properties": properties,
            "discovered_at": datetime.now().isoformat(),
        }
        
        self.services.append(service_data)
        
        # Group by IP address
        for ip in addresses:
            if ip not in self.devices:
                self.devices[ip] = {
                    "ip": ip,
                    "hostname": info.server,
                    "services": [],
                }
            self.devices[ip]["services"].append({
                "type": service_type_clean,
                "name": name,
                "port": info.port,
                "properties": properties,
            })
        
        # Print discovery
        ip_str = ", ".join(addresses)
        print(f"  Found: {name}")
        print(f"         Type: {service_type_clean}")
        print(f"         IP: {ip_str}:{info.port}")
        if properties:
            # Show key properties (often contains model, firmware, etc.)
            props_preview = {k: v for k, v in list(properties.items())[:5]}
            print(f"         Properties: {props_preview}")
        print()


def discover_services(service_types=None, duration=15):
    """
    Discover mDNS services on the local network.
    
    Listens for service advertisements for the specified duration.
    Devices on the network that use mDNS will advertise their services,
    and we'll collect that information.
    
    Args:
        service_types: List of mDNS service types to scan for.
                      Default: IOT_SERVICE_TYPES (covers common IoT services).
        duration: How long to listen in seconds (default 15).
                 Longer = find more devices (some advertise infrequently).
    
    Returns:
        Tuple of (services_list, devices_dict).
    """
    if not ZEROCONF_AVAILABLE:
        print("[ERROR] Zeroconf not available.")
        return [], {}
    
    if service_types is None:
        service_types = IOT_SERVICE_TYPES
    
    print(f"\n--- Zeroconf/mDNS Service Discovery ---")
    print(f"    Listening for {duration} seconds...")
    print(f"    Scanning {len(service_types)} service types")
    print()
    
    zc = Zeroconf()
    listener = IoTServiceListener()
    
    # Start browsing for each service type
    browsers = []
    for stype in service_types:
        try:
            browser = ServiceBrowser(zc, stype, listener)
            browsers.append(browser)
        except Exception as e:
            print(f"  [WARNING] Could not browse {stype}: {e}")
    
    # Wait for discoveries
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        print("\n  Scan interrupted by user.")
    
    # Clean up
    zc.close()
    
    # Print summary
    print(f"\n  {'='*50}")
    print(f"  Discovery Summary")
    print(f"  {'='*50}")
    print(f"  Total services found: {len(listener.services)}")
    print(f"  Unique devices: {len(listener.devices)}")
    
    if listener.devices:
        print(f"\n  Devices by IP:")
        for ip, device in sorted(listener.devices.items()):
            service_types_found = [s["type"] for s in device["services"]]
            print(f"    {ip} ({device['hostname']})")
            for svc in device["services"]:
                print(f"      - {svc['type']} on port {svc['port']}")
    
    return listener.services, listener.devices


def discover_specific(service_type, duration=10):
    """
    Discover a specific service type on the network.
    
    Useful when you're looking for a particular type of device.
    
    Examples:
        discover_specific("_googlecast._tcp.local.")  # Find Chromecast/Google Home
        discover_specific("_hap._tcp.local.")          # Find HomeKit devices
        discover_specific("_printer._tcp.local.")      # Find printers
    
    Args:
        service_type: mDNS service type string (must end with .local.)
        duration: How long to listen in seconds.
    
    Returns:
        Tuple of (services_list, devices_dict).
    """
    print(f"\n--- Searching for: {service_type} ---")
    return discover_services(service_types=[service_type], duration=duration)


def quick_scan(duration=10):
    """
    Quick scan for the most common IoT devices.
    
    Only scans for the most popular service types to save time.
    
    Args:
        duration: How long to listen in seconds.
    
    Returns:
        Tuple of (services_list, devices_dict).
    """
    common_types = [
        "_http._tcp.local.",
        "_googlecast._tcp.local.",
        "_airplay._tcp.local.",
        "_hap._tcp.local.",
        "_printer._tcp.local.",
        "_ssh._tcp.local.",
        "_hue._tcp.local.",
        "_spotify-connect._tcp.local.",
    ]
    
    print("\n--- Quick mDNS Scan (common services only) ---")
    return discover_services(service_types=common_types, duration=duration)


if __name__ == "__main__":
    if not check_zeroconf_installed():
        sys.exit(1)
    
    duration = 15  # seconds
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print(f"Usage: python zeroconf_scanner.py [duration_seconds]")
            sys.exit(1)
    
    print(f"\nListening for mDNS services for {duration} seconds...")
    print("=" * 60)
    print("NOTE: This is passive scanning -- no packets are sent.")
    print("      Devices must advertise via mDNS to be discovered.")
    print("      Use nmap or ARP scanning for comprehensive discovery.")
    print("=" * 60)
    
    services, devices = discover_services(duration=duration)
    
    print("\n" + "=" * 60)
    print("Zeroconf scan complete.")
    print(f"\nTo scan longer (find more devices): python zeroconf_scanner.py 30")
