"""
Nmap Scanner - Industry-standard network scanning using python-nmap.

Requirements:
    - Nmap must be installed on the system (https://nmap.org/download.html)
    - pip install python-nmap

Capabilities:
    - Host discovery (ping sweep)
    - Port scanning
    - Service/version detection
    - OS fingerprinting
    - NSE script scanning

Notes:
    - Some features (OS detection, SYN scan) require admin/root privileges.
    - On Windows, run your terminal as Administrator for full features.
    - Scans can be slow on large networks. Use -T4 or -T5 for faster timing.
"""

import nmap
import json
import sys
from datetime import datetime


def check_nmap_installed():
    """Verify that nmap is installed and accessible."""
    try:
        nm = nmap.PortScanner()
        print(f"[OK] Nmap found: version {nm.nmap_version()}")
        return True
    except nmap.PortScannerError:
        print("[ERROR] Nmap is not installed or not found in PATH.")
        print("       Download from: https://nmap.org/download.html")
        return False


def ping_sweep(network="192.168.1.0/24"):
    """
    Quick host discovery using ping sweep.
    Finds all live hosts on the network without port scanning.
    
    This is the fastest scan type -- good for initial discovery.
    
    Args:
        network: CIDR notation of the network to scan (e.g. "192.168.1.0/24")
    
    Returns:
        List of dicts with ip and hostname for each discovered host.
    """
    print(f"\n--- Nmap Ping Sweep: {network} ---")
    nm = nmap.PortScanner()
    
    # -sn: Ping scan (no port scan)
    # This just checks which hosts are alive
    nm.scan(hosts=network, arguments="-sn")
    
    hosts = []
    for host in nm.all_hosts():
        host_info = {
            "ip": host,
            "hostname": nm[host].hostname() or "unknown",
            "state": nm[host].state(),
        }
        hosts.append(host_info)
        print(f"  Found: {host_info['ip']} ({host_info['hostname']}) - {host_info['state']}")
    
    print(f"\nTotal hosts found: {len(hosts)}")
    return hosts


def service_scan(target, ports="1-1024"):
    """
    Scan a target for open ports and detect service versions.
    
    This is the most useful scan for IoTriage -- it tells us what software
    is running on each device, which we need for CVE lookups.
    
    Args:
        target: IP address or hostname to scan.
        ports: Port range to scan (default "1-1024" for common ports).
    
    Returns:
        Dict with detailed service information for the target.
    """
    print(f"\n--- Nmap Service Scan: {target} (ports {ports}) ---")
    nm = nmap.PortScanner()
    
    # -sV: Service/version detection
    # -T4: Aggressive timing (faster)
    nm.scan(hosts=target, ports=ports, arguments="-sV -T4")
    
    results = {}
    for host in nm.all_hosts():
        host_data = {
            "ip": host,
            "hostname": nm[host].hostname() or "unknown",
            "state": nm[host].state(),
            "protocols": {},
        }
        
        for proto in nm[host].all_protocols():
            ports_data = {}
            for port in sorted(nm[host][proto].keys()):
                port_info = nm[host][proto][port]
                ports_data[port] = {
                    "state": port_info["state"],
                    "service": port_info["name"],
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                    "extrainfo": port_info.get("extrainfo", ""),
                    "cpe": port_info.get("cpe", ""),
                }
                
                print(f"  Port {port}/{proto}: {port_info['state']} "
                      f"| {port_info['name']} "
                      f"| {port_info.get('product', '')} {port_info.get('version', '')}")
            
            host_data["protocols"][proto] = ports_data
        
        results[host] = host_data
    
    return results


def os_detection(target):
    """
    Detect the operating system of a target device.
    
    REQUIRES ADMIN/ROOT PRIVILEGES.
    
    Useful for identifying IoT device types (e.g. Linux-based smart devices,
    embedded systems, etc.)
    
    Args:
        target: IP address or hostname to scan.
    
    Returns:
        Dict with OS detection results.
    """
    print(f"\n--- Nmap OS Detection: {target} ---")
    print("  (Requires admin/root privileges)")
    nm = nmap.PortScanner()
    
    try:
        # -O: OS detection
        # -T4: Aggressive timing
        nm.scan(hosts=target, arguments="-O -T4")
    except nmap.PortScannerError as e:
        print(f"  [ERROR] OS detection failed: {e}")
        print("  Tip: Run this script as Administrator/root.")
        return None
    
    results = {}
    for host in nm.all_hosts():
        os_matches = []
        if "osmatch" in nm[host]:
            for os_match in nm[host]["osmatch"]:
                os_info = {
                    "name": os_match["name"],
                    "accuracy": os_match["accuracy"],
                }
                os_matches.append(os_info)
                print(f"  OS Match: {os_match['name']} (accuracy: {os_match['accuracy']}%)")
        
        results[host] = {
            "ip": host,
            "os_matches": os_matches,
        }
    
    return results


def aggressive_scan(target):
    """
    Full aggressive scan combining OS detection, version detection,
    script scanning, and traceroute.
    
    This is the most comprehensive scan but also the slowest and most
    intrusive. REQUIRES ADMIN/ROOT PRIVILEGES.
    
    Args:
        target: IP address or hostname to scan.
    
    Returns:
        Dict with comprehensive scan results.
    """
    print(f"\n--- Nmap Aggressive Scan: {target} ---")
    print("  (This may take a while...)")
    nm = nmap.PortScanner()
    
    try:
        # -A: Aggressive scan (OS detection, version, scripts, traceroute)
        # -T4: Faster timing
        nm.scan(hosts=target, arguments="-A -T4")
    except nmap.PortScannerError as e:
        print(f"  [ERROR] Aggressive scan failed: {e}")
        return None
    
    results = {}
    for host in nm.all_hosts():
        host_data = {
            "ip": host,
            "hostname": nm[host].hostname() or "unknown",
            "state": nm[host].state(),
            "protocols": {},
            "os_matches": [],
        }
        
        # Ports and services
        for proto in nm[host].all_protocols():
            ports_data = {}
            for port in sorted(nm[host][proto].keys()):
                port_info = nm[host][proto][port]
                ports_data[port] = {
                    "state": port_info["state"],
                    "service": port_info["name"],
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                    "cpe": port_info.get("cpe", ""),
                }
            host_data["protocols"][proto] = ports_data
        
        # OS matches
        if "osmatch" in nm[host]:
            for os_match in nm[host]["osmatch"]:
                host_data["os_matches"].append({
                    "name": os_match["name"],
                    "accuracy": os_match["accuracy"],
                })
        
        results[host] = host_data
        
        print(f"  Host: {host} ({host_data['hostname']})")
        print(f"  State: {host_data['state']}")
        if host_data["os_matches"]:
            print(f"  OS: {host_data['os_matches'][0]['name']}")
        for proto in host_data["protocols"]:
            for port, info in host_data["protocols"][proto].items():
                print(f"  Port {port}/{proto}: {info['service']} "
                      f"{info['product']} {info['version']}")
    
    return results


def iot_scan(network="192.168.1.0/24"):
    """
    IoT-focused scan: discover devices and probe for common IoT services.
    
    Uses nmap scripts to detect:
    - UPnP devices (smart TVs, media players, routers)
    - HTTP servers (web interfaces on IoT devices)
    - SNMP services (network-managed devices)
    - Banner information
    
    Args:
        network: CIDR notation of the network to scan.
    
    Returns:
        Dict with IoT-relevant scan results.
    """
    print(f"\n--- Nmap IoT Scan: {network} ---")
    print("  Scanning for IoT-specific services...")
    nm = nmap.PortScanner()
    
    # Common IoT ports:
    # 80, 443: Web interfaces
    # 8080, 8443: Alternate web
    # 1900: UPnP/SSDP
    # 5353: mDNS
    # 23: Telnet (many IoT devices)
    # 22: SSH
    # 161: SNMP
    # 554: RTSP (cameras)
    # 1883: MQTT (IoT messaging)
    # 5683: CoAP (IoT protocol)
    iot_ports = "22,23,80,161,443,554,1883,1900,5353,5683,8080,8443,49152"
    
    # Scripts useful for IoT:
    # banner: grab service banners
    # http-title: get web page titles
    # upnp-info: UPnP device information
    scripts = "banner,http-title"
    
    nm.scan(
        hosts=network,
        ports=iot_ports,
        arguments=f"-sV --script={scripts} -T4"
    )
    
    devices = []
    for host in nm.all_hosts():
        device = {
            "ip": host,
            "hostname": nm[host].hostname() or "unknown",
            "state": nm[host].state(),
            "services": [],
            "scan_time": datetime.now().isoformat(),
        }
        
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                port_info = nm[host][proto][port]
                if port_info["state"] == "open":
                    service = {
                        "port": port,
                        "protocol": proto,
                        "service": port_info["name"],
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "cpe": port_info.get("cpe", ""),
                    }
                    device["services"].append(service)
        
        if device["services"]:  # Only include devices with open ports
            devices.append(device)
            print(f"\n  Device: {device['ip']} ({device['hostname']})")
            for svc in device["services"]:
                print(f"    Port {svc['port']}: {svc['service']} "
                      f"- {svc['product']} {svc['version']}")
    
    print(f"\nTotal IoT devices found: {len(devices)}")
    return devices


if __name__ == "__main__":
    if not check_nmap_installed():
        sys.exit(1)
    
    # Default network - change this to match your network
    network = "192.168.1.0/24"
    
    if len(sys.argv) > 1:
        network = sys.argv[1]
    
    print(f"\nTarget network: {network}")
    print("=" * 60)
    
    # 1. Quick discovery
    hosts = ping_sweep(network)
    
    if hosts:
        # 2. Service scan on first discovered host
        first_host = hosts[0]["ip"]
        service_scan(first_host)
        
        # 3. IoT-specific scan on full network
        iot_scan(network)
    
    print("\n" + "=" * 60)
    print("Nmap scan complete.")
    print("\nTo run OS detection or aggressive scans, run as admin:")
    print("  python nmap_scanner.py")
