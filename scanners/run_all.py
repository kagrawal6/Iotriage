"""
IoTriage Scanner Test Runner

Runs all available scanning technologies to test them on your network.
Use this to see which scanners work in your environment and what
kind of data each one produces.

Usage:
    python run_all.py [network]

Example:
    python run_all.py 192.168.1.0/24

Requirements:
    pip install -r requirements.txt

Notes:
    - Some scanners require admin/root privileges
    - Nmap and/or Masscan must be installed separately
    - On Windows, run as Administrator for full functionality
    - On Windows, install Npcap for scapy to work
"""

import sys
import json
from datetime import datetime


def separator(title):
    print("\n")
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def run_nmap_scanner(network):
    """Test nmap scanning."""
    separator("NMAP SCANNER")
    
    try:
        from nmap_scanner import check_nmap_installed, ping_sweep, service_scan, iot_scan
    except ImportError:
        print("[SKIP] nmap_scanner module not found.")
        return None
    
    if not check_nmap_installed():
        print("[SKIP] Nmap not installed.")
        return None
    
    results = {"scanner": "nmap", "timestamp": datetime.now().isoformat()}
    
    # Ping sweep
    print("\n[1/2] Running ping sweep...")
    hosts = ping_sweep(network)
    results["hosts_discovered"] = len(hosts)
    results["hosts"] = hosts
    
    # Service scan on first host (if any found)
    if hosts:
        first_host = hosts[0]["ip"]
        print(f"\n[2/2] Running service scan on {first_host}...")
        services = service_scan(first_host, ports="22,80,443,8080")
        results["service_scan"] = services
    else:
        print("\n[2/2] No hosts found, skipping service scan.")
    
    return results


def run_masscan_scanner(network):
    """Test masscan scanning."""
    separator("MASSCAN SCANNER")
    
    try:
        from masscan_scanner import check_masscan_installed, quick_port_scan
    except ImportError:
        print("[SKIP] masscan_scanner module not found.")
        return None
    
    if not check_masscan_installed():
        print("[SKIP] Masscan not installed.")
        return None
    
    results = {"scanner": "masscan", "timestamp": datetime.now().isoformat()}
    
    print("\n[1/1] Running quick port scan...")
    ports = quick_port_scan(network, ports="22,80,443,8080", rate=500)
    results["open_ports"] = ports
    
    return results


def run_scapy_scanner(network):
    """Test scapy scanning."""
    separator("SCAPY SCANNER")
    
    try:
        from scapy_scanner import check_scapy_installed, arp_scan, detect_os_ttl, tcp_syn_scan
    except ImportError:
        print("[SKIP] scapy_scanner module not found.")
        return None
    
    if not check_scapy_installed():
        print("[SKIP] Scapy not available.")
        return None
    
    results = {"scanner": "scapy", "timestamp": datetime.now().isoformat()}
    
    # ARP scan
    print("\n[1/2] Running ARP scan...")
    try:
        devices = arp_scan(network)
        results["arp_devices"] = devices
        
        # TTL OS detection on first device
        if devices:
            first_ip = devices[0]["ip"]
            print(f"\n[2/2] Running TTL OS detection on {first_ip}...")
            os_info = detect_os_ttl(first_ip)
            results["os_detection"] = os_info
        else:
            print("\n[2/2] No devices found, skipping OS detection.")
    except PermissionError:
        print("[ERROR] Permission denied. Run as Administrator/root for scapy scans.")
        results["error"] = "Permission denied"
    except Exception as e:
        print(f"[ERROR] Scapy scan failed: {e}")
        results["error"] = str(e)
    
    return results


def run_arp_scanner(network):
    """Test ARP scanning with manufacturer lookup."""
    separator("ARP SCANNER (with manufacturer lookup)")
    
    try:
        from arp_scanner import check_dependencies, full_arp_scan
    except ImportError:
        print("[SKIP] arp_scanner module not found.")
        return None
    
    if not check_dependencies():
        print("[SKIP] Missing dependencies.")
        return None
    
    results = {"scanner": "arp", "timestamp": datetime.now().isoformat()}
    
    print("\n[1/1] Running ARP scan with manufacturer lookup...")
    try:
        devices = full_arp_scan(network)
        results["devices"] = devices
    except PermissionError:
        print("[ERROR] Permission denied. Run as Administrator/root.")
        results["error"] = "Permission denied"
    except Exception as e:
        print(f"[ERROR] ARP scan failed: {e}")
        results["error"] = str(e)
    
    return results


def run_zeroconf_scanner():
    """Test zeroconf/mDNS scanning."""
    separator("ZEROCONF/mDNS SCANNER")
    
    try:
        from zeroconf_scanner import check_zeroconf_installed, quick_scan
    except ImportError:
        print("[SKIP] zeroconf_scanner module not found.")
        return None
    
    if not check_zeroconf_installed():
        print("[SKIP] Zeroconf not available.")
        return None
    
    results = {"scanner": "zeroconf", "timestamp": datetime.now().isoformat()}
    
    print("\n[1/1] Running quick mDNS scan (10 seconds)...")
    services, devices = quick_scan(duration=10)
    results["services_found"] = len(services)
    results["devices_found"] = len(devices)
    # Convert devices dict for JSON serialization
    results["devices"] = {ip: {
        "ip": d["ip"],
        "hostname": d["hostname"],
        "services": d["services"],
    } for ip, d in devices.items()}
    
    return results


def main():
    # Determine target network
    if len(sys.argv) > 1:
        network = sys.argv[1]
    else:
        # Try to auto-detect
        try:
            from arp_scanner import get_local_network
            network = get_local_network() or "192.168.1.0/24"
        except ImportError:
            network = "192.168.1.0/24"
    
    print("=" * 70)
    print("  IoTriage Scanner Test Runner")
    print("=" * 70)
    print(f"  Target network: {network}")
    print(f"  Timestamp: {datetime.now().isoformat()}")
    print(f"  Platform: {sys.platform}")
    print()
    print("  This will test each scanning technology to see what works")
    print("  in your environment and what data each scanner produces.")
    print()
    print("  Some scanners require:")
    print("    - Admin/root privileges")
    print("    - External tools (nmap, masscan)")
    print("    - Npcap (on Windows, for scapy)")
    print("=" * 70)
    
    all_results = {}
    
    # Run each scanner
    # Order: passive first (zeroconf), then active scans
    
    # 1. Zeroconf (passive, no privileges needed)
    result = run_zeroconf_scanner()
    if result:
        all_results["zeroconf"] = result
    
    # 2. ARP Scanner (needs privileges)
    result = run_arp_scanner(network)
    if result:
        all_results["arp"] = result
    
    # 3. Scapy Scanner (needs privileges)
    result = run_scapy_scanner(network)
    if result:
        all_results["scapy"] = result
    
    # 4. Nmap Scanner (needs nmap installed)
    result = run_nmap_scanner(network)
    if result:
        all_results["nmap"] = result
    
    # 5. Masscan Scanner (needs masscan installed)
    result = run_masscan_scanner(network)
    if result:
        all_results["masscan"] = result
    
    # Final summary
    separator("SCAN SUMMARY")
    print(f"\n  Scanners tested: {len(all_results)}")
    
    for name, result in all_results.items():
        status = "ERROR" if "error" in result else "OK"
        details = ""
        
        if name == "zeroconf":
            details = f"services={result.get('services_found', 0)}, devices={result.get('devices_found', 0)}"
        elif name == "arp":
            details = f"devices={len(result.get('devices', []))}"
        elif name == "scapy":
            details = f"devices={len(result.get('arp_devices', []))}"
        elif name == "nmap":
            details = f"hosts={result.get('hosts_discovered', 0)}"
        elif name == "masscan":
            details = f"open_ports={len(result.get('open_ports', []))}"
        
        print(f"  [{status}] {name}: {details}")
    
    # Save results to JSON
    output_file = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(output_file, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\n  Results saved to: {output_file}")
    except Exception as e:
        print(f"\n  Could not save results: {e}")
    
    print("\n" + "=" * 70)
    print("  All scans complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
