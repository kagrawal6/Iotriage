"""
Masscan Scanner - Ultra-fast port scanner.

Requirements:
    - Masscan must be installed on the system (https://github.com/robertdavidgraham/masscan)
    - On Windows: download pre-built binary or build from source
    - On Linux: sudo apt install masscan
    - On macOS: brew install masscan

Capabilities:
    - Asynchronous TCP/UDP scanning
    - Extremely fast (1000x faster than nmap for raw port scanning)
    - Banner grabbing
    - Outputs results in JSON/XML format

Tradeoffs vs Nmap:
    - MUCH faster for large-scale port discovery
    - But NO service version detection
    - No OS fingerprinting
    - No script engine
    - Can overwhelm small networks (use rate limiting!)
    
Best used as:
    - Quick initial scan to find open ports
    - Then hand off to nmap for detailed service detection on discovered ports
"""

import subprocess
import json
import shutil
import sys
import os
import tempfile


def check_masscan_installed():
    """Verify that masscan is installed and accessible."""
    path = shutil.which("masscan")
    if path:
        print(f"[OK] Masscan found at: {path}")
        return True
    else:
        print("[ERROR] Masscan is not installed or not found in PATH.")
        print("       Install:")
        print("         Windows: Download from https://github.com/robertdavidgraham/masscan/releases")
        print("         Linux:   sudo apt install masscan")
        print("         macOS:   brew install masscan")
        return False


def quick_port_scan(target, ports="0-1024", rate=1000):
    """
    Fast port scan using masscan.
    
    This finds open ports very quickly but doesn't identify what services
    are running on them. Use nmap afterwards for service detection.
    
    Args:
        target: IP address or CIDR range to scan.
        ports: Port range to scan (default "0-1024").
        rate: Packets per second (default 1000, max 10000000).
              WARNING: High rates can overwhelm your network!
              For home networks, keep this at 1000 or less.
    
    Returns:
        List of dicts with ip, port, protocol, and state.
    """
    print(f"\n--- Masscan Quick Port Scan: {target} (ports {ports}) ---")
    print(f"    Rate: {rate} packets/sec")
    
    # Create a temp file for JSON output
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        output_file = f.name
    
    try:
        cmd = [
            "masscan",
            target,
            "-p", ports,
            "--rate", str(rate),
            "-oJ", output_file,
            "--open",  # Only show open ports
        ]
        
        print(f"    Command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,  # 2 minute timeout
        )
        
        if result.returncode != 0 and result.stderr:
            # Masscan often prints progress to stderr, not always an error
            stderr_lines = result.stderr.strip().split("\n")
            for line in stderr_lines:
                if "error" in line.lower() or "FAIL" in line:
                    print(f"    [WARNING] {line}")
        
        # Parse JSON output
        results = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                content = f.read().strip()
                if content:
                    # Masscan JSON output has trailing commas and
                    # is wrapped in array brackets with a final metadata entry.
                    # We need to handle this carefully.
                    try:
                        # Try standard JSON parse first
                        data = json.loads(content)
                        for entry in data:
                            if "ip" in entry and "ports" in entry:
                                for port_info in entry["ports"]:
                                    result_entry = {
                                        "ip": entry["ip"],
                                        "port": port_info["port"],
                                        "protocol": port_info["proto"],
                                        "state": port_info["status"],
                                    }
                                    results.append(result_entry)
                                    print(f"  Found: {result_entry['ip']}:"
                                          f"{result_entry['port']}/{result_entry['protocol']} "
                                          f"- {result_entry['state']}")
                    except json.JSONDecodeError:
                        # Masscan JSON can be malformed, try line-by-line
                        for line in content.split("\n"):
                            line = line.strip().rstrip(",")
                            if line.startswith("{") and line.endswith("}"):
                                try:
                                    entry = json.loads(line)
                                    if "ip" in entry and "ports" in entry:
                                        for port_info in entry["ports"]:
                                            result_entry = {
                                                "ip": entry["ip"],
                                                "port": port_info["port"],
                                                "protocol": port_info["proto"],
                                                "state": port_info["status"],
                                            }
                                            results.append(result_entry)
                                            print(f"  Found: {result_entry['ip']}:"
                                                  f"{result_entry['port']}/{result_entry['protocol']} "
                                                  f"- {result_entry['state']}")
                                except json.JSONDecodeError:
                                    continue
        
        print(f"\nTotal open ports found: {len(results)}")
        return results
    
    except subprocess.TimeoutExpired:
        print("  [ERROR] Scan timed out after 120 seconds.")
        return []
    except FileNotFoundError:
        print("  [ERROR] Masscan executable not found.")
        return []
    finally:
        # Clean up temp file
        if os.path.exists(output_file):
            os.remove(output_file)


def banner_grab(target, ports="80,443,8080", rate=500):
    """
    Scan with banner grabbing enabled.
    
    Banner grabbing retrieves the initial response from a service,
    which can help identify what software is running (though not as
    accurately as nmap's service detection).
    
    Args:
        target: IP address or CIDR range to scan.
        ports: Ports to scan (default common web ports).
        rate: Packets per second.
    
    Returns:
        List of dicts with ip, port, and banner data.
    """
    print(f"\n--- Masscan Banner Grab: {target} (ports {ports}) ---")
    
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        output_file = f.name
    
    try:
        cmd = [
            "masscan",
            target,
            "-p", ports,
            "--rate", str(rate),
            "--banners",        # Enable banner grabbing
            "--open",
            "-oJ", output_file,
        ]
        
        print(f"    Command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        
        results = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                content = f.read().strip()
                if content:
                    try:
                        data = json.loads(content)
                        for entry in data:
                            if "ip" in entry and "ports" in entry:
                                for port_info in entry["ports"]:
                                    result_entry = {
                                        "ip": entry["ip"],
                                        "port": port_info["port"],
                                        "protocol": port_info["proto"],
                                        "state": port_info.get("status", "unknown"),
                                        "banner": port_info.get("service", {}).get("banner", ""),
                                    }
                                    results.append(result_entry)
                                    banner_preview = result_entry["banner"][:80] if result_entry["banner"] else "no banner"
                                    print(f"  {result_entry['ip']}:{result_entry['port']} "
                                          f"- {banner_preview}")
                    except json.JSONDecodeError:
                        print("  [WARNING] Could not parse JSON output.")
        
        print(f"\nTotal results: {len(results)}")
        return results
    
    except subprocess.TimeoutExpired:
        print("  [ERROR] Scan timed out.")
        return []
    except FileNotFoundError:
        print("  [ERROR] Masscan executable not found.")
        return []
    finally:
        if os.path.exists(output_file):
            os.remove(output_file)


def masscan_then_nmap(target, ports="0-1024", rate=1000):
    """
    Hybrid approach: Use masscan for fast port discovery, then nmap for
    detailed service detection on discovered ports.
    
    This is the recommended workflow for scanning larger networks:
    1. Masscan finds open ports quickly
    2. Nmap does deep service detection only on those ports
    
    Args:
        target: IP address or CIDR range.
        ports: Port range for initial masscan sweep.
        rate: Masscan packet rate.
    
    Returns:
        Dict mapping IPs to their detailed service information.
    """
    print(f"\n--- Hybrid Scan (Masscan + Nmap): {target} ---")
    
    # Step 1: Fast discovery with masscan
    print("\nStep 1: Fast port discovery with masscan...")
    open_ports = quick_port_scan(target, ports, rate)
    
    if not open_ports:
        print("No open ports found. Skipping nmap scan.")
        return {}
    
    # Group ports by IP
    ip_ports = {}
    for entry in open_ports:
        ip = entry["ip"]
        port = entry["port"]
        if ip not in ip_ports:
            ip_ports[ip] = []
        ip_ports[ip].append(str(port))
    
    # Step 2: Detailed scan with nmap
    print("\nStep 2: Detailed service detection with nmap...")
    try:
        import nmap
        nm = nmap.PortScanner()
    except ImportError:
        print("  [ERROR] python-nmap not installed. pip install python-nmap")
        return ip_ports
    
    detailed_results = {}
    for ip, ports_list in ip_ports.items():
        port_str = ",".join(ports_list)
        print(f"\n  Scanning {ip} ports: {port_str}")
        
        nm.scan(hosts=ip, ports=port_str, arguments="-sV -T4")
        
        if ip in nm.all_hosts():
            services = {}
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto]:
                    port_info = nm[ip][proto][port]
                    services[port] = {
                        "service": port_info["name"],
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "cpe": port_info.get("cpe", ""),
                    }
                    print(f"    Port {port}: {port_info['name']} "
                          f"{port_info.get('product', '')} "
                          f"{port_info.get('version', '')}")
            
            detailed_results[ip] = services
    
    return detailed_results


if __name__ == "__main__":
    if not check_masscan_installed():
        print("\nMasscan is not installed. This scanner requires masscan.")
        print("You can still use nmap_scanner.py for network scanning.")
        sys.exit(1)
    
    # Default target - change to match your network
    target = "192.168.1.0/24"
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    
    print(f"\nTarget: {target}")
    print("=" * 60)
    
    # Quick port scan
    results = quick_port_scan(target, ports="22,80,443,8080", rate=500)
    
    print("\n" + "=" * 60)
    print("Masscan scan complete.")
