"""
Scapy Scanner - Custom packet crafting and network discovery.

Requirements:
    - pip install scapy
    - On Windows: also install Npcap (https://npcap.com/) for packet capture
    - Admin/root privileges required for raw socket operations

Capabilities:
    - ARP scanning (local network device discovery)
    - TCP SYN scanning (port scanning)
    - ICMP ping sweep
    - Custom packet crafting
    - Passive network sniffing

Tradeoffs vs Nmap:
    - More flexible (build any packet you want)
    - Python-native (no subprocess, no external binary)
    - But more code to write
    - Less polished output
    - Requires deeper networking knowledge
    - Slower than nmap for standard scans

Best used for:
    - Quick ARP scans on local network
    - Custom IoT protocol analysis
    - When you need fine-grained control over packets
    - Passive traffic monitoring
"""

import sys
import logging

# Suppress Scapy's verbose startup messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import (
        ARP, Ether, IP, TCP, ICMP, UDP,
        srp, sr1, sr, conf, get_if_addr, get_if_hwaddr
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def check_scapy_installed():
    """Verify that scapy is installed."""
    if SCAPY_AVAILABLE:
        print("[OK] Scapy is installed.")
        try:
            iface = conf.iface
            ip = get_if_addr(str(iface))
            print(f"     Default interface: {iface}")
            print(f"     Local IP: {ip}")
        except Exception:
            print("     (Could not detect network interface)")
        return True
    else:
        print("[ERROR] Scapy is not installed.")
        print("        pip install scapy")
        print("        On Windows, also install Npcap: https://npcap.com/")
        return False


def arp_scan(network="192.168.1.0/24", timeout=3):
    """
    ARP scan to discover all devices on the local network.
    
    ARP (Address Resolution Protocol) is Layer 2, so this only works
    on your local network segment. It's very fast and reliable because
    devices MUST respond to ARP requests to communicate on the network.
    
    This is often faster than nmap's ping sweep for local networks.
    
    Args:
        network: CIDR notation of the network to scan.
        timeout: Seconds to wait for responses (default 3).
    
    Returns:
        List of dicts with ip and mac for each discovered device.
    """
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy not available.")
        return []
    
    print(f"\n--- Scapy ARP Scan: {network} ---")
    
    # Build ARP request packet
    # Ether(dst="ff:ff:ff:ff:ff:ff") = broadcast to all devices
    # ARP(pdst=network) = ask "who has this IP?"
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    
    print(f"  Sending ARP requests to {network}...")
    
    # srp = send and receive at layer 2 (Ethernet)
    # timeout: how long to wait for responses
    # verbose=0: suppress scapy output
    answered, unanswered = srp(packet, timeout=timeout, verbose=0)
    
    devices = []
    for sent, received in answered:
        device = {
            "ip": received.psrc,
            "mac": received.hwsrc,
        }
        devices.append(device)
        print(f"  Found: {device['ip']} (MAC: {device['mac']})")
    
    print(f"\nTotal devices found: {len(devices)}")
    return devices


def icmp_ping_sweep(network_prefix="192.168.1", start=1, end=254, timeout=1):
    """
    ICMP ping sweep to discover live hosts.
    
    Sends ICMP Echo Request (ping) to each IP in the range.
    Less reliable than ARP scan (some devices block ICMP) but works
    across subnets.
    
    Args:
        network_prefix: First three octets of the network.
        start: Starting host number.
        end: Ending host number.
        timeout: Seconds to wait for each response.
    
    Returns:
        List of IPs that responded to ping.
    """
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy not available.")
        return []
    
    print(f"\n--- Scapy ICMP Ping Sweep: {network_prefix}.{start}-{end} ---")
    
    live_hosts = []
    total = end - start + 1
    
    for i in range(start, end + 1):
        target_ip = f"{network_prefix}.{i}"
        
        # Print progress every 50 hosts
        if (i - start) % 50 == 0:
            print(f"  Scanning {target_ip}... ({i - start}/{total})")
        
        # Build ICMP Echo Request
        icmp_packet = IP(dst=target_ip) / ICMP()
        
        # sr1 = send one packet and receive one response
        response = sr1(icmp_packet, timeout=timeout, verbose=0)
        
        if response is not None:
            live_hosts.append(target_ip)
            print(f"  Found: {target_ip} (ICMP response)")
    
    print(f"\nTotal live hosts: {len(live_hosts)}")
    return live_hosts


def tcp_syn_scan(target, ports=None, timeout=2):
    """
    TCP SYN scan (half-open scan) on a single target.
    
    Sends TCP SYN packet to each port. If we get SYN-ACK back,
    the port is open. If RST, it's closed.
    
    This is the same technique nmap uses with -sS (SYN scan).
    REQUIRES ADMIN/ROOT PRIVILEGES.
    
    Args:
        target: IP address to scan.
        ports: List of port numbers to scan (default: common ports).
        timeout: Seconds to wait for responses.
    
    Returns:
        Dict with port numbers as keys and state as values.
    """
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy not available.")
        return {}
    
    if ports is None:
        # Common ports including IoT-relevant ones
        ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
            443, 445, 554, 993, 995, 1883, 1900, 3306,
            5353, 5683, 8080, 8443, 8883, 49152
        ]
    
    print(f"\n--- Scapy TCP SYN Scan: {target} ---")
    print(f"    Ports: {len(ports)} ports")
    
    open_ports = {}
    
    for port in ports:
        # Build SYN packet
        # sport=RandShort() would randomize source port
        syn_packet = IP(dst=target) / TCP(dport=port, flags="S")
        
        # Send and wait for response
        response = sr1(syn_packet, timeout=timeout, verbose=0)
        
        if response is not None:
            # Check TCP flags in response
            tcp_flags = response.getlayer(TCP).flags if response.haslayer(TCP) else None
            
            if tcp_flags == 0x12:  # SYN-ACK (port is open)
                open_ports[port] = "open"
                print(f"  Port {port}: OPEN")
                
                # Send RST to close the connection (be polite)
                rst_packet = IP(dst=target) / TCP(dport=port, flags="R")
                sr1(rst_packet, timeout=1, verbose=0)
                
            elif tcp_flags == 0x14:  # RST-ACK (port is closed)
                open_ports[port] = "closed"
        else:
            open_ports[port] = "filtered"  # No response = filtered
    
    # Summary
    open_count = sum(1 for s in open_ports.values() if s == "open")
    print(f"\nOpen ports: {open_count} / {len(ports)} scanned")
    
    return open_ports


def detect_os_ttl(target, timeout=2):
    """
    Simple OS detection based on TTL (Time To Live) values.
    
    Different operating systems use different default TTL values:
    - Windows: 128
    - Linux/macOS: 64
    - Network equipment (Cisco, etc.): 255
    - Some IoT devices: 64 or 128
    
    This is a rough heuristic, not as accurate as nmap's OS detection.
    
    Args:
        target: IP address to probe.
        timeout: Seconds to wait for response.
    
    Returns:
        Dict with TTL value and estimated OS family.
    """
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy not available.")
        return {}
    
    print(f"\n--- Scapy TTL-based OS Detection: {target} ---")
    
    # Send ICMP ping and check TTL in response
    icmp_packet = IP(dst=target) / ICMP()
    response = sr1(icmp_packet, timeout=timeout, verbose=0)
    
    if response is None:
        print("  No response from target.")
        return {"target": target, "ttl": None, "os_guess": "unknown"}
    
    ttl = response.ttl
    
    # Guess OS based on TTL
    if ttl <= 64:
        os_guess = "Linux/macOS/Unix (TTL 64)"
    elif ttl <= 128:
        os_guess = "Windows (TTL 128)"
    elif ttl <= 255:
        os_guess = "Network device / Solaris (TTL 255)"
    else:
        os_guess = "Unknown"
    
    result = {
        "target": target,
        "ttl": ttl,
        "os_guess": os_guess,
    }
    
    print(f"  TTL: {ttl}")
    print(f"  OS Guess: {os_guess}")
    
    return result


def passive_sniff(interface=None, count=50, timeout=30):
    """
    Passive network sniffing - listen to traffic without sending packets.
    
    This discovers devices by watching who is talking on the network.
    Completely silent (no packets sent), so it won't trigger any alarms.
    
    Useful for:
    - Discovering devices that don't respond to active scans
    - Monitoring network activity
    - Finding devices that are "phoning home"
    
    Args:
        interface: Network interface to sniff on (None = default).
        count: Number of packets to capture.
        timeout: Max seconds to sniff.
    
    Returns:
        Dict of discovered IPs with packet counts.
    """
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy not available.")
        return {}
    
    from scapy.all import sniff as scapy_sniff
    
    print(f"\n--- Scapy Passive Sniff (capturing {count} packets, {timeout}s timeout) ---")
    print("  Listening for network traffic...")
    
    try:
        if interface:
            packets = scapy_sniff(iface=interface, count=count, timeout=timeout)
        else:
            packets = scapy_sniff(count=count, timeout=timeout)
    except PermissionError:
        print("  [ERROR] Permission denied. Run as Administrator/root.")
        return {}
    except Exception as e:
        print(f"  [ERROR] Sniffing failed: {e}")
        return {}
    
    # Analyze captured packets
    discovered = {}
    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            # Track source IPs (devices on our network)
            if src not in discovered:
                discovered[src] = {"packets_sent": 0, "packets_received": 0, "protocols": set()}
            discovered[src]["packets_sent"] += 1
            
            # Track destination IPs
            if dst not in discovered:
                discovered[dst] = {"packets_sent": 0, "packets_received": 0, "protocols": set()}
            discovered[dst]["packets_received"] += 1
            
            # Track protocols
            if pkt.haslayer(TCP):
                discovered[src]["protocols"].add(f"TCP:{pkt[TCP].dport}")
            elif pkt.haslayer(UDP):
                discovered[src]["protocols"].add(f"UDP:{pkt[UDP].dport}")
    
    # Convert sets to lists for JSON serialization
    for ip in discovered:
        discovered[ip]["protocols"] = list(discovered[ip]["protocols"])
    
    print(f"\n  Captured {len(packets)} packets")
    print(f"  Discovered {len(discovered)} unique IPs:")
    for ip, info in sorted(discovered.items()):
        print(f"    {ip}: sent={info['packets_sent']}, "
              f"recv={info['packets_received']}, "
              f"protocols={info['protocols'][:5]}")
    
    return discovered


if __name__ == "__main__":
    if not check_scapy_installed():
        sys.exit(1)
    
    # Default network - change to match yours
    network = "192.168.1.0/24"
    
    if len(sys.argv) > 1:
        network = sys.argv[1]
    
    print(f"\nTarget network: {network}")
    print("=" * 60)
    print("NOTE: Most scapy scans require admin/root privileges.")
    print("      On Windows, run as Administrator.")
    print("      On Linux/macOS, use sudo.")
    print("=" * 60)
    
    # 1. ARP Scan (fastest for local network)
    devices = arp_scan(network)
    
    if devices:
        # 2. TTL-based OS detection on first device
        first_ip = devices[0]["ip"]
        detect_os_ttl(first_ip)
        
        # 3. TCP SYN scan on first device
        tcp_syn_scan(first_ip, ports=[22, 80, 443, 8080])
    
    print("\n" + "=" * 60)
    print("Scapy scan complete.")
    print("\nOther available functions:")
    print("  icmp_ping_sweep() - ICMP-based host discovery")
    print("  passive_sniff()   - Listen to network traffic")
