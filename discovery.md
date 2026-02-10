# IoTriage Network Discovery Findings

**Scan Date:** February 9, 2026
**Network:** 192.168.0.0/24
**Local IP:** 192.168.0.101
**Platform:** Windows 10

---

## Scanner Status

| Scanner | Status | Notes |
|---------|--------|-------|
| Zeroconf/mDNS | Working | Found 1 device |
| ARP Scanner | Failed | Npcap not installed (required for Layer 2) |
| Scapy Scanner | Failed | Npcap not installed (required for Layer 2) |
| Nmap | Not Installed | Needs to be downloaded from nmap.org |
| Masscan | Not Installed | Optional, not yet installed |

---

## Discovered Devices

### Device 1: Manan's MacBook Pro

| Field | Value |
|-------|-------|
| **IP Address** | 192.168.0.156 |
| **Hostname** | Manans-MacBook-Pro.local. |
| **Device ID (MAC)** | 0E:22:43:C2:08:A9 |
| **Model** | Mac16,1 |
| **Discovered Via** | Zeroconf/mDNS (passive) |

**Advertised Services:**

| Service | Port | Protocol Version |
|---------|------|-----------------|
| AirPlay | 7000 | 1.1 |

**AirPlay Properties:**
- Source Version: 890.79.5
- Features: 0x4A7FCFD5, 0x38174FDE
- Group ID: 97A50D6F-8130-4363-AE55-66B63BE7D103
- Public Key: b5ff71c8e2cc08560f90b4635c8b76104ab6015ab7a9635191d17afc563ed553

---

## Errors Encountered

### ARP Scanner
```
Sniffing and sending packets is not available at layer 2: winpcap is not installed.
You may use conf.L3socket or conf.L3socket6 to access layer 3
```

### Scapy Scanner
```
Sniffing and sending packets is not available at layer 2: winpcap is not installed.
You may use conf.L3socket or conf.L3socket6 to access layer 3
```

**Root Cause:** Npcap is not installed on this Windows machine. Both scapy and ARP scanning require Npcap for raw packet capture at Layer 2.

---

## Next Steps

1. **Install Npcap** -- https://npcap.com/
   - Check "Install in WinPcap API-compatible mode" during setup
   - This will unlock both the ARP and Scapy scanners

2. **Install Nmap** -- https://nmap.org/download.html
   - The nmap installer can bundle Npcap, potentially fixing both issues at once
   - This is the primary scanning tool the team plans to use

3. **Re-run scanners** after installing the above to get full network visibility

4. **Run as Administrator** -- scapy-based scans require elevated privileges on Windows

---

## Observations

- The Zeroconf scanner worked without any special privileges or extra software, making it the easiest scanner to get running on Windows.
- Even with just passive mDNS listening for 10 seconds, we discovered a MacBook Pro on the network advertising AirPlay.
- The mDNS data includes useful device metadata (model number, device ID, protocol versions) that could be used for vulnerability lookups.
- More devices would likely be discovered with a longer listen duration or with active scanning (nmap/ARP).

---

*Raw scan results saved to: `scanners/scan_results_20260209_162640.json`*
