# IoTriage Scanners - Getting Started

## Install Dependencies

```bash
cd scanners
pip install -r requirements.txt
```

## Test Individually

```bash
python nmap_scanner.py 192.168.1.0/24        # Nmap (needs nmap installed)
python scapy_scanner.py 192.168.1.0/24       # Scapy (needs admin)
python arp_scanner.py 192.168.1.0/24         # ARP scan (needs admin)
python zeroconf_scanner.py 15                 # mDNS listen for 15 seconds
python masscan_scanner.py 192.168.1.0/24     # Masscan (needs masscan installed)
```

## Run Everything At Once

```bash
python run_all.py 192.168.1.0/24
```

## Important Notes for Windows

- Run your terminal **as Administrator** for scapy-based scans
- Install **Npcap** (https://npcap.com/) for scapy packet capture
- Install **nmap** (https://nmap.org/download.html) for nmap scanner
- Masscan is optional (install separately if you want speed testing)

## Notes

Each file is heavily documented with explanations of what every function does, why, and the tradeoffs involved.
