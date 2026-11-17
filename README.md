# Local Network Scanner & Port Auditor (`port_auditor.py`)

A lightweight, zero-dependency Python CLI tool for local subnet discovery, hardware vendor fingerprinting, and multithreaded TCP port auditing on Linux.

## Features
- **Fast Subnet Sweep (`--sweep`)**: Scans all 254 hosts in a `/24` subnet in parallel using ICMP ping and local ARP cache inspection (`ip neigh`).
- **Offline Hardware Vendor Lookup**: Queries the local IEEE OUI database (`/usr/share/hwdata/oui.txt`) and detects randomized MAC addresses used by mobile devices.
- **Multithreaded Port Auditor**: Scans common TCP ports concurrently, grabs service banners, and flags basic security recommendations.
- **Full Combo Mode (`--sweep --audit`)**: Automatically discovers live devices on a network and runs a port audit on each active host.
- **Report Logging (`--save`)**: Exports timestamped audit reports to `.txt` files.

## Usage
```bash
# Audit open ports on a single target IP
python3 port_auditor.py 192.168.1.1

# Sweep a local subnet and identify connected devices
python3 port_auditor.py 192.168.1.0/24 --sweep

# Sweep subnet, audit ports on every live host, and save report
python3 port_auditor.py 192.168.1.0/24 --sweep --audit --save
```

## Disclaimer
Built for educational purposes and authorized home-lab network auditing only. Always ensure you have permission before scanning any network or device.
