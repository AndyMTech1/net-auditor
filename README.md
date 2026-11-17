# Local Network Scanner & Port Auditor (`port_auditor.py`)

A lightweight, zero-dependency Python CLI tool for local subnet discovery, hardware vendor fingerprinting, and multithreaded TCP port auditing on Linux.

## Features
- **Fast Subnet Sweep (`--sweep`)**: Scans all 254 hosts in a `/24` subnet in parallel using ICMP ping and local ARP cache inspection (`ip neigh`).
- **Offline Hardware Vendor Lookup**: Queries the local IEEE OUI database (`/usr/share/hwdata/oui.txt`) and detects randomized MAC addresses used by mobile devices.
- **Multithreaded Port Auditor**: Scans common TCP ports concurrently, grabs service banners, and flags basic security recommendations.
- **Full Combo Mode (`--sweep --audit`)**: Automatically discovers live devices on a network and runs a port audit on each active host.
- **Report Logging (`--save`)**: Exports timestamped audit reports to `.txt` files (automatically excluded from Git via `.gitignore`).

## Installation & Setup
No external `pip` libraries are required—it runs natively using Python 3's standard library on Linux.

```bash
# 1. Clone the repository
git clone https://github.com<your-username>/net-auditor.git
cd net-auditor

# 2. Make the script executable
chmod +x port_auditor.py
```

## Step-by-Step Usage
1. **Audit open ports on a single device (e.g., your local router):**
   ```bash
   python3 port_auditor.py 192.168.1.1
   ```
2. **Discover all active devices on your local subnet:**
   ```bash
   python3 port_auditor.py 192.168.1.0/24 --sweep
   ```
3. **Run a full subnet sweep + port audit and save a timestamped report:**
   ```bash
   python3 port_auditor.py 192.168.1.0/24 --sweep --audit --save
   ```

## Example Output
```text
===========================================================================
Subnet Sweep : 192.168.1.0/24
Scanning 254 host IPs (ICMP Ping + ARP Cache + Offline OUI DB)...
===========================================================================
[+] 192.168.1.1     | MAC: 00:11:22:33:44:55 | Router Vendor Corp
    Host Info: _gateway
[+] 192.168.1.42    | MAC: AA:BB:CC:DD:EE:FF | Apple, Inc.
    Host Info: Silent Host (ARP Only)
===========================================================================
Sweep complete. Total active devices found: 2
```

## Disclaimer
Built for educational purposes and authorized home-lab network auditing only. Always ensure you have permission before scanning any network or device.
