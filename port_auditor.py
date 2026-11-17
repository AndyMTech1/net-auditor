#!/usr/bin/env python3
import argparse
import ipaddress
import os
import re
import socket
import subprocess
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: ("FTP", "Unencrypted file transfer; consider SFTP instead."),
    22: ("SSH", "Encrypted remote shell; ensure key auth & strong passwords."),
    23: ("Telnet", "HIGH RISK: Unencrypted remote access; disable if unused."),
    25: ("SMTP", "Mail transfer service."),
    53: ("DNS", "Domain Name System resolver."),
    80: ("HTTP", "Unencrypted web interface; prefer HTTPS (443)."),
    110: ("POP3", "Unencrypted email retrieval."),
    139: ("NetBIOS", "Legacy Windows file/printer sharing."),
    143: ("IMAP", "Unencrypted email access."),
    443: ("HTTPS", "Encrypted web interface."),
    445: ("SMB", "File sharing; restrict to trusted local devices only."),
    3306: ("MySQL", "Database service; should not be exposed externally."),
    3389: ("RDP", "Remote Desktop; high target for brute-force attacks."),
    5432: ("PostgreSQL", "Database service; verify access controls."),
    8080: ("HTTP-Proxy", "Alternate web/proxy port.")
}

def load_local_oui_db():
    """Loads Fedora's built-in IEEE OUI hardware database for instant offline lookups."""
    oui_db = {}
    for path in ("/usr/share/hwdata/oui.txt", "/usr/share/ieee-data/oui.txt"):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if "(hex)" in line:
                            raw_prefix, raw_vendor = line.split("(hex)", 1)
                            prefix = raw_prefix.strip().replace("-", ":").upper()
                            oui_db[prefix] = raw_vendor.strip()
                break
            except Exception:
                pass
    return oui_db

OUI_DATABASE = load_local_oui_db()

def identify_vendor(mac):
    """Detects randomized phone MACs or looks up the vendor in Fedora's local OUI database."""
    if not mac or mac == "Local / N/A":
        return "This Device (Localhost)"

    # Extract 2nd hex character safely without bracket indexing
    first_octet = mac.split(":", 1).pop(0).upper()
    if len(first_octet) == 2 and first_octet.endswith(("2", "6", "A", "E")):
        return "Randomized MAC (Likely Phone/Tablet)"

    oui = mac[:8].upper()
    return OUI_DATABASE.get(oui, "Unknown / Private Vendor")

def get_arp_table():
    """Reads the local Linux ARP cache (ip neigh) to map IPs to MAC addresses."""
    arp_map = {}
    try:
        output = subprocess.check_output(["ip", "neigh", "show"], text=True)
        for line in output.splitlines():
            match = re.search(r"^(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-fA-F:]{17})", line)
            if match:
                arp_map[match.group(1)] = match.group(2).upper()
    except Exception:
        pass
    return arp_map

def ping_host(ip_str):
    """Pings a single IP once with a 1-second timeout."""
    res = subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip_str],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if res.returncode == 0:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_str)
        except Exception:
            hostname = "No Reverse DNS"
        return (ip_str, hostname)
    return None

def scan_port(ip, port):
    """Tests if a single TCP port is open and grabs any initial banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.8)
            result = s.connect_ex((ip, port))
            if result == 0:
                service, note = COMMON_PORTS.get(port, ("Unknown", "Unrecognized service."))
                banner = ""
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    raw_lines = s.recv(1024).decode(errors="ignore").splitlines()
                    if raw_lines:
                        banner = raw_lines.pop(0).strip()
                except Exception:
                    pass
                return (port, service, banner, note)
    except Exception:
        pass
    return None

def audit_ports(target):
    """Scans common ports on a single target IP or hostname."""
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        sys.exit(1)

    lines = [
        "-" * 75,
        f"Port Audit  : {target_ip} ({target})",
        f"Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "-" * 75
    ]

    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(scan_port, target_ip, port) for port in COMMON_PORTS]
        for future in futures:
            res = future.result()
            if res:
                open_ports.append(res)

    if open_ports:
        for port, service, banner, note in sorted(open_ports):
            lines.append(f"[+] Port {port:<5} ({service:<10}) OPEN")
            if banner:
                lines.append(f"    Banner : {banner[:60]}")
            lines.append(f"    Audit  : {note}")
    else:
        lines.append("[-] No common ports found open.")

    lines.append("-" * 75)
    lines.append(f"Audit complete. Total open ports: {len(open_ports)}")
    return "\n".join(lines), target_ip

def sweep_subnet(cidr, run_audit=False):
    """Sweeps an entire subnet and identifies each device via Ping, ARP, and offline OUI lookup."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print(f"[!] Invalid network range: {cidr} (Example: 192.168.12.0/24)")
        sys.exit(1)

    hosts = [str(ip) for ip in network.hosts()]
    lines = [
        "=" * 75,
        f"Subnet Sweep : {network}",
        f"Scan Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Scanning {len(hosts)} host IPs (ICMP Ping + ARP Cache + Offline OUI DB)...",
        "=" * 75
    ]

    discovered = {}
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(ping_host, ip) for ip in hosts]
        for future in futures:
            res = future.result()
            if res:
                found_ip, found_host = res
                discovered[found_ip] = found_host

    arp_table = get_arp_table()
    for ip_str, mac in arp_table.items():
        if ipaddress.ip_address(ip_str) in network and ip_str not in discovered:
            discovered[ip_str] = "Silent Host (ARP Only)"

    sorted_ips = sorted(discovered.keys(), key=lambda ip: ipaddress.ip_address(ip))

    if sorted_ips:
        for ip in sorted_ips:
            mac = arp_table.get(ip, "Local / N/A")
            vendor = identify_vendor(mac)
            hostname = discovered[ip]
            lines.append(f"[+] {ip:<15} | MAC: {mac:<17} | {vendor}")
            lines.append(f"    Host Info: {hostname}")
    else:
        lines.append("[-] No active devices found on this subnet.")

    lines.append("=" * 75)
    lines.append(f"Sweep complete. Total active devices found: {len(sorted_ips)}")

    if run_audit and sorted_ips:
        lines.append("\n[*] Running automated port audit on all discovered hosts...\n")
        for ip in sorted_ips:
            audit_report, _ = audit_ports(ip)
            lines.append(audit_report)

    return "\n".join(lines), str(network.network_address)

def main():
    parser = argparse.ArgumentParser(description="Local Network Scanner & Port Auditor")
    parser.add_argument("target", help="Target IP (e.g., 192.168.12.1) OR subnet with --sweep (e.g., 192.168.12.0/24)")
    parser.add_argument("--sweep", action="store_true", help="Discover all active devices on a local subnet")
    parser.add_argument("--audit", action="store_true", help="When used with --sweep, automatically port-scan every live device")
    parser.add_argument("--save", action="store_true", help="Save report to a timestamped .txt file")
    args = parser.parse_args()

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    if args.sweep:
        report, label = sweep_subnet(args.target, run_audit=args.audit)
        prefix = "full_audit" if args.audit else "sweep"
    else:
        report, label = audit_ports(args.target)
        prefix = "audit"

    print(report)

    if args.save:
        filename = f"{prefix}_{label}_{timestamp}.txt"
        with open(filename, "w") as f:
            f.write(report + "\n")
        print(f"\n[*] Report saved to: {filename}")

if __name__ == "__main__":
    main()
