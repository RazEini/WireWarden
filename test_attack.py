#!/usr/bin/env python3
"""
WireWarden NIDS - Safe Attack Simulator Script
Simulates various attack patterns (DPI, Port Scanning, Stealth Scans, 
DNS Tunneling, SYN Flood, Port 0) to validate NIDS detection rules 
and observability pipelines safely.
"""

import socket
import sys
import time
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, send


def get_local_ip() -> str:
    """Dynamically detects the active local IPv4 address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# Target IP resolution: CLI Argument > Dynamic LAN IP Discovery > Fallback
TARGET_IP: str = sys.argv[1] if len(sys.argv) > 1 else get_local_ip()


def print_step(title: str) -> None:
    print(f"\n{'='*50}\n[+] {title}\n{'='*50}")


def test_dpi_signatures() -> None:
    """
    Simulates L7 Payload attacks (SQL Injection, Credential Leak, Path Traversal)
    """
    print_step("Testing DPI Engine (Layer 7 Signatures)")

    payloads = [
        ("SQL Injection", "GET /products?id=1' UNION SELECT username, password FROM users-- HTTP/1.1\r\n\r\n"),
        ("Cleartext Credentials", "POST /login HTTP/1.1\r\nHost: test.com\r\n\r\nuser=admin&password=123456&secret=key"),
        ("Path Traversal", "GET /../../../../etc/passwd HTTP/1.1\r\nHost: victim.com\r\n\r\n"),
        ("Command Injection", "POST /api/exec HTTP/1.1\r\n\r\ncmd=cat /etc/shadow; id; whoami"),
    ]

    for name, payload in payloads:
        print(f"  [>] Sending {name} payload...")
        pkt = IP(dst=TARGET_IP) / TCP(dport=80) / Raw(load=payload)
        send(pkt, verbose=False)
        time.sleep(0.2)

    print("[✔] DPI Test Suite Finished!")


def test_port_scan() -> None:
    """
    Simulates a horizontal port scan across 60 distinct ports (TCP SYN)
    """
    print_step("Testing Port Scan Detection (Sliding Window)")
    print("  [>] Scanning ports 1000 to 1060...")

    # Spoofed IP to ensure safe testing without rate-limiting self
    for port in range(1000, 1061):  # 61 unique ports to cross threshold=50
        pkt = IP(src="203.0.113.51", dst=TARGET_IP) / TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.02)

    print("[✔] Port Scan Test Finished!")


def test_stealth_scans() -> None:
    """
    Simulates TCP Stealth Scans (NULL, FIN, XMAS)
    """
    print_step("Testing Stealth Scans (NULL, FIN, XMAS)")

    scans = [
        ("NULL Scan", TCP(dport=80, flags="")),
        ("FIN Scan", TCP(dport=80, flags="F")),
        ("XMAS Scan", TCP(dport=80, flags="FPU")),
    ]

    for name, tcp_layer in scans:
        print(f"  [>] Sending {name} packet...")
        pkt = IP(dst=TARGET_IP) / tcp_layer
        send(pkt, verbose=False)
        time.sleep(0.2)

    print("[✔] Stealth Scans Test Finished!")


def test_dns_tunneling() -> None:
    """
    Simulates DNS Tunneling (High Entropy / Exfiltration Subdomain Query)
    """
    print_step("Testing DNS Tunneling & Entropy Detection")

    suspicious_domain = "a8f9x2z1q9m4k7v0p3w8x1z9c2v4b6n8m0q2w4e6r8t0y2.malicious-exfil-domain.com"
    print(f"  [>] Sending high-entropy DNS query: {suspicious_domain[:35]}...")

    pkt = IP(dst=TARGET_IP) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=suspicious_domain))
    send(pkt, verbose=False)

    print("[✔] DNS Tunneling Test Finished!")


def test_port_zero() -> None:
    """
    Simulates edge-case scan targeting TCP Port 0 (Verifies Port 0 Bug Fix)
    """
    print_step("Testing Port 0 Detection (Edge Case)")
    print("  [>] Sending packet targeting TCP Port 0...")

    pkt = IP(dst=TARGET_IP) / TCP(dport=0, flags="S")
    send(pkt, verbose=False)

    print("[✔] Port 0 Test Finished!")


def test_syn_flood() -> None:
    """
    Simulates a controlled DoS SYN Flood attack (High rate in short time)
    """
    print_step("Testing DoS / SYN Flood Detection")
    print("  [>] Bursting 600 SYN packets to port 80...")

    # Spoofed IP to ensure simulator triggers explicit threat signature
    pkt_template = IP(src="203.0.113.50", dst=TARGET_IP) / TCP(dport=80, flags="S")
    for _ in range(600):
        send(pkt_template, verbose=False)

    print("[✔] SYN Flood Test Finished!")


def main() -> None:
    print("🕵️  WireWarden Attack Simulator Initializing...")
    print(f"🎯 Target IP set to: {TARGET_IP}")
    print("⚠️  Safe mode active: Sending synthetic packets only.\n")

    try:
        test_dpi_signatures()
        time.sleep(1)

        test_port_scan()
        time.sleep(1)

        test_stealth_scans()
        time.sleep(1)

        test_dns_tunneling()
        time.sleep(1)

        test_port_zero()
        time.sleep(1)

        test_syn_flood()

        print("\n" + "=" * 50)
        print("🎉 All test vectors executed successfully!")
        print("📊 Check your Grafana Dashboard and Loki logs for alerts.")
        print("=" * 50)

    except PermissionError:
        print("\n❌ Error: Permission denied!")
        print("👉 Raw Sockets require Administrator / Root privileges.")
        print("   On Windows: Run PowerShell / CMD as Administrator.")
        print("   On Linux: Run with 'sudo python test_attack.py'")
        sys.exit(1)


if __name__ == "__main__":
    main()
