import logging

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Raw

from conftest import GATEWAY, LOCAL, FakeRunner, types
from main import FirewallManager, NetworkGuardian, calculate_entropy

REMOTE = "203.0.113.7"
HIGH_ENTROPY = "a8f9x2z1q9m4k7v0p3w8x1z9c2v4b6n8m0q2w4e6r8t0y2.evil.example"


def inbound(flags="S", dport=80, src=REMOTE, sport=40000, payload=None):
    pkt = IP(src=src, dst=LOCAL) / TCP(sport=sport, dport=dport, flags=flags)
    return pkt / Raw(load=payload) if payload else pkt


# ---- DoS ------------------------------------------------------------------
def test_syn_flood_is_detected_and_blocked_once(guardian, fw):
    for i in range(guardian.DOS_THRESHOLD + 50):
        guardian.analyze_packet(inbound("S", sport=1000 + i))
    assert types(guardian).count("DOS_ATTACK") == 1
    assert fw.blocked == [REMOTE]
    assert REMOTE in guardian.blacklist


def test_syn_ack_replies_are_not_a_flood(guardian, fw):
    """Regression: SYN-ACK has the SYN bit set but is a legitimate reply."""
    for i in range(guardian.DOS_THRESHOLD * 2):
        guardian.analyze_packet(inbound("SA", sport=443, dport=40000 + i % 500))
    assert "DOS_ATTACK" not in types(guardian)
    assert fw.blocked == []


def test_outbound_traffic_is_never_counted(guardian, fw):
    for i in range(guardian.DOS_THRESHOLD * 2):
        guardian.analyze_packet(IP(src=LOCAL, dst=REMOTE) / TCP(sport=1000 + i, dport=80, flags="S"))
    assert types(guardian) == []
    assert fw.blocked == []


def test_whitelisted_source_is_alerted_but_never_blocked(guardian, fw):
    for i in range(guardian.DOS_THRESHOLD + 5):
        guardian.analyze_packet(inbound("S", src=GATEWAY, sport=1000 + i))
    assert "DOS_ATTACK_WHITELISTED" in types(guardian)
    assert "DOS_ATTACK" not in types(guardian)
    assert fw.blocked == []


def test_block_expires_and_firewall_rule_is_removed(guardian, fw):
    for i in range(guardian.DOS_THRESHOLD + 5):
        guardian.analyze_packet(inbound("S", sport=1000 + i), now=100.0)
    assert REMOTE in guardian.blacklist
    guardian._cleanup_once(now=100.0 + guardian.BLOCK_DURATION - 1)
    assert fw.unblocked == []
    guardian._cleanup_once(now=100.0 + guardian.BLOCK_DURATION + 1)
    assert fw.unblocked == [REMOTE]
    assert REMOTE not in guardian.blacklist


# ---- Port scans -----------------------------------------------------------
def test_port_scan_detected_on_inbound_syn_probes(guardian):
    for port in range(1000, 1060):
        guardian.analyze_packet(inbound("S", dport=port))
    assert "PORT_SCAN" in types(guardian)


def test_established_traffic_to_many_ports_is_not_a_scan(guardian):
    for port in range(1000, 1100):
        guardian.analyze_packet(inbound("A", dport=port))
    assert "PORT_SCAN" not in types(guardian)


def test_server_replying_to_many_clients_is_not_a_scan(guardian):
    for port in range(50000, 50100):
        guardian.analyze_packet(IP(src=LOCAL, dst=REMOTE) / TCP(sport=443, dport=port, flags="A"))
    assert types(guardian) == []


def test_tcp_and_udp_ports_are_counted_separately(guardian):
    for port in range(1000, 1030):
        guardian.analyze_packet(inbound("S", dport=port))
        guardian.analyze_packet(IP(src=REMOTE, dst=LOCAL) / UDP(sport=5000, dport=port))
    # 30 tcp + 30 udp = 60 distinct (proto, port) pairs
    assert "PORT_SCAN" in types(guardian)


# ---- Stealth scans --------------------------------------------------------
def test_stealth_scans(guardian):
    for flags, name in [("", "NULL"), ("F", "FIN"), ("FPU", "XMAS")]:
        guardian.analyze_packet(inbound(flags))
        assert any(name in a["details"] for a in guardian.alerts), name


def test_normal_flag_combinations_are_not_stealth(guardian):
    for flags in ["S", "SA", "A", "PA", "FA", "R", "RA"]:
        guardian.analyze_packet(inbound(flags))
    assert "STEALTH_SCAN" not in types(guardian)


# ---- DNS ------------------------------------------------------------------
def dns_query(name):
    return IP(src=LOCAL, dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname=name))


def test_dns_tunneling_query_is_flagged_against_the_asker(guardian):
    guardian.analyze_packet(dns_query(HIGH_ENTROPY))
    hit = [a for a in guardian.alerts if a["event_type"] == "DNS_TUNNELING"]
    assert hit and hit[0]["src_ip"] == LOCAL


def test_dns_response_is_not_attributed_to_the_resolver(guardian):
    resp = (IP(src="8.8.8.8", dst=LOCAL) / UDP(sport=53, dport=5353) /
            DNS(qr=1, qd=DNSQR(qname=HIGH_ENTROPY), an=DNSRR(rrname=HIGH_ENTROPY, rdata="1.2.3.4")))
    guardian.analyze_packet(resp)
    assert "DNS_TUNNELING" not in types(guardian)


def test_normal_dns_and_mdns_are_ignored(guardian):
    guardian.analyze_packet(dns_query("www.google.com"))
    guardian.analyze_packet(dns_query("printer.local"))
    assert "DNS_TUNNELING" not in types(guardian)


def test_entropy_math():
    assert calculate_entropy("") == 0.0
    assert calculate_entropy("aaaa") == 0.0
    assert abs(calculate_entropy("abcd") - 2.0) < 1e-9


# ---- DPI (live path) ------------------------------------------------------
def test_sqli_is_caught_regardless_of_case(guardian):
    for body in [b"id=1' UNION SELECT user,pass", b"id=1' union select user,pass", b"id=1' UnIoN sElEcT user"]:
        guardian.alerts.clear()
        guardian.analyze_packet(inbound("PA", payload=b"GET /p?" + body + b" HTTP/1.1\r\n\r\n"))
        assert "DPI_ALERT_NATIVE" in types(guardian), body


def test_url_encoded_traversal_is_decoded_before_matching(guardian):
    guardian.analyze_packet(inbound("PA", payload=b"GET /%2e%2e/%2e%2e/%65tc/passwd HTTP/1.1\r\n\r\n"))
    assert "DPI_ALERT_NATIVE" in types(guardian)


def test_signature_split_across_two_segments_is_caught(guardian):
    guardian.analyze_packet(inbound("PA", payload=b"GET /search?q=1' UNI"))
    assert "DPI_ALERT_NATIVE" not in types(guardian)
    guardian.analyze_packet(inbound("PA", payload=b"ON SELECT password FROM users HTTP/1.1\r\n"))
    assert types(guardian).count("DPI_ALERT_NATIVE") == 1


def test_split_signature_is_not_matched_across_different_flows(guardian):
    guardian.analyze_packet(inbound("PA", sport=1111, payload=b"GET /search?q=1' UNI"))
    guardian.analyze_packet(inbound("PA", sport=2222, payload=b"ON SELECT password FROM users HTTP/1.1\r\n"))
    assert "DPI_ALERT_NATIVE" not in types(guardian)


def test_a_match_is_reported_once_not_again_on_the_next_segment(guardian):
    guardian.analyze_packet(inbound("PA", payload=b"GET /../../etc/passwd HTTP/1.1\r\n"))
    guardian.analyze_packet(inbound("PA", payload=b"Host: victim.example\r\n\r\n"))
    assert types(guardian).count("DPI_ALERT_NATIVE") == 1


def test_word_password_alone_does_not_alert(guardian):
    guardian.analyze_packet(inbound("PA", payload=b"GET /forgot-password HTTP/1.1\r\nHost: x\r\n\r\n"))
    assert types(guardian) == []


def test_cleartext_credentials_alert_once(guardian):
    guardian.analyze_packet(inbound("PA", payload=b"POST /login HTTP/1.1\r\n\r\nuser=a&Password=hunter2"))
    assert types(guardian).count("DPI_ALERT") == 1


def test_encrypted_looking_payload_is_skipped(guardian):
    tls = bytes([0x17, 0x03, 0x03, 0x00, 0x40]) + bytes(range(128, 200)) + b" UNION SELECT "
    guardian.analyze_packet(inbound("PA", dport=443, payload=tls))
    assert types(guardian) == []


def test_plaintext_attack_on_port_443_is_still_inspected(guardian):
    """Regression: a port allow-list let attackers hide plaintext attacks on 443."""
    guardian.analyze_packet(inbound("PA", dport=443, payload=b"GET /?x=<script>alert(1)</script> HTTP/1.1\r\n\r\n"))
    assert "DPI_ALERT_NATIVE" in types(guardian)


def test_flow_table_is_bounded(guardian):
    guardian.MAX_TRACKED_FLOWS = 50
    for i in range(500):
        guardian.analyze_packet(inbound("PA", sport=10000 + i, payload=b"GET /index.html HTTP/1.1\r\n\r\n"))
    assert len(guardian._flow_tails) <= 50


# ---- Engine health --------------------------------------------------------
def test_queue_overflow_is_counted_not_silent(tmp_path, fw, libdpi):
    g = NetworkGuardian(local_ips={LOCAL}, log_dir=str(tmp_path), firewall=fw, queue_size=5)
    for i in range(20):
        g._enqueue_packet(inbound("S", sport=2000 + i))
    assert g.dropped == 15 and g.captured == 20


def test_blacklisted_source_is_not_enqueued(guardian):
    guardian.blacklist[REMOTE] = 10**12
    guardian._enqueue_packet(inbound("S"))
    assert guardian.packet_queue.qsize() == 0


def test_repeated_construction_does_not_duplicate_log_handlers(tmp_path, fw, libdpi):
    NetworkGuardian(local_ips={LOCAL}, log_dir=str(tmp_path), firewall=fw)
    n = len(logging.getLogger("NetworkGuardian").handlers)
    NetworkGuardian(local_ips={LOCAL}, log_dir=str(tmp_path), firewall=fw)
    assert len(logging.getLogger("NetworkGuardian").handlers) == n


# ---- Firewall manager -----------------------------------------------------
def scripted_runner(exit_codes):
    """Runner that returns the given exit codes in order (then 0) and records commands."""
    codes, calls = iter(exit_codes), []

    def run(cmd, **kwargs):
        calls.append(cmd)
        return type("R", (), {"returncode": next(codes, 0), "stderr": ""})()

    run.calls = calls
    return run


def test_firewall_block_then_unblock_uses_matching_iptables_commands(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    runner = scripted_runner([1, 0])  # -C: rule absent -> -I: added
    fwm = FirewallManager(logging.getLogger("t"), runner=runner)
    assert fwm.block("203.0.113.9", blocking=True) is True
    assert runner.calls[0][:2] == ["iptables", "-C"]
    assert ["iptables", "-I", "INPUT", "1", "-s", "203.0.113.9", "-j", "DROP"] in runner.calls
    assert fwm.unblock("203.0.113.9") is True
    assert ["iptables", "-D", "INPUT", "-s", "203.0.113.9", "-j", "DROP"] in runner.calls
    assert fwm.rules == set()


def test_unblock_all_removes_every_rule_it_added(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    runner = scripted_runner([1, 0, 1, 0])
    fwm = FirewallManager(logging.getLogger("t2"), runner=runner)
    fwm.block("203.0.113.9", blocking=True)
    fwm.block("203.0.113.10", blocking=True)
    fwm.unblock_all()
    deletes = [c for c in runner.calls if "-D" in c]
    assert len(deletes) == 2 and fwm.rules == set()


def test_firewall_failure_is_reported_not_swallowed(monkeypatch, caplog):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    logger = logging.getLogger("fw-fail")
    logger.propagate = True

    def failing(cmd, **kw):
        return type("R", (), {"returncode": 1, "stderr": "Permission denied"})()

    fwm = FirewallManager(logger, runner=failing)
    with caplog.at_level(logging.ERROR):
        assert fwm.block("203.0.113.9", blocking=True) is False
    assert "FAILED" in caplog.text and fwm.rules == set()


def test_dry_run_never_runs_a_command():
    runner = FakeRunner()
    fwm = FirewallManager(logging.getLogger("dry"), dry_run=True, runner=runner)
    fwm.block("203.0.113.9", blocking=True)
    assert runner.calls == []


# ---- Windows (netsh) command construction ---------------------------------
def test_windows_block_and_unblock_use_matching_netsh_commands(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Windows")
    runner = scripted_runner([0, 0])
    fwm = FirewallManager(logging.getLogger("win"), runner=runner)
    ip = "203.0.113.9"

    assert fwm.block(ip, blocking=True) is True
    assert runner.calls[0] == ["netsh", "advfirewall", "firewall", "add", "rule",
                               f"name=WireWarden_Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"]
    assert ip in fwm.rules

    assert fwm.unblock(ip) is True
    assert runner.calls[1] == ["netsh", "advfirewall", "firewall", "delete", "rule",
                               f"name=WireWarden_Block_{ip}"]
    assert fwm.rules == set()


def test_windows_rule_name_matches_between_add_and_delete(monkeypatch):
    """If the delete used a different rule name, blocks would never be lifted."""
    monkeypatch.setattr("platform.system", lambda: "Windows")
    runner = scripted_runner([0, 0])
    fwm = FirewallManager(logging.getLogger("win2"), runner=runner)
    fwm.block("198.51.100.4", blocking=True)
    fwm.unblock("198.51.100.4")
    add_name = next(a for a in runner.calls[0] if a.startswith("name="))
    del_name = next(a for a in runner.calls[1] if a.startswith("name="))
    assert add_name == del_name


def test_windows_failed_add_is_not_recorded_as_applied(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Windows")
    runner = scripted_runner([1])  # netsh returns non-zero (e.g. not elevated)
    fwm = FirewallManager(logging.getLogger("win3"), runner=runner)
    assert fwm.block("203.0.113.9", blocking=True) is False
    assert fwm.rules == set()


def test_unsupported_os_never_pretends_to_block(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Plan9")
    runner = scripted_runner([])
    fwm = FirewallManager(logging.getLogger("other"), runner=runner)
    assert fwm.block("203.0.113.9", blocking=True) is False
    assert runner.calls == [] and fwm.rules == set()