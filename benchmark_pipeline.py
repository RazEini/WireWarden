"""Where does per-packet time go? Single-thread cost breakdown of the live pipeline.

Measures, per packet, on synthetic HTTP-over-TCP frames:
  1. Scapy dissection of raw bytes into layers (done by the sniffer thread before analysis)
  2. analyze_packet(): every detector plus DPI, on an already-parsed packet
  3. inside (2): both DPI engines, the C signature scan alone, the Aho-Corasick scan alone

The result decides what is worth optimizing: if dissection dominates, a faster DPI
engine cannot move end-to-end throughput.
"""
import argparse
import gc
import logging
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.resolve()))
from scapy.all import IP, TCP, Ether, Raw  # noqa: E402

from main import NetworkGuardian  # noqa: E402


class NullFirewall:
    def block(self, *a, **k): pass
    def unblock(self, *a, **k): pass
    def unblock_all(self): pass


def http_request(i: int) -> bytes:
    return (b"GET /api/v1/items?id=%d&token=abc HTTP/1.1\r\nHost: example.com\r\n"
            b"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n" % i)


def best_us_per_packet(fn, n: int, reps: int = 3) -> float:
    best = float("inf")
    for _ in range(reps):
        gc.collect()
        gc.disable()
        try:
            t0 = time.perf_counter()
            fn()
            best = min(best, time.perf_counter() - t0)
        finally:
            gc.enable()
    return best / n * 1e6


def main():
    ap = argparse.ArgumentParser(description="Per-packet cost breakdown")
    ap.add_argument("--packets", type=int, default=5000)
    n = ap.parse_args().packets

    guardian = NetworkGuardian(local_ips={"192.168.1.50"}, log_dir=tempfile.mkdtemp(), firewall=NullFirewall())
    guardian.logger.setLevel(logging.CRITICAL)

    raws = [bytes(Ether() / IP(src="203.0.113.%d" % (i % 200 + 1), dst="192.168.1.50")
                  / TCP(sport=40000 + i % 2000, dport=80, flags="PA") / Raw(http_request(i))) for i in range(n)]
    parsed = [Ether(r) for r in raws]
    payloads = [bytes(p[Raw].load) for p in parsed]

    t_parse = best_us_per_packet(lambda: [Ether(r) for r in raws], n)
    t_analyze = best_us_per_packet(lambda: [guardian.analyze_packet(p) for p in parsed], n)
    t_dpi = best_us_per_packet(lambda: [guardian._check_dpi(pl, "203.0.113.9", None) for pl in payloads], n)
    t_c = best_us_per_packet(lambda: [guardian.native.scan(pl) for pl in payloads], n)
    t_ac = best_us_per_packet(lambda: [guardian.keywords.scan(pl) for pl in payloads], n)

    print(f"{n:,} packets, ~{len(payloads[0])}-byte payload, single thread, best of 3\n")
    print(f"{'step':60s} {'us/packet':>10} {'packets/s':>11}")
    rows = [("Scapy dissects raw bytes into layers", t_parse),
            ("analyze_packet: all detectors + DPI (already parsed)", t_analyze),
            ("   of which both DPI engines + URL decode + flow tail", t_dpi),
            ("   of which the C signature scan alone", t_c),
            ("   of which the Aho-Corasick keyword scan alone", t_ac)]
    for name, t in rows:
        print(f"{name:60s} {t:>10.1f} {1e6 / t:>11,.0f}")

    total = t_parse + t_analyze
    print(f"\nEnd-to-end estimate (dissect + analyze): {total:.1f} us/packet = ~{1e6 / total:,.0f} packets/s per thread")
    print(f"Share of per-packet time:  Scapy dissection {t_parse / total * 100:.1f}%  |  "
          f"all DPI {t_dpi / total * 100:.1f}%  |  C signature scan {t_c / total * 100:.2f}%")


if __name__ == "__main__":
    main()
