"""WireWarden - hybrid Python/C network intrusion detection & prevention engine."""
import argparse
import ctypes
import ipaddress
import json
import logging
import math
import os
import platform
import subprocess
import sys
import threading
import time
from collections import OrderedDict, defaultdict, deque
from datetime import datetime
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Optional
from urllib.parse import unquote_to_bytes

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, sniff

try:
    import colorama
    colorama.init()
except ImportError:
    pass

try:
    import ahocorasick
    HAS_AHOCORASICK = True
except ImportError:
    HAS_AHOCORASICK = False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"


class ColoredConsoleFormatter(logging.Formatter):
    COLOR_MAP = {
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.RED,
        logging.INFO: Colors.CYAN,
    }

    def format(self, record):
        color = self.COLOR_MAP.get(record.levelno, Colors.RESET)
        return f"{color}{super().format(record)}{Colors.RESET}"


class JsonFileFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.fromtimestamp(record.created).astimezone().isoformat(),
            "level": record.levelname,
            "message": str(record.getMessage()),
            "logger": record.name,
        }
        for field in ("src_ip", "event_type", "details"):
            if hasattr(record, field):
                log_record[field] = str(getattr(record, field))
        return json.dumps(log_record, ensure_ascii=False)


def setup_logger(log_dir: str = "logs") -> logging.Logger:
    logger = logging.getLogger("NetworkGuardian")
    if logger.handlers:  # never stack duplicate handlers on repeated construction
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False
    os.makedirs(log_dir, exist_ok=True)

    ch = logging.StreamHandler()
    ch.setFormatter(ColoredConsoleFormatter("%(asctime)s [%(levelname)s] %(message)s"))
    fh = logging.FileHandler(os.path.join(log_dir, "network_security.json"), encoding="utf-8")
    fh.setFormatter(JsonFileFormatter())

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def calculate_entropy(text: str) -> float:
    """Shannon entropy (bits/char) of a string."""
    if not text:
        return 0.0
    n = len(text)
    freq = defaultdict(int)
    for ch in text:
        freq[ch] += 1
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def discover_local_ips() -> set:
    """Best-effort set of this machine's IPv4 addresses (used for direction + whitelist)."""
    ips = {"127.0.0.1"}
    try:
        from scapy.all import get_if_addr, get_if_list
        for iface in get_if_list():
            try:
                ips.add(get_if_addr(iface))
            except Exception:
                pass
    except Exception:
        pass
    ips.discard("0.0.0.0")
    return ips


def discover_default_gateway() -> Optional[str]:
    try:
        from scapy.all import conf
        gw = conf.route.route("0.0.0.0")[2]
        return gw if gw and gw != "0.0.0.0" else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Firewall (active response)
# ---------------------------------------------------------------------------
class FirewallManager:
    """Adds AND removes OS firewall rules, and reports what actually happened.

    Every rule this class adds is tracked, so expired blocks are removed and
    unblock_all() restores the firewall on shutdown.
    """

    def __init__(self, logger: logging.Logger, dry_run: bool = False, runner=subprocess.run):
        self.logger = logger
        self.dry_run = dry_run
        self._runner = runner
        self._lock = threading.Lock()
        self.rules = set()

    def _commands(self, action: str, ip: str):
        system = platform.system().lower()
        if system == "linux":
            if action == "block":
                return [["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]], \
                       ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
            return None, ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        if system == "windows":
            name = f"name=WireWarden_Block_{ip}"
            if action == "block":
                return None, ["netsh", "advfirewall", "firewall", "add", "rule", name,
                              "dir=in", "action=block", f"remoteip={ip}"]
            return None, ["netsh", "advfirewall", "firewall", "delete", "rule", name]
        return None, None

    def _run(self, cmd) -> tuple:
        try:
            res = self._runner(cmd, capture_output=True, text=True, timeout=10)
            return res.returncode == 0, (res.stderr or "").strip()
        except FileNotFoundError:
            return False, f"{cmd[0]} not found"
        except PermissionError:
            return False, "permission denied (run as root/Administrator)"
        except Exception as e:  # timeout etc.
            return False, str(e)

    def _block_now(self, ip: str) -> bool:
        if self.dry_run:
            self.logger.warning(f"[FIREWALL][DRY-RUN] would block {ip}",
                                extra={"src_ip": ip, "event_type": "FIREWALL_DRY_RUN", "details": "block"})
            return False
        check, add = self._commands("block", ip)
        if add is None:
            self.logger.error(f"[FIREWALL] unsupported OS '{platform.system()}', cannot block {ip}")
            return False
        if check and self._run(check[0])[0]:  # rule already present
            with self._lock:
                self.rules.add(ip)
            return True
        ok, err = self._run(add)
        if ok:
            with self._lock:
                self.rules.add(ip)
            self.logger.warning(f"[FIREWALL] rule applied: {ip} blocked",
                                extra={"src_ip": ip, "event_type": "FIREWALL_BLOCK", "details": "applied"})
        else:
            self.logger.error(f"[FIREWALL] FAILED to block {ip}: {err}",
                              extra={"src_ip": ip, "event_type": "FIREWALL_ERROR", "details": err})
        return ok

    def block(self, ip: str, blocking: bool = False):
        if blocking:
            return self._block_now(ip)
        threading.Thread(target=self._block_now, args=(ip,), daemon=True, name="FirewallBlock").start()

    def unblock(self, ip: str) -> bool:
        with self._lock:
            if ip not in self.rules:
                return False
            self.rules.discard(ip)
        _, delete = self._commands("unblock", ip)
        if delete is None:
            return False
        ok, err = self._run(delete)
        level = logging.WARNING if ok else logging.ERROR
        self.logger.log(level, f"[FIREWALL] rule {'removed' if ok else 'removal FAILED'} for {ip}" + ("" if ok else f": {err}"),
                        extra={"src_ip": ip, "event_type": "FIREWALL_UNBLOCK", "details": "removed" if ok else err})
        return ok

    def unblock_all(self):
        with self._lock:
            pending = list(self.rules)
        for ip in pending:
            self.unblock(ip)


# ---------------------------------------------------------------------------
# DPI engines
# ---------------------------------------------------------------------------
def _looks_like_plaintext(payload: bytes, sample_size: int = 32, min_printable_ratio: float = 0.85) -> bool:
    """Cheap filter: substring DPI on encrypted/binary bytes wastes CPU and
    risks chance matches. Decided by content, NOT by port, so plaintext
    attacks on 443/8443/etc. are still inspected."""
    if not payload:
        return False
    sample = payload[:sample_size]
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(sample)) >= min_printable_ratio


def _get_lib_filename() -> str:
    if sys.platform == "win32":
        return "libdpi.dll"
    if sys.platform == "darwin":
        return "libdpi.dylib"
    return "libdpi.so"


class NativeSignatureEngine:
    """ctypes wrapper around libdpi. Signature names come from the C library itself."""

    def __init__(self, logger: logging.Logger, lib_path: Optional[Path] = None):
        self.available = False
        self.names = []
        self.max_len = 0
        lib_path = lib_path or Path(__file__).parent.resolve() / _get_lib_filename()

        if not lib_path.exists():
            logger.info(f"[+] Note: '{lib_path.name}' not found. Native C DPI disabled "
                        f"(run 'make -C c_src'). Keyword DPI only.")
            return
        try:
            lib = ctypes.CDLL(str(lib_path))
            lib.inspect_payload_index.argtypes = [ctypes.c_char_p, ctypes.c_int]
            lib.inspect_payload_index.restype = ctypes.c_int
            lib.signature_count.restype = ctypes.c_int
            lib.signature_name.argtypes = [ctypes.c_int]
            lib.signature_name.restype = ctypes.c_char_p
            lib.max_signature_len.restype = ctypes.c_int
            self._lib = lib
            self.names = [lib.signature_name(i).decode() for i in range(lib.signature_count())]
            self.max_len = lib.max_signature_len()
            self.available = True
            logger.info(f"[+] Native C DPI engine loaded ({len(self.names)} signatures).")
        except (OSError, AttributeError) as e:
            logger.warning(f"[!] Failed to load native C DPI engine: {e}. Rebuild with 'make -C c_src'.")

    def scan(self, data: bytes) -> Optional[str]:
        if not self.available or not data:
            return None
        idx = self._lib.inspect_payload_index(data, len(data))
        return self.names[idx] if 0 <= idx < len(self.names) else None


class KeywordEngine:
    """Aho-Corasick multi-pattern scan (pure-Python fallback if pyahocorasick is missing).

    Patterns target cleartext *credential/query leaks*, not generic words: a
    page that merely contains the word "password" must not alert.
    """
    DEFAULT_KEYWORDS = [b"password=", b"passwd=", b"pwd=", b"authorization: basic",
                        b"api_key=", b"apikey=", b"select * from"]

    def __init__(self, keywords=None):
        self.keywords = [k.lower() for k in (keywords or self.DEFAULT_KEYWORDS)]
        self.max_len = max(len(k) for k in self.keywords)
        self.automaton = None
        if HAS_AHOCORASICK:
            self.automaton = ahocorasick.Automaton()
            for kw in self.keywords:
                text = kw.decode("latin-1")
                self.automaton.add_word(text, text)
            self.automaton.make_automaton()

    def scan(self, data: bytes, min_end: int = 0) -> set:
        """Keywords found whose match ends at or after byte `min_end`
        (lets callers ignore matches already reported from a previous segment)."""
        lowered = data.lower()  # ASCII-only lowering, byte positions preserved
        hits = set()
        if self.automaton is not None:
            for end_index, kw in self.automaton.iter(lowered.decode("latin-1")):
                if end_index + 1 > min_end:
                    hits.add(kw)
        else:
            for kw in self.keywords:
                pos = lowered.rfind(kw)
                if pos != -1 and pos + len(kw) > min_end:
                    hits.add(kw.decode("latin-1"))
        return hits


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------
class NetworkGuardian:
    MAX_TRACKED_FLOWS = 10_000
    FLOW_TTL_SEC = 30
    DNS_ENTROPY_THRESHOLD = 4.3
    DNS_MAX_LABEL_LEN = 45

    def __init__(self, dos_threshold=500, scan_threshold=50, time_window_sec=10,
                 cleanup_interval_sec=30, block_duration_sec=300, queue_size=20000,
                 whitelist=(), local_ips=None, dry_run=False, log_dir="logs", firewall=None,
                 include_outbound=False):
        self.logger = setup_logger(log_dir)
        self.packet_queue = Queue(maxsize=queue_size)
        self.stop_event = threading.Event()
        self.lock = threading.Lock()

        self.DOS_THRESHOLD = dos_threshold
        self.SCAN_THRESHOLD = scan_threshold
        self.TIME_WINDOW = float(time_window_sec)
        self.CLEANUP_INTERVAL = cleanup_interval_sec
        self.BLOCK_DURATION = block_duration_sec

        # State guarded by self.lock. Timestamps use time.monotonic() so a
        # wall-clock change (NTP, DST, manual) cannot corrupt the windows.
        self.blacklist = {}  # {ip: unblock_monotonic_time}
        self.syn_history = defaultdict(lambda: deque(maxlen=1000))
        self.port_history = defaultdict(lambda: deque(maxlen=1000))

        # Per-flow tail so a signature split across two TCP segments is still seen.
        self._flow_tails = OrderedDict()
        self._tail_lock = threading.Lock()

        # Observability of the engine itself
        self.captured = 0
        self.dropped = 0
        self.alerts = deque(maxlen=1000)

        # Direction + whitelist. Without a known local address we cannot tell
        # inbound from outbound, so every packet is treated as inbound.
        # include_outbound=True is a LAB mode: DoS/port-scan windows also count packets this
        # host sends (e.g. aiming test_attack.py at your router). Off by default so normal
        # outbound traffic and replies can never look like an attack.
        self.include_outbound = include_outbound
        self.local_ips = set(local_ips) if local_ips is not None else discover_local_ips()
        nets = [ipaddress.ip_network("127.0.0.0/8")]
        nets += [ipaddress.ip_network(ip, strict=False) for ip in self.local_ips]
        gw = discover_default_gateway() if local_ips is None else None
        if gw:
            nets.append(ipaddress.ip_network(gw))
        nets += [ipaddress.ip_network(w, strict=False) for w in whitelist]
        self.whitelist_nets = nets

        self.firewall = firewall or FirewallManager(self.logger, dry_run=dry_run)
        self.keywords = KeywordEngine()
        self.native = NativeSignatureEngine(self.logger)
        self._tail_len = max(self.keywords.max_len, self.native.max_len) - 1

        if HAS_AHOCORASICK:
            self.logger.info("[+] Aho-Corasick keyword engine initialized.")
        else:
            self.logger.info("[+] Note: 'pyahocorasick' not found; using substring fallback.")

    # -- helpers -----------------------------------------------------------
    def _alert(self, level, event_type, src_ip, message, details):
        self.alerts.append({"event_type": event_type, "src_ip": src_ip, "details": details})
        self.logger.log(level, message, extra={"src_ip": src_ip, "event_type": event_type, "details": details})

    def _is_whitelisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.whitelist_nets)

    def _is_inbound(self, dst_ip: str) -> bool:
        return self.include_outbound or not self.local_ips or dst_ip in self.local_ips

    def _is_blacklisted(self, src_ip, now) -> bool:
        # Lock-free read (single dict.get). Expired entries are removed by the cleanup thread.
        exp = self.blacklist.get(src_ip)
        return exp is not None and now < exp

    def _clean_old_records(self, history_deque, now):
        while history_deque and (now - history_deque[0][0]) > self.TIME_WINDOW:
            history_deque.popleft()

    # -- capture side ------------------------------------------------------
    def _enqueue_packet(self, pkt):
        if not pkt.haslayer(IP):
            return
        self.captured += 1
        if self._is_blacklisted(pkt[IP].src, time.monotonic()):
            return
        try:
            self.packet_queue.put_nowait(pkt)
        except Full:
            self.dropped += 1  # backpressure: drop, but count it

    # -- housekeeping ------------------------------------------------------
    def _cleanup_once(self, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            for table in (self.syn_history, self.port_history):
                for ip in list(table.keys()):
                    self._clean_old_records(table[ip], now)
                    if not table[ip]:
                        del table[ip]
            expired = [ip for ip, exp in self.blacklist.items() if now >= exp]
            for ip in expired:
                del self.blacklist[ip]

        for ip in expired:  # outside the lock: firewall calls are slow
            self.firewall.unblock(ip)

        with self._tail_lock:
            stale = [f for f, (ts, _) in self._flow_tails.items() if now - ts > self.FLOW_TTL_SEC]
            for f in stale:
                del self._flow_tails[f]

        if self.dropped:
            self.logger.warning(
                f"[STATS] captured={self.captured} dropped={self.dropped} queue={self.packet_queue.qsize()}",
                extra={"event_type": "ENGINE_STATS", "details": f"dropped={self.dropped}"})

    def _cleanup_worker(self):
        while not self.stop_event.wait(self.CLEANUP_INTERVAL):
            self._cleanup_once()

    # -- DPI ---------------------------------------------------------------
    def _check_dpi(self, payload: bytes, src_ip: str, flow=None, now=None):
        now = time.monotonic() if now is None else now
        data = unquote_to_bytes(payload) if b"%" in payload else payload  # defeat %2e%2e%2f-style encoding

        tail = b""
        if flow is not None:
            with self._tail_lock:
                entry = self._flow_tails.get(flow)
                if entry:
                    tail = entry[1]

        combined = tail + data
        keyword_hits = self.keywords.scan(combined, min_end=len(tail))

        native_hit = self.native.scan(data)
        if native_hit is None and tail and self.native.available:
            # Only the segment boundary can hold a match we haven't seen yet.
            native_hit = self.native.scan(tail + data[: self.native.max_len - 1])

        for kw in sorted(keyword_hits):
            self._alert(logging.WARNING, "DPI_ALERT", src_ip,
                        f"[SECURITY DPI] Cleartext keyword '{kw}' from {src_ip}", f"Keyword match: {kw}")
        if native_hit:
            self._alert(logging.WARNING, "DPI_ALERT_NATIVE", src_ip,
                        f"[SECURITY DPI-C] Signature match '{native_hit}' from {src_ip}",
                        f"Native C signature match: {native_hit}")

        if flow is not None and self._tail_len > 0:
            new_tail = b"" if (keyword_hits or native_hit) else combined[-self._tail_len:]
            with self._tail_lock:
                self._flow_tails[flow] = (now, new_tail)
                self._flow_tails.move_to_end(flow)
                while len(self._flow_tails) > self.MAX_TRACKED_FLOWS:
                    self._flow_tails.popitem(last=False)

    # -- analysis ----------------------------------------------------------
    def analyze_packet(self, pkt, now=None):
        now = time.monotonic() if now is None else now
        ip = pkt[IP]
        src_ip, dst_ip = ip.src, ip.dst

        if self._is_blacklisted(src_ip, now):
            return
        inbound = self._is_inbound(dst_ip)

        # 1. DNS tunneling - QUERIES only (qr == 0). Responses echo the question
        #    section, which would misattribute the alert to the resolver.
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            try:
                query = pkt[DNSQR].qname.decode("ascii", errors="ignore").strip(".")
                if query and not query.endswith(".local"):
                    subdomain = query.split(".")[0]
                    entropy = calculate_entropy(subdomain)
                    if len(subdomain) > self.DNS_MAX_LABEL_LEN or entropy > self.DNS_ENTROPY_THRESHOLD:
                        self._alert(logging.WARNING, "DNS_TUNNELING", src_ip,
                                    f"[DNS TUNNELING SUSPECT] Host {src_ip} query len={len(query)} entropy={entropy:.2f}: {query}",
                                    f"Len: {len(query)}, Entropy: {entropy:.2f}")
                    else:
                        self.logger.info(f"[DNS] Device {src_ip} query: {query}",
                                         extra={"src_ip": src_ip, "event_type": "DNS_QUERY", "details": query})
            except Exception as e:
                self.logger.debug(f"[DNS] Parsing error: {e}")

        dst_port = None
        proto = None
        is_pure_syn = False  # SYN without ACK = a connection attempt (SYN-ACK is a reply, not an attack)
        is_probe = False     # packet that looks like a port probe
        flow = None

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            dst_port, proto = tcp.dport, "tcp"
            flags = int(tcp.flags)
            fin, syn, rst = bool(flags & 0x01), bool(flags & 0x02), bool(flags & 0x04)
            psh, ack, urg = bool(flags & 0x08), bool(flags & 0x10), bool(flags & 0x20)
            is_pure_syn = syn and not ack
            flow = (src_ip, tcp.sport, dst_ip, tcp.dport)

            stealth_type = None
            if (flags & 0x3F) == 0:
                stealth_type = "NULL Scan"
            elif fin and not (syn or rst or psh or ack or urg):
                stealth_type = "FIN Scan"
            elif fin and psh and urg and not (syn or rst or ack):
                stealth_type = "XMAS Scan"

            if stealth_type:
                self._alert(logging.WARNING, "STEALTH_SCAN", src_ip,
                            f"[STEALTH SCAN DETECTED] {stealth_type} from {src_ip} to port {dst_port}",
                            f"{stealth_type} on port {dst_port}")
            is_probe = is_pure_syn or bool(stealth_type)

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            dst_port, proto = udp.dport, "udp"
            is_probe = True
            flow = (src_ip, udp.sport, dst_ip, udp.dport)

        # 2. DoS and port-scan windows - INBOUND traffic only. Our own outbound
        #    connections and replies must never count as an attack.
        block_ip = None
        if inbound:
            with self.lock:
                if is_pure_syn:
                    syn_deque = self.syn_history[src_ip]
                    self._clean_old_records(syn_deque, now)
                    syn_deque.append((now, None))
                    if len(syn_deque) > self.DOS_THRESHOLD:
                        syn_deque.clear()
                        if self._is_whitelisted(src_ip):
                            self._alert(logging.WARNING, "DOS_ATTACK_WHITELISTED", src_ip,
                                        f"[DoS THRESHOLD] {src_ip} exceeded SYN threshold but is whitelisted - NOT blocked",
                                        "SYN threshold exceeded (whitelisted)")
                        else:
                            self.blacklist[src_ip] = now + self.BLOCK_DURATION
                            block_ip = src_ip

                if is_probe and dst_port is not None:
                    ports_deque = self.port_history[src_ip]
                    self._clean_old_records(ports_deque, now)
                    ports_deque.append((now, (proto, dst_port)))
                    if len(ports_deque) > self.SCAN_THRESHOLD:  # unique <= len, so skip the set build otherwise
                        unique = {p for _, p in ports_deque}
                        if len(unique) > self.SCAN_THRESHOLD:
                            self._alert(logging.WARNING, "PORT_SCAN", src_ip,
                                        f"[PORT SCAN DETECTED] Host {src_ip} probed {len(unique)} unique ports",
                                        f"{len(unique)} ports scanned")
                            ports_deque.clear()

            if block_ip:
                self._alert(logging.CRITICAL, "DOS_ATTACK", block_ip,
                            f"[DoS DETECTED] Isolating IP: {block_ip} for {self.BLOCK_DURATION}s",
                            "SYN Flood threshold exceeded")
                self.firewall.block(block_ip)

        # 3. DPI - decided by payload content, not by port.
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if _looks_like_plaintext(payload):
                self._check_dpi(payload, src_ip, flow, now)

    # -- threads -----------------------------------------------------------
    def packet_worker(self):
        while not self.stop_event.is_set():
            try:
                packet = self.packet_queue.get(timeout=0.5)
            except Empty:
                continue
            try:
                self.analyze_packet(packet)
            except Exception as e:
                self.logger.error(f"[WORKER ERROR] {e}")
            finally:
                self.packet_queue.task_done()

    def start(self, num_workers=4, iface=None):
        self.logger.info("WireWarden engine starting...")
        workers = [threading.Thread(target=self.packet_worker, daemon=True, name=f"Worker-{i}")
                   for i in range(num_workers)]
        cleanup = threading.Thread(target=self._cleanup_worker, daemon=True, name="CleanupGC")
        for t in workers + [cleanup]:
            t.start()

        self.logger.info(f"[*] Engine active: {num_workers} workers, local IPs={sorted(self.local_ips)}")
        try:
            sniff(prn=self._enqueue_packet, store=0, filter="ip", iface=iface,
                  stop_filter=lambda _: self.stop_event.is_set())
        except KeyboardInterrupt:
            self.logger.info("Shutting down engine...")
        finally:
            self.stop_event.set()
            for t in workers + [cleanup]:
                t.join(timeout=2)
            self.firewall.unblock_all()  # leave the host firewall as we found it
            self.logger.info(f"[STATS] captured={self.captured} dropped={self.dropped}")


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="WireWarden NIDS/NIPS")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--iface", default=None, help="interface to sniff (default: scapy default)")
    p.add_argument("--whitelist", default="", help="comma-separated IPs/CIDRs that must never be blocked")
    p.add_argument("--dry-run", action="store_true", help="detect and log, but never touch the firewall")
    p.add_argument("--include-outbound", action="store_true",
                   help="LAB MODE: also count traffic this host sends (use when test_attack.py targets another device, e.g. your router)")
    p.add_argument("--dos-threshold", type=int, default=500)
    p.add_argument("--scan-threshold", type=int, default=50)
    p.add_argument("--block-seconds", type=int, default=300)
    return p.parse_args(argv)


if __name__ == "__main__":
    args = parse_args()
    guardian = NetworkGuardian(
        dos_threshold=args.dos_threshold, scan_threshold=args.scan_threshold,
        block_duration_sec=args.block_seconds,
        whitelist=[w.strip() for w in args.whitelist.split(",") if w.strip()],
        dry_run=args.dry_run, include_outbound=args.include_outbound)
    guardian.start(num_workers=args.workers, iface=args.iface)