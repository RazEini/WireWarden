import ctypes
import math
import json
import logging
import os
import platform
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from queue import Queue, Empty
from scapy.all import sniff, IP, TCP, UDP, Raw, DNSQR

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


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"


class ColoredConsoleFormatter(logging.Formatter):
    COLOR_MAP = {
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.RED,
        logging.INFO: Colors.CYAN
    }

    def format(self, record):
        color = self.COLOR_MAP.get(record.levelno, Colors.RESET)
        message = super().format(record)
        return f"{color}{message}{Colors.RESET}"


class JsonFileFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.fromtimestamp(record.created).astimezone().isoformat(),
            "level": record.levelname,
            "message": str(record.getMessage()),
            "logger": record.name
        }

        if hasattr(record, 'src_ip'):
            log_record['src_ip'] = str(record.src_ip)
        if hasattr(record, 'event_type'):
            log_record['event_type'] = str(record.event_type)
        if hasattr(record, 'details'):
            log_record['details'] = str(record.details)

        return json.dumps(log_record, ensure_ascii=False)


def setup_logger():
    logger = logging.getLogger("NetworkGuardian")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    os.makedirs("logs", exist_ok=True)

    ch = logging.StreamHandler()
    ch.setFormatter(ColoredConsoleFormatter('%(asctime)s [%(levelname)s] %(message)s'))

    fh = logging.FileHandler(os.path.join("logs", "network_security.json"), encoding="utf-8")
    fh.setFormatter(JsonFileFormatter())

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger


def calculate_entropy(text: str) -> float:
    """Calculates Shannon Entropy of a string."""
    if not text:
        return 0.0
    text_len = len(text)
    frequencies = defaultdict(int)
    for char in text:
        frequencies[char] += 1

    entropy = 0.0
    for count in frequencies.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return entropy


def block_ip_firewall_async(ip: str):
    """Executes OS Firewall block in a background thread to avoid blocking worker queue."""
    def _block():
        system = platform.system().lower()
        try:
            if system == "linux":
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif system == "windows":
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=WireWarden_Block_{ip}", "dir=in", "action=block",
                    f"remoteip={ip}"
                ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    threading.Thread(target=_block, daemon=True).start()


# ---------------------------------------------------------------------------
# DPI eligibility filtering
#
# Substring-based DPI (both Aho-Corasick and the native C engine) is only
# meaningful on plaintext payloads. Running it against encrypted traffic
# (TLS, SSH, etc.) wastes CPU and — worse — can produce false positives,
# since high-entropy encrypted bytes can coincidentally match a short
# signature. We filter on two cheap heuristics before calling either engine:
#   1. Skip well-known encrypted/binary ports.
#   2. Skip payloads that don't look like mostly-printable ASCII text.
# ---------------------------------------------------------------------------
COMMON_ENCRYPTED_PORTS = {443, 8443, 465, 993, 995, 636, 22, 3389}


def _looks_like_plaintext(payload: bytes, sample_size: int = 32, min_printable_ratio: float = 0.85) -> bool:
    if not payload:
        return False
    sample = payload[:sample_size]
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(sample)) >= min_printable_ratio


# ---------------------------------------------------------------------------
# Native C DPI Engine (optional, loaded lazily)
#
# Mirrors the ctypes binding used in benchmark_dpi.py, but wired into the
# live detection path here. If libdpi.so/.dll hasn't been compiled yet
# (see c_src/Makefile), the engine degrades gracefully: WireWarden still runs
# with the Aho-Corasick engine alone and logs a note explaining why.
# ---------------------------------------------------------------------------

# Must stay in sync with the SIGNATURES array in c_src/dpi.c — used only to
# turn the matched index back into a human-readable name for logging.
NATIVE_SIGNATURE_NAMES = [
    "' OR '1'='1",
    "UNION SELECT",
    "<script>",
    "../../",
    "etc/passwd",
    "cmd.exe",
    "; whoami",
]


def _get_lib_filename() -> str:
    if sys.platform == "win32":
        return "libdpi.dll"
    elif sys.platform == "darwin":
        return "libdpi.dylib"
    else:
        return "libdpi.so"


def _load_c_dpi_engine(logger: logging.Logger):
    base_dir = Path(__file__).parent.resolve()
    lib_filename = _get_lib_filename()
    lib_path = base_dir / lib_filename

    if not lib_path.exists():
        logger.info(
            f"[+] Note: '{lib_filename}' not found. Native C DPI engine disabled "
            f"(run 'make -C c_src' to build it). Falling back to Aho-Corasick only."
        )
        return None

    try:
        lib = ctypes.CDLL(str(lib_path))
        lib.inspect_payload_index.argtypes = [ctypes.c_char_p, ctypes.c_int]
        lib.inspect_payload_index.restype = ctypes.c_int
        logger.info("[+] Native C DPI Engine loaded successfully (libdpi).")
        return lib
    except (OSError, AttributeError) as e:
        logger.warning(
            f"[!] Failed to load native C DPI engine: {e}. "
            f"If you compiled an older libdpi without inspect_payload_index, rebuild via 'make -C c_src'. "
            f"Falling back to Aho-Corasick only."
        )
        return None


class NetworkGuardian:
    def __init__(self, dos_threshold=500, scan_threshold=50, time_window_sec=10, cleanup_interval_sec=30):
        self.logger = setup_logger()
        self.packet_queue = Queue(maxsize=20000)
        self.stop_event = threading.Event()
        self.lock = threading.Lock()

        self.DOS_THRESHOLD = dos_threshold
        self.SCAN_THRESHOLD = scan_threshold
        self.TIME_WINDOW = timedelta(seconds=time_window_sec)
        self.CLEANUP_INTERVAL = cleanup_interval_sec

        self.blacklist = {}  # {ip: unblock_time}

        self.syn_history = defaultdict(lambda: deque(maxlen=1000))
        self.port_history = defaultdict(lambda: deque(maxlen=1000))

        # Layer-7 keyword signatures (matched by the Aho-Corasick engine below)
        self.suspicious_keywords = [b"admin", b"password", b"etc/passwd", b"select * from"]

        if HAS_AHOCORASICK:
            self.automaton = ahocorasick.Automaton()
            for idx, key in enumerate(self.suspicious_keywords):
                key_str = key.decode('utf-8', errors='ignore').lower() if isinstance(key, bytes) else str(key).lower()
                key_bytes = key.lower() if isinstance(key, bytes) else key.encode('utf-8').lower()
                self.automaton.add_word(key_str, (idx, key_bytes))
            self.automaton.make_automaton()
            self.logger.info("[+] Aho-Corasick Bytes DPI Engine initialized successfully.")
        else:
            self.automaton = None
            self.logger.info("[+] Note: 'pyahocorasick' library not found. Falling back to native bytes searching.")

        # Native C engine: bounds-checked signature scan for injection-style
        # attacks (SQLi, XSS, path traversal, command injection). Runs
        # alongside, not instead of, the Aho-Corasick keyword scan above.
        self.c_dpi = _load_c_dpi_engine(self.logger)

    def _is_blacklisted(self, src_ip, now):
        """Must be called inside lock."""
        exp_time = self.blacklist.get(src_ip)
        if exp_time:
            if now < exp_time:
                return True
            else:
                del self.blacklist[src_ip]
        return False

    def _enqueue_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        now = datetime.now()

        with self.lock:
            if self._is_blacklisted(src_ip, now):
                return

        try:
            self.packet_queue.put_nowait(pkt)
        except Exception:
            pass

    def _clean_old_records(self, history_deque, now):
        while history_deque and (now - history_deque[0][0]) > self.TIME_WINDOW:
            history_deque.popleft()

    def _cleanup_worker(self):
        while not self.stop_event.is_set():
            time.sleep(self.CLEANUP_INTERVAL)
            now = datetime.now()

            with self.lock:
                for ip in list(self.syn_history.keys()):
                    history = self.syn_history[ip]
                    self._clean_old_records(history, now)
                    if not history:
                        del self.syn_history[ip]

                for ip in list(self.port_history.keys()):
                    history = self.port_history[ip]
                    self._clean_old_records(history, now)
                    if not history:
                        del self.port_history[ip]

                expired = [ip for ip, exp_time in self.blacklist.items() if now >= exp_time]
                for ip in expired:
                    del self.blacklist[ip]

    def _check_dpi_keywords(self, payload: bytes, src_ip: str):
        """Aho-Corasick (or pure-Python fallback) keyword scan."""
        payload_str = payload.decode('utf-8', errors='ignore').lower()
        matched_keywords = set()

        if self.automaton:
            for end_index, (idx, kw_bytes) in self.automaton.iter(payload_str):
                matched_keywords.add(kw_bytes.decode('utf-8', errors='ignore'))
        else:
            payload_lower = payload.lower()
            for kw in self.suspicious_keywords:
                if kw.lower() in payload_lower:
                    matched_keywords.add(kw.decode('utf-8', errors='ignore'))

        for kw_str in matched_keywords:
            self.logger.warning(
                f"[SECURITY DPI] Suspicious keyword '{kw_str}' from {src_ip}",
                extra={"src_ip": src_ip, "event_type": "DPI_ALERT", "details": f"Keyword match: {kw_str}"}
            )

    def _check_dpi_native(self, payload: bytes, src_ip: str):
        """Native C signature scan (SQLi / XSS / path traversal / cmd injection)."""
        if self.c_dpi is None:
            return

        try:
            idx = self.c_dpi.inspect_payload_index(payload, len(payload))
        except Exception as e:
            self.logger.debug(f"[DPI-C] Native engine call failed: {e}")
            return

        if idx is not None and idx >= 0:
            sig_name = NATIVE_SIGNATURE_NAMES[idx] if idx < len(NATIVE_SIGNATURE_NAMES) else f"index {idx}"
            self.logger.warning(
                f"[SECURITY DPI-C] Native signature match '{sig_name}' from {src_ip}",
                extra={"src_ip": src_ip, "event_type": "DPI_ALERT_NATIVE", "details": f"Native C signature match: {sig_name}"}
            )

    def _check_dpi(self, payload: bytes, src_ip: str):
        self._check_dpi_keywords(payload, src_ip)
        self._check_dpi_native(payload, src_ip)

    def analyze_packet(self, pkt):
        now = datetime.now()
        src_ip = pkt[IP].src

        with self.lock:
            if self._is_blacklisted(src_ip, now):
                return

        # 1. DNS Inspection & Tunneling Detection
        if pkt.haslayer(DNSQR):
            try:
                raw_query = pkt[DNSQR].qname
                query = raw_query.decode('ascii', errors='ignore').strip('.')

                if query and not query.endswith(".local"):
                    subdomain = query.split('.')[0]
                    entropy = calculate_entropy(subdomain)

                    if len(subdomain) > 45 or entropy > 4.3:
                        self.logger.warning(
                            f"[DNS TUNNELING SUSPECT] Host {src_ip} query len={len(query)} entropy={entropy:.2f}: {query}",
                            extra={"src_ip": src_ip, "event_type": "DNS_TUNNELING", "details": f"Len: {len(query)}, Entropy: {entropy:.2f}"}
                        )
                    else:
                        self.logger.info(
                            f"[DNS] Device {src_ip} query: {query}",
                            extra={"src_ip": src_ip, "event_type": "DNS_QUERY", "details": query}
                        )
            except Exception as e:
                self.logger.debug(f"[DNS] Parsing error: {e}")

        dst_port = None
        is_syn = False

        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
            tcp_flags = int(pkt[TCP].flags)

            if tcp_flags & 0x02:  # SYN Flag
                is_syn = True

            # 2. Bitwise Stealth Scan Detection
            fin = bool(tcp_flags & 0x01)
            syn = bool(tcp_flags & 0x02)
            rst = bool(tcp_flags & 0x04)
            psh = bool(tcp_flags & 0x08)
            ack = bool(tcp_flags & 0x10)
            urg = bool(tcp_flags & 0x20)

            stealth_type = None
            if tcp_flags == 0:
                stealth_type = "NULL Scan"
            elif fin and not (syn or rst or psh or ack or urg):
                stealth_type = "FIN Scan"
            elif fin and psh and urg and not (syn or rst or ack):
                stealth_type = "XMAS Scan"

            if stealth_type:
                self.logger.warning(
                    f"[STEALTH SCAN DETECTED] {stealth_type} from {src_ip} to port {dst_port}",
                    extra={"src_ip": src_ip, "event_type": "STEALTH_SCAN", "details": f"{stealth_type} on port {dst_port}"}
                )

        elif pkt.haslayer(UDP):
            dst_port = pkt[UDP].dport

        # 3. DoS & Port Scan Detection (Atomic State Updates)
        with self.lock:
            if is_syn:
                syn_deque = self.syn_history[src_ip]
                self._clean_old_records(syn_deque, now)
                syn_deque.append((now, None))

                if len(syn_deque) > self.DOS_THRESHOLD:
                    self.blacklist[src_ip] = now + timedelta(minutes=5)
                    block_ip_firewall_async(src_ip)
                    self.logger.critical(
                        f"[DoS DETECTED] Isolating IP: {src_ip} for 5 minutes (Firewall Rule Applied)",
                        extra={"src_ip": src_ip, "event_type": "DOS_ATTACK", "details": "SYN Flood threshold exceeded"}
                    )
                    syn_deque.clear()

            if dst_port is not None:
                ports_deque = self.port_history[src_ip]
                self._clean_old_records(ports_deque, now)
                ports_deque.append((now, dst_port))

                unique_ports = {port for _, port in ports_deque}
                if len(unique_ports) > self.SCAN_THRESHOLD:
                    self.logger.warning(
                        f"[PORT SCAN DETECTED] Host {src_ip} scanned {len(unique_ports)} unique ports",
                        extra={"src_ip": src_ip, "event_type": "PORT_SCAN", "details": f"{len(unique_ports)} ports scanned"}
                    )
                    ports_deque.clear()

        # 4. Deep Packet Inspection (DPI) — Aho-Corasick keywords + Native C signatures.
        # Skipped for well-known encrypted ports and non-plaintext-looking payloads,
        # since substring DPI over encrypted/binary bytes is both wasted work and a
        # false-positive risk.
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if dst_port not in COMMON_ENCRYPTED_PORTS and _looks_like_plaintext(payload):
                self._check_dpi(payload, src_ip)

    def packet_worker(self):
        while not self.stop_event.is_set():
            try:
                packet = self.packet_queue.get(timeout=0.5)
                self.analyze_packet(packet)
                self.packet_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"[WORKER ERROR] {e}")

    def start(self, num_workers=4):
        self.logger.info("NetworkGuardian Engine Starting...")

        workers = []
        for i in range(num_workers):
            w = threading.Thread(target=self.packet_worker, daemon=True, name=f"Worker-{i}")
            w.start()
            workers.append(w)

        cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True, name="CleanupGC")
        cleanup_thread.start()

        self.logger.info(f"[*] Engine Active. Listening with {num_workers} worker threads...")
        try:
            sniff(
                prn=self._enqueue_packet,
                store=0,
                filter="ip",
                stop_filter=lambda _: self.stop_event.is_set()
            )
        except KeyboardInterrupt:
            self.logger.info("Shutting down engine...")
            self.stop_event.set()
            for w in workers:
                w.join(timeout=2)
            cleanup_thread.join(timeout=2)


if __name__ == "__main__":
    guardian = NetworkGuardian(dos_threshold=500, scan_threshold=50, time_window_sec=10)
    guardian.start(num_workers=4)