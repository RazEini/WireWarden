"""DPI micro-benchmark: native C signature engine vs. pure-Python baselines.

Default run: 100,000 identical short payloads, five engines, all matching the same
signatures case-insensitively:

  * Python loop   - naive baseline: lowercase once, `sig in payload` per signature
  * Python regex  - one compiled, case-insensitive alternation
  * Aho-Corasick  - pyahocorasick on the lowercased payload (the project's own Python alternative)
  * C per-call    - what the live pipeline does (one ctypes call per packet)
  * C batch       - one ctypes call for the whole batch (call overhead amortized)

`--sweep` repeats the comparison on varied, realistic payloads of 64 to 1460 bytes
(5% malicious), because a single short payload repeated 100,000 times flatters
per-call overhead differences.

Only "C per-call" reflects the live pipeline. None of these numbers is end-to-end
throughput: see benchmark_pipeline.py for where per-packet time actually goes.
"""
import argparse
import ctypes
import gc
import random
import re
import sys
import time
from pathlib import Path

try:
    import ahocorasick
except ImportError:  # the Aho-Corasick row is skipped without the library
    ahocorasick = None


def _get_lib_filename() -> str:
    if sys.platform == "win32":
        return "libdpi.dll"
    if sys.platform == "darwin":
        return "libdpi.dylib"
    return "libdpi.so"


lib_path = Path(__file__).parent.resolve() / _get_lib_filename()
if not lib_path.exists():
    print(f"[-] {lib_path.name} not found. Run: make -C c_src")
    sys.exit(1)

c_lib = ctypes.CDLL(str(lib_path))
c_lib.inspect_payload_index.argtypes = [ctypes.c_char_p, ctypes.c_int]
c_lib.inspect_payload_index.restype = ctypes.c_int
c_lib.inspect_batch.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_int),
                                ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
c_lib.inspect_batch.restype = ctypes.c_int
c_lib.signature_count.restype = ctypes.c_int
c_lib.signature_name.argtypes = [ctypes.c_int]
c_lib.signature_name.restype = ctypes.c_char_p

# Single source of truth: the signature list comes from the C library itself.
SIGNATURES = [c_lib.signature_name(i) for i in range(c_lib.signature_count())]
REGEX = re.compile(b"|".join(re.escape(s) for s in SIGNATURES), re.IGNORECASE)

AUTOMATON = None
if ahocorasick is not None:
    AUTOMATON = ahocorasick.Automaton()
    for _sig in SIGNATURES:
        AUTOMATON.add_word(_sig.decode("latin-1"), _sig)
    AUTOMATON.make_automaton()


def py_loop(payload: bytes) -> bool:
    low = payload.lower()
    for sig in SIGNATURES:
        if sig in low:
            return True
    return False


def py_regex(payload: bytes) -> bool:
    return REGEX.search(payload) is not None


def py_aho(payload: bytes) -> bool:
    for _ in AUTOMATON.iter(payload.lower().decode("latin-1")):
        return True
    return False


def c_single(payload: bytes) -> bool:
    return c_lib.inspect_payload_index(payload, len(payload)) >= 0


def best_of(fn, runs: int) -> float:
    """Best (minimum) time over `runs`: the standard way to reduce scheduler noise."""
    fn()  # warm-up
    times = []
    for _ in range(runs):
        gc.collect()
        gc.disable()
        try:
            t0 = time.perf_counter()
            fn()
            times.append(time.perf_counter() - t0)
        finally:
            gc.enable()
    return min(times)


def c_batch_runner(payloads):
    n = len(payloads)
    ptrs = (ctypes.c_char_p * n)(*payloads)
    lens = (ctypes.c_int * n)(*[len(p) for p in payloads])
    out = (ctypes.c_int * n)()
    return lambda: c_lib.inspect_batch(ptrs, lens, n, out)


def engines(payloads):
    rows = [("Python loop (naive)", lambda: [py_loop(p) for p in payloads]),
            ("Python regex (IGNORECASE)", lambda: [py_regex(p) for p in payloads])]
    if AUTOMATON is not None:
        rows.append(("Aho-Corasick (pyahocorasick)", lambda: [py_aho(p) for p in payloads]))
    rows.append(("C per-call (live-path style)", lambda: [c_single(p) for p in payloads]))
    rows.append(("C batch (1 call)", c_batch_runner(payloads)))
    return rows


def check_agreement(payloads):
    for p in payloads:
        results = {py_loop(p), py_regex(p), c_single(p)}
        if AUTOMATON is not None:
            results.add(py_aho(p))
        assert len(results) == 1, f"engines disagree on {p[:60]!r}"


def default_run(n: int, runs: int):
    clean = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    bad = b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin' OR '1'='1"
    payloads = [bad if i % 10 == 0 else clean for i in range(n)]  # 10% malicious
    check_agreement([clean, bad])

    results = [(name, best_of(fn, runs)) for name, fn in engines(payloads)]
    base = results[0][1]
    print(f"=== {n:,} identical short payloads (~{len(clean)} bytes), {len(SIGNATURES)} signatures, best of {runs} runs ===")
    print(f"{'engine':34s} {'time':>9s} {'pkts/sec':>12s} {'vs naive':>9s}")
    for name, t in results:
        print(f"{name:34s} {t:8.4f}s {n / t:12,.0f} {base / t:8.2f}x")


WORDS = [w.encode() for w in ("GET POST Host User-Agent Accept Content-Type application json text html "
                              "index login api v1 users items search q id name value token session cookie data").split()]
SEPARATORS = [b" ", b"/", b"=", b"&", b"\r\n"]


def make_payload(rng: random.Random, size: int, malicious: bool) -> bytes:
    parts, total = [], 0
    while total < size:
        w = rng.choice(WORDS) + rng.choice(SEPARATORS)
        parts.append(w)
        total += len(w)
    payload = bytearray(b"".join(parts)[:size])
    if malicious:
        sig = rng.choice(SIGNATURES)
        pos = rng.randint(0, max(0, size - len(sig)))
        payload[pos:pos + len(sig)] = sig.upper() if rng.random() < 0.5 else sig
    return bytes(payload)


def sweep(n: int, runs: int):
    rng = random.Random(7)
    names = [name for name, _ in engines([b"x"])]
    print(f"=== Payload-size sweep: {n:,} varied HTTP-like payloads per size, 5% malicious, best of {runs}; packets/sec ===")
    print(f"{'size':>6} | " + " ".join(f"{nm.split(' (')[0]:>14s}" for nm in names) + " | C per-call vs best Python")
    for size in (64, 256, 1024, 1460):
        payloads = [make_payload(rng, size, rng.random() < 0.05) for _ in range(n)]
        check_agreement(payloads[:2000])
        times = [best_of(fn, runs) for _, fn in engines(payloads)]
        py_best = min(t for nm, t in zip(names, times) if nm.startswith(("Python", "Aho")))
        c_call = times[names.index("C per-call (live-path style)")]
        print(f"{size:>6} | " + " ".join(f"{n / t:>14,.0f}" for t in times) + f" | {py_best / c_call:>5.2f}x")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="WireWarden DPI micro-benchmark")
    ap.add_argument("--sweep", action="store_true", help="payload-size sweep on varied payloads")
    ap.add_argument("--packets", type=int, default=100_000)
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()
    if args.sweep:
        sweep(min(args.packets, 20_000), args.runs)
    else:
        default_run(args.packets, args.runs)
    print("\nOnly 'C per-call' reflects the live pipeline; 'C batch' is the engine's ceiling.")
    print("For end-to-end cost per packet (Scapy parsing, detectors, DPI) run: python benchmark_pipeline.py")