"""DPI micro-benchmark: native C signature engine vs. pure-Python baselines.

Reports FOUR numbers so the result can't be misread:

  * Python loop   - naive baseline: lowercase once, `sig in payload` per signature
  * Python regex  - stronger baseline: ONE compiled, case-insensitive alternation
  * C per-call    - what the live pipeline actually does (one ctypes call per packet)
  * C batch       - one ctypes call for the whole batch (FFI overhead amortized)

Only "C per-call" reflects the live path. "C batch" shows the engine's ceiling.
All engines match the same signatures, case-insensitively.
"""
import ctypes
import gc
import re
import sys
import time
from pathlib import Path


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


def py_loop(payload: bytes) -> bool:
    low = payload.lower()
    for sig in SIGNATURES:
        if sig in low:
            return True
    return False


def py_regex(payload: bytes) -> bool:
    return REGEX.search(payload) is not None


def c_single(payload: bytes) -> bool:
    return c_lib.inspect_payload_index(payload, len(payload)) >= 0


def timed(fn) -> float:
    gc.collect()
    gc.disable()
    try:
        t0 = time.perf_counter()
        fn()
        return time.perf_counter() - t0
    finally:
        gc.enable()


def avg(fn, runs):
    fn()  # warm-up
    return sum(timed(fn) for _ in range(runs)) / runs


if __name__ == "__main__":
    N, RUNS = 100_000, 5
    clean = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    bad = b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin' OR '1'='1"
    payloads = [bad if i % 10 == 0 else clean for i in range(N)]  # 10% malicious

    # correctness first: all engines must agree on every payload
    assert all(py_loop(p) == py_regex(p) == c_single(p) for p in (clean, bad)), "engines disagree"

    ptrs = (ctypes.c_char_p * N)(*payloads)
    lens = (ctypes.c_int * N)(*[len(p) for p in payloads])
    out = (ctypes.c_int * N)()

    results = [
        ("Python loop  (naive)",            avg(lambda: [py_loop(p) for p in payloads], RUNS)),
        ("Python regex (1 compiled, IGNORECASE)", avg(lambda: [py_regex(p) for p in payloads], RUNS)),
        ("C per-call   (live-path style)",  avg(lambda: [c_single(p) for p in payloads], RUNS)),
        ("C batch      (1 FFI call)",       avg(lambda: c_lib.inspect_batch(ptrs, lens, N, out), RUNS)),
    ]
    base = results[0][1]
    print(f"=== WireWarden DPI benchmark: {N:,} packets, {len(SIGNATURES)} signatures, avg of {RUNS} runs ===")
    print(f"{'engine':42s} {'time':>9s} {'pkts/sec':>12s} {'vs naive':>9s}")
    for name, t in results:
        print(f"{name:42s} {t:8.4f}s {N / t:12,.0f} {base / t:8.2f}x")
    print("\nNote: only 'C per-call' reflects the live pipeline; 'C batch' is the engine's ceiling.")
