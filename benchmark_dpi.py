import ctypes
import gc
import os
from pathlib import Path
import sys
import time

# ---------------------------------------------------------------------------
# 1. Load Native C Extension
# ---------------------------------------------------------------------------
def _get_lib_filename() -> str:
    if sys.platform == "win32":
        return "libdpi.dll"
    elif sys.platform == "darwin":
        return "libdpi.dylib"
    else:
        return "libdpi.so"


BASE_DIR = Path(__file__).parent.resolve()
lib_filename = _get_lib_filename()
lib_path = BASE_DIR / lib_filename

if not lib_path.exists():
    print(f"[-] Shared library not found at {lib_path}. Compile it first.")
    sys.exit(1)

c_lib = ctypes.CDLL(str(lib_path))

c_lib.inspect_batch.argtypes = [
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.POINTER(ctypes.c_int),
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int),
]
c_lib.inspect_batch.restype = ctypes.c_int


# ---------------------------------------------------------------------------
# 2. Pure Python Engine Implementation
#
# NOTE: kept in sync with the SIGNATURES array in c_src/dpi.c. "../../" (6
# bytes) is used instead of "../" (3 bytes) — short substrings risk matching
# by chance inside high-entropy binary/encrypted payloads.
# ---------------------------------------------------------------------------
SIGNATURES_PY = [
    b"' OR '1'='1",
    b"UNION SELECT",
    b"<script>",
    b"../../",
    b"etc/passwd",
    b"cmd.exe",
    b"; whoami",
]


def inspect_payload_py(payload: bytes) -> int:
    for sig in SIGNATURES_PY:
        if sig in payload:
            return 1
    return 0


def run_python_benchmark(payloads: list[bytes]) -> float:
    # Disable GC and clean memory prior to execution
    gc.collect()
    gc.disable()
    try:
        start_time = time.perf_counter()
        _ = [inspect_payload_py(p) for p in payloads]
        end_time = time.perf_counter()
    finally:
        gc.enable()
    return end_time - start_time


# ---------------------------------------------------------------------------
# 3. Native C Extension Batch Benchmark
# ---------------------------------------------------------------------------
def prepare_c_buffers(payloads: list[bytes]):
    count = len(payloads)

    payload_ptrs = (ctypes.c_char_p * count)()
    lengths = (ctypes.c_int * count)()
    results = (ctypes.c_int * count)()

    for i, p in enumerate(payloads):
        payload_ptrs[i] = p
        lengths[i] = len(p)

    return payload_ptrs, lengths, count, results


def run_c_batch_benchmark(payload_ptrs, lengths, count, results) -> float:
    gc.collect()
    gc.disable()
    try:
        start_time = time.perf_counter()
        c_lib.inspect_batch(payload_ptrs, lengths, count, results)
        end_time = time.perf_counter()
    finally:
        gc.enable()

    return end_time - start_time


# ---------------------------------------------------------------------------
# 4. Benchmark Execution & Comparison (Averaged & Stable)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    NUM_PACKETS = 100_000
    NUM_RUNS = 5

    sample_clean = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    sample_malicious = b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin' OR '1'='1"

    print(f"=== WireWarden DPI Benchmark ({NUM_PACKETS:,} Packets | Averaged over {NUM_RUNS} runs) ===")

    test_payloads = [
        sample_malicious if i % 10 == 0 else sample_clean
        for i in range(NUM_PACKETS)
    ]

    c_buffers = prepare_c_buffers(test_payloads)

    # Warmup runs to fill CPU caches
    _ = run_python_benchmark(test_payloads)
    _ = run_c_batch_benchmark(*c_buffers)

    # Multi-run evaluation for Python
    py_times = [run_python_benchmark(test_payloads) for _ in range(NUM_RUNS)]
    py_avg_time = sum(py_times) / NUM_RUNS
    py_pps = NUM_PACKETS / py_avg_time
    print(f"🐍 Python Engine:  {py_avg_time:.4f} sec | {py_pps:,.0f} Packets/sec (Avg)")

    # Multi-run evaluation for C
    c_times = [run_c_batch_benchmark(*c_buffers) for _ in range(NUM_RUNS)]
    c_avg_time = sum(c_times) / NUM_RUNS
    c_pps = NUM_PACKETS / c_avg_time
    print(f"⚡ C Extension:     {c_avg_time:.4f} sec | {c_pps:,.0f} Packets/sec (Avg)")

    # Stable Speedup
    speedup = py_avg_time / c_avg_time if c_avg_time > 0 else 0
    print(f"🚀 Speedup Factor: {speedup:.2f}x faster with C Extension!")