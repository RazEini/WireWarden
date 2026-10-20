import ctypes
import random

import pytest


@pytest.fixture(scope="module")
def lib(libdpi):
    lib = ctypes.CDLL(str(libdpi))
    lib.inspect_payload_index.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.inspect_payload_index.restype = ctypes.c_int
    lib.signature_count.restype = ctypes.c_int
    lib.signature_name.argtypes = [ctypes.c_int]
    lib.signature_name.restype = ctypes.c_char_p
    lib.max_signature_len.restype = ctypes.c_int
    return lib


def sigs(lib):
    return [lib.signature_name(i) for i in range(lib.signature_count())]


def scan(lib, data: bytes) -> int:
    return lib.inspect_payload_index(data, len(data))


def test_signature_table_is_exposed(lib):
    names = sigs(lib)
    assert len(names) >= 10
    assert lib.signature_name(-1) is None and lib.signature_name(len(names)) is None
    assert lib.max_signature_len() == max(len(n) for n in names)


def test_every_signature_matches_in_any_case_and_position(lib):
    names = sigs(lib)
    for sig in names:
        for variant in (sig, sig.upper(), sig.swapcase()):
            for data in (variant, b"xx" + variant, variant + b"xx", b"\x00\xff" + variant + b"\x00\xff"):
                idx = scan(lib, data)
                assert idx >= 0, (sig, data)
                assert names[idx] in data.lower(), (sig, data, names[idx])


def test_signature_missing_its_last_byte_does_not_match(lib):
    names = sigs(lib)
    for sig in names:
        data = b"padding " + sig[:-1]
        idx = scan(lib, data)
        assert idx == -1 or names[idx] in data.lower(), (sig, idx)  # only a different, fully present signature may fire


def test_benign_traffic_has_no_match(lib):
    assert scan(lib, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n") == -1


def test_embedded_null_bytes_do_not_truncate_the_scan(lib):
    assert scan(lib, b"\x00\x00\x00union select\x00") >= 0
    assert scan(lib, b"AAAA\x00BBBB\x00" + b"cmd.exe") >= 0


def test_degenerate_inputs_are_safe(lib):
    assert lib.inspect_payload_index(None, 10) == -1
    assert lib.inspect_payload_index(b"x", 0) == -1
    assert lib.inspect_payload_index(b"union select", -1) == -1
    assert scan(lib, b"") == -1
    assert scan(lib, b"u") == -1


def test_length_shorter_than_buffer_is_respected(lib):
    buf = b"union select"
    assert lib.inspect_payload_index(buf, len(buf) - 1) == -1  # last byte excluded by length


def test_random_buffers_never_crash(lib):
    rng = random.Random(1234)
    for _ in range(20000):
        data = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 80)))
        scan(lib, data)
