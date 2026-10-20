import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LIB = {"win32": "libdpi.dll", "darwin": "libdpi.dylib"}.get(sys.platform, "libdpi.so")


@pytest.fixture(scope="session")
def libdpi():
    """Build the native library if needed; skip native tests if no compiler."""
    path = ROOT / LIB
    if not path.exists():
        if not (shutil.which("make") and (shutil.which("gcc") or shutil.which("cc"))):
            pytest.skip("no C toolchain available")
        subprocess.run(["make", "-C", str(ROOT / "c_src")], check=True, capture_output=True)
    return path


class FakeRunner:
    """Stands in for subprocess.run; records commands, returns scripted exit codes."""

    def __init__(self, returncode=0, stderr=""):
        self.calls = []
        self.returncode = returncode
        self.stderr = stderr

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)

        class R:
            pass

        r = R()
        r.returncode = self.returncode
        r.stderr = self.stderr
        return r


class FakeFirewall:
    def __init__(self):
        self.blocked, self.unblocked = [], []

    def block(self, ip, blocking=False):
        self.blocked.append(ip)

    def unblock(self, ip):
        self.unblocked.append(ip)

    def unblock_all(self):
        pass


LOCAL = "192.168.1.50"
GATEWAY = "192.168.1.1"


@pytest.fixture
def fw():
    return FakeFirewall()


@pytest.fixture
def guardian(tmp_path, fw, libdpi):
    from main import NetworkGuardian
    return NetworkGuardian(local_ips={LOCAL}, whitelist=[GATEWAY], log_dir=str(tmp_path), firewall=fw)


def types(g):
    return [a["event_type"] for a in g.alerts]
