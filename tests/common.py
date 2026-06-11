"""pbridge suite — shared plumbing: shell helpers, fixed names/addresses, failure type.

Fixed names are safe because run.py executes every unit inside its own mount+net
namespace (private /run/netns + /tmp), so parallel units can never collide.
"""

import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Binaries default to the host build tree, but each is overridable so the GKI
# executor can point at the aarch64 binaries staged inside the guest rootfs.
BIN = Path(os.environ.get("PBRIDGE_BIN", ROOT / "target/debug/pbridge"))
UPSIM = Path(os.environ.get("UPSIM_BIN",
                            ROOT / "tools/upsim/target/x86_64-unknown-linux-musl/release/upsim"))
NOEBPF = Path(os.environ.get("NOEBPF_BIN", ROOT / "tests/finaltest/noebpf"))

HMAC = "02:00:00:00:00:01"
GW4, GW6 = "10.0.0.1", "fd00::1"
HOST4, HOST6 = "10.0.0.2", "fd00::2"
VM1_4, VM1_6 = "10.0.0.5", "fd00::5"
VM2_4, VM2_6 = "10.0.0.6", "fd00::6"
VM3_4, VM3_6 = "10.0.0.7", "fd00::7"
# wan-segment "household" devices (siblings of the gw, NOT behind the MAC-NAT)
NEIGH1_4, NEIGH1_6 = "10.0.0.8", "fd00::8"
NEIGH2_4, NEIGH2_6 = "10.0.0.9", "fd00::9"
# the address that hops VM -> neigh in the handover case
HANDOVER_4, HANDOVER_6 = "10.0.0.50", "fd00::50"
NS_ALL = ("gw", "phone", "vm1", "vm2", "vm3", "neigh1", "neigh2")
LEAK_LOG = Path("/tmp/upsim-leak.log")
MAGIC = "4243672773"


class Fail(Exception):
    """A case assertion failure (message = what was being asserted)."""


def sh(*args: str, ns: str | None = None, check: bool = False) -> subprocess.CompletedProcess:
    """Run a command (optionally inside a netns), capturing output."""
    cmd = list(args)
    if ns:
        cmd = ["ip", "netns", "exec", ns] + cmd
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def sh_ok(*args: str, ns: str | None = None) -> bool:
    return sh(*args, ns=ns).returncode == 0


def spawn(*args: str, ns: str | None = None, log: str | None = None) -> subprocess.Popen:
    """Start a long-running process (optionally inside a netns), output to `log`."""
    cmd = list(args)
    if ns:
        cmd = ["ip", "netns", "exec", ns] + cmd
    out = open(log, "w") if log else subprocess.DEVNULL
    return subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT)


def until_ok(budget_s: float, fn, *, interval: float = 0.5) -> bool:
    """Eventual success: poll `fn` (returning truthy) within `budget_s`."""
    end = time.monotonic() + budget_s
    while time.monotonic() < end:
        if fn():
            return True
        time.sleep(interval)
    return False


def ping(ns: str, dst: str, src: str | None = None, count: int = 1, wait: int = 2) -> bool:
    cmd = ["ping", f"-c{count}", f"-W{wait}"]
    if src:
        cmd += ["-I", src]
    return sh_ok(*cmd, dst, ns=ns)


# ---- assertion helpers (raise Fail with the description) ----

def expect(cond: bool, what: str):
    if not cond:
        raise Fail(what)


def expect_ping(ns: str, dst: str, what: str, *, budget: float = 15, src: str | None = None):
    if not until_ok(budget, lambda: ping(ns, dst, src=src)):
        raise Fail(what)


def expect_no_ping(ns: str, dst: str, what: str, *, count: int = 3, src: str | None = None):
    if ping(ns, dst, src=src, count=count, wait=1):
        raise Fail(f"{what} (unexpectedly succeeded)")


def leak_count() -> int:
    """Foreign-src frames upsim dropped+logged — the unified leak detector."""
    try:
        return sum(1 for line in LEAK_LOG.read_text().splitlines() if line.startswith("leak"))
    except FileNotFoundError:
        return 0
