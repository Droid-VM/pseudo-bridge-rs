"""Layer 3 — pbridge lifecycle in the phone ns. Cases may restart with different
flags (the arp-keepalive lifecycle cases do)."""

import subprocess
import time
from pathlib import Path

from common import BIN, sh_ok, spawn, until_ok

PB_LOG = "/tmp/pbridge.log"
PB_TIMEOUT = 6  # entry aging seconds (timeout/keepalive cases depend on it)


class Pbridge:
    def __init__(self, mode: str, engine: str, wrap: tuple[str, ...] = ()):
        self.mode = mode
        self.engine = engine
        self.wrap = wrap
        self.proc: subprocess.Popen | None = None

    def start(self, *extra_flags: str) -> bool:
        args = [*self.wrap, str(BIN), "-i", "up0", "-e", self.engine, "-m", self.mode,
                "--timeout", str(PB_TIMEOUT), "-b", "vmbr"]
        if self.mode != "direct":
            args += ["--fwd-device-if", "vmif", "--fwd-device-br", "vmport"]
        args += extra_flags
        self.proc = spawn(*args, ns="phone", log=PB_LOG)
        ok = until_ok(20, self._running, interval=0.3)
        if ok:
            # -b vmbr enslaved the guest-facing port at init; let the bridge and the
            # (nft) BRMAC ruleset rebuild settle.
            time.sleep(1)
        return ok

    def _running(self) -> bool:
        if self.proc.poll() is not None:
            return False
        try:
            return "backend running" in Path(PB_LOG).read_text()
        except FileNotFoundError:
            return False

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            self.proc = None

    def restart(self, *extra_flags: str) -> bool:
        self.stop()
        time.sleep(1)
        return self.start(*extra_flags)

    @staticmethod
    def nft_table_present() -> bool:
        return sh_ok("sh", "-c", "nft list tables 2>/dev/null | grep -q pbridge", ns="phone")
