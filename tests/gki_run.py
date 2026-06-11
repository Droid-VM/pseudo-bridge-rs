"""GKI executor: build the aarch64 binaries, stage the suite into the Alpine arm64
rootfs, boot ONE QEMU running the stock android15-6.6 GKI kernel, and run every gki
unit inside the guest via `suite.py --gki-batch`. The guest console is the result
channel (@@UNIT/@@UNITEND markers); this parses it back into per-unit/per-case results
in the same shape run.py uses for host units.

TCG (no KVM on an x86 host) makes the aarch64 guest slow, so the whole gki matrix runs
in a single boot rather than one boot per unit.

Requires tests/setup-artifacts.sh to have produced artifacts/{Image,aroot} already
(this calls it if aroot is missing). GKI has TUN+BRIDGE+VETH+NET_XGRESS+BPF_SYSCALL but
no NF_TABLES (ebpf only) and no dnsmasq in the rootfs (dhcp_v4 self-skips).
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "tests/artifacts"
AROOT = ART / "aroot"
ARM = "aarch64-unknown-linux-musl"

# guest /init: mount the basics, then run the batch and power off. The console log is
# the only channel out, so everything the host needs is printed by --gki-batch.
GKI_INIT = """#!/bin/sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
mount -t tmpfs tmpfs /tmp 2>/dev/null
mount -t tmpfs tmpfs /run 2>/dev/null
mkdir -p /run/netns
# upsim needs /dev/net/tun; devtmpfs in this minimal initramfs may not create it.
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
ip link set lo up 2>/dev/null
export PBRIDGE_BIN=/opt/pb/pbridge UPSIM_BIN=/opt/pb/upsim
export SUITE_UNSHARE="unshare --mount --net"
export SUITE_TIME_SCALE=3
cd /opt/pb/suite
python3 run_all_test.py --gki-guest -j 1
echo "@@GKI_EXIT $?"
sync
poweroff -f 2>/dev/null
echo o > /proc/sysrq-trigger 2>/dev/null
"""


def _build_arm():
    subprocess.run(["bash", str(ROOT / "build.sh"), "arm64"], cwd=ROOT, check=True)
    env = {**os.environ, "RUSTFLAGS": "-C linker=rust-lld"}
    subprocess.run(["cargo", "build", "--release", "--target", ARM],
                   cwd=ROOT / "tools/upsim", env=env, check=True)


def _stage():
    if not AROOT.exists():
        subprocess.run(["bash", str(ROOT / "tests/setup-artifacts.sh")], cwd=ROOT, check=True)
    pbdir = AROOT / "opt/pb"
    suitedir = pbdir / "suite"
    suitedir.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "dist/pbridge-android-arm64", pbdir / "pbridge")
    shutil.copy(ROOT / f"tools/upsim/target/{ARM}/release/upsim", pbdir / "upsim")
    (pbdir / "pbridge").chmod(0o755)
    (pbdir / "upsim").chmod(0o755)
    for f in (ROOT / "tests").glob("*.py"):
        shutil.copy(f, suitedir / f.name)
    init = AROOT / "init"
    init.write_text(GKI_INIT)
    init.chmod(0o755)
    for node, args in (("dev/console", (5, 1)), ("dev/null", (1, 3))):
        p = AROOT / node
        p.unlink(missing_ok=True)
        subprocess.run(["mknod", "-m", "600" if "console" in node else "666",
                        str(p), "c", str(args[0]), str(args[1])], check=True)
    cpio = ART / "gki-suite.cpio.gz"
    subprocess.run(
        f"cd {AROOT} && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -1 > {cpio}",
        shell=True, check=True)
    return cpio


_RESULT_RX = re.compile(r"^(ok|fail|skip) (\S+)")


def _parse(console: str):
    """console text -> {unit_name: (ok_bool, {case: status})}."""
    units = {}
    cur = None
    cases = {}
    for line in console.splitlines():
        line = line.rstrip("\r")
        if line.startswith("@@UNIT "):
            cur = line[len("@@UNIT "):].strip()
            cases = {}
        elif line.startswith("@@UNITEND"):
            if cur is not None:
                ok = all(v != "fail" for v in cases.values()) and bool(cases)
                units[cur] = (ok, cases)
            cur = None
        elif cur is not None:
            m = _RESULT_RX.match(line)
            if m:
                cases[m.group(2)] = m.group(1)
    return units


def run_gki(timeout: int = 2400):
    """Boot the GKI guest and run the whole gki matrix. Returns
    {unit_name: (ok, cases)} plus the console log path."""
    _build_arm()
    cpio = _stage()
    log = ART / "gki-suite-console.log"
    cmd = [
        "timeout", str(timeout), "qemu-system-aarch64", "-M", "virt", "-cpu", "max",
        "-smp", "4", "-m", "6144", "-nographic", "-no-reboot",
        "-kernel", str(ART / "Image"), "-initrd", str(cpio),
        "-append", "console=ttyAMA0 rdinit=/init panic=1",
    ]
    with open(log, "w") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)
    text = log.read_text(errors="replace")
    units = _parse(text)
    complete = "@@GKI_COMPLETE" in text
    return units, complete, log


if __name__ == "__main__":
    import sys
    units, complete, log = run_gki()
    print(f"\n=== GKI result (complete={complete}, log={log}) ===")
    rc = 0 if complete else 1
    for name, (ok, cases) in units.items():
        nf = sum(1 for v in cases.values() if v == "fail")
        no = sum(1 for v in cases.values() if v == "ok")
        ns = sum(1 for v in cases.values() if v == "skip")
        print(f"  {'PASS' if ok else 'FAIL'}  {name:34} {no} ok, {nf} fail, {ns} skip")
        if not ok:
            rc = 1
    if not complete:
        print("  !! @@GKI_COMPLETE missing — guest did not finish (see log)")
    sys.exit(rc)
