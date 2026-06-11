#!/usr/bin/env bash
# Probe whether the stock GKI kernels actually support AF_XDP at runtime (beyond
# the static CONFIG_XDP_SOCKETS=y). Cross-compiles afxdp/probe.c to an aarch64
# static binary with `zig cc`, packs it as a tiny /init initramfs, and boots each
# kernel under QEMU/TCG. The probe (PID 1) exercises socket(AF_XDP) -> UMEM_REG
# -> FILL/COMPLETION/RX rings -> XDP_MMAP_OFFSETS -> bind() in generic/copy mode
# (on lo and a self-created dummy netdev), then powers off.
#
# Note: this measures *kernel* capability with a bare rootfs (no Android SELinux
# policy). On a real device, creating AF_XDP sockets / loading the XDP redirect
# program is gated by sepolicy (bpfloader/netd domains) — see SURVEY-android15.md.
set -euo pipefail
cd "$(dirname "$0")"
command -v qemu-system-aarch64 >/dev/null || { echo "need qemu-system-aarch64" >&2; exit 1; }
ZIG=$(python3 -c 'import ziglang,os;print(os.path.join(os.path.dirname(ziglang.__file__),"zig"))')

echo "== compile afxdp/probe.c -> aarch64 static =="
"$ZIG" cc -target aarch64-linux-musl -static -O2 -o afxdp/afxdp_probe afxdp/probe.c

echo "== pack tiny initramfs (/init = probe) =="
rm -rf afxdp/ir && mkdir -p afxdp/ir/dev
cp afxdp/afxdp_probe afxdp/ir/init
mknod -m600 afxdp/ir/dev/console c 5 1
mknod -m666 afxdp/ir/dev/null    c 1 3
( cd afxdp/ir && find . | cpio -o -H newc 2>/dev/null | gzip -1 ) > afxdp/afxdp-initrd.cpio.gz

run() { # $1=kernel image  $2=label
  echo
  echo "######## $2 ($1) ########"
  timeout "${TIMEOUT:-300}" qemu-system-aarch64 -M virt -cpu max -smp 2 -m 1024 \
    -nographic -no-reboot -kernel "$1" -initrd afxdp/afxdp-initrd.cpio.gz \
    -append "console=ttyAMA0 rdinit=/init panic=1" 2>&1 \
    | sed -n '/AFXDP_PROBE_START/,/AFXDP_PROBE_DONE/p'
}

ART=../artifacts
[ -s "$ART/Image"   ] && run "$ART/Image"   "GKI 6.6 (android15)" || echo "($ART/Image missing — run tests/setup-artifacts.sh)"
[ -s "$ART/Image15" ] && run "$ART/Image15" "GKI (2nd image)"     || echo "($ART/Image15 missing)"
