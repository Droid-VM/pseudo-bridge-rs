#!/usr/bin/env bash
# Boot the stock android15-6.6 GKI kernel under QEMU and run the ENV=android
# test matrix (ebpf only; nft skipped — stock GKI has no NF_TABLES).
# ../setup-artifacts.sh fetches + boot-verifies Image/aroot/redroid first; this
# script then stages pbridge+matrix into the Alpine rootfs and runs the matrix.
#
# On an x86 host the aarch64 guest runs under TCG (no KVM accel), so it's slow
# (~5-15 min for the full matrix); the matrix uses adaptive timing to cope.
set -euo pipefail
cd "$(dirname "$0")"               # tests/finaltest/
ART=../artifacts
PBRIDGE_BIN="${PBRIDGE_BIN:-../../dist/pbridge-android-arm64}"
command -v qemu-system-aarch64 >/dev/null || { echo "need qemu-system-aarch64" >&2; exit 1; }

bash ../setup-artifacts.sh

# stage pbridge + matrix into the Alpine rootfs -> matrix initramfs
[ -x "$PBRIDGE_BIN" ] || { echo "pbridge binary not found at $PBRIDGE_BIN — build it first (or set PBRIDGE_BIN=...)" >&2; exit 1; }
echo "== stage pbridge + matrix into aroot, pack matrix initramfs =="
AR="$ART/aroot"; mkdir -p "$AR/opt/pb"
install -m755 "$PBRIDGE_BIN" "$AR/opt/pb/pbridge"
install -m644 matrix.sh       "$AR/opt/pb/matrix.sh"
install -m755 android-init.sh "$AR/init"
rm -f "$AR/dev/console" "$AR/dev/null"
mknod -m600 "$AR/dev/console" c 5 1; mknod -m666 "$AR/dev/null" c 1 3
( cd "$AR" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -1 ) > "$ART/android-initramfs.cpio.gz"

LOG="${LOG:-$ART/android-matrix.log}"
TIMEOUT="${TIMEOUT:-1400}"
echo "== boot QEMU (TCG); log -> $LOG =="
timeout "$TIMEOUT" qemu-system-aarch64 -M virt -cpu max -smp 4 -m 6144 -nographic -no-reboot \
  -kernel "$ART/Image" -initrd "$ART/android-initramfs.cpio.gz" \
  -append "console=ttyAMA0 rdinit=/init panic=1" > "$LOG" 2>&1 || true

echo
echo "================= ENV=android result ================="
sed -n '/SUMMARY (ENV=android)/,/===========/p' "$LOG" || true
grep -q 'PBRIDGE_ANDROID_RUN_COMPLETE' "$LOG" || { echo "!! matrix did not complete — see $LOG"; exit 1; }
grep -q 'ALL CONFIGS PASSED' "$LOG" && echo "ALL CONFIGS PASSED" || { echo "!! some android configs failed — see $LOG"; exit 1; }
