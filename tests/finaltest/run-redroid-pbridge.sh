#!/usr/bin/env bash
# Redroid15 + pbridge smoke: prove the aarch64 static-musl pbridge binary executes
# under redroid's Android (bionic) userspace on the real GKI 6.6 kernel (QEMU/TCG).
# redroid lacks bpftool/bash/iproute2-tc so it's not the matrix rootfs (that's Alpine);
# this only asserts the binary starts there. Run setup-artifacts.sh first.
set -euo pipefail
cd "$(dirname "$0")"                       # tests/finaltest/
ART=../artifacts
PBRIDGE_BIN="${PBRIDGE_BIN:-../../dist/pbridge-android-arm64}"
command -v qemu-system-aarch64 >/dev/null || { echo "need qemu-system-aarch64" >&2; exit 1; }
[ -s "$ART/Image" ] || { echo "missing $ART/Image — run setup-artifacts.sh" >&2; exit 1; }
[ -d "$ART/redroid" ] || { echo "missing $ART/redroid — run setup-artifacts.sh" >&2; exit 1; }
[ -s "$ART/busybox-arm64" ] || { echo "missing $ART/busybox-arm64 — run setup-artifacts.sh" >&2; exit 1; }
[ -x "$PBRIDGE_BIN" ] || { echo "missing $PBRIDGE_BIN — build aarch64 first" >&2; exit 1; }

echo "== build redroid+pbridge smoke initramfs =="
R="$ART/redroid"; RD="$ART/rd-pb"; rm -rf "$RD"
mkdir -p "$RD"/{bin,dev,proc,sys,opt/pb} "$RD/apex/com.android.runtime/bin" \
         "$RD/system/bin/bootstrap" "$RD/system/lib64/bootstrap"
install -m755 "$ART/busybox-arm64" "$RD/bin/busybox"
install -m755 "$PBRIDGE_BIN"        "$RD/opt/pb/pbridge"
install -m755 rd-pb-init            "$RD/init"
cp -a "$R/system/bin/sh"                 "$RD/system/bin/"            2>/dev/null || true
cp -a "$R/system/bin/toybox"             "$RD/system/bin/"            2>/dev/null || true
cp -a "$R/system/bin/bootstrap/linker64" "$RD/system/bin/bootstrap/" 2>/dev/null || true
cp -a "$R"/system/lib64/bootstrap/*      "$RD/system/lib64/bootstrap/" 2>/dev/null || true
ln -sf /apex/com.android.runtime/bin/linker64 "$RD/system/bin/linker64"
ln -sf /system/bin/bootstrap/linker64         "$RD/apex/com.android.runtime/bin/linker64"
mknod -m600 "$RD/dev/console" c 5 1; mknod -m666 "$RD/dev/null" c 1 3
( cd "$RD" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -1 ) > "$ART/rd-pb.cpio.gz"

LOG="${LOG:-$ART/redroid-pbridge.log}"
echo "== boot GKI 6.6 + redroid15 + pbridge (TCG); log -> $LOG =="
timeout "${TIMEOUT:-300}" qemu-system-aarch64 -M virt -cpu max -smp 2 -m 2048 -nographic -no-reboot \
  -kernel "$ART/Image" -initrd "$ART/rd-pb.cpio.gz" \
  -append "console=ttyAMA0 rdinit=/init panic=1" > "$LOG" 2>&1 || true
sed -n '/REDROID-PBRIDGE-ON-GKI/,/DONE/p' "$LOG" || true
grep -q PBRIDGE_REDROID_RUN_OK "$LOG" \
  && echo "[PASS] pbridge runs on redroid15 rootfs + GKI 6.6" \
  || { echo "[FAIL] redroid+pbridge smoke — see $LOG"; exit 1; }
