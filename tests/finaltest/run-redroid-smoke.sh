#!/usr/bin/env bash
# Redroid15 smoke (SEPARATE from the matrix): boot the GKI 6.6 kernel with the
# redroid15 smoke initramfs (artifacts/rd-mini.cpio.gz) under QEMU/TCG and verify
# redroid's /system/bin/sh comes up via the bootstrap linker chain.
# Build artifacts first: sudo bash tests/setup-artifacts.sh
set -euo pipefail
cd "$(dirname "$0")"               # tests/finaltest/
ART=../artifacts
command -v qemu-system-aarch64 >/dev/null || { echo "need qemu-system-aarch64" >&2; exit 1; }
[ -s "$ART/Image" ] && [ -s "$ART/rd-mini.cpio.gz" ] || {
  echo "missing $ART/Image or $ART/rd-mini.cpio.gz — run: sudo bash tests/setup-artifacts.sh" >&2; exit 1; }

LOG="${LOG:-$ART/redroid-smoke.log}"
echo "== boot GKI 6.6 + redroid15 smoke (TCG); log -> $LOG =="
timeout "${TIMEOUT:-300}" qemu-system-aarch64 -M virt -cpu max -smp 2 -m 2048 -nographic -no-reboot \
  -kernel "$ART/Image" -initrd "$ART/rd-mini.cpio.gz" \
  -append "console=ttyAMA0 rdinit=/init panic=1" 2>&1 | tee "$LOG" \
  | sed -n '/REDROID-SH-ON-GKI/,/DONE/p' || true

grep -q 'REDROID_SYSTEM_BIN_SH_OK' "$LOG" \
  && echo "[PASS] redroid15 /system/bin/sh ran on GKI 6.6" \
  || { echo "[FAIL] redroid smoke — see $LOG"; exit 1; }
