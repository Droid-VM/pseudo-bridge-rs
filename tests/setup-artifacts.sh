#!/usr/bin/env bash
# Download the building blocks for the aarch64-ebpf test env and QEMU-verify each
# rootfs actually boots to a shell on the GKI kernel. All output is .gitignore'd
# under tests/artifacts/ (large/regenerable):
#   1. artifacts/Image            - raw arm64 kernel from android15-6.6 GKI boot.img (KernelSU v2.1.2)
#   2. artifacts/aroot/           - Alpine arm64 rootfs (+ iproute2/bpftool/bash/tcpdump for the matrix)
#   3. artifacts/redroid/         - redroid15 arm64 rootfs (docker export)
# Then boots GKI + each rootfs under QEMU and asserts a shell came up:
#   4. Alpine  -> /bin/sh         (artifacts/alpine-verify.cpio.gz -> ALPINE_BIN_SH_OK)
#   5. redroid -> /system/bin/sh  (artifacts/rd-mini.cpio.gz, bootstrap linker -> REDROID_SYSTEM_BIN_SH_OK)
#
# Idempotent: existing downloads reused; the QEMU verifies always re-run.
# Needs root (chroot/mknod), qemu-system-aarch64, binfmt qemu-aarch64 (cross apk),
# and docker (for the redroid arm64 image). On x86 the guest runs under TCG (slow).
set -euo pipefail
cd "$(dirname "$0")"                       # tests/
ART=artifacts; mkdir -p "$ART"
FT=finaltest                               # unpack_boot.py / rd-init live here

BOOT_IMG_URL="${BOOT_IMG_URL:-https://github.com/tiann/KernelSU/releases/download/v2.1.2/android15-6.6.102_2025-10-boot.img.gz}"
BOOT_IMG_SHA="fc156e8ba0b2bc2252622fe59c61dbe1e1f13c1b77be8f95517e837f270fc120"
ALPINE_MIRROR="${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64}"
PKGS="iproute2 iputils tcpdump bpftool bash"
REDROID_IMG="${REDROID_IMG:-redroid/redroid:15.0.0-latest}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"

say()  { printf '\n== %s ==\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }; }
need curl; need python3; need cpio; need gzip; need qemu-system-aarch64
[ "$(id -u)" = 0 ] || { echo "run as root (chroot/mknod needed)" >&2; exit 1; }
[ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ] || echo "warning: binfmt qemu-aarch64 not registered; cross apk may fail" >&2
QEMU_STATIC="$(command -v qemu-aarch64-static || true)"
FAILED=0

# boot GKI + an initramfs, assert a marker shows up ------------------------------
qboot() { # $1=initrd  $2=marker  $3=label  [$4=mem MiB]
  local log="$ART/verify-$(echo "$3" | tr ' /' '__').log"
  say "verify: $3 — boot GKI 6.6 + $(basename "$1") (TCG, ${BOOT_TIMEOUT}s)"
  timeout "$BOOT_TIMEOUT" qemu-system-aarch64 -M virt -cpu max -smp 2 -m "${4:-2048}" \
    -nographic -no-reboot -kernel "$ART/Image" -initrd "$1" \
    -append "console=ttyAMA0 rdinit=/init panic=1" > "$log" 2>&1 || true
  if grep -q "$2" "$log"; then echo "  [PASS] $3 ($2)"; else echo "  [FAIL] $3 — see $log"; FAILED=1; fi
}

# 1. kernel Image (GKI 6.6) -----------------------------------------------------
if [ ! -s "$ART/Image" ]; then
  say "download: GKI 6.6 boot.img -> Image"
  [ -s "$ART/boot.img.gz" ] || curl -fSL -o "$ART/boot.img.gz" "$BOOT_IMG_URL"
  echo "$BOOT_IMG_SHA  $ART/boot.img.gz" | sha256sum -c - || { echo "boot.img.gz checksum mismatch" >&2; exit 1; }
  gunzip -kf "$ART/boot.img.gz"
  python3 "$FT/unpack_boot.py" "$ART/boot.img" "$ART/Image"
fi
echo "Image: $(strings -n12 "$ART/Image" | grep -m1 'Linux version' | cut -d'(' -f1)"

# 2. Alpine arm64 rootfs (+ matrix tools) ---------------------------------------
if [ ! -e "$ART/aroot/.pb-ready" ]; then
  say "download: Alpine arm64 rootfs + $PKGS"
  [ -n "$QEMU_STATIC" ] || { echo "need qemu-aarch64-static to populate the arm64 rootfs" >&2; exit 1; }
  if [ ! -s "$ART/alpine-arm64.tar.gz" ]; then
    f=$(curl -fsSL "$ALPINE_MIRROR/latest-releases.yaml" | grep -m1 -oE 'alpine-minirootfs[^ ]*\.tar\.gz')
    echo "  fetching $f"; curl -fSL -o "$ART/alpine-arm64.tar.gz" "$ALPINE_MIRROR/$f"
  fi
  rm -rf "$ART/aroot" && mkdir -p "$ART/aroot"
  tar -C "$ART/aroot" -xzf "$ART/alpine-arm64.tar.gz"
  cp "$QEMU_STATIC" "$ART/aroot/usr/bin/qemu-aarch64-static"
  cp /etc/resolv.conf "$ART/aroot/etc/resolv.conf"
  chroot "$ART/aroot" /usr/bin/qemu-aarch64-static /sbin/apk add --no-cache $PKGS
  rm -f "$ART/aroot/usr/bin/qemu-aarch64-static"
  touch "$ART/aroot/.pb-ready"
fi
echo "aroot: $(du -sh "$ART/aroot" | cut -f1)"

# 3. redroid15 arm64 rootfs -----------------------------------------------------
HAVE_DOCKER=0
if command -v docker >/dev/null 2>&1; then
  HAVE_DOCKER=1
  if [ ! -e "$ART/redroid/.pb-ready" ]; then
    say "download: redroid15 arm64 rootfs (docker export)"
    docker pull --platform=linux/arm64 "$REDROID_IMG"
    cid=$(docker create --platform=linux/arm64 "$REDROID_IMG")
    rm -rf "$ART/redroid" && mkdir -p "$ART/redroid"
    docker export "$cid" | tar -C "$ART/redroid" -x
    docker rm "$cid" >/dev/null
    touch "$ART/redroid/.pb-ready"
  fi
  if [ ! -s "$ART/busybox-arm64" ]; then            # static musl busybox for the redroid initramfs /init helper
    say "download: static busybox (musl arm64)"
    bid=$(docker create --platform=linux/arm64 busybox:musl); docker cp "$bid:/bin/busybox" "$ART/busybox-arm64"; docker rm "$bid" >/dev/null
  fi
  echo "redroid: $(du -sh "$ART/redroid" | cut -f1)"
else
  echo "redroid: docker not found — cannot fetch the arm64 image; redroid verify will be SKIPPED"
fi

# 4. VERIFY Alpine boots /bin/sh ------------------------------------------------
say "pack alpine verify initramfs"
cat > "$ART/aroot/init" <<'SH'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null; mount -t sysfs sys /sys 2>/dev/null; mount -t devtmpfs dev /dev 2>/dev/null
echo "########## ALPINE-SH-ON-GKI ##########"; cat /proc/version
/bin/sh -c 'echo ALPINE_BIN_SH_OK; uname -a'
echo "########## DONE ##########"; sync; poweroff -f
SH
chmod 755 "$ART/aroot/init"
rm -f "$ART/aroot/dev/console" "$ART/aroot/dev/null"
mknod -m600 "$ART/aroot/dev/console" c 5 1; mknod -m666 "$ART/aroot/dev/null" c 1 3
( cd "$ART/aroot" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -1 ) > "$ART/alpine-verify.cpio.gz"
qboot "$ART/alpine-verify.cpio.gz" ALPINE_BIN_SH_OK "Alpine /bin/sh"

# 5. VERIFY redroid boots /system/bin/sh (via bootstrap linker chain) -----------
if [ "$HAVE_DOCKER" = 1 ]; then
  say "pack redroid smoke initramfs (bootstrap linker)"
  R="$ART/redroid"; RD="$ART/rd-mini"; rm -rf "$RD"
  mkdir -p "$RD"/{bin,dev,proc,sys} "$RD/apex/com.android.runtime/bin" "$RD/system/bin/bootstrap" "$RD/system/lib64/bootstrap"
  install -m755 "$ART/busybox-arm64" "$RD/bin/busybox"
  install -m755 "$FT/rd-init"        "$RD/init"
  cp -a "$R/system/bin/sh"                 "$RD/system/bin/"            2>/dev/null || true
  cp -a "$R/system/bin/toybox"             "$RD/system/bin/"            2>/dev/null || true
  cp -a "$R/system/bin/bootstrap/linker64" "$RD/system/bin/bootstrap/" 2>/dev/null || true
  cp -a "$R"/system/lib64/bootstrap/*      "$RD/system/lib64/bootstrap/" 2>/dev/null || true
  ln -sf /apex/com.android.runtime/bin/linker64 "$RD/system/bin/linker64"
  ln -sf /system/bin/bootstrap/linker64         "$RD/apex/com.android.runtime/bin/linker64"
  mknod -m600 "$RD/dev/console" c 5 1; mknod -m666 "$RD/dev/null" c 1 3
  ( cd "$RD" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -1 ) > "$ART/rd-mini.cpio.gz"
  qboot "$ART/rd-mini.cpio.gz" REDROID_SYSTEM_BIN_SH_OK "redroid15 /system/bin/sh"
else
  echo "  [SKIP] redroid15 /system/bin/sh — no docker"
fi

say "result"
echo "  Image   : $(du -h "$ART/Image" | cut -f1)   aroot: $(du -sh "$ART/aroot" | cut -f1)   redroid: $(du -sh "$ART/redroid" 2>/dev/null | cut -f1 || echo -)"
[ "$FAILED" = 0 ] && echo "  ALL ROOTFS BOOTED TO A SHELL ON GKI 6.6" || { echo "  !! some rootfs failed to boot — see artifacts/verify-*.log"; exit 1; }
