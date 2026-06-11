#!/usr/bin/env bash
# Build pbridge static binaries into dist/.
#
#   ./build.sh            # both targets (default)
#   ./build.sh x64        # x86_64-unknown-linux-musl  -> dist/pbridge-linux-x64
#   ./build.sh arm64      # aarch64-unknown-linux-musl -> dist/pbridge-android-arm64
#   ./build.sh host       # quick host debug build (./target/debug/pbridge)
#
# Both release targets are fully static (musl), so they run under any libc —
# glibc, musl, or Android bionic. The aarch64 target links with the bundled
# rust-lld (no external cross toolchain needed). build.rs compiles the BPF
# datapath with clang into one arch-independent object embedded in the binary.
set -euo pipefail
cd "$(dirname "$0")"                         # repo root

TARGET="${1:-all}"
X64=x86_64-unknown-linux-musl
ARM=aarch64-unknown-linux-musl

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: missing required tool '$1'" >&2; exit 1; }; }
need cargo
need clang                                   # build.rs needs it for the BPF object

add_target() { command -v rustup >/dev/null 2>&1 && rustup target add "$1" >/dev/null 2>&1 || true; }

build_x64() {
    add_target "$X64"
    echo "== build $X64 =="
    cargo build --release --target "$X64"
    install -Dm755 "target/$X64/release/pbridge" dist/pbridge-linux-x64
}
build_arm() {
    add_target "$ARM"
    echo "== build $ARM (rust-lld) =="
    RUSTFLAGS="-C linker=rust-lld" cargo build --release --target "$ARM"
    install -Dm755 "target/$ARM/release/pbridge" dist/pbridge-android-arm64
}

case "$TARGET" in
    all)            build_x64; build_arm ;;
    x64|x86_64)     build_x64 ;;
    arm64|aarch64)  build_arm ;;
    host)           echo "== host debug build =="; cargo build; exit 0 ;;
    -h|--help)      sed -n '2,13p' "$0"; exit 0 ;;
    *)              echo "usage: $0 [all|x64|arm64|host]" >&2; exit 2 ;;
esac

echo
echo "== artifacts =="
for f in dist/pbridge-linux-x64 dist/pbridge-android-arm64; do
    [ -f "$f" ] && printf '%-32s %8s  %s\n' "$f" "$(du -h "$f" | cut -f1)" "$(file -b "$f" | cut -d, -f1-2)"
done
