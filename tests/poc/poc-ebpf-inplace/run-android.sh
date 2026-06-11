#!/usr/bin/env bash
# Boot android15-6.6 GKI (artifacts/Image15) under QEMU and run the ebpf in-place
# rewrite PoC on the real GKI kernel. Reuses the Alpine arm64 rootfs
# (artifacts/aroot, from tests/setup-artifacts.sh) which already has tc/bpftool/python3.
# NOTE: overwrites aroot/init with the PoC init; re-run setup-artifacts.sh to restore.
set -u
cd "$(dirname "$0")"
T=../../artifacts  # tests/artifacts/
AROOT=$T/aroot
command -v qemu-system-aarch64 >/dev/null || { echo "need qemu-system-aarch64"; exit 1; }
[ -s $T/Image15 ]    || { echo "need tests/artifacts/Image15"; exit 1; }
[ -e $AROOT/.pb-ready ] || { echo "need tests/artifacts/aroot (run tests/setup-artifacts.sh)"; exit 1; }

echo "== compile poc.o (bpf bytecode, arch-agnostic) =="
clang -O2 -g -target bpf -I /usr/include/x86_64-linux-gnu -c poc.bpf.c -o poc.o || exit 1

echo "== stage into aroot =="
mkdir -p $AROOT/opt/pbpoc
cp poc.o poc.py $AROOT/opt/pbpoc/
cp android-init.sh $AROOT/init; chmod 755 $AROOT/init
rm -f $AROOT/dev/console $AROOT/dev/null
mknod -m600 $AROOT/dev/console c 5 1
mknod -m666 $AROOT/dev/null    c 1 3

echo "== pack initramfs =="
( cd $AROOT && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -1 ) > $T/ebpf-poc-initrd.cpio.gz
echo "  initrd: $(du -h $T/ebpf-poc-initrd.cpio.gz | cut -f1)"

echo "== boot android15-6.6 (Image15) QEMU/TCG (timeout 360) =="
timeout 360 qemu-system-aarch64 -M virt -cpu max -smp 2 -m 2048 -nographic -no-reboot \
  -kernel $T/Image15 -initrd $T/ebpf-poc-initrd.cpio.gz \
  -append "console=ttyAMA0 rdinit=/init panic=1" 2>&1 | tee /tmp/ebpf-poc-android15.log \
  | sed -n '/PBRIDGE_EBPF_POC_BOOT/,/PBRIDGE_EBPF_POC_COMPLETE/p'
echo "== full log: /tmp/ebpf-poc-android15.log =="
