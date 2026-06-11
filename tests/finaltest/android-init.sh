#!/bin/bash
# rdinit for the android16-6.12 GKI QEMU boot: mount the basics, then run the
# pbridge test matrix with ENV=android (engines: ebpf, userspace — nft skipped,
# since stock GKI has no NF_TABLES). Prints a parseable banner and powers off.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /run /tmp /sys/fs/bpf
mount -t tmpfs tmpfs /run 2>/dev/null
mount -t bpf bpf /sys/fs/bpf 2>/dev/null
ip link set lo up 2>/dev/null

echo "PBRIDGE_ANDROID_BOOT_OK $(uname -r) $(uname -m)"
echo "===== running android matrix (ENV=android) ====="
cd /opt/pb
BIN=/opt/pb/pbridge ENV=android bash /opt/pb/matrix.sh
echo "===== android matrix done (rc=$?) ====="

# --- diagnostics for the ebpf backend (it failed on GKI; surface why) ---
echo "===== EBPF DIAG ====="
echo "--- bpftool version ---"; bpftool version 2>&1 | head -2
echo "--- tc -V ---"; tc -V 2>&1
echo "--- pbridge log (direct/ebpf) ---"; sed -n '1,40p' /tmp/pb-direct-ebpf.log 2>&1
echo "--- dmesg bpf/verifier tail ---"; dmesg 2>/dev/null | grep -iE 'bpf|verifier|cls' | tail -20
echo "===== EBPF DIAG END ====="

echo "PBRIDGE_ANDROID_RUN_COMPLETE"

# clean power off so QEMU exits
sync
poweroff -f 2>/dev/null
echo o > /proc/sysrq-trigger 2>/dev/null
while true; do sleep 1; done
