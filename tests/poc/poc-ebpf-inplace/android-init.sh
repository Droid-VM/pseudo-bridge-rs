#!/bin/sh
# rdinit for booting android15-6.6 GKI under QEMU and running the ebpf in-place
# rewrite PoC (ARP sha / ND LLA + ICMPv6 csum) on the real GKI kernel.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /sys/fs/bpf
mount -t bpf bpf /sys/fs/bpf 2>/dev/null
ip link set lo up 2>/dev/null

echo "PBRIDGE_EBPF_POC_BOOT $(uname -r) $(uname -m)"
PIN=/sys/fs/bpf/poc

ip link add a0 type veth peer name a1
ip link add b0 type veth peer name b1
for d in a0 a1 b0 b1; do ip link set $d up; echo 1 > /proc/sys/net/ipv6/conf/$d/disable_ipv6 2>/dev/null; done
BIFX=$(cat /sys/class/net/b0/ifindex)
echo "b0 ifindex=$BIFX"

echo "--- bpftool prog loadall ---"
bpftool prog loadall /opt/pbpoc/poc.o $PIN pinmaps $PIN 2>&1 || echo "LOAD FAIL"
PROG=$(ls $PIN 2>/dev/null | grep -v config | head -1)
echo "prog=$PROG"
i0=$((BIFX&255)); i1=$(((BIFX>>8)&255)); i2=$(((BIFX>>16)&255)); i3=$(((BIFX>>24)&255))
bpftool map update pinned $PIN/config key 0 0 0 0 value $i0 $i1 $i2 $i3 2 0x11 0x22 0x33 0x44 0x55 0 0 2>&1 || echo "MAP FAIL"

echo "--- tc attach a0 ingress ---"
tc qdisc add dev a0 clsact 2>&1
tc filter add dev a0 ingress bpf da object-pinned $PIN/$PROG 2>&1 || echo "ATTACH FAIL"

echo "===== EBPF POC ====="
python3 /opt/pbpoc/poc.py 2>&1
echo "===== EBPF POC DONE ====="
echo "--- diag ---"; bpftool --version 2>&1 | head -1; tc -V 2>&1
echo "PBRIDGE_EBPF_POC_COMPLETE"
sync
poweroff -f 2>/dev/null
echo o > /proc/sysrq-trigger 2>/dev/null
while true; do sleep 1; done
