#!/usr/bin/env bash
# PoC: ebpf tc/cls_bpf in-place rewrite (ARP sha / ND LLA + ICMPv6 csum) — the
# "ebpf in-place modify" path in ARCHITECTURE.md §offload modify-vs-channel.
#   a1 ─send─▶ a0 [cls_bpf: rewrite + fix csum + redirect b0] ─▶ b0 ~veth~ b1 ─recv▶
# Runs in the host root netns (veths carry no IP; pin lives in the real bpffs,
# which an `ip netns exec` mount-ns would hide).
set -u
PIN=/sys/fs/bpf/pocebpf
BT=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1); [ -x "$BT" ] || BT=bpftool
cd "$(dirname "$0")"
cleanup() { tc qdisc del dev a0 clsact 2>/dev/null; ip link del a0 2>/dev/null; ip link del b0 2>/dev/null; rm -rf $PIN 2>/dev/null; }
trap cleanup EXIT
cleanup

echo "== compile =="
clang -O2 -g -target bpf -I /usr/include/x86_64-linux-gnu -c poc.bpf.c -o poc.o || exit 1

echo "== veth =="
ip link add a0 type veth peer name a1
ip link add b0 type veth peer name b1
for d in a0 a1 b0 b1; do ip link set $d up; sysctl -qw net.ipv6.conf.$d.disable_ipv6=1; done
BIFX=$(cat /sys/class/net/b0/ifindex); echo "  b0 ifindex=$BIFX"

echo "== load prog + config(ifx=b0, mac=02:11:22:33:44:55) =="
$BT prog loadall poc.o $PIN pinmaps $PIN || exit 1
PROG=$(ls $PIN | grep -v config | head -1); echo "  prog=$PROG"
# value = struct cfg { u32 ifx(LE); u8 mac[6]; u8 pad[2] }
i0=$((BIFX&255)); i1=$(((BIFX>>8)&255)); i2=$(((BIFX>>16)&255)); i3=$(((BIFX>>24)&255))
$BT map update pinned $PIN/config key 0 0 0 0 value $i0 $i1 $i2 $i3 2 0x11 0x22 0x33 0x44 0x55 0 0 || exit 1

echo "== attach cls_bpf on a0 ingress =="
tc qdisc add dev a0 clsact
tc filter add dev a0 ingress bpf da object-pinned $PIN/$PROG || exit 1

echo "== run probe =="
python3 poc.py
