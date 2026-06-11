#!/bin/bash
# Focused ebpf-on-GKI probe: build the direct/ebpf env, run pbridge, force a
# guest learn (arp+ping), then dump the actual BPF/tc state to find why the
# fast path doesn't forward. Mirrors matrix.sh's direct/ebpf config.
set -u
BIN=/opt/pb/pbridge
GW=10.0.0.1; HOSTIP=10.0.0.2; GUEST=10.0.0.5
BT=$(command -v bpftool)

for ns in up hostns g1; do ip netns add "$ns"; done
ip link add up0 netns hostns type veth peer name u0 netns up
ip link add gbr netns hostns type veth peer name g1eth netns g1
ip -n up addr add $GW/24 dev u0; ip -n up link set u0 up; ip -n up link set lo up
ip -n hostns link add br0 type bridge
ip -n hostns link set gbr master br0
ip -n hostns link set up0 up; ip -n hostns link set gbr up; ip -n hostns link set br0 up
ip -n hostns addr add $HOSTIP/24 dev up0
ip -n g1 addr add $GUEST/24 dev g1eth; ip -n g1 link set g1eth up; ip -n g1 link set lo up
# direct: pre-create the inner veth pair
ip -n hostns link add mtnat1 type veth peer name mtnat1p
ip -n hostns link set mtnat1p master br0
ip -n hostns link set mtnat1 up; ip -n hostns link set mtnat1p up

echo "@@ ifindexes in hostns:"; ip -n hostns -o link | awk -F': ' '{print $1, $2}'

PB_EBPF_DEBUG=1 ip netns exec hostns "$BIN" --upstream up0 --fwd-device mtnat1 --l2nat-backend ebpf --entry-timeout 30 \
   >/tmp/pb.log 2>&1 &
PB=$!
# wait until install completes (TCG is slow: loadall+BTF verify can take >15s)
for i in $(seq 1 40); do grep -q 'userspace backend running' /tmp/pb.log && break; sleep 1; done
echo "@@ waited $(grep -c 'userspace backend running' /tmp/pb.log) (1=ready) for install"
echo "@@ pbridge log (install diag):"; cat /tmp/pb.log

echo "@@ PING 1 (cold: triggers ARP->learn->map program):"
ip netns exec g1 ping -c3 -W3 $GW; echo "ping1 rc=$?"
echo "@@ ip2mac4 after learn:"; ip netns exec hostns $BT map dump pinned /run/pbridge-bpf/o/ip2mac4 2>&1 || $BT map dump name ip2mac4 2>&1
echo "@@ PING 2 (warm: fast path should forward):"
ip netns exec g1 ping -c3 -W3 $GW; echo "ping2 rc=$?"
sleep 1

echo "@@ tc filter show (mtnat1 ingress) in hostns:"; ip netns exec hostns tc filter show dev mtnat1 ingress
echo "@@ tc filter show (up0 ingress) in hostns:"; ip netns exec hostns tc filter show dev up0 ingress
echo "@@ bpftool prog show:"; ip netns exec hostns $BT prog show 2>&1 | grep -A3 -iE 'cls_inner|cls_upstream|classifier|sched_cls' | head
echo "@@ pin dir listing:"; ls -la /run/pbridge-bpf/o 2>&1
echo "@@ config map dump:"; $BT map dump pinned /run/pbridge-bpf/o/config 2>&1
echo "@@ ip2mac4 map dump:"; $BT map dump pinned /run/pbridge-bpf/o/ip2mac4 2>&1
echo "@@ pbridge log (after):"; cat /tmp/pb.log
kill $PB 2>/dev/null
echo "@@ EBPF_DEBUG_DONE"
