#!/bin/bash
# Quick single-guest smoke for one (mode,engine): guest v4+v6 reach gateway through
# the pseudo-bridge, and on the upstream wire every src mac == HOSTMAC.
#   ns up (gw) ── up0(hostns: pbridge) [br0] ── g1
# fwd mode: pbridge makes mt-if/mt-br, mt-br in br0, guest port gbr in br0.
# direct mode: up0 itself enslaved in br0; pbridge hooks up0 egress/ingress.
set -u
BIN=${BIN:-/root/gitrs/pseudo-bridge-rs/target/debug/pbridge}
MODE=${1:-fwd}; ENGINE=${2:-nft}
HMAC=02:00:00:00:00:01
PB=""
cleanup(){ [ -n "$PB" ] && kill $PB 2>/dev/null; for n in up hostns g1; do ip netns del $n 2>/dev/null; done; }
trap cleanup EXIT
for n in up hostns g1; do ip netns add $n; done
ip link add up0 netns hostns type veth peer name u0 netns up
ip link add gbr netns hostns type veth peer name g1eth netns g1
ip -n up addr add 10.0.0.1/24 dev u0
ip -n up addr add fd00::1/64 dev u0 nodad
ip -n up link set u0 up; ip -n up link set lo up
ip -n hostns link set up0 address $HMAC
ip -n hostns link set up0 up
ip -n hostns link add br0 type bridge; ip -n hostns link set br0 up
ip -n hostns link set gbr master br0; ip -n hostns link set gbr up
ip netns exec hostns sysctl -q net.ipv4.conf.all.rp_filter=0 2>/dev/null
ARGS=(-i up0 -e "$ENGINE" -m "$MODE")
if [ "$MODE" = fwd ]; then
  ip -n hostns addr add 10.0.0.2/24 dev up0
  ip -n hostns addr add fd00::2/64 dev up0 nodad
  ARGS+=(--fwd-device-if mt-if --fwd-device-br mt-br)
else
  # direct: up0 in br0, IP on br0
  ip -n hostns link set up0 master br0
  ip -n hostns addr add 10.0.0.2/24 dev br0
  ip -n hostns addr add fd00::2/64 dev br0 nodad
fi
# guest in br0
ip -n g1 addr add 10.0.0.5/24 dev g1eth
ip -n g1 addr add fd00::5/64 dev g1eth nodad
ip -n g1 link set g1eth up; ip -n g1 link set lo up
# upstream single-MAC enforcement on u0 ingress
ip netns exec up nft -f - <<EOF
table netdev g {
  chain c {
    type filter hook ingress device "u0" priority -300
    ether saddr $HMAC accept
    meta pkttype { broadcast, multicast } accept
    ether type arp accept
    ether saddr != $HMAC drop
  }
}
EOF
ip netns exec hostns "${BIN[@]}" "${ARGS[@]}" >/tmp/pb-smoke.log 2>&1 &
PB=$!
for i in $(seq 1 20); do grep -q 'backend running' /tmp/pb-smoke.log && break; sleep 0.3; done
grep -q 'backend running' /tmp/pb-smoke.log || { echo "NOT RUNNING"; cat /tmp/pb-smoke.log; exit 1; }
# fwd: pbridge made mt-if/mt-br but enslaving fwd1 into the VM bridge is the operator's
# job (pbridge only pins up0; it tracks mt-br's master dynamically). Do it now.
if [ "$MODE" = fwd ]; then
  for i in $(seq 1 20); do ip -n hostns link show mt-br >/dev/null 2>&1 && break; sleep 0.2; done
  ip -n hostns link set mt-br master br0
  sleep 1   # let pbridge react to the new master (nft rebuild for BRMAC) + bridge warm up
fi
rc=0
echo "== [$MODE/$ENGINE] guest v4 -> gateway =="
if ip netns exec g1 ping -c2 -W3 10.0.0.1 >/dev/null 2>&1; then echo "  v4 OK"; else echo "  v4 FAIL"; rc=1; fi
echo "== guest v6 -> gateway =="
if ip netns exec g1 ping -c2 -W3 fd00::1 >/dev/null 2>&1; then echo "  v6 OK"; else echo "  v6 FAIL"; rc=1; fi
echo "== no leak on wire (all src == HOSTMAC) =="
GMAC=$(ip -n g1 -br link show g1eth | awk '{print $3}')
ip netns exec up timeout 3 tcpdump -i u0 -e -n 'icmp or icmp6 or arp' >/tmp/cap.txt 2>/dev/null &
TPID=$!
sleep 0.3; ip netns exec g1 ping -c2 -W2 10.0.0.1 >/dev/null 2>&1; ip netns exec g1 ping -c2 -W2 fd00::1 >/dev/null 2>&1; wait $TPID 2>/dev/null
if grep -q "$GMAC >" /tmp/cap.txt; then echo "  LEAK: guest mac on wire"; rc=1; else echo "  no leak OK"; fi
exit $rc
