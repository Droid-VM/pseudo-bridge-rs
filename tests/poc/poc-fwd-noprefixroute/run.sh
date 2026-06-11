#!/usr/bin/env bash
# Faithful fwd-mode scenario (matches the intended deployment):
#   eth0  = real upstream : 192.168.50.10/24  (NORMAL -> connected route + default via gw)
#   vethL = br side       : 192.168.50.250/24  NOPREFIXROUTE  (SAME subnet as eth0!)
#   /32 //128 VM routes -> vethL (src pinned to vethL's own addr)
#   vethR = the VM        : 192.168.50.101/24
# Prove:
#   (A) host NORMAL traffic (gw / internet) still egresses eth0, NOT vethL  -> route NOT stolen
#   (B) host -> VM egresses vethL with the right src
#   (C) VM -> host: ARP/ND replies on vethL
#   (D) contrast: drop noprefixroute -> 2 connected routes -> gw resolution becomes ambiguous
set -u
HOST=fwH; UP=fwUP; VM=fwVM
cleanup(){ for n in $HOST $UP $VM; do ip netns del $n 2>/dev/null; done; }
trap cleanup EXIT; cleanup
for n in $HOST $UP $VM; do ip netns add $n; done
ip link add eth0  netns $HOST type veth peer name uplink netns $UP
ip link add vethL netns $HOST type veth peer name vethR netns $VM
for d in eth0 vethL lo; do ip -n $HOST link set $d up; done
ip -n $UP link set uplink up; ip -n $UP link set lo up
ip -n $VM link set vethR up; ip -n $VM link set lo up

# HOST: eth0 normal, vethL same-subnet noprefixroute
ip -n $HOST addr add 192.168.50.10/24  dev eth0
ip -n $HOST addr add 192.168.50.250/24 dev vethL noprefixroute
ip -n $HOST addr add 2001:db8:50::10/64  dev eth0 nodad
ip -n $HOST addr add 2001:db8:50::250/64 dev vethL noprefixroute nodad
# UP = gateway (+ a stand-in "internet" host 8.8.8.8 on its lo)
ip -n $UP addr add 192.168.50.1/24 dev uplink
ip -n $UP addr add 2001:db8:50::1/64 dev uplink nodad
ip -n $UP addr add 8.8.8.8/32 dev lo
ip netns exec $UP sysctl -qw net.ipv4.ip_forward=1
# VM
ip -n $VM addr add 192.168.50.101/24 dev vethR
ip -n $VM addr add 2001:db8:50::101/64 dev vethR nodad
sleep 0.4
# HOST routing: default via gw on eth0; explicit VM /32 //128 via vethL (src = vethL own addr)
ip -n $HOST route add default via 192.168.50.1 dev eth0
ip -n $HOST -6 route add default via 2001:db8:50::1 dev eth0
ip -n $HOST route add 192.168.50.101/32 dev vethL src 192.168.50.250
ip -n $HOST -6 route add 2001:db8:50::101/128 dev vethL src 2001:db8:50::250

echo "== connected routes for the subnet (expect ONLY eth0 — vethL is noprefixroute) =="
ip -n $HOST route show | grep "192.168.50.0/24" | sed 's/^/  /'
echo "  (count: $(ip -n $HOST route show | grep -c '192.168.50.0/24'))"

echo
echo "== (A) host NORMAL traffic must egress eth0, NOT vethL =="
echo "  -> gw 192.168.50.1 : $(ip -n $HOST route get 192.168.50.1 | head -1)"
echo "  -> internet 8.8.8.8: $(ip -n $HOST route get 8.8.8.8 | head -1)"
ip -n $HOST route get 192.168.50.1 | grep -q "dev eth0" && ip -n $HOST route get 8.8.8.8 | grep -q "dev eth0" \
  && echo "  [PASS] normal traffic stays on eth0" || echo "  [FAIL] route stolen by vethL"
ip netns exec $HOST ping -c2 -W1 192.168.50.1 >/dev/null 2>&1 && echo "  [PASS] gw reachable via eth0"   || echo "  [FAIL] gw unreachable"
ip netns exec $HOST ping -c2 -W1 8.8.8.8      >/dev/null 2>&1 && echo "  [PASS] internet reachable via eth0" || echo "  [FAIL] internet unreachable"

echo
echo "== (B) host -> VM must egress vethL with src 192.168.50.250 =="
echo "  v4: $(ip -n $HOST route get 192.168.50.101 | head -1)"
echo "  v6: $(ip -n $HOST -6 route get 2001:db8:50::101 | head -1)"
ip netns exec $HOST ping -c2 -W1 192.168.50.101  >/dev/null 2>&1 && echo "  v4 [PASS] VM reachable" || echo "  v4 [FAIL]"
ip netns exec $HOST ping -c2 -W1 2001:db8:50::101 >/dev/null 2>&1 && echo "  v6 [PASS] VM reachable" || echo "  v6 [FAIL]"

echo
echo "== (C) VM -> host: ARP(v4)/ND(v6) reply on vethL =="
ip netns exec $VM ping -c2 -W1 192.168.50.250  >/dev/null 2>&1 && echo "  v4 [PASS] $(ip -n $VM neigh show dev vethR | grep '192.168.50.250')" || echo "  v4 [FAIL]"
ip netns exec $VM ping -c2 -W1 2001:db8:50::250 >/dev/null 2>&1 && echo "  v6 [PASS] $(ip -n $VM neigh show dev vethR | grep '2001:db8:50::250')" || echo "  v6 [FAIL]"

echo
echo "== (D) CONTRAST: drop noprefixroute on vethL -> 2 connected routes -> ambiguity =="
ip -n $HOST addr del 192.168.50.250/24 dev vethL
ip -n $HOST addr add 192.168.50.250/24 dev vethL    # NORMAL this time
echo "  connected routes now: $(ip -n $HOST route show | grep -c '192.168.50.0/24') (eth0 + vethL)"
ip -n $HOST route show | grep "192.168.50.0/24" | sed 's/^/    /'
echo "  -> gw 192.168.50.1 : $(ip -n $HOST route get 192.168.50.1 | head -1)"
echo "  (^ if this shows dev vethL, host would ARP the gw on the wrong segment = the breakage)"
