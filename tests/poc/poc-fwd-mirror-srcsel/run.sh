#!/usr/bin/env bash
# Scenario: vethL MIRRORS eth0's EXACT addrs (no extra IP consumed), across TWO subnets.
#   eth0  = 192.168.50.10/24 + 192.168.51.10/24 (+ v6)  NORMAL  (upstream: connected + default gw)
#   vethL = 192.168.50.10/24 + 192.168.51.10/24 (+ v6)  NOPREFIXROUTE  (br side, same IPs)
#   VMs   = 192.168.50.101 + 192.168.51.101 (+ v6) on vethR  (two subnets, one L2 seg)
# Q the user wants answered: with MULTIPLE src candidates (50.10 & 51.10 both on vethL),
#   does host->VM pick the RIGHT src per dst-subnet? And does duplicating the IP onto vethL break
#   normal upstream / ARP / return path?  (target: per-entry pin works, strict rp_filter OK)
set -u
HOST=msH; UP=msUP; VM=msVM
cleanup(){ for n in $HOST $UP $VM; do ip netns del $n 2>/dev/null; done; }
trap cleanup EXIT; cleanup
for n in $HOST $UP $VM; do ip netns add $n; done
ip link add eth0  netns $HOST type veth peer name uplink netns $UP
ip link add vethL netns $HOST type veth peer name vethR netns $VM
for d in eth0 vethL lo; do ip -n $HOST link set $d up; done
ip -n $UP link set uplink up; ip -n $UP link set lo up
ip -n $VM link set vethR up; ip -n $VM link set lo up

echo "== add SAME addrs to eth0(normal) and vethL(noprefixroute) — does dup add succeed? =="
for sub in 50 51; do
  ip -n $HOST addr add 192.168.$sub.10/24 dev eth0                 && echo "  eth0  192.168.$sub.10/24 OK"
  ip -n $HOST addr add 192.168.$sub.10/24 dev vethL noprefixroute  && echo "  vethL 192.168.$sub.10/24 noprefixroute OK"
  ip -n $HOST addr add 2001:db8:$sub::10/64 dev eth0 nodad
  ip -n $HOST addr add 2001:db8:$sub::10/64 dev vethL noprefixroute nodad
done
ip -n $UP addr add 192.168.50.1/24 dev uplink
ip -n $UP addr add 2001:db8:50::1/64 dev uplink nodad
ip -n $UP addr add 8.8.8.8/32 dev lo
ip netns exec $UP sysctl -qw net.ipv4.ip_forward=1 >/dev/null
ip -n $VM addr add 192.168.50.101/24 dev vethR
ip -n $VM addr add 192.168.51.101/24 dev vethR
ip -n $VM addr add 2001:db8:50::101/64 dev vethR nodad
ip -n $VM addr add 2001:db8:51::101/64 dev vethR nodad
sleep 0.4
ip -n $HOST route add default via 192.168.50.1 dev eth0
ip -n $HOST -6 route add default via 2001:db8:50::1 dev eth0

echo
echo "== local table: the duplicated addrs (one local entry per dev) =="
ip -n $HOST route show table local | grep -E "192.168.5[01].10 " | sed 's/^/  /'

echo
echo "== connected routes for the subnets (expect ONLY eth0 — vethL noprefixroute => none) =="
ip -n $HOST route show | grep -E "192.168.5[01].0/24" | sed 's/^/  /'
n=$(ip -n $HOST route show | grep -cE "192.168.5[01].0/24")
[ "$n" = 2 ] && echo "  [PASS] 2 connected routes, both eth0 (50+51)" || echo "  [??] count=$n"

echo
echo "== (A) normal traffic stays on eth0 + reachable =="
echo "  gw  -> $(ip -n $HOST route get 192.168.50.1 | head -1)"
echo "  net -> $(ip -n $HOST route get 8.8.8.8 | head -1)"
ip netns exec $HOST ping -c1 -W1 192.168.50.1 >/dev/null 2>&1 && echo "  [PASS] gw reachable"       || echo "  [FAIL] gw"
ip netns exec $HOST ping -c1 -W1 8.8.8.8      >/dev/null 2>&1 && echo "  [PASS] internet reachable" || echo "  [FAIL] net"

echo
echo "== (B) host->VM /32 WITHOUT explicit src — kernel auto-pick (expect 51.101 gets WRONG src) =="
ip -n $HOST route add 192.168.50.101/32 dev vethL
ip -n $HOST route add 192.168.51.101/32 dev vethL
echo "  50.101 -> $(ip -n $HOST route get 192.168.50.101 | head -1)"
echo "  51.101 -> $(ip -n $HOST route get 192.168.51.101 | head -1)   <- src likely 50.10 = WRONG subnet"

echo
echo "== (C) host->VM /32 WITH per-entry pin src — expect RIGHT src per subnet =="
ip -n $HOST route change 192.168.50.101/32 dev vethL src 192.168.50.10
ip -n $HOST route change 192.168.51.101/32 dev vethL src 192.168.51.10
ip -n $HOST -6 route add 2001:db8:50::101/128 dev vethL src 2001:db8:50::10
ip -n $HOST -6 route add 2001:db8:51::101/128 dev vethL src 2001:db8:51::10
g50=$(ip -n $HOST route get 192.168.50.101 | head -1); echo "  50.101 -> $g50"
g51=$(ip -n $HOST route get 192.168.51.101 | head -1); echo "  51.101 -> $g51"
v50=$(ip -n $HOST -6 route get 2001:db8:50::101 | head -1); echo "  v6 50  -> $v50"
v51=$(ip -n $HOST -6 route get 2001:db8:51::101 | head -1); echo "  v6 51  -> $v51"
echo "$g50"|grep -q "src 192.168.50.10" && echo "$g51"|grep -q "src 192.168.51.10" \
  && echo "$v50"|grep -q "src 2001:db8:50::10" && echo "$v51"|grep -q "src 2001:db8:51::10" \
  && echo "  [PASS] every dst-subnet got its matching src (v4+v6)" || echo "  [FAIL] wrong src somewhere"

echo
echo "== (D) reachability both subnets both dirs, under STRICT rp_filter (symmetric return) =="
ip netns exec $HOST sysctl -qw net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.vethL.rp_filter=1 net.ipv4.conf.eth0.rp_filter=1 >/dev/null
for d in 192.168.50.101 192.168.51.101 2001:db8:50::101 2001:db8:51::101; do
  ip netns exec $HOST ping -c1 -W1 $d >/dev/null 2>&1 && echo "  host->$d [PASS]" || echo "  host->$d [FAIL]"
done
for s in 192.168.50.10 192.168.51.10 2001:db8:50::10 2001:db8:51::10; do
  ip netns exec $VM ping -c1 -W1 $s >/dev/null 2>&1 && echo "  VM->$s   [PASS]" || echo "  VM->$s   [FAIL]"
done

echo
echo "== (E) ARP/ND for the SHARED ip 50.10 must resolve to vethL's mac (not eth0's) on the VM seg =="
LMAC=$(ip -n $HOST -br link show vethL | awk '{print $3}')
echo "  vethL mac = $LMAC"
echo "  VM neigh 192.168.50.10  : $(ip -n $VM neigh show dev vethR | grep '192.168.50.10 ')"
echo "  VM neigh 2001:db8:50::10: $(ip -n $VM neigh show dev vethR | grep '2001:db8:50::10 ')"
