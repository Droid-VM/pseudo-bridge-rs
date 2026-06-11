#!/usr/bin/env bash
# Default fwd design: br0 has NO IP; the host's IP lives on up0 (a DIFFERENT L2 seg, not in br0).
# A VM on br0 wants to reach the host (VM->host). It ARPs for the host IP on the br0 segment.
# Q: does the host answer that ARP, given the IP is on up0 (not br0)?  And does data flow?
#
#   ns HOST: up0=192.168.50.10/24 (real host IP, standalone)  +  br0(NO IP){ vmtap }
#   ns VM:   vmeth=192.168.50.101/24
#   (real fwd also has fwd1 in br0 -> fwd0 -> pbridge -> up0; the VM's bcast ARP additionally
#    leaks upstream there, harmless. This PoC isolates the host-reply question.)
set -u
HOST=ivH; UP=ivUP; VM=ivVM
cleanup(){ for n in $HOST $UP $VM; do ip netns del $n 2>/dev/null; done; }
trap cleanup EXIT; cleanup
for n in $HOST $UP $VM; do ip netns add $n; done
ip link add up0   netns $HOST type veth peer name upstub netns $UP   # up0 = the physical port
ip link add vmtap netns $HOST type veth peer name vmeth  netns $VM   # vmtap -> bridged; vmeth = VM
ip -n $HOST link add name br0 type bridge forward_delay 0
ip -n $HOST link set vmtap master br0          # vmtap in bridge; up0 is NOT in bridge
for d in up0 vmtap br0 lo; do ip -n $HOST link set $d up; done
ip -n $UP link set upstub up; ip -n $UP link set lo up
ip -n $VM link set vmeth up; ip -n $VM link set lo up

ip -n $HOST addr add 192.168.50.10/24 dev up0          # host IP on up0
ip -n $HOST addr add 2001:db8:50::10/64 dev up0 nodad
# br0 stays IP-less
ip -n $VM addr add 192.168.50.101/24 dev vmeth
ip -n $VM addr add 2001:db8:50::101/64 dev vmeth nodad
sleep 0.3

BRMAC=$(ip -n $HOST -br link show br0 | awk '{print $3}')
echo "br0 mac = $BRMAC   (host's IP 192.168.50.10 is on up0, NOT on br0)"
echo "host routes touching the VM subnet:"
ip -n $HOST route show | grep 192.168.50 | sed 's/^/  /'

echo
echo "== (1) WITH /32 route (VM learned): VM -> host, default arp_ignore =="
ip -n $HOST route add 192.168.50.101/32 dev br0 src 192.168.50.10
ip -n $HOST -6 route add 2001:db8:50::101/128 dev br0 src 2001:db8:50::10
ip netns exec $VM ping -c2 -W1 192.168.50.10  >/dev/null 2>&1 && echo "  v4 [PASS] VM->host" || echo "  v4 [FAIL] VM->host"
ip netns exec $VM ping -c2 -W1 2001:db8:50::10 >/dev/null 2>&1 && echo "  v6 [PASS] VM->host" || echo "  v6 [FAIL] VM->host"
echo "  VM resolved 192.168.50.10 -> $(ip -n $VM neigh show dev vmeth | grep '192.168.50.10 ')"
echo "    (expect lladdr == br0 mac $BRMAC => host answered on br0)"

echo
echo "== (2) host arp_ignore values: does the host still answer for an up0 IP on br0? =="
for ai in 0 1 2; do
  ip netns exec $HOST sysctl -qw net.ipv4.conf.all.arp_ignore=$ai net.ipv4.conf.br0.arp_ignore=$ai
  ip -n $VM neigh flush dev vmeth
  ip netns exec $VM ping -c1 -W1 192.168.50.10 >/dev/null 2>&1 && r=REACHABLE || r=FAIL
  echo "  arp_ignore=$ai -> VM->host $r   $(ip -n $VM neigh show dev vmeth | grep '192.168.50.10 ')"
done
ip netns exec $HOST sysctl -qw net.ipv4.conf.all.arp_ignore=0 net.ipv4.conf.br0.arp_ignore=0 >/dev/null

echo
echo "== (3) WITHOUT the /32 route: host's reply routes via up0's connected route (wrong seg) =="
ip -n $HOST route del 192.168.50.101/32 dev br0 2>/dev/null
ip -n $VM neigh flush dev vmeth
echo "  route to VM now: $(ip -n $HOST route get 192.168.50.101 | head -1)"
ip netns exec $VM ping -c2 -W1 192.168.50.10 >/dev/null 2>&1 && echo "  v4 [PASS] VM->host" || echo "  v4 [FAIL] VM->host (reply went out up0, not br0)"
