#!/usr/bin/env bash
# Scenario: host has MULTIPLE IPs in the guest's subnet — 50.10 (primary) + 50.11 (secondary).
# br0 has only the peer addr for the primary: `50.10 peer 50.100`.
# Q: can guest 50.100 reach the host's SECONDARY 50.11 over br0? (v4 + v6)
# Finding: guest reaches a host IP over br0 only if the host OWNS that IP on br0.
#   50.10 (owned via peer) -> v4+v6 ok.
#   50.11 (only on up0)    -> v4 ok ONLY via arp_ignore=0 cross-iface (dies at arp_ignore=1); v6 FAILs.
#   => must ALSO own 50.11 on br0 (mirror noprefixroute) for robust v4+v6.
# Principle: OWNERSHIP is per-host-IP & must be on br0 (mirror the whole host-IP set);
#            ROUTING+src is per-guest. peer-addr only bundles the per-guest selected-src.
set -u
H=secH; U=secU; V=secV
cleanup(){ for n in $H $U $V; do ip netns del $n 2>/dev/null; done; }
trap cleanup EXIT; cleanup
for n in $H $U $V; do ip netns add $n; done
ip link add up0 netns $H type veth peer name upstub netns $U
ip link add vmtap netns $H type veth peer name vmeth netns $V
ip -n $H link add name br0 type bridge forward_delay 0
ip -n $H link set vmtap master br0
for d in up0 vmtap br0 lo; do ip -n $H link set $d up; done
ip -n $U link set upstub up; ip -n $U link set lo up
ip -n $V link set vmeth up; ip -n $V link set lo up
ip -n $H addr add 192.168.50.10/24 dev up0        # primary
ip -n $H addr add 192.168.50.11/24 dev up0        # SECONDARY (same subnet)
ip -n $H addr add 2001:db8:50::10/64 dev up0 nodad
ip -n $H addr add 2001:db8:50::11/64 dev up0 nodad
ip -n $H addr add 192.168.50.10 peer 192.168.50.100 dev br0          # only the primary is owned on br0
ip -n $H addr add 2001:db8:50::10 peer 2001:db8:50::100 dev br0 nodad
ip -n $V addr add 192.168.50.100/24 dev vmeth
ip -n $V addr add 2001:db8:50::100/64 dev vmeth nodad
sleep 0.4
g(){ ip netns exec $V ping -c1 -W1 "$1" >/dev/null 2>&1 && echo PASS || echo FAIL; }

echo "== (1) guest -> 50.10/::10 (owned on br0 via peer) =="
echo "   v4=$(g 192.168.50.10)  v6=$(g 2001:db8:50::10)"
echo "== (2) guest -> 50.11/::11 (secondary, only on up0), arp_ignore=0 =="
echo "   v4=$(g 192.168.50.11)  v6=$(g 2001:db8:50::11)   <- expect v4 PASS(fragile) / v6 FAIL"
echo "== (3) guest -> 50.11, arp_ignore=1 (v4 cross-iface path now blocked) =="
ip netns exec $H sysctl -qw net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.br0.arp_ignore=1 >/dev/null
ip -n $V neigh flush dev vmeth
echo "   v4=$(g 192.168.50.11)   <- expect FAIL"
ip netns exec $H sysctl -qw net.ipv4.conf.all.arp_ignore=0 net.ipv4.conf.br0.arp_ignore=0 >/dev/null
echo "== (4) FIX: also own 50.11/::11 on br0 (mirror noprefixroute) =="
ip -n $H addr add 192.168.50.11/24 dev br0 noprefixroute
ip -n $H addr add 2001:db8:50::11/64 dev br0 noprefixroute nodad
sleep 0.5; ip -n $V neigh flush dev vmeth
echo "   v4 50.11=$(g 192.168.50.11)  v6 ::11=$(g 2001:db8:50::11)   <- expect both PASS"
echo "   sanity 50.10=$(g 192.168.50.10)  ::10=$(g 2001:db8:50::10)"
