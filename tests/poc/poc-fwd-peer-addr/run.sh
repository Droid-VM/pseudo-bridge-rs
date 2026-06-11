#!/usr/bin/env bash
# Approach: instead of (mirror /24 noprefixroute) + (per-VM /32 route) + (manual pinned src),
# use ONE point-to-point peer address per VM:
#       ip addr add <selected-src> peer <vm-ip> dev br0
# which in a single command gives: (a) host owns <selected-src> on br0 (ARP/ND answer + src),
# (b) auto /32 route to <vm-ip> with prefsrc=<selected-src>, (c) NO /24 connected route.
# Tests: multi-subnet, multiple VMs sharing one local, auto per-subnet src, v4+v6, strict
# rp_filter, and the delete-one-of-shared-local lifecycle (refcounted ownership).
set -u
H=peH; U=peU; V=peV
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
ip -n $H addr add 192.168.50.10/24 dev up0          # real host IPs on up0 (separate seg)
ip -n $H addr add 192.168.51.10/24 dev up0
ip -n $H addr add 2001:db8:50::10/64 dev up0 nodad
ip -n $U addr add 192.168.50.1/24 dev upstub
ip -n $H route add default via 192.168.50.1 dev up0
ip -n $V addr add 192.168.50.101/24 dev vmeth       # VM in BOTH subnets + v6
ip -n $V addr add 192.168.51.101/24 dev vmeth
ip -n $V addr add 2001:db8:50::101/64 dev vmeth nodad
sleep 0.3

echo "== one peer-address per VM-ip (selected-src = host IP in that VM's subnet) =="
ip -n $H addr add 192.168.50.10  peer 192.168.50.101  dev br0       && echo "  v4 50.101 OK"
ip -n $H addr add 192.168.51.10  peer 192.168.51.101  dev br0       && echo "  v4 51.101 OK (diff subnet)"
ip -n $H addr add 192.168.50.10  peer 192.168.50.102  dev br0       && echo "  v4 50.102 OK (SAME local 50.10, diff peer)"
ip -n $H addr add 2001:db8:50::10 peer 2001:db8:50::101 dev br0 nodad && echo "  v6 ::101 OK"

echo
echo "== auto routes + NO /24 connected (no gw ambiguity) + per-subnet src is automatic =="
ip -n $H route show dev br0 | sed 's/^/  /'
ip -n $H route show dev br0 | grep -qE "/24" && echo "  [FAIL] /24 connected route exists" || echo "  [PASS] no /24 connected route"
echo "  50.101 -> $(ip -n $H route get 192.168.50.101 | head -1)"
echo "  51.101 -> $(ip -n $H route get 192.168.51.101 | head -1)"
echo "  gw     -> $(ip -n $H route get 192.168.50.1   | head -1)  (must stay on up0)"

echo
echo "== reachability host<->VM, both subnets v4 + v6, STRICT rp_filter =="
ip netns exec $H sysctl -qw net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.br0.rp_filter=1 >/dev/null
for d in 192.168.50.101 192.168.51.101 2001:db8:50::101; do
  ip netns exec $H ping -c1 -W1 $d >/dev/null 2>&1 && echo "  host->$d [PASS]" || echo "  host->$d [FAIL]"
done
for s in 192.168.50.10 192.168.51.10 2001:db8:50::10; do
  ip netns exec $V ping -c1 -W1 $s >/dev/null 2>&1 && echo "  VM->$s [PASS]" || echo "  VM->$s [FAIL]"
done

echo
echo "== lifecycle: deleting one peer that SHARES a local must not break the others =="
owns(){ ip -n $H route show table local | grep -q "local 192.168.50.10 dev br0" && echo "br0owns50.10=Y" || echo "br0owns50.10=N"; }  # dev-specific: up0 also holds 50.10
echo "  before del: $(owns) ; route50.101=$(ip -n $H route get 192.168.50.101|grep -o 'src [0-9.]*')"
ip -n $H addr del 192.168.50.10 peer 192.168.50.102 dev br0
echo "  del .102  : $(owns) (50.101 peer remains) ; VM->50.10=$(ip netns exec $V ping -c1 -W1 192.168.50.10 >/dev/null 2>&1 && echo PASS || echo FAIL)"
ip -n $H addr del 192.168.50.10 peer 192.168.50.101 dev br0
echo "  del .101  : $(owns) (last peer gone => ownership drops)"
