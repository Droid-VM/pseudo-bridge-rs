#!/usr/bin/env bash
# Claim: direct mode needs ZERO host->VM route writes.
#   up0 enslaved in br (NO ip), br holds ip/cidr (+ its connected/prefix route), VMs in br.
#   => VM is on-link via br's connected route => host reaches it natively, no /32 //128 needed.
#
#   ns H:  br0 { up0(no ip, the physical wire stub), vmtap }  br0=192.168.70.1/24
#   ns V:  vmeth = 192.168.70.101/24   (a guest, bridged in via vmtap<->vmeth)
set -u
H=dirH; V=dirV
cleanup(){ for n in $H $V; do ip netns del $n 2>/dev/null; done; }
trap cleanup EXIT; cleanup
ip netns add $H; ip netns add $V
ip -n $H link add name br0 type bridge forward_delay 0
ip link add vmtap netns $H type veth peer name vmeth netns $V
ip -n $H link add up0 type veth peer name up0p           # up0p = stub standing in for the physical wire
ip -n $H link set up0 master br0
ip -n $H link set vmtap master br0
for d in br0 up0 up0p vmtap lo; do ip -n $H link set $d up; done
ip -n $V link set vmeth up; ip -n $V link set lo up
ip -n $H addr add 192.168.70.1/24 dev br0                # br holds the IP — up0 has NONE
ip -n $H addr add 2001:db8:70::1/64 dev br0 nodad
ip -n $V addr add 192.168.70.101/24 dev vmeth
ip -n $V addr add 2001:db8:70::101/64 dev vmeth nodad
sleep 0.4

echo "== host route tables — WE ADDED NOTHING (only kernel's own connected routes) =="
ip -n $H  route show | sed 's/^/  v4 /'
ip -n $H -6 route show | grep -v fe80 | sed 's/^/  v6 /'

echo "== route get to VM (expect: on-link dev br0, src = br0.ip — no /32 needed) =="
echo "  v4: $(ip -n $H  route get 192.168.70.101 | head -1)"
echo "  v6: $(ip -n $H -6 route get 2001:db8:70::101 | head -1)"

echo "== host -> VM, with ZERO route writes =="
ip netns exec $H ping -c2 -W1 192.168.70.101    >/dev/null 2>&1 && echo "  v4 [PASS]" || echo "  v4 [FAIL]"
ip netns exec $H ping -c2 -W1 2001:db8:70::101   >/dev/null 2>&1 && echo "  v6 [PASS]" || echo "  v6 [FAIL]"
echo "== VM -> host =="
ip netns exec $V ping -c2 -W1 192.168.70.1       >/dev/null 2>&1 && echo "  v4 [PASS]" || echo "  v4 [FAIL]"
ip netns exec $V ping -c2 -W1 2001:db8:70::1      >/dev/null 2>&1 && echo "  v6 [PASS]" || echo "  v6 [FAIL]"
