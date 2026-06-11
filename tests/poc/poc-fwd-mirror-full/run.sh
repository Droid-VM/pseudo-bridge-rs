#!/usr/bin/env bash
# General fwd host<->VM approach: MIRROR host's whole IP set onto br0 (noprefixroute, globals only;
# IPv6 link-local left as the auto one, NOT noprefixroute) + per-guest /32 //128 route with pinned src.
# IPv6 link-local: never gets a /128 route (scope link, unroutable) -> reach LL only via `ping -I`.
# Coverage: host same-subnet multi IP (50.10 primary + 50.11 secondary) + diff subnet (51.10);
#           VM same-subnet multi IP (50.100 + 50.101) + diff subnet (51.100); v4+v6; strict rp_filter.
set -u
H=mrH; U=mrU; V=mrV
cleanup(){ for n in $H $U $V; do ip netns del $n 2>/dev/null; done; }
trap cleanup EXIT; cleanup
for n in $H $U $V; do ip netns add $n; done
ip link add up0 netns $H type veth peer name upstub netns $U
ip link add vmtap netns $H type veth peer name vmeth netns $V
ip -n $H link add name br0 type bridge forward_delay 0
ip -n $H link set br0 address 02:bb:bb:00:00:01      # fixed br0 mac (best practice) -> stable LL
ip -n $H link set vmtap master br0
for d in up0 vmtap br0 lo; do ip -n $H link set $d up; done
ip -n $U link set upstub up; ip -n $U link set lo up
ip -n $V link set vmeth up; ip -n $V link set lo up

# host real IPs on up0
for a in 192.168.50.10/24 192.168.50.11/24 192.168.51.10/24; do ip -n $H addr add $a dev up0; done
for a in 2001:db8:50::10/64 2001:db8:50::11/64 2001:db8:51::10/64; do ip -n $H addr add $a dev up0 nodad; done
# MIRROR the whole set onto br0 (noprefixroute, globals only — LL is auto)
for a in 192.168.50.10/24 192.168.50.11/24 192.168.51.10/24; do ip -n $H addr add $a dev br0 noprefixroute; done
for a in 2001:db8:50::10/64 2001:db8:50::11/64 2001:db8:51::10/64; do ip -n $H addr add $a dev br0 noprefixroute nodad; done
# upstream gw + "internet"
ip -n $U addr add 192.168.50.1/24 dev upstub; ip -n $U addr add 2001:db8:50::1/64 dev upstub nodad
ip -n $U addr add 8.8.8.8/32 dev lo; ip netns exec $U sysctl -qw net.ipv4.ip_forward=1 >/dev/null
ip -n $H route add default via 192.168.50.1 dev up0
ip -n $H -6 route add default via 2001:db8:50::1 dev up0
# VM IPs: same-subnet multi (50.100,50.101) + diff subnet (51.100)
for a in 192.168.50.100/24 192.168.50.101/24 192.168.51.100/24; do ip -n $V addr add $a dev vmeth; done
for a in 2001:db8:50::100/64 2001:db8:50::101/64 2001:db8:51::100/64; do ip -n $V addr add $a dev vmeth nodad; done
sleep 0.5
# per-guest routes: /32 //128 dev br0 src <primary of that subnet> ; NO route for any fe80 LL
ip -n $H route add 192.168.50.100/32 dev br0 src 192.168.50.10
ip -n $H route add 192.168.50.101/32 dev br0 src 192.168.50.10
ip -n $H route add 192.168.51.100/32 dev br0 src 192.168.51.10
ip -n $H -6 route add 2001:db8:50::100/128 dev br0 src 2001:db8:50::10
ip -n $H -6 route add 2001:db8:50::101/128 dev br0 src 2001:db8:50::10
ip -n $H -6 route add 2001:db8:51::100/128 dev br0 src 2001:db8:51::10
# strict rp_filter
ip netns exec $H sysctl -qw net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.br0.rp_filter=1 net.ipv4.conf.up0.rp_filter=1 >/dev/null
hp(){ ip netns exec $H ping -c1 -W1 "$1" >/dev/null 2>&1 && echo PASS || echo FAIL; }
vp(){ ip netns exec $V ping -c1 -W1 "$1" >/dev/null 2>&1 && echo PASS || echo FAIL; }

echo "== br0 addresses: globals noprefixroute + auto LL (no noprefixroute on LL) =="
ip -n $H addr show dev br0 | grep -E "inet6? " | sed 's/^/  /'

echo
echo "== no /24 //64 connected route on br0 (noprefixroute); normal traffic stays up0 =="
echo "  br0 connected: $(ip -n $H route show dev br0 | grep -cE '/(24|64)') (expect 0 for the mirrored subnets)"
echo "  gw  -> $(ip -n $H route get 192.168.50.1 | head -1)"
echo "  8.8.8.8 -> $(ip -n $H route get 8.8.8.8 | head -1)"
echo "  gw v4 reachable: $(hp 192.168.50.1)   8.8.8.8: $(hp 8.8.8.8)"

echo
echo "== route get per VM IP — correct per-subnet src? =="
for d in 192.168.50.100 192.168.50.101 192.168.51.100; do echo "  $d -> $(ip -n $H route get $d | head -1)"; done
for d in 2001:db8:50::100 2001:db8:51::100; do echo "  $d -> $(ip -n $H -6 route get $d | head -1)"; done

echo
echo "== host -> VM (same-subnet multi + diff subnet), v4 + v6, strict rp_filter =="
for d in 192.168.50.100 192.168.50.101 192.168.51.100 2001:db8:50::100 2001:db8:50::101 2001:db8:51::100; do
  printf "  host->%-20s %s\n" "$d" "$(hp $d)"; done

echo
echo "== VM -> host (ALL host IPs incl secondary 50.11/::11), v4 + v6 =="
for s in 192.168.50.10 192.168.50.11 192.168.51.10 2001:db8:50::10 2001:db8:50::11 2001:db8:51::10; do
  printf "  VM->%-20s %s\n" "$s" "$(vp $s)"; done

echo
echo "== IPv6 link-local: NOT routed; reach only via -I =="
BRLL=$(ip -n $H -6 addr show dev br0 scope link | grep -oE 'fe80::[0-9a-f:]+' | head -1)
VMLL=$(ip -n $V -6 addr show dev vmeth scope link | grep -oE 'fe80::[0-9a-f:]+' | head -1)
echo "  br0 LL=$BRLL   vmeth LL=$VMLL"
echo "  fe80 /128 routes written for VM LLs: $(ip -n $H -6 route show | grep fe80 | grep -c '/128') (expect 0)"
echo "  (the fe80::/64 per-iface on-link routes are kernel-auto & REQUIRED for -I; their multiplicity is why no-scope fails)"
echo "  host->VM LL WITHOUT -I : $(ip netns exec $H ping -c1 -W1 "$VMLL" >/dev/null 2>&1 && echo PASS || echo 'FAIL (expected: needs scope)')"
echo "  host->VM LL with -I br0 : $(ip netns exec $H ping -c1 -W1 -I br0 "$VMLL" >/dev/null 2>&1 && echo PASS || echo FAIL)"
echo "  VM->host LL with -I vmeth: $(ip netns exec $V ping -c1 -W1 -I vmeth "$BRLL" >/dev/null 2>&1 && echo PASS || echo FAIL)"
