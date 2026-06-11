#!/usr/bin/env bash
# Q: can `noprefixroute` give an address that does src-selection + ARP/ND response
#    but does NOT participate in routing (no auto connected/prefix route)?
# Context: fwd mode keeps br IP-less because a same-subnet IP on br adds a 2nd connected
#   route -> host's default-gw resolution goes to br ~half the time -> breaks host internet.
#   noprefixroute suppresses exactly that connected route. Does the addr still work as
#   a src candidate + answer ARP/ND? And does it auto-select the right per-subnet src?
#
# NOTE: must put the "VM" in a SEPARATE netns. A veth pair with both ends in one netns
#   makes the kernel treat both IPs as local and never does an on-wire ARP exchange
#   (even a NORMAL address shows no reply) -> false negative.
#
#   ns H: brX (noprefixroute addrs) ╌╌veth╌╌ ns V: vm (the guest)
set -u
H=nopfxH; V=nopfxV
cleanup(){ for n in $H $V; do ip netns del $n 2>/dev/null; done; }
trap cleanup EXIT; cleanup
ip netns add $H; ip netns add $V
ip link add brX netns $H type veth peer name vm netns $V
ip -n $H link set lo up; ip -n $H link set brX up
ip -n $V link set lo up; ip -n $V link set vm up
ip -n $V addr add 10.9.0.101/24 dev vm
ip -n $V addr add 10.8.0.101/24 dev vm   # a 2nd-subnet guest

echo "== setup: brX gets two same-subnet addrs in DIFFERENT subnets, both noprefixroute =="
ip -n $H addr add 10.9.0.5/24 dev brX noprefixroute
ip -n $H addr add 10.8.0.5/24 dev brX noprefixroute
ip -n $H route add 10.9.0.101/32 dev brX
ip -n $H route add 10.8.0.101/32 dev brX

echo
echo "== (1) main table: any auto connected route? (expect NONE = does NOT route) =="
if ip -n $H route show table main | grep -E "10\.(8|9)\.0\.0/24"; then
  echo "  [FAIL] a connected prefix route was installed"
else
  echo "  [PASS] no 10.8/10.9 connected route in main — addr does NOT participate in routing"
fi

echo
echo "== (2) local table: host owns the addrs? (=> answers ARP/ND, usable as src) =="
ip -n $H route show table local | grep -E "local 10\.(8|9)\.0\.5" \
  && echo "  [PASS] local /32 present" || echo "  [FAIL] no local route"

echo
echo "== (3) ARP/ND response: vm (separate netns) reaches 10.9.0.5 ? =="
ip netns exec $V ping -c2 -W1 10.9.0.5 >/dev/null 2>&1 \
  && echo "  [PASS] host answers ARP for noprefixroute addr: $(ip -n $V neigh show dev vm | grep 10.9.0.5)" \
  || echo "  [FAIL] no ARP reply"

echo
echo "== (4) src-selection: /32 route, NO explicit src — does kernel auto-pick per-subnet? =="
echo "   10.9.0.101 -> $(ip -n $H route get 10.9.0.101 | head -1)"
echo "   10.8.0.101 -> $(ip -n $H route get 10.8.0.101 | head -1)"
echo "   EXPECT: both show src 10.9.0.5 (FIRST primary) — noprefixroute removed the"
echo "           prefix route's prefsrc, so NO automatic same-subnet selection."

echo
echo "== (4b) ... so pin src explicitly per /32 (= what rust must do, but to br's OWN addr) =="
ip -n $H route change 10.8.0.101/32 dev brX src 10.8.0.5
echo "   10.8.0.101 -> $(ip -n $H route get 10.8.0.101 | head -1)  [expect src 10.8.0.5]"

echo
echo "== (5) compare: NORMAL addrs (prefix route present) DO auto-select per-subnet =="
ip -n $H addr del 10.9.0.5/24 dev brX; ip -n $H addr del 10.8.0.5/24 dev brX
ip -n $H addr add 10.9.0.5/24 dev brX; ip -n $H addr add 10.8.0.5/24 dev brX
echo "   10.9.0.101 -> $(ip -n $H route get 10.9.0.101 | head -1)"
echo "   10.8.0.101 -> $(ip -n $H route get 10.8.0.101 | head -1)  [src 10.8.0.5 = auto, from prefix prefsrc]"

echo
echo "== (6) IPv6 noprefixroute: local entry kept, no on-link prefix route =="
ip -n $H addr add 2001:db8:9::5/64 dev brX noprefixroute nodad; sleep 0.3
ip -n $H -6 route show table main | grep -q "2001:db8:9::/64" \
  && echo "  [FAIL] v6 on-link prefix route installed" || echo "  [PASS] no v6 on-link prefix route"
ip -n $H -6 route show table local | grep -q "2001:db8:9::5" \
  && echo "  [PASS] v6 local entry present" || echo "  [FAIL] no v6 local entry"

echo
echo "SUMMARY: noprefixroute = local-route ownership (ARP/ND reply + src candidate) WITHOUT the"
echo "  connected route. It does NOT auto per-subnet src-select (prefsrc gone) -> still pin src/32,"
echo "  but to br's OWN same-subnet addr => symmetric return on br => no rp_filter loosening."
