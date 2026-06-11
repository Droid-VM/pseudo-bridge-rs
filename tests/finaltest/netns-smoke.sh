#!/usr/bin/env bash
# End-to-end smoke test for the userspace backend.
#
#   ns up            ns hostns (runs pbridge)             ns g1
#  ┌────────┐ veth  ┌──────────────────────────────┐ veth ┌────────┐
#  │ u0     │══════ │ up0(UPSTREAM)                 │      │ g1eth  │
#  │10.0.0.1│       │   br0 ── gbr   mtnat1╌mtnat1p │══════│10.0.0.5│
#  └────────┘       │   (pbridge creates mtnat1*)   │      └────────┘
#                   └──────────────────────────────┘
# Guest 10.0.0.5 should reach gateway 10.0.0.1; on the wire (u0) every src mac
# must be HOSTMAC (= up0's mac).
set -u
BIN="${1:-./target/debug/pbridge}"
GUEST_IP=10.0.0.5
GW_IP=10.0.0.1
HOST_IP=10.0.0.2
PBPID=""
cleanup() {
    [ -n "$PBPID" ] && kill "$PBPID" 2>/dev/null
    sleep 0.3
    for ns in up hostns g1; do ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }

echo "== setup namespaces =="
for ns in up hostns g1; do ip netns add "$ns"; done
# upstream link
ip link add up0 netns hostns type veth peer name u0 netns up
# guest link (guest <-> bridge port)
ip link add gbr netns hostns type veth peer name g1eth netns g1

# upstream ns
ip -n up addr add $GW_IP/24 dev u0
ip -n up link set u0 up; ip -n up link set lo up

# host ns: bridge + ports
ip -n hostns link add br0 type bridge
ip -n hostns link set gbr master br0
ip -n hostns link set up0 up; ip -n hostns link set gbr up; ip -n hostns link set br0 up
ip -n hostns addr add $HOST_IP/24 dev up0           # host's own IP (coexistence)
ip netns exec hostns sysctl -q net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 net.ipv4.conf.up0.rp_filter=0 net.ipv4.conf.br0.rp_filter=0 2>/dev/null

# guest ns
ip -n g1 addr add $GUEST_IP/24 dev g1eth
ip -n g1 link set g1eth up; ip -n g1 link set lo up

HOSTMAC=$(cat /sys/class/net/up0/address 2>/dev/null || ip netns exec hostns cat /sys/class/net/up0/address)
echo "HOSTMAC(up0)=$HOSTMAC  guest g1eth=$(ip netns exec g1 cat /sys/class/net/g1eth/address)"

echo "== start pbridge in hostns =="
# no --host-route-dev: nt is derived dynamically from master(veth-peer), so a
# bridge/master change re-points the host->VM routes (PLAN req 2).
ip netns exec hostns "$BIN" \
    --upstream up0 --fwd-device mtnat1 --bridge br0 \
    --l2nat-backend userspace --entry-timeout 30 >/tmp/pbridge.log 2>&1 &
PBPID=$!
sleep 1.5
kill -0 "$PBPID" 2>/dev/null || { echo "--- pbridge.log ---"; cat /tmp/pbridge.log; fail "pbridge died"; }
echo "--- pbridge.log ---"; sed 's/^/  /' /tmp/pbridge.log

echo "== test 1: guest -> gateway ping (through MAC-NAT) =="
if ip netns exec g1 ping -c 3 -W 2 $GW_IP >/tmp/ping.log 2>&1; then
    echo "PASS: guest ping gateway"; grep -E 'packets transmitted' /tmp/ping.log | sed 's/^/  /'
else
    cat /tmp/ping.log; fail "guest cannot reach gateway"
fi

echo "== test 2: on-the-wire src mac is HOSTMAC (capture on u0) =="
ip netns exec up timeout 4 tcpdump -i u0 -e -n -c 6 icmp >/tmp/tcap.log 2>&1 &
TPID=$!
sleep 0.5
ip netns exec g1 ping -c 3 -W 2 $GW_IP >/dev/null 2>&1
wait $TPID 2>/dev/null
echo "--- captured (u0) ---"; sed 's/^/  /' /tmp/tcap.log | grep -iE 'icmp|>' | head
if grep -qi "$HOSTMAC > " /tmp/tcap.log; then
    echo "PASS: src mac on wire == HOSTMAC"
else
    echo "WARN: could not confirm HOSTMAC src in capture (see above)"
fi
# negative: guest's own mac must NOT appear as src on the wire
GMAC=$(ip netns exec g1 cat /sys/class/net/g1eth/address)
if grep -qi "$GMAC > " /tmp/tcap.log; then fail "LEAK: guest mac $GMAC seen on upstream wire"; else echo "PASS: guest mac never leaked to upstream"; fi

echo "== test 3: host's own communication still works =="
if ip netns exec hostns ping -c 2 -W 2 $GW_IP >/dev/null 2>&1; then
    echo "PASS: host ping gateway (coexistence)"
else
    echo "WARN: host ping failed"
fi

echo "== test 4: host -> guest via auto /32 route (nt=br0, no duplicate IP) =="
sleep 0.5   # let pbridge program the route after learning the guest
ROUTE=$(ip -n hostns route get $GUEST_IP 2>/dev/null | head -1)
echo "  route get $GUEST_IP: $ROUTE"
if echo "$ROUTE" | grep -q 'dev br0'; then echo "PASS: host route for guest points at br0 (nt)"; else echo "WARN: /32 route not via br0"; fi
if ip netns exec hostns ping -c 2 -W 2 $GUEST_IP >/tmp/h2g.log 2>&1; then
    echo "PASS: host -> guest reachable via /32->nt"
else
    cat /tmp/h2g.log; echo "WARN: host->guest failed"
fi

echo "== test 5: upstream lost -> withdraw all -> return -> re-establish (req 1) =="
ip -n hostns link set up0 down
sleep 3
if ip -n hostns route get $GUEST_IP 2>/dev/null | grep -q 'dev br0'; then
    echo "WARN: route still present after upstream down"
else
    echo "PASS: routes withdrawn on upstream loss"
fi
ip -n hostns link set up0 up
sleep 4
if ip netns exec g1 ping -c 2 -W 2 $GW_IP >/dev/null 2>&1; then
    echo "PASS: connectivity re-established after upstream returned"
else
    echo "WARN: not re-established after upstream return"; tail -5 /tmp/pbridge.log | sed 's/^/    /'
fi

echo "== test 6: upstream MAC change -> adopt new HOSTMAC + gratuitous ARP =="
NEWMAC=02:00:00:00:00:99
ip -n hostns link set up0 address $NEWMAC
sleep 3   # maint detects (<=2s) and sends GARP
if grep -q "host-side: HOSTMAC -> $NEWMAC" /tmp/pbridge.log; then echo "PASS: pbridge adopted new HOSTMAC"; else echo "WARN: HOSTMAC change not logged"; fi
ip netns exec up timeout 4 tcpdump -i u0 -e -n -c 4 icmp >/tmp/t6.log 2>&1 &
TP=$!; sleep 0.5
ip netns exec g1 ping -c 3 -W 2 $GW_IP >/dev/null 2>&1
wait $TP 2>/dev/null
if grep -qi "$NEWMAC > " /tmp/t6.log; then echo "PASS: wire src mac == new HOSTMAC"; else echo "WARN: new mac not seen on wire"; fi
if ip netns exec g1 ping -c 2 -W 2 $GW_IP >/dev/null 2>&1; then echo "PASS: guest online after MAC change (GARP healed upstream cache)"; else echo "WARN: guest offline after MAC change"; fi

echo "== test 7: master change — migrate VM + veth-peer to new bridge br1 -> immediately online =="
ip -n hostns link add br1 type bridge 2>/dev/null
ip -n hostns link set br1 up
ip netns exec hostns sysctl -q net.ipv4.conf.br1.rp_filter=0 2>/dev/null
ip -n hostns link set gbr master br1       # VM port migrates
ip -n hostns link set mtnat1p master br1   # pbridge's veth-peer migrates with it
sleep 0.5
if ip netns exec g1 ping -c 2 -W 2 $GW_IP >/dev/null 2>&1; then echo "PASS: VM immediately online after migrating to br1"; else echo "WARN: VM offline after master change"; fi
sleep 3   # maint re-resolves nt = master(mtnat1p) = br1
RT=$(ip -n hostns route get $GUEST_IP 2>/dev/null | head -1); echo "  route get $GUEST_IP: $RT"
if echo "$RT" | grep -q 'dev br1'; then echo "PASS: nt re-pointed to br1 (host routes follow)"; else echo "WARN: nt not re-pointed to br1"; fi
if ip netns exec hostns ping -c 2 -W 2 $GUEST_IP >/dev/null 2>&1; then echo "PASS: host->guest works via new bridge br1"; else echo "WARN: host->guest failed after migrate"; fi

echo "ALL DONE"
