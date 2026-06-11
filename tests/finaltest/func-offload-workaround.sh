#!/bin/bash
# Offload-workaround functional test, fwd mode, using the apfsim helper as a faithful
# "upstream NIC with ARP/ND offload" (models Android APF: drops ARP/NS whose target isn't
# a configured up0 address; answers the rest with HOSTMAC).
#
#   gateway(up) ── veth ── u_host ─[apfsim:apfbr]── tap1 ║apfsim║ tap2(=up0) ── pbridge(fwd) ── g1
#
# We test the ROOT the workaround fixes: can the gateway *resolve* the guest. So we probe
# GATEWAY-INITIATED (gw -> guest), with the gateway's neigh flushed first — this is the
# case APF breaks (the gw's ARP/NS for the guest is dropped) and avoids the netns artefact
# where a Linux guest's nexthop-NS is global-sourced and accidentally teaches the gateway.
#
#   A) workaround OFF: gw->guest v4 AND v6 both FAIL (apfsim drops the gw's ARP/NS).
#   B) workaround ON : both work (apfsim offload-answers from the up0 proxy addrs),
#                      + proxies present on up0 (magic metric), absent from the bridge.
set -u
ROOT=/root/gitrs/pseudo-bridge-rs
BIN=${BIN:-$ROOT/target/debug/pbridge}
APFSIM=${APFSIM:-$ROOT/tools/upsim/target/x86_64-unknown-linux-musl/release/upsim}
ENGINE=${1:-nft}
HMAC=02:00:00:00:00:01
MAGIC=4243672773
PB=""; AP=""
rc=0
note(){ echo "  $*"; }
ck(){ if eval "$2"; then note "OK   $1"; else note "FAIL $1"; rc=1; fi; }

cleanup(){ for p in "$PB" "$AP"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
           for n in apfup apfhost apfg1; do ip netns del $n 2>/dev/null; done; }
trap cleanup EXIT

[ -x "$APFSIM" ] || { echo "building apfsim..."; (cd "$ROOT/tools/upsim" && cargo build --release --target x86_64-unknown-linux-musl >/dev/null 2>&1); }
[ -x "$APFSIM" ] || { echo "no apfsim at $APFSIM"; exit 1; }
[ -x "$BIN" ] || { echo "no pbridge at $BIN (cargo build)"; exit 1; }

# distinct netns names so this can't collide with a concurrent matrix run.
UP=apfup HOST=apfhost G1=apfg1
for n in $UP $HOST $G1; do ip netns add $n; done
ip link add u0 netns $UP type veth peer name u_host netns $HOST
ip -n $UP addr add 10.0.0.1/24 dev u0
ip -n $UP addr add fd00::1/64 dev u0 nodad
ip -n $UP link set u0 up; ip -n $UP link set lo up
ip -n $HOST link set u_host up
ip link add gbr netns $HOST type veth peer name g1eth netns $G1
ip -n $G1 addr add 10.0.0.5/24 dev g1eth
ip -n $G1 addr add fd00::5/64 dev g1eth nodad
ip -n $G1 link set g1eth up; ip -n $G1 link set lo up
ip -n $HOST link add br0 type bridge; ip -n $HOST link set br0 up
ip -n $HOST link set gbr master br0; ip -n $HOST link set gbr up
ip netns exec $HOST sysctl -q net.ipv4.conf.all.rp_filter=0 2>/dev/null

ip netns exec $HOST "$APFSIM" --upstream u_host --up-tap tap1 --host-tap tap2 >/tmp/apfsim.log 2>&1 &
AP=$!
for _ in $(seq 1 30); do ip -n $HOST link show tap2 >/dev/null 2>&1 && break; sleep 0.2; done
ip -n $HOST link show tap2 >/dev/null 2>&1 || { echo "apfsim taps not up"; cat /tmp/apfsim.log; exit 1; }
ip -n $HOST link set tap2 address $HMAC
ip -n $HOST link set tap2 up
ip -n $HOST addr add 10.0.0.2/24 dev tap2
ip -n $HOST addr add fd00::2/64 dev tap2 nodad

start_pb(){
  ip netns exec $HOST "$BIN" -i tap2 -e "$ENGINE" -m fwd \
    --fwd-device-if mt-if --fwd-device-br mt-br "$@" >/tmp/pb-ow.log 2>&1 &
  PB=$!
  for _ in $(seq 1 30); do grep -q 'backend running' /tmp/pb-ow.log && break; sleep 0.2; done
  grep -q 'backend running' /tmp/pb-ow.log || { echo "pbridge NOT RUNNING"; cat /tmp/pb-ow.log; exit 1; }
  for _ in $(seq 1 20); do ip -n $HOST link show mt-br >/dev/null 2>&1 && break; sleep 0.2; done
  ip -n $HOST link set mt-br master br0
  sleep 1
}
stop_pb(){ [ -n "$PB" ] && { kill "$PB" 2>/dev/null; wait "$PB" 2>/dev/null; }; PB=""; }
prime(){ ip netns exec $G1 ping -c1 -W2 10.0.0.1 >/dev/null 2>&1 || true
         ip netns exec $G1 ping -c1 -W2 fd00::1 >/dev/null 2>&1 || true; }
gw_v4(){ ip -n $UP neigh flush all; ip netns exec $UP ping -c2 -W3 10.0.0.5 >/dev/null 2>&1; }
gw_v6(){ ip -n $UP neigh flush all; ip netns exec $UP ping -c2 -W3 fd00::5 >/dev/null 2>&1; }

echo "== A) workaround OFF =="
start_pb
prime                       # guest learned, but no proxy installed
ck "v4 gateway->guest FAILS (gw's ARP for guest dropped)" "! gw_v4"
ck "v6 gateway->guest FAILS (gw's NS for guest dropped)"  "! gw_v6"
stop_pb

echo "== B) workaround ON (--offload-workaround v4,v6) =="
start_pb --offload-workaround v4,v6
prime                       # learn guest -> install proxies on up0
sleep 1.5                   # apfsim picks up the proxy addrs
ck "v4 gateway->guest works (apfsim offloads guest v4)" "gw_v4"
ck "v6 gateway->guest works (apfsim offloads guest v6)" "gw_v6"
UP0=$(ip -n $HOST addr show dev tap2)
ck "v4 /32 proxy on up0 (metric $MAGIC)"  "grep -q '10.0.0.5/32 metric $MAGIC' <<<\"\$UP0\""
ck "v6 /128 proxy on up0 (metric $MAGIC)" "grep -q 'fd00::5/128 metric $MAGIC' <<<\"\$UP0\""
ck "guest LL NOT proxied (v6ll off)"      "! grep -qE 'fe80:.*metric $MAGIC' <<<\"\$UP0\""
BR=$(ip -n $HOST addr show dev br0)
ck "proxies absent from bridge"           "! grep -qE '10.0.0.5/32|fd00::5/128' <<<\"\$BR\""
ck "host's own up0 IPs intact"            "grep -q '10.0.0.2/24' <<<\"\$UP0\" && grep -q 'fd00::2/64' <<<\"\$UP0\""
stop_pb
ck "proxies removed after teardown"       "! ip -n $HOST addr show dev tap2 | grep -q 'metric $MAGIC'"

echo "== C) keepalive: timeout=5, guest sends then goes SILENT 15s — gw->guest must stay up =="
ip -n $UP neigh flush all
start_pb --offload-workaround v4,v6 --timeout 5
prime                       # guest sends once -> learned -> proxy installed
sleep 1.5
ck "v6 gw->guest works (initial)"  "gw_v6"
ck "v4 gw->guest works (initial)"  "gw_v4"
echo "   guest now SILENT for 15s (3x timeout); keepalive probe must hold the proxy..."
sleep 15
ck "proxy still on up0 after 15s silence" "ip -n $HOST addr show dev tap2 | grep -q 'metric $MAGIC'"
ck "v6 gw->guest STILL works (probe kept entry)" "gw_v6"
ck "v4 gw->guest STILL works"                    "gw_v4"
# and once the guest releases its IPs, it should become unreachable + evicted
ip netns exec $G1 ip addr flush dev g1eth
sleep 8
ck "proxy evicted after guest releases IPs" "! ip -n $HOST addr show dev tap2 | grep -q 'metric $MAGIC'"
ck "v6 gw->guest now FAILS (released)"      "! gw_v6"
stop_pb

echo "== offload-workaround: $([ $rc = 0 ] && echo PASS || echo FAIL) =="
exit $rc
