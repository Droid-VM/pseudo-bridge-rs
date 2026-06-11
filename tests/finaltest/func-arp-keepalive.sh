#!/bin/bash
# --arp-keepalive: work around Wi-Fi firmware ARP offload that answers v4 ARP only for
# the host's single programmed address (e.g. Qualcomm WMI_SET_ARP_NS_OFFLOAD) and drops
# ARP requests for everything else while in powersave. Inbound resolution of guest IPs
# is then ~dead (gateway flaps INCOMPLETE/FAILED/STALE/PROBE); only outbound frames are
# reliable. The keepalive pushes from our side: per learned guest v4, a unicast ARP
# reply (spa=guest, sha=HOSTMAC) to every v4 neighbour on up0 (unicast replies assert
# NUD_REACHABLE on Linux) + a periodic GARP broadcast.
#
# Equivalent-scenario simulation (per the real-device diagnosis):
#   helper  : tc flower on the gateway egress passes ARP requests for the HOST ip only,
#             drops ARP requests for any other tpa (= firmware single-v4-slot behavior;
#             replies pass). Host<->gw traffic is untouched.
#   neigh   : host talks to gw first -> gw is in up0's neighbour table (keepalive target).
#   guest   : g1 has a PERMANENT neigh for gw (warm cache, never re-ARPs), so the gw can
#             only learn g1 via inbound ARP -- which the helper kills. This models the
#             99%-drop window where the guest isn't re-ARPing the gateway.
#   gw NUD  : timers shrunk so REACHABLE decays in seconds.
#
# Asserts, per engine (nft under the bpf()-blocking wrapper):
#   sanity  : gw<->host still fine under the helper filter
#   phase A : keepalive OFF -> guest<->gw v4 fails (gw stuck INCOMPLETE/FAILED on guest)
#   phase B : --arp-keepalive 2 -> guest<->gw v4 recovers (keepalive reply resolves the
#             gw's INCOMPLETE/FAILED entry), and after >2x reachable decay of guest
#             silence the gw entry is still REACHABLE and gw->guest works 100%.
set -u
ROOT=/root/gitrs/pseudo-bridge-rs
BIN=${BIN:-$ROOT/target/debug/pbridge}
NOEBPF=${NOEBPF:-$ROOT/tests/finaltest/noebpf}
HMAC=02:00:00:00:00:01
rc=0

one(){ # $1 = engine
  local engine=$1 PB=""
  cleanup(){ [ -n "$PB" ] && kill "$PB" 2>/dev/null; for n in up hostns g1; do ip netns del $n 2>/dev/null; done; }
  trap cleanup RETURN
  for n in up hostns g1; do ip netns del $n 2>/dev/null; done
  for n in up hostns g1; do ip netns add $n; done
  ip link add up0 netns hostns type veth peer name u0 netns up
  ip link add gbr netns hostns type veth peer name g1eth netns g1
  ip -n up addr add 10.0.0.1/24 dev u0
  ip -n up link set u0 up; ip -n up link set lo up
  ip -n hostns link set up0 address $HMAC; ip -n hostns link set up0 up
  ip -n hostns link add br0 type bridge; ip -n hostns link set br0 up
  ip -n hostns link set gbr master br0; ip -n hostns link set gbr up
  ip netns exec hostns sysctl -q net.ipv4.conf.all.rp_filter=0 2>/dev/null
  ip -n hostns addr add 10.0.0.2/24 dev up0
  ip -n g1 addr add 10.0.0.5/24 dev g1eth
  ip -n g1 link set g1eth up; ip -n g1 link set lo up

  # gw NUD timers: REACHABLE decays in [1.5,4.5]s, probes fail fast.
  ip netns exec up sysctl -q \
    net.ipv4.neigh.u0.base_reachable_time_ms=3000 \
    net.ipv4.neigh.u0.delay_first_probe_time=1 \
    net.ipv4.neigh.u0.retrans_time_ms=200 \
    net.ipv4.neigh.u0.ucast_solicit=2 \
    net.ipv4.neigh.u0.mcast_solicit=2 2>/dev/null

  # "Qualcomm firmware" helper: on the gw egress, ARP requests reach the host ONLY if
  # they ask for the host's address; requests for any other tpa are dropped. (Filtering
  # the gw's egress == the host's IN never sees them, without perturbing pbridge hooks.)
  tc -n up qdisc add dev u0 clsact
  tc -n up filter add dev u0 egress prio 1 protocol arp flower arp_op request arp_tip 10.0.0.2 action pass
  tc -n up filter add dev u0 egress prio 2 protocol arp flower arp_op request action drop
  tc -n up filter show dev u0 egress | grep -q arp_tip || { echo "  [$engine] SKIP: flower arp match unavailable"; return; }

  start_pb(){ # $1.. = extra args
    local wrap=(); [ "$engine" = nft ] && wrap=("$NOEBPF")
    ip netns exec hostns "${wrap[@]}" "$BIN" -i up0 -e "$engine" -m fwd \
      --fwd-device-if mt-if --fwd-device-br mt-br "$@" >/tmp/pb-arpka-$engine.log 2>&1 &
    PB=$!
    for _ in $(seq 1 40); do grep -q 'backend running' /tmp/pb-arpka-$engine.log && break; sleep 0.2; done
    grep -q 'backend running' /tmp/pb-arpka-$engine.log || return 1
    for _ in $(seq 1 20); do ip -n hostns link show mt-br >/dev/null 2>&1 && break; sleep 0.2; done
    ip -n hostns link set mt-br master br0; sleep 1
  }

  ck(){ local what=$1; shift; if "$@" >/dev/null 2>&1; then echo "  [$engine] ok: $what"; else echo "  [$engine] FAIL: $what"; rc=1; fi; }
  ckfail(){ local what=$1; shift; if "$@" >/dev/null 2>&1; then echo "  [$engine] FAIL: $what (unexpectedly succeeded)"; rc=1; else echo "  [$engine] ok: $what"; fi; }

  # ---- phase A: keepalive OFF ----
  start_pb || { echo "  [$engine] NOT RUNNING"; rc=1; return; }

  # host <-> gw first: populates up0's neighbour table (the keepalive target list)
  # and proves the helper passes host ARP.
  ip -n up neigh flush dev u0
  ck "sanity: host->gw under filter" ip netns exec hostns ping -c1 -W2 10.0.0.1
  ck "sanity: gw->host under filter" ip netns exec up ping -c1 -W2 10.0.0.2

  # guest: warm (permanent) gw entry -> it never re-ARPs; learn it via one outbound
  # packet (the echo reaches the gw; the gw's reply dies on unresolvable G).
  local gwmac; gwmac=$(ip -n up link show u0 | awk '/ether/{print $2}')
  ip -n g1 neigh replace 10.0.0.1 lladdr "$gwmac" dev g1eth nud permanent
  ckfail "A: guest->gw fails (gw can't resolve guest)" ip netns exec g1 ping -c3 -W1 10.0.0.1
  ip -n up neigh show dev u0 10.0.0.5 | grep -Eq "FAILED|INCOMPLETE" \
    && echo "  [$engine] ok: A: gw entry for guest is dead ($(ip -n up neigh show dev u0 10.0.0.5 | awk '{print $NF}'))" \
    || { echo "  [$engine] FAIL: A: unexpected gw entry: $(ip -n up neigh show dev u0 10.0.0.5)"; rc=1; }

  kill "$PB" 2>/dev/null; wait "$PB" 2>/dev/null; PB=""
  sleep 1

  # ---- phase B: --arp-keepalive 2 ----
  start_pb --arp-keepalive 2 || { echo "  [$engine] NOT RUNNING (B)"; rc=1; return; }
  ip netns exec hostns ping -c1 -W2 10.0.0.1 >/dev/null 2>&1   # ensure gw in neigh table

  # guest speaks once -> learned -> next keepalive tick (<=2s) unicast-replies the gw,
  # resolving its INCOMPLETE/FAILED entry; pings then flow.
  local okB=0
  for _ in $(seq 1 10); do
    ip netns exec g1 ping -c1 -W1 10.0.0.1 >/dev/null 2>&1 && { okB=1; break; }
  done
  [ $okB = 1 ] && echo "  [$engine] ok: B: guest->gw recovers with keepalive" \
              || { echo "  [$engine] FAIL: B: guest->gw still dead"; rc=1; }

  # guest goes silent >2x reachable decay; keepalive alone must hold the gw entry
  # REACHABLE and keep gw->guest at 100%.
  sleep 10
  ip -n up neigh show dev u0 10.0.0.5 | grep -q REACHABLE \
    && echo "  [$engine] ok: B: gw entry REACHABLE after 10s guest silence" \
    || { echo "  [$engine] FAIL: B: gw entry not REACHABLE: $(ip -n up neigh show dev u0 10.0.0.5)"; rc=1; }
  ck "B: gw->guest 100% while guest silent" ip netns exec up ping -c3 -W1 10.0.0.5
  ip -n up neigh show dev u0 10.0.0.5 | grep -q REACHABLE \
    && echo "  [$engine] ok: B: gw entry still REACHABLE after traffic" \
    || { echo "  [$engine] FAIL: B: entry decayed: $(ip -n up neigh show dev u0 10.0.0.5)"; rc=1; }
}

for e in ${ENGINES:-nft ebpf}; do echo "-- engine $e --"; one "$e"; done
echo "== arp-keepalive: $([ $rc = 0 ] && echo PASS || echo FAIL) =="
[ $rc = 0 ]
