#!/bin/bash
# Offload keepalive probe: in offload mode a proxied guest that goes silent (still holds its
# IP but sends nothing) must NOT be evicted — otherwise its up0 proxy is removed and the
# upstream (APF) can no longer resolve it, with no rediscovery path (APF answers/drops the
# gw's NS, so it never floods to the bridge). The syncer runs aging at timeout/2 and
# alternates probe/flush: the probe solicits every proxied guest on fwd0 (AF_PACKET inject —
# no ebpf); a present guest replies → seen refreshed (OUT path) → survives the flush. A guest
# that *released* its IP never replies → seen expires → evicted ~timeout later.
#
# Asserts, per engine: (1) silent-but-present proxy survives > 2.5×timeout; (2) after the VM
# releases its IPs, the proxy is evicted. nft runs under the bpf()-blocking wrapper.
set -u
ROOT=/root/gitrs/pseudo-bridge-rs
BIN=${BIN:-$ROOT/target/debug/pbridge}
NOEBPF=${NOEBPF:-$ROOT/tests/finaltest/noebpf}
HMAC=02:00:00:00:00:01
MAGIC=4243672773
TMO=6
rc=0

one(){ # $1 = engine
  local engine=$1 PB=""
  cleanup(){ [ -n "$PB" ] && kill "$PB" 2>/dev/null; for n in up hostns g1; do ip netns del $n 2>/dev/null; done; }
  trap cleanup RETURN
  for n in up hostns g1; do ip netns del $n 2>/dev/null; done
  for n in up hostns g1; do ip netns add $n; done
  ip link add up0 netns hostns type veth peer name u0 netns up
  ip link add gbr netns hostns type veth peer name g1eth netns g1
  ip -n up addr add 10.0.0.1/24 dev u0; ip -n up addr add fd00::1/64 dev u0 nodad
  ip -n up link set u0 up; ip -n up link set lo up
  ip -n hostns link set up0 address $HMAC; ip -n hostns link set up0 up
  ip -n hostns link add br0 type bridge; ip -n hostns link set br0 up
  ip -n hostns link set gbr master br0; ip -n hostns link set gbr up
  ip netns exec hostns sysctl -q net.ipv4.conf.all.rp_filter=0 net.ipv6.conf.all.forwarding=1 2>/dev/null
  ip -n hostns addr add 10.0.0.2/24 dev up0; ip -n hostns addr add fd00::2/64 dev up0 nodad
  ip -n g1 addr add 10.0.0.5/24 dev g1eth; ip -n g1 addr add fd00::5/64 dev g1eth nodad
  ip -n g1 link set g1eth up; ip -n g1 link set lo up
  local wrap=(); [ "$engine" = nft ] && wrap=("$NOEBPF")  # nft under bpf()-blocked seccomp
  ip netns exec hostns "${wrap[@]}" "$BIN" -i up0 -e "$engine" -m fwd-with-offload --timeout $TMO \
    --fwd-device-if mt-if --fwd-device-br mt-br >/tmp/pb-ka-$engine.log 2>&1 &
  PB=$!
  for _ in $(seq 1 40); do grep -q 'backend running' /tmp/pb-ka-$engine.log && break; sleep 0.2; done
  grep -q 'backend running' /tmp/pb-ka-$engine.log || { echo "  [$engine] NOT RUNNING"; rc=1; return; }
  for _ in $(seq 1 20); do ip -n hostns link show mt-br >/dev/null 2>&1 && break; sleep 0.2; done
  ip -n hostns link set mt-br master br0; sleep 1
  # learn the VM (one packet each family), then go silent (still holding the IPs).
  ip netns exec g1 ping -c1 -W2 10.0.0.1 >/dev/null 2>&1; ip netns exec g1 ping -c1 -W2 fd00::1 >/dev/null 2>&1; sleep 1
  local n0; n0=$(ip -n hostns addr show dev up0 | grep -c "metric $MAGIC")
  [ "$n0" = 2 ] && echo "  [$engine] proxies installed (2)" || { echo "  [$engine] expected 2 proxies, got $n0"; rc=1; }
  sleep $((TMO*5/2 + 1))    # > 2.5×timeout of silence
  local n1; n1=$(ip -n hostns addr show dev up0 | grep -c "metric $MAGIC")
  [ "$n1" = 2 ] && echo "  [$engine] silent-but-present: proxies kept (probe works)" || { echo "  [$engine] silent proxies dropped ($n1) — probe failed"; rc=1; }
  ip -n g1 addr flush dev g1eth                       # VM releases its IPs
  sleep $((TMO*5/2 + 1))
  local n2; n2=$(ip -n hostns addr show dev up0 | grep -c "metric $MAGIC")
  [ "$n2" = 0 ] && echo "  [$engine] released: proxies evicted" || { echo "  [$engine] released proxies not evicted ($n2)"; rc=1; }
}

for e in ${ENGINES:-nft ebpf}; do one "$e"; done
echo "== offload-keepalive: $([ $rc = 0 ] && echo PASS || echo FAIL) =="
exit $rc
