#!/bin/bash
# Silent-VM discovery (fwd mode): a guest that configures a static IP but sends NO traffic
# (no DHCP, no DAD/gratuitous) has no learned entry and no /32-/128 vmroute — so without
# help, host→VM resolves the VM's IP on up0 (the upstream prefix) and the ARP/NS goes to the
# gateway, never the VM. pbridge's up0-egress discovery dup clones the host's ARP-req/NS to
# fwd0→bridge; the silent VM replies, gets learned, the vmroute appears, and host→VM works.
#
#   ns up (gw) ── up0(hostns: pbridge fwd) [br0] ── g1 (SILENT static IP)
#
# Runs per engine (default both). The VM never initiates; only the host pings it.
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
  ip -n up addr add 10.0.0.1/24 dev u0; ip -n up addr add fd00::1/64 dev u0 nodad
  ip -n up link set u0 up; ip -n up link set lo up
  ip -n hostns link set up0 address $HMAC; ip -n hostns link set up0 up
  ip -n hostns link add br0 type bridge; ip -n hostns link set br0 up
  ip -n hostns link set gbr master br0; ip -n hostns link set gbr up
  ip netns exec hostns sysctl -q net.ipv4.conf.all.rp_filter=0 net.ipv6.conf.all.forwarding=1 2>/dev/null
  ip -n hostns addr add 10.0.0.2/24 dev up0; ip -n hostns addr add fd00::2/64 dev up0 nodad
  # SILENT VM: static IPs (nodad so no DAD NS), and it never sends anything.
  ip -n g1 addr add 10.0.0.5/24 dev g1eth; ip -n g1 addr add fd00::5/64 dev g1eth nodad
  ip -n g1 link set g1eth up; ip -n g1 link set lo up
  local wrap=(); [ "$engine" = nft ] && wrap=("$NOEBPF")
  ip netns exec hostns "${wrap[@]}" "$BIN" -i up0 -e "$engine" -m fwd \
    --fwd-device-if mt-if --fwd-device-br mt-br >/tmp/pb-silent-$engine.log 2>&1 &
  PB=$!
  for _ in $(seq 1 40); do grep -q 'backend running' /tmp/pb-silent-$engine.log && break; sleep 0.2; done
  grep -q 'backend running' /tmp/pb-silent-$engine.log || { echo "  [$engine] pbridge NOT RUNNING"; rc=1; return; }
  for _ in $(seq 1 20); do ip -n hostns link show mt-br >/dev/null 2>&1 && break; sleep 0.2; done
  ip -n hostns link set mt-br master br0; sleep 1
  # The VM has sent nothing; only the host probes it. ping retries give the discovery dup
  # time to learn the VM and create the vmroute (resolved on the bridge on retry).
  if ip netns exec hostns ping -c4 -W2 10.0.0.5 >/dev/null 2>&1; then echo "  [$engine] host -> silent VM v4 OK"; else echo "  [$engine] host -> silent VM v4 FAIL"; rc=1; fi
  if ip netns exec hostns ping -c4 -W2 fd00::5 >/dev/null 2>&1; then echo "  [$engine] host -> silent VM v6 OK"; else echo "  [$engine] host -> silent VM v6 FAIL"; rc=1; fi
}

for e in ${ENGINES:-nft ebpf}; do one "$e"; done
echo "== silent-vm: $([ $rc = 0 ] && echo PASS || echo FAIL) =="
exit $rc
