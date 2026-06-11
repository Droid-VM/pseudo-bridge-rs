#!/usr/bin/env bash
# Does a BRIDGED frame (guest-port -> up0-port) actually hit a bridge-family
# `queue` hook? Tests direct-mode's path-to-userspace for OUT learn (no fwd at
# netdev egress; bridge family has no fwd but DOES have queue).
#   gAp ─send ARP/ND─▶ gA [br0] uB ─▶ uBp ─recv
#                         └ nft bridge hook forward: <verdict>
# With `queue num 1` (no listener, no bypass): caught -> DROPPED (won't reach uBp).
# With `queue num 1 bypass`: no listener -> fail-open -> reaches uBp.
# With `accept`: baseline -> reaches uBp.
set -u
NS=brq
cd "$(dirname "$0")"
cleanup(){ ip netns del $NS 2>/dev/null; }
trap cleanup EXIT; cleanup
ip netns add $NS
ip -n $NS link add br0 type bridge
ip -n $NS link add gA type veth peer name gAp
ip -n $NS link add uB type veth peer name uBp
ip -n $NS link set gA master br0
ip -n $NS link set uB master br0
for d in br0 gA gAp uB uBp lo; do ip -n $NS link set $d up; ip netns exec $NS sysctl -qw net.ipv6.conf.$d.disable_ipv6=1; done

run_case(){ # $1 = verdict line, $2 = label
  ip netns exec $NS nft flush ruleset
  ip netns exec $NS nft -f - <<EOF
table bridge t {
  chain c {
    type filter hook forward priority 0;
    ether type arp $1
    icmpv6 type { nd-neighbor-solicit, nd-router-solicit } $1
  }
}
EOF
  printf '  [%-18s] ' "$2"
  ip netns exec $NS python3 probe.py
}

echo "== bridge forward verdict on bridged ARP =="
run_case "accept"          "accept (baseline)"
run_case "queue num 1"     "queue (no listener)"
run_case "queue num 1 bypass" "queue bypass"
