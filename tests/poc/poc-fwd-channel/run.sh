#!/usr/bin/env bash
# PoC: nft netdev-ingress `fwd to <channel veth>` carries ARP / any ethertype, and
# can rewrite+fwd — the premise behind ARCHITECTURE.md §5 (fwd-to-channel slow path).
#   a1 ─send─▶ a0 [nft ingress: rewrite? + fwd to chan0] ─▶ chan0 ~veth~ chan1 ─recv▶
set -u
NS=pbpoc
cd "$(dirname "$0")"
cleanup() { ip netns del $NS 2>/dev/null; }
trap cleanup EXIT
cleanup

ip netns add $NS
ipx() { ip -n $NS "$@"; }
ipx link add a0   type veth peer name a1
ipx link add chan0 type veth peer name chan1
for d in a0 a1 chan0 chan1 lo; do ipx link set $d up; done

ip netns exec $NS nft -f - <<'EOF'
table netdev t {
  chain c {
    type filter hook ingress device "a0" priority -300;
    ether saddr 02:00:00:00:00:11 ether saddr set 02:00:00:00:00:99 fwd to "chan0"
    ether type arp fwd to "chan0"
    fwd to "chan0"
  }
}
EOF
echo "== installed ruleset =="
ip netns exec $NS nft list table netdev t
echo "== run probe =="
ip netns exec $NS python3 poc.py
