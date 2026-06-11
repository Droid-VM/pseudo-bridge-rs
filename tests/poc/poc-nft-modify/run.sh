#!/usr/bin/env bash
# Survey: nft in-kernel `set` of arp.sha / nd.lla behaviour + ICMPv6 csum.
#   a0p ─send─▶ a0 [nft: set arp.sha/nd.lla + eth.src ; fwd b0] ─▶ b0 ~ b0p ─recv▶
set -u
NS=nftmod
cd "$(dirname "$0")"
cleanup() { ip netns del $NS 2>/dev/null; }
trap cleanup EXIT
cleanup
ip netns add $NS
ip -n $NS link add a0 type veth peer name a0p
ip -n $NS link add b0 type veth peer name b0p
for d in a0 a0p b0 b0p lo; do ip -n $NS link set $d up; ip netns exec $NS sysctl -qw net.ipv6.conf.$d.disable_ipv6=1; done

ip netns exec $NS nft -f - <<'EOF'
table netdev t {
  chain c {
    type filter hook ingress device "a0" priority -300;
    ether type arp arp saddr ether set 02:11:22:33:44:55 ether saddr set 02:11:22:33:44:55 fwd to "b0"
    icmpv6 type 136 @th,208,48 set 0x021122334455 ether saddr set 02:11:22:33:44:55 fwd to "b0"
    fwd to "b0"
  }
}
EOF
echo "== ruleset =="; ip netns exec $NS nft list table netdev t | sed -n '/chain c/,/}/p'
echo "== survey =="; ip netns exec $NS python3 poc.py