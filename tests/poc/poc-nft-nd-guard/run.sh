#!/usr/bin/env bash
# Test the proposed in-kernel ND LLA rewrite + DAD-safety via `!= HOSTMAC` guard.
#   a0p ─send─▶ a0 [nft: NS/NA @th,208 != HOSTMAC -> set HOSTMAC ; fwd b0] ─▶ b0 ~ b0p ─recv▶
# DAD NS (no option, 24B ND) must fall through UNCHANGED (OOB @th,208 -> no match).
set -u
NS=ndguard
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
    icmpv6 type 135 ip6 saddr != :: @th,208,48 != 0x020000000001 @th,208,48 set 0x020000000001 fwd to "b0"
    icmpv6 type 136 @th,208,48 != 0x020000000001 @th,208,48 set 0x020000000001 fwd to "b0"
    icmpv6 type 133 ip6 saddr != :: @th,80,48 != 0x020000000001 @th,80,48 set 0x020000000001 fwd to "b0"
    fwd to "b0"
  }
}
EOF
echo "== ruleset =="; ip netns exec $NS nft list table netdev t | sed -n '/chain c/,/}/p'
echo "== test =="; ip netns exec $NS python3 poc.py
