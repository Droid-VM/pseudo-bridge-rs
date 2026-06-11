#!/usr/bin/env bash
# PoC: does nft (udp context) auto-fixup UDP csum when mangling a byte deep in the
# UDP *payload* (BOOTP broadcast flag)? = the modify_dhcpv4 nft-path premise.
#   a1 ─DHCP req─▶ a0 [nft: udp dport 67 @th,144,16 set 0x8000 ; fwd b0] ─▶ b0~b1 ─recv▶
set -u
NS=pocdhcp
cd "$(dirname "$0")"
cleanup() { ip netns del $NS 2>/dev/null; }
trap cleanup EXIT
cleanup

ip netns add $NS
ip -n $NS link add a0 type veth peer name a1
ip -n $NS link add b0 type veth peer name b1
for d in a0 a1 b0 b1 lo; do ip -n $NS link set $d up; done

ip netns exec $NS nft -f - <<'EOF'
table netdev t {
  chain c {
    type filter hook ingress device "a0" priority -300;
    udp dport 67 @th,144,16 set 0x8000 udp checksum set 0 fwd to "b0"
    fwd to "b0"
  }
}
EOF
echo "== ruleset =="; ip netns exec $NS nft list table netdev t
echo "== probe =="; ip netns exec $NS python3 poc.py
