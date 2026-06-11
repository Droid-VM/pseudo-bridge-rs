#!/usr/bin/env bash
# Verify nft `dup to` (NFT_DUP_NETDEV) for fwd-mode IN multicast→guest:
#   (1) does `dup to` load?  (= NFT_DUP_NETDEV present)
#   (2) does it copy broadcast + multicast to fwd0 (the guest side)?
#   (3) is `dup` non-terminal? (original must still reach host stack — host also needs mcast)
#   up0p ─send bcast/mcast─▶ up0 [nft: meta pkttype {bcast,mcast} dup to fwd0 counter] ─▶ fwd0 ~ fwd0p ─recv
set -u
NS=nftdup
cd "$(dirname "$0")"
cleanup(){ ip netns del $NS 2>/dev/null; }
trap cleanup EXIT; cleanup
ip netns add $NS
ip -n $NS link add up0  type veth peer name up0p
ip -n $NS link add fwd0 type veth peer name fwd0p
for d in up0 up0p fwd0 fwd0p lo; do ip -n $NS link set $d up; ip netns exec $NS sysctl -qw net.ipv6.conf.$d.disable_ipv6=1; done

echo "== (1) load 'dup to' =="
ip netns exec $NS nft -f - <<'EOF' && echo "  NFT_DUP_NETDEV: present" || { echo "  NFT_DUP_NETDEV: MISSING"; exit 1; }
table netdev t {
  chain c {
    type filter hook ingress device "up0" priority -300;
    meta pkttype { broadcast, multicast } dup to "fwd0" counter
  }
}
EOF

echo "== (2)/(3) send bcast+mcast into up0, check copy on fwd0p + counter (non-terminal) =="
ip netns exec $NS python3 - <<'PY'
import socket,struct,time
def mac(s): return bytes.fromhex(s.replace(":",""))
rx=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); rx.bind(("fwd0p",0)); rx.settimeout(2)
tx=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); tx.bind(("up0p",0))
bcast=mac("ff:ff:ff:ff:ff:ff")+mac("02:aa:aa:aa:aa:aa")+struct.pack("!H",0x0806)+struct.pack("!HHBBH",1,0x0800,6,4,1)+mac("02:aa:aa:aa:aa:aa")+bytes([10,0,0,5])+mac("0:0:0:0:0:0")+bytes([10,0,0,1])
mcast=mac("33:33:00:00:00:01")+mac("02:bb:bb:bb:bb:bb")+struct.pack("!H",0x88b5)+b"\xde\xad\xbe\xef"
tx.send(bcast); tx.send(mcast)
got=set(); t0=time.time()
while time.time()-t0<2:
    try: d=rx.recv(2048)
    except socket.timeout: break
    got.add(d[6:12].hex(":"))
ok = "02:aa:aa:aa:aa:aa" in got and "02:bb:bb:bb:bb:bb" in got
print(f"  fwd0p got srcs={sorted(got)}")
print("  [%s] dup copied broadcast+multicast to guest side" % ("PASS" if ok else "FAIL"))
PY
echo "  counter (after dup) — non-zero = dup 非終結、原包續走 host:"
ip netns exec $NS nft list table netdev t | grep -o "counter packets [0-9]*"
