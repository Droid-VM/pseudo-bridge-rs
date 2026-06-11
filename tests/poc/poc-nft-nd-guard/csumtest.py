#!/usr/bin/env python3
# Does nft fix the ICMPv6 checksum when you change `ip6 saddr` (pseudo-header)?
# Send NS (src=LL_G, valid csum); nft sets ip6 saddr = ::; check recv csum.
import socket, struct, time
ETH_P_ALL = 3
GUEST = "02:aa:aa:aa:aa:aa"
def mac(s): return bytes.fromhex(s.replace(":", ""))
def cksum(b):
    if len(b) % 2: b += b"\x00"
    s = 0
    for i in range(0, len(b), 2): s += (b[i] << 8) | b[i+1]
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
def icmp6_csum(src, dst, msg):
    return cksum(src + dst + struct.pack("!I", len(msg)) + b"\x00\x00\x00" + bytes([58]) + msg)
LL_G  = bytes.fromhex("fe800000000000000000000000000aaa")
LL_GW = bytes.fromhex("fe800000000000000000000000000001")
UNSPEC= bytes(16)
def frame(src6, dst6, msg, dmac):
    msg = msg[:2] + struct.pack("!H", icmp6_csum(src6, dst6, msg)) + msg[4:]
    ip6 = bytes([0x60,0,0,0]) + struct.pack("!H", len(msg)) + bytes([58,255]) + src6 + dst6
    return mac(dmac) + mac(GUEST) + struct.pack("!H", 0x86dd) + ip6 + msg
def build_ns():
    msg = bytes([135,0]) + b"\x00\x00" + b"\x00\x00\x00\x00" + LL_GW + bytes([1,1]) + mac(GUEST)
    return frame(LL_G, LL_GW, msg, "33:33:00:00:00:01")

rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); rx.bind(("b0p",0)); rx.settimeout(2)
tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); tx.bind(("a0p",0))
tx.send(build_ns()); time.sleep(0.2)

t0 = time.time()
while time.time()-t0 < 2:
    try: d = rx.recv(2048)
    except socket.timeout: break
    if struct.unpack("!H", d[12:14])[0] != 0x86dd or len(d) < 86 or d[20] != 58 or d[54] != 135: continue
    saddr = d[22:38]; recv = struct.unpack("!H", d[56:58])[0]
    print(f"  ip6.saddr after nft = {saddr.hex()}  ({'== ::' if saddr==UNSPEC else 'NOT ::'})")
    fresh_unspec = icmp6_csum(UNSPEC, d[38:54], d[54:56]+b"\x00\x00"+d[58:])
    fresh_old    = icmp6_csum(LL_G,   d[38:54], d[54:56]+b"\x00\x00"+d[58:])
    print(f"  recv csum=0x{recv:04x}  fresh(src=::)=0x{fresh_unspec:04x}  fresh(src=old)=0x{fresh_old:04x}")
    if   recv == fresh_unspec: print("  => nft FIXED the ICMPv6 csum for the new src ✓")
    elif recv == fresh_old:    print("  => nft did NOT fix csum (still matches old src) ✗")
    else:                      print("  => csum matches NEITHER (broken) ✗")
    break
else:
    print("  no NS received")
