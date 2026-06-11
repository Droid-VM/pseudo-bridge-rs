#!/usr/bin/env python3
# Behaviour survey: nft sets arp.sha / nd.lla (+ eth.src). Verify the set takes
# effect, and crucially whether nft fixes the ICMPv6 checksum after mangling the
# ND LLA (it should NOT → ND needs userspace fix_csum; ARP has no csum → fine).
import socket, struct, time
ETH_P_ALL = 3
GUEST = "02:aa:aa:aa:aa:aa"
TEST  = "02:11:22:33:44:55"
def mac(s): return bytes.fromhex(s.replace(":", ""))
def cksum(b):
    if len(b) % 2: b += b"\x00"
    s = 0
    for i in range(0, len(b), 2): s += (b[i] << 8) | b[i+1]
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
def icmp6_csum(src, dst, msg):
    return cksum(src + dst + struct.pack("!I", len(msg)) + b"\x00\x00\x00" + bytes([58]) + msg)

def build_arp():
    eth = mac("ff:ff:ff:ff:ff:ff") + mac(GUEST) + struct.pack("!H", 0x0806)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + mac(GUEST) + bytes([10,0,0,5]) + mac("00:00:00:00:00:00") + bytes([10,0,0,1])
    return eth + arp
def build_na():
    src = bytes.fromhex("fe800000000000000000000000000001")
    dst = bytes.fromhex("fe800000000000000000000000000002")
    # NA: type136 code0 csum(2) flags(4) target(16) + TLLAO(type2 len1 mac6)
    msg = bytes([136,0]) + b"\x00\x00" + b"\x20\x00\x00\x00" + src + bytes([2,1]) + mac(GUEST)
    msg = msg[:2] + struct.pack("!H", icmp6_csum(src, dst, msg)) + msg[4:]
    ip6 = bytes([0x60,0,0,0]) + struct.pack("!H", len(msg)) + bytes([58,255]) + src + dst
    return mac("33:33:00:00:00:01") + mac(GUEST) + struct.pack("!H", 0x86dd) + ip6 + msg

rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); rx.bind(("b0p",0)); rx.settimeout(2)
tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); tx.bind(("a0p",0))
tx.send(build_arp()); time.sleep(0.1)
tx.send(build_na());  time.sleep(0.1)

got = {}
t0 = time.time()
while time.time()-t0 < 2:
    try: d = rx.recv(2048)
    except socket.timeout: break
    et = struct.unpack("!H", d[12:14])[0]
    if et == 0x0806: got["arp"] = d
    elif et == 0x86dd and len(d)>=86 and d[20]==58 and d[54]==136 and d[22:38]==bytes.fromhex("fe800000000000000000000000000001"): got["na"] = d

ok = True
def chk(n,c):
    global ok; ok &= c; print(f"  [{'PASS' if c else 'FAIL'}] {n}")
T = mac(TEST)
if "arp" in got:
    a = got["arp"]
    chk("ARP eth.src set by nft", a[6:12]==T)
    chk("ARP sha   set by nft", a[22:28]==T)
else: chk("ARP received", False)
if "na" in got:
    n = got["na"]
    chk("NA eth.src set by nft", n[6:12]==T)
    chk("NA lla    set by nft (off 80)", n[80:86]==T)
    recv = struct.unpack("!H", n[56:58])[0]
    fresh = icmp6_csum(n[22:38], n[38:54], n[54:56]+b"\x00\x00"+n[58:])
    chk(f"NA ICMPv6 csum CORRECT after nft set lla? (recv=0x{recv:04x} fresh=0x{fresh:04x})", recv==fresh)
    print(f"      → nft {'修了' if recv==fresh else '沒修'} ICMPv6 csum;沒修則需 userspace fix_csum")
else: chk("NA received", False)
print("SURVEY DONE")
