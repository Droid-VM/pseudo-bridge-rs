#!/usr/bin/env python3
# Inject ARP + ND-NS on a1, receive rewritten frames on b1, verify:
#   - eth.src / arp.sha / ND-LLA rewritten to TESTMAC
#   - ICMPv6 checksum still correct after ebpf in-place LLA rewrite
import socket, struct, time

ETH_P_ALL = 3
GUEST = "02:aa:aa:aa:aa:aa"
TEST  = "02:11:22:33:44:55"   # cfg.mac the prog rewrites to

def mac(s): return bytes.fromhex(s.replace(":", ""))

def icmp6_csum(src, dst, msg):
    plen = len(msg)
    buf = src + dst + struct.pack("!I", plen) + b"\x00\x00\x00" + bytes([58]) + msg
    if len(buf) % 2: buf += b"\x00"
    s = 0
    for i in range(0, len(buf), 2):
        s += (buf[i] << 8) | buf[i + 1]
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def build_arp():
    eth = mac("ff:ff:ff:ff:ff:ff") + mac(GUEST) + struct.pack("!H", 0x0806)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac(GUEST) + bytes([10,0,0,9]) \
          + mac("00:00:00:00:00:00") + bytes([10,0,0,1])
    return eth + arp

def build_ns():
    src = bytes.fromhex("fe800000000000000000000000000001")  # fe80::1
    dst = bytes.fromhex("ff020000000000000000000000000001")  # ff02::1
    target = src
    # NS: type135 code0 csum(0) reserved(4) target(16) + SLLAO(type1 len1 mac6)
    sllao = bytes([1, 1]) + mac(GUEST)
    msg = bytes([135, 0]) + b"\x00\x00" + b"\x00\x00\x00\x00" + target + sllao
    csum = icmp6_csum(src, dst, msg)
    msg = msg[:2] + struct.pack("!H", csum) + msg[4:]
    ip6 = bytes([0x60,0,0,0]) + struct.pack("!H", len(msg)) + bytes([58, 255]) + src + dst
    eth = mac("33:33:00:00:00:01") + mac(GUEST) + struct.pack("!H", 0x86dd)
    return eth + ip6 + msg

rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); rx.bind(("b1", 0)); rx.settimeout(2)
tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); tx.bind(("a1", 0))

tx.send(build_arp()); time.sleep(0.1)
tx.send(build_ns());  time.sleep(0.1)

got = {}
t0 = time.time()
while time.time() - t0 < 2:
    try: d = rx.recv(2048)
    except socket.timeout: break
    et = struct.unpack("!H", d[12:14])[0]
    if et == 0x0806: got["arp"] = d
    elif et == 0x86dd and d[22:38] == bytes.fromhex("fe800000000000000000000000000001"): got["nd"] = d

ok = True
def check(name, cond):
    global ok; ok &= cond; print(f"  [{'PASS' if cond else 'FAIL'}] {name}")

T = mac(TEST)
if "arp" in got:
    a = got["arp"]
    check("ARP eth.src rewritten", a[6:12] == T)
    check("ARP sha rewritten",     a[14+8:14+14] == T)
else:
    check("ARP received", False)

if "nd" in got:
    n = got["nd"]
    check("ND eth.src rewritten", n[6:12] == T)
    check("ND LLA rewritten",     n[80:86] == T)   # opt 78, mac at 80
    # recompute ICMPv6 csum over received frame; valid means recompute==0
    src, dst = n[22:38], n[38:54]
    msg = n[54:]
    recv_csum = struct.unpack("!H", n[56:58])[0]
    fresh = icmp6_csum(src, dst, msg[:2] + b"\x00\x00" + msg[4:])
    check(f"ND ICMPv6 csum correct (recv=0x{recv_csum:04x} recompute=0x{fresh:04x})", recv_csum == fresh)
else:
    check("ND received", False)

print("VERDICT:", "ALL PASS" if ok else "SOME FAIL")
