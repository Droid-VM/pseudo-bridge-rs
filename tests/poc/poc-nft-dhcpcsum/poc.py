#!/usr/bin/env python3
# Send a DHCPv4 request (correct UDP csum) on a1; nft on a0 ingress sets the BOOTP
# broadcast flag via `@th,144,16 set 0x8000` and fwd to b0. Receive on b1, check the
# flag is set AND whether nft auto-fixed the UDP checksum (the modify_dhcpv4 nft premise).
import socket, struct, time
ETH_P_ALL = 3
def mac(s): return bytes.fromhex(s.replace(":", ""))
def cksum(b):
    if len(b) % 2: b = b + b"\x00"
    s = 0
    for i in range(0, len(b), 2): s += (b[i] << 8) | b[i+1]
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

GUEST = "02:aa:aa:aa:aa:aa"
src_ip, dst_ip = bytes(4), bytes([255,255,255,255])
# BOOTP: op htype hlen hops | xid(4) | secs(2) | flags(2)=0 | 32 bytes ci/yi/si/gi+chaddr
bootp = bytes([1,1,6,0]) + b"\x12\x34\x56\x78" + b"\x00\x00" + b"\x00\x00" + b"\x00"*32
udplen = 8 + len(bootp)
pseudo = src_ip + dst_ip + bytes([0,17]) + struct.pack("!H", udplen)
ucsum = cksum(pseudo + struct.pack("!HHH",68,67,udplen) + b"\x00\x00" + bootp)
udp = struct.pack("!HHHH",68,67,udplen,ucsum) + bootp
totlen = 20 + len(udp)
iph = bytes([0x45,0]) + struct.pack("!H",totlen) + b"\x00\x00\x00\x00" + bytes([64,17]) + b"\x00\x00" + src_ip + dst_ip
ip = iph[:10] + struct.pack("!H", cksum(iph)) + iph[12:]
pkt = mac("ff:ff:ff:ff:ff:ff") + mac(GUEST) + struct.pack("!H",0x0800) + ip + udp

rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); rx.bind(("b1",0)); rx.settimeout(2)
tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); tx.bind(("a1",0))
print(f"sent: flags=0x{struct.unpack('!H',bootp[10:12])[0]:04x} udpcsum=0x{ucsum:04x}")
tx.send(pkt); time.sleep(0.2)

d = None
t0 = time.time()
while time.time()-t0 < 2:
    try: x = rx.recv(2048)
    except socket.timeout: break
    if len(x) >= 54 and x[12:14] == b"\x08\x00" and x[23] == 17 and x[36:38] == b"\x00\x43":
        d = x; break

ok = True
def chk(n,c):
    global ok; ok &= c; print(f"  [{'PASS' if c else 'FAIL'}] {n}")
if d is None:
    chk("received DHCP at b1", False)
else:
    flags = struct.unpack("!H", d[52:54])[0]
    chk(f"BOOTP broadcast flag set (0x{flags:04x})", flags == 0x8000)
    recv = struct.unpack("!H", d[40:42])[0]
    rsrc, rdst = d[26:30], d[30:34]; rudplen = struct.unpack("!H", d[38:40])[0]
    rudp = d[34:34+rudplen]
    fresh = cksum(rsrc + rdst + bytes([0,17]) + struct.pack("!H",rudplen) + rudp[:6] + b"\x00\x00" + rudp[8:])
    valid = (recv == 0) or (recv == fresh)   # IPv4 UDP csum=0 = 不檢查(合法);或正確值
    chk(f"UDP csum valid after mangle (recv=0x{recv:04x}; 0=off or fresh=0x{fresh:04x})", valid)
    print(f"      nft 對 L7 payload set 不自動 fixup → 需 `udp checksum set 0` 歸零(recv==0? {recv==0})")
print("VERDICT:", "ALL PASS" if ok else "SOME FAIL")
