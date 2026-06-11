#!/usr/bin/env python3
# Send a broadcast ARP from gAp; report whether it arrives at uBp (bridged).
import socket, struct, time
ETH_P_ALL = 3
GUEST = "02:aa:aa:aa:aa:aa"
def mac(s): return bytes.fromhex(s.replace(":", ""))
def build_arp():
    eth = mac("ff:ff:ff:ff:ff:ff") + mac(GUEST) + struct.pack("!H", 0x0806)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac(GUEST) + bytes([10,0,0,5]) \
          + mac("00:00:00:00:00:00") + bytes([10,0,0,1])
    return eth + arp

rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); rx.bind(("uBp",0)); rx.settimeout(1.5)
tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); tx.bind(("gAp",0))
tx.send(build_arp())
got = False
t0 = time.time()
while time.time()-t0 < 1.5:
    try: d = rx.recv(2048)
    except socket.timeout: break
    if len(d) >= 28 and struct.unpack("!H", d[12:14])[0] == 0x0806 and d[6:12] == mac(GUEST):
        got = True; break
print("ARP reached up0-port:", "YES" if got else "NO")
