#!/usr/bin/env python3
# Runs inside the netns. Verifies the fwd-to-channel premise:
#   a1 --send--> a0 (nft netdev ingress: fwd to chan0) --> chan0 ~veth~ chan1 --recv-->
# Sends 3 frames and checks chan1 receives them (and that the rewrite rule fired).
import socket, struct, time

ETH_P_ALL = 3

def mac(s): return bytes.fromhex(s.replace(":", ""))
def frame(dst, src, etype, payload=b""):
    return mac(dst) + mac(src) + struct.pack("!H", etype) + payload

def open_sock(ifname):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((ifname, 0))
    return s

rx = open_sock("chan1"); rx.settimeout(2.0)
tx = open_sock("a1")

BCAST = "ff:ff:ff:ff:ff:ff"
sends = {
    "ARP":          frame(BCAST, "02:00:00:00:00:22", 0x0806, b"\x00" * 28),
    "custom-88b5":  frame(BCAST, "02:00:00:00:00:33", 0x88b5, b"hello" + b"\x00" * 41),
    # src mac 02:..:11 triggers the nft rewrite rule -> src should arrive as 02:..:99
    "ipv4-rewrite": frame("02:00:00:00:00:aa", "02:00:00:00:00:11", 0x0800, b"\x00" * 46),
}
for f in sends.values():
    tx.send(f); time.sleep(0.1)

got = []
t0 = time.time()
while time.time() - t0 < 2.0:
    try:
        d = rx.recv(2048)
    except socket.timeout:
        break
    got.append((d[6:12].hex(), "%04x" % struct.unpack("!H", d[12:14])[0]))

print("received on chan1:", got)
def seen(src, et): return (src, et) in got
ok = True
for name, src, et in [("ARP fwd", "020000000022", "0806"),
                      ("custom ethertype fwd", "020000000033", "88b5"),
                      ("rewrite(src 11->99)+fwd", "020000000099", "0800")]:
    p = seen(src, et); ok &= p
    print(f"  [{'PASS' if p else 'FAIL'}] {name}  (src={src} et={et})")
# negative: the original un-rewritten src 11 must NOT appear (rule changed it)
if seen("020000000011", "0800"):
    print("  [WARN] saw un-rewritten src 11 (rewrite didn't fire?)"); ok = False
print("VERDICT:", "ALL PASS" if ok else "SOME FAIL")
