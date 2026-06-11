#!/usr/bin/env python3
# NFLOG listener (debug): PF_BIND + group BIND + COPY_PACKET; print ACK errors and
# every PACKET's NFULA_HWADDR / NFULA_HWHEADER / payload. Q: is src mac carried?
import socket, struct, sys, time
NETLINK_NETFILTER = 12
NFNL_SUBSYS_ULOG  = 6
NFULNL_MSG_PACKET = 0; NFULNL_MSG_CONFIG = 1
NFULA_CFG_CMD = 1; NFULA_CFG_MODE = 2
NFULNL_CFG_CMD_BIND = 1; NFULNL_CFG_CMD_PF_BIND = 2; NFULNL_COPY_PACKET = 2
NFULA_HWADDR = 8; NFULA_PAYLOAD = 9; NFULA_HWHEADER = 16
GROUP = int(sys.argv[1]) if len(sys.argv) > 1 else 5

s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
s.bind((0, 0))
seq = [0]
def attr(t, p):
    l = 4 + len(p); return struct.pack("HH", l, t) + p + b"\x00"*((-l) % 4)
def cfg(family, group, a):
    seq[0] += 1
    body = struct.pack("BBH", family, 0, socket.htons(group)) + a
    s.send(struct.pack("IHHII", 16+len(body), (NFNL_SUBSYS_ULOG<<8)|NFULNL_MSG_CONFIG, 1, seq[0], 0) + body)
cfg(0, GROUP, attr(NFULA_CFG_CMD, struct.pack("B", NFULNL_CFG_CMD_BIND)))       # bind group (cmd = 1 byte)
cfg(0, GROUP, attr(NFULA_CFG_MODE, struct.pack(">IBB", 0xffffffff, NFULNL_COPY_PACKET, 0)))

def parse_attrs(b):
    out = {}; i = 0
    while i + 4 <= len(b):
        l, t = struct.unpack_from("HH", b, i)
        if l < 4: break
        out[t & 0x3fff] = b[i+4:i+l]; i += (l + 3) & ~3
    return out

s.settimeout(5); print(f"  listening NFLOG group {GROUP}")
t0 = time.time(); n = 0
while time.time() - t0 < 5 and n < 4:
    try: data = s.recv(65536)
    except socket.timeout: break
    off = 0
    while off + 16 <= len(data):
        mlen, mtype, flags, sq, pid = struct.unpack_from("IHHII", data, off)
        if mlen < 16: break
        body = data[off+16:off+mlen]
        print(f"  [recv] type=0x{mtype:04x} len={mlen} body={body[:24].hex()}")
        if mtype == 2:  # NLMSG_ERROR / ACK
            err = struct.unpack_from("i", body, 0)[0]
            if err != 0: print(f"  [ACK] error={err}")
        elif (mtype >> 8) == NFNL_SUBSYS_ULOG and (mtype & 0xff) == NFULNL_MSG_PACKET:
            a = parse_attrs(body[4:]); n += 1
            hw = a.get(NFULA_HWADDR); hh = a.get(NFULA_HWHEADER); pl = a.get(NFULA_PAYLOAD, b"")
            srcmac = None
            if hw and len(hw) >= 4:
                alen = struct.unpack_from(">H", hw, 0)[0]; srcmac = hw[4:4+alen].hex(":")
            print(f"  PKT NFULA_HWADDR(src mac)={srcmac}")
            print(f"      NFULA_HWHEADER       ={hh.hex(':') if hh else None}")
            print(f"      payload[:16]         ={pl[:16].hex()}")
        off += (mlen + 3) & ~3
print(f"  ({n} packet(s) parsed)")
