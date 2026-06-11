#!/usr/bin/env python3
# Parse a DLT_NFLOG pcap: for each record show which NFULA_* TLVs are present,
# and decode NFULA_HWADDR(8) / NFULA_HWHEADER(16) — i.e. is the src mac carried?
import struct, sys
NFULA = {1:"PACKET_HDR",2:"MARK",3:"TIMESTAMP",4:"IFINDEX_INDEV",5:"IFINDEX_OUTDEV",
         8:"HWADDR",9:"PAYLOAD",10:"PREFIX",16:"HWHEADER",17:"HWLEN"}
d = open(sys.argv[1],"rb").read()
magic = struct.unpack_from("<I", d, 0)[0]
le = magic in (0xa1b2c3d4, 0xa1b23c4d)
en = "<" if le else ">"
off = 24  # global header
rec = 0
while off + 16 <= len(d):
    ts, tu, incl, orig = struct.unpack_from(en+"IIII", d, off); off += 16
    body = d[off:off+incl]; off += incl
    rec += 1
    if len(body) < 4: continue
    fam, ver, rid = struct.unpack_from(">BBH", body, 0)
    i = 4; tlvs = {}
    while i + 4 <= len(body):
        l, t = struct.unpack_from(en+"HH", body, i)  # nflog tlv len,type host order
        if l < 4: break
        tlvs[t] = body[i+4:i+l]; i += (l + 3) & ~3
    names = [NFULA.get(t, str(t)) for t in tlvs]
    print(f"rec {rec}: TLVs={names}")
    if 8 in tlvs:
        hw = tlvs[8]; alen = struct.unpack_from(">H", hw, 0)[0]
        print(f"   HWADDR src mac = {hw[4:4+alen].hex(':')}")
    if 16 in tlvs:
        hh = tlvs[16]
        print(f"   HWHEADER       = {hh.hex(':')}  (src mac = {hh[6:12].hex(':') if len(hh)>=12 else '?'})")
    if 9 in tlvs:
        print(f"   PAYLOAD[:16]   = {tlvs[9][:16].hex()}")
