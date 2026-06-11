#!/usr/bin/env python3
# Verify the proposed in-kernel ND LLA rewrite design:
#   NS:  cond @th,208,48(SLLAO) != HOSTMAC -> set SLLAO=HOSTMAC ; fwd
#   NA:  cond @th,208,48(TLLAO) != HOSTMAC -> set TLLAO=HOSTMAC ; fwd
#   else (incl DAD NS, src=:: , NO option) -> fwd unchanged
# Crux: does nft's `@th,208,48 != HOSTMAC` on a DAD NS (24-byte ND, no option,
# byte 208 is PAST packet end) safely *not match* (skip) instead of erroring /
# corrupting?  If yes, the != guard is a DAD-safe presence guard for free.
import socket, struct, time
ETH_P_ALL = 3
GUEST   = "02:aa:aa:aa:aa:aa"
HOSTMAC = "02:00:00:00:00:01"
def mac(s): return bytes.fromhex(s.replace(":", ""))
def cksum(b):
    if len(b) % 2: b += b"\x00"
    s = 0
    for i in range(0, len(b), 2): s += (b[i] << 8) | b[i+1]
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
def icmp6_csum(src, dst, msg):
    return cksum(src + dst + struct.pack("!I", len(msg)) + b"\x00\x00\x00" + bytes([58]) + msg)
def frame(src6, dst6, msg, dmac):
    msg = msg[:2] + struct.pack("!H", icmp6_csum(src6, dst6, msg)) + msg[4:]
    ip6 = bytes([0x60,0,0,0]) + struct.pack("!H", len(msg)) + bytes([58,255]) + src6 + dst6
    return mac(dmac) + mac(GUEST) + struct.pack("!H", 0x86dd) + ip6 + msg

LL_G  = bytes.fromhex("fe800000000000000000000000000aaa")  # guest link-local
LL_GW = bytes.fromhex("fe800000000000000000000000000001")  # gateway
UNSPEC= bytes(16)                                          # ::
SOL   = bytes.fromhex("ff0200000000000000000001ff00000a")  # solicited-node (dummy)

def build_dad_ns():   # type135 src=:: NO option (24B msg)
    msg = bytes([135,0]) + b"\x00\x00" + b"\x00\x00\x00\x00" + LL_G
    return frame(UNSPEC, SOL, msg, "33:33:ff:00:00:0a")
def build_dad_ns_opt():  # type135 src=:: + a NON-LLA option (e.g. SEND nonce type14) at off208
    nonce = bytes([14,1]) + bytes([0xde,0xad,0xbe,0xef,0xca,0xfe])  # type14 len1 + 6B "nonce"
    msg = bytes([135,0]) + b"\x00\x00" + b"\x00\x00\x00\x00" + LL_G + nonce
    return frame(UNSPEC, SOL, msg, "33:33:ff:00:00:0a")
def build_ns():       # type135 src=LL_G + SLLAO(type1) (32B msg)
    msg = bytes([135,0]) + b"\x00\x00" + b"\x00\x00\x00\x00" + LL_GW + bytes([1,1]) + mac(GUEST)
    return frame(LL_G, LL_GW, msg, "33:33:00:00:00:01")
def build_na():       # type136 src=LL_G + TLLAO(type2) (32B msg)
    msg = bytes([136,0]) + b"\x00\x00" + b"\x20\x00\x00\x00" + LL_G + bytes([2,1]) + mac(GUEST)
    return frame(LL_G, LL_GW, msg, "33:33:00:00:00:01")
ALLRTR = bytes.fromhex("ff020000000000000000000000000002")  # all-routers
def build_rs():       # type133 src=LL_G + SLLAO(type1) (16B msg) -> SLLAO at @th,80
    msg = bytes([133,0]) + b"\x00\x00" + b"\x00\x00\x00\x00" + bytes([1,1]) + mac(GUEST)
    return frame(LL_G, ALLRTR, msg, "33:33:00:00:00:02")
def build_rs_unspec():# type133 src=:: NO option (8B msg) -> @th,80 OOB + ip6.src==::
    msg = bytes([133,0]) + b"\x00\x00" + b"\x00\x00\x00\x00"
    return frame(UNSPEC, ALLRTR, msg, "33:33:00:00:00:02")

rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); rx.bind(("b0p",0)); rx.settimeout(2)
tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); tx.bind(("a0p",0))
for b in (build_dad_ns(), build_dad_ns_opt(), build_ns(), build_na(), build_rs(), build_rs_unspec()):
    tx.send(b); time.sleep(0.1)

got = {}
t0 = time.time()
while time.time()-t0 < 2:
    try: d = rx.recv(2048)
    except socket.timeout: break
    if struct.unpack("!H", d[12:14])[0] != 0x86dd or len(d) < 54 or d[20] != 58: continue
    t = d[54]                       # icmpv6 type
    src6 = d[22:38]
    if   t == 135 and src6 == UNSPEC and len(d) == 78: got["dad"]     = d
    elif t == 135 and src6 == UNSPEC:                  got["dad_opt"] = d
    elif t == 135:                                     got["ns"]      = d
    elif t == 136:                                     got["na"]      = d
    elif t == 133 and src6 == UNSPEC:                  got["rs_uns"]  = d
    elif t == 133:                                     got["rs"]      = d

ok = True
def chk(n,c):
    global ok; ok &= c; print(f"  [{'PASS' if c else 'FAIL'}] {n}")
H = mac(HOSTMAC); G = mac(GUEST)
LLA_OFF = 14 + 40 + 26   # eth + ipv6 + icmpv6 offset 26 == @th,208

# 1) DAD NS must arrive, be 78 bytes (no option), UNCHANGED, csum valid
if "dad" in got:
    d = got["dad"]
    chk("DAD NS delivered (rule didn't drop/error on OOB @th,208)", True)
    chk(f"DAD NS length == 78 (no option appended/overwritten) got {len(d)}", len(d) == 78)
    recv = struct.unpack("!H", d[56:58])[0]
    fresh = icmp6_csum(d[22:38], d[38:54], d[54:56]+b"\x00\x00"+d[58:])
    chk(f"DAD NS csum intact (recv=0x{recv:04x} fresh=0x{fresh:04x})", recv == fresh)
    chk("DAD NS target intact", d[62:78] == LL_G)
else: chk("DAD NS delivered", False)

# 1b) DAD NS *with* a non-LLA option (src=::): `ip6 saddr != ::` guard must skip it
#     -> byte 208 (the bogus option) MUST be untouched (proves != :: protects it)
if "dad_opt" in got:
    d = got["dad_opt"]
    chk("DAD-NS+opt delivered", True)
    chk("DAD-NS+opt off208 UNTOUCHED (ip6 saddr != :: skipped rewrite)",
        d[LLA_OFF:LLA_OFF+6] == bytes([0xde,0xad,0xbe,0xef,0xca,0xfe]))
else: chk("DAD-NS+opt delivered", False)

# 2) NS SLLAO rewritten to HOSTMAC
if "ns" in got:
    d = got["ns"]
    chk(f"NS SLLAO set to HOSTMAC (off {LLA_OFF})", d[LLA_OFF:LLA_OFF+6] == H)
    chk("NS eth.src untouched (=guest, left for learn)", d[6:12] == G)
else: chk("NS delivered", False)

# 3) NA TLLAO rewritten to HOSTMAC
if "na" in got:
    d = got["na"]
    chk(f"NA TLLAO set to HOSTMAC (off {LLA_OFF})", d[LLA_OFF:LLA_OFF+6] == H)
    chk("NA eth.src untouched (=guest, left for learn)", d[6:12] == G)
else: chk("NA delivered", False)

# 4) RS SLLAO rewritten to HOSTMAC at @th,80 (frame off 64)
RS_OFF = 14 + 40 + 10   # eth + ipv6 + icmpv6 offset 10 == @th,80
if "rs" in got:
    d = got["rs"]
    chk(f"RS SLLAO set to HOSTMAC (off {RS_OFF}, @th,80)", d[RS_OFF:RS_OFF+6] == H)
    chk("RS eth.src untouched (=guest, left for learn)", d[6:12] == G)
else: chk("RS delivered", False)

# 5) RS from :: (no SLLAO): ip6 saddr != :: guard skips -> unchanged, 62 bytes
if "rs_uns" in got:
    d = got["rs_uns"]
    chk(f"RS-from-:: length == 62 (unchanged, OOB @th,80 + src==::) got {len(d)}", len(d) == 62)
else: chk("RS-from-:: delivered", False)

print("RESULT:", "ALL PASS" if ok else "SOME FAIL")
