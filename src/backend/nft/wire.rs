//! Hand-rolled nfnetlink (nf_tables) wire encoder. Pure Rust over a NETLINK_NETFILTER
//! socket — no libnftnl, no shelling out. Constants verified against the kernel uapi
//! headers. nft scalar attributes are big-endian; data values are raw bytes.

#![allow(dead_code)]

use anyhow::{bail, Context, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// ---- constants (values printed from kernel headers) ----
pub const NETLINK_NETFILTER: i32 = 12;
pub const NFNL_SUBSYS_NFTABLES: u16 = 10;
pub const NFNL_MSG_BATCH_BEGIN: u16 = 16;
pub const NFNL_MSG_BATCH_END: u16 = 17;

pub const NFT_MSG_NEWTABLE: u16 = 0;
pub const NFT_MSG_DELTABLE: u16 = 2;
pub const NFT_MSG_NEWCHAIN: u16 = 3;
pub const NFT_MSG_NEWRULE: u16 = 6;
pub const NFT_MSG_NEWSET: u16 = 9;
pub const NFT_MSG_NEWSETELEM: u16 = 12;
pub const NFT_MSG_GETSETELEM: u16 = 13;
pub const NFT_MSG_DELSETELEM: u16 = 14;

pub const NFPROTO_NETDEV: u8 = 5;
pub const NF_NETDEV_INGRESS: u32 = 0;
pub const NF_NETDEV_EGRESS: u32 = 1;

// netlink message flags
pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLA_F_NESTED: u16 = 0x8000;

// attribute ids
pub const NFTA_TABLE_NAME: u16 = 1;
pub const NFTA_CHAIN_TABLE: u16 = 1;
pub const NFTA_CHAIN_NAME: u16 = 3;
pub const NFTA_CHAIN_HOOK: u16 = 4;
pub const NFTA_CHAIN_POLICY: u16 = 5;
pub const NFTA_CHAIN_TYPE: u16 = 7;
pub const NFTA_HOOK_HOOKNUM: u16 = 1;
pub const NFTA_HOOK_PRIORITY: u16 = 2;
pub const NFTA_HOOK_DEV: u16 = 3;
pub const NFTA_RULE_TABLE: u16 = 1;
pub const NFTA_RULE_CHAIN: u16 = 2;
pub const NFTA_RULE_EXPRESSIONS: u16 = 4;
pub const NFTA_EXPR_NAME: u16 = 1;
pub const NFTA_EXPR_DATA: u16 = 2;
pub const NFTA_LIST_ELEM: u16 = 1;

pub const NFTA_CMP_SREG: u16 = 1;
pub const NFTA_CMP_OP: u16 = 2;
pub const NFTA_CMP_DATA: u16 = 3;
pub const NFT_CMP_EQ: u32 = 0;
pub const NFT_CMP_NEQ: u32 = 1;

pub const NFTA_DATA_VALUE: u16 = 1;
pub const NFTA_DATA_VERDICT: u16 = 2;
pub const NFTA_VERDICT_CODE: u16 = 1;
pub const NFTA_VERDICT_CHAIN: u16 = 2;

pub const NFTA_META_DREG: u16 = 1;
pub const NFTA_META_KEY: u16 = 2;
pub const NFT_META_PROTOCOL: u32 = 1;
pub const NFT_META_L4PROTO: u32 = 16;
pub const NFT_META_PKTTYPE: u32 = 19;

pub const NFTA_PAYLOAD_DREG: u16 = 1;
pub const NFTA_PAYLOAD_BASE: u16 = 2;
pub const NFTA_PAYLOAD_OFFSET: u16 = 3;
pub const NFTA_PAYLOAD_LEN: u16 = 4;
pub const NFTA_PAYLOAD_SREG: u16 = 5;
pub const NFTA_PAYLOAD_CSUM_TYPE: u16 = 6;
pub const NFTA_PAYLOAD_CSUM_OFFSET: u16 = 7;
pub const NFTA_PAYLOAD_CSUM_FLAGS: u16 = 8;
pub const NFT_PAYLOAD_LL_HEADER: u32 = 0;
pub const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
pub const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
pub const NFT_PAYLOAD_CSUM_NONE: u32 = 0;
pub const NFT_PAYLOAD_CSUM_INET: u32 = 1;

pub const NFTA_IMMEDIATE_DREG: u16 = 1;
pub const NFTA_IMMEDIATE_DATA: u16 = 2;

pub const NFTA_LOOKUP_SET: u16 = 1;
pub const NFTA_LOOKUP_SREG: u16 = 2;
pub const NFTA_LOOKUP_DREG: u16 = 3;
pub const NFTA_LOOKUP_FLAGS: u16 = 5;

pub const NFTA_DYNSET_SET_NAME: u16 = 1;
pub const NFTA_DYNSET_OP: u16 = 3;
pub const NFTA_DYNSET_SREG_KEY: u16 = 4;
pub const NFTA_DYNSET_SREG_DATA: u16 = 5;
pub const NFTA_DYNSET_TIMEOUT: u16 = 6;
pub const NFTA_DYNSET_FLAGS: u16 = 9;
pub const NFT_DYNSET_OP_ADD: u32 = 0;
pub const NFT_DYNSET_OP_UPDATE: u32 = 1;

pub const NFTA_LOG_GROUP: u16 = 1;
pub const NFTA_LOG_PREFIX: u16 = 2;

pub const NFTA_FWD_SREG_DEV: u16 = 1;
pub const NFTA_DUP_SREG_DEV: u16 = 2;

pub const NFTA_SET_TABLE: u16 = 1;
pub const NFTA_SET_NAME: u16 = 2;
pub const NFTA_SET_FLAGS: u16 = 3;
pub const NFTA_SET_KEY_TYPE: u16 = 4;
pub const NFTA_SET_KEY_LEN: u16 = 5;
pub const NFTA_SET_DATA_TYPE: u16 = 6;
pub const NFTA_SET_DATA_LEN: u16 = 7;
pub const NFTA_SET_DESC: u16 = 9;
pub const NFTA_SET_ID: u16 = 10;
pub const NFTA_SET_TIMEOUT: u16 = 11;
pub const NFTA_SET_DESC_SIZE: u16 = 1;
pub const NFTA_SET_DESC_CONCAT: u16 = 2;
pub const NFTA_SET_FIELD_LEN: u16 = 1;
pub const NFT_SET_MAP: u32 = 8;
pub const NFT_SET_TIMEOUT: u32 = 16;
pub const NFT_SET_EVAL: u32 = 32;
pub const NFT_SET_CONCAT: u32 = 128;

pub const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
pub const NFTA_SET_ELEM_LIST_SET: u16 = 2;
pub const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
pub const NFTA_SET_ELEM_KEY: u16 = 1;
pub const NFTA_SET_ELEM_DATA: u16 = 2;
pub const NFTA_SET_ELEM_TIMEOUT: u16 = 4;

pub const NF_ACCEPT: u32 = 1;
pub const NF_DROP: u32 = 0;
pub const NFT_JUMP: u32 = 0xffff_fffd; // -3
pub const NFT_RETURN: u32 = 0xffff_fffb; // -5

pub const NFT_REG_VERDICT: u32 = 0;
pub const NFT_REG_1: u32 = 1;
pub const NFT_REG_2: u32 = 2;
pub const NFT_REG_3: u32 = 3;
pub const NFT_REG32_00: u32 = 8;
pub const NFT_REG32_01: u32 = 9;

// register byte offset within network-byte-order data (for cmp/payload). We use the
// 16-byte classic registers NFT_REG_1.. which the kernel accepts for cmp/lookup/payload.

// ---- attribute encoding ----

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Encode one netlink attribute (TLV) with 4-byte alignment.
pub fn nla(typ: u16, payload: &[u8]) -> Vec<u8> {
    let len = 4 + payload.len();
    let mut v = Vec::with_capacity(align4(len));
    v.extend_from_slice(&(len as u16).to_ne_bytes());
    v.extend_from_slice(&typ.to_ne_bytes());
    v.extend_from_slice(payload);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

pub fn nla_be32(typ: u16, val: u32) -> Vec<u8> {
    nla(typ, &val.to_be_bytes())
}
pub fn nla_be16(typ: u16, val: u16) -> Vec<u8> {
    nla(typ, &val.to_be_bytes())
}
pub fn nla_be64(typ: u16, val: u64) -> Vec<u8> {
    nla(typ, &val.to_be_bytes())
}
pub fn nla_str(typ: u16, s: &str) -> Vec<u8> {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    nla(typ, &b)
}
pub fn nla_nested(typ: u16, inner: &[u8]) -> Vec<u8> {
    nla(typ | NLA_F_NESTED, inner)
}

/// concat a list of attr byte vectors.
pub fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

// ---- expression encoders: each returns one NFTA_LIST_ELEM (an expression) ----

fn expr(name: &str, data: &[u8]) -> Vec<u8> {
    let inner = cat(&[nla_str(NFTA_EXPR_NAME, name), nla_nested(NFTA_EXPR_DATA, data)]);
    nla_nested(NFTA_LIST_ELEM, &inner)
}

pub fn meta_load(key: u32, dreg: u32) -> Vec<u8> {
    expr("meta", &cat(&[nla_be32(NFTA_META_KEY, key), nla_be32(NFTA_META_DREG, dreg)]))
}

/// cmp reg <op> value(raw bytes)
pub fn cmp(sreg: u32, op: u32, value: &[u8]) -> Vec<u8> {
    let data = nla_nested(NFTA_CMP_DATA, &nla(NFTA_DATA_VALUE, value));
    expr("cmp", &cat(&[nla_be32(NFTA_CMP_SREG, sreg), nla_be32(NFTA_CMP_OP, op), data]))
}

pub fn payload_load(base: u32, offset: u32, len: u32, dreg: u32) -> Vec<u8> {
    expr(
        "payload",
        &cat(&[
            nla_be32(NFTA_PAYLOAD_DREG, dreg),
            nla_be32(NFTA_PAYLOAD_BASE, base),
            nla_be32(NFTA_PAYLOAD_OFFSET, offset),
            nla_be32(NFTA_PAYLOAD_LEN, len),
        ]),
    )
}

/// payload mangle (write) from sreg, with optional inet csum fixup.
pub fn payload_set(
    base: u32,
    offset: u32,
    len: u32,
    sreg: u32,
    csum: Option<(u32, u32)>, // (csum_offset, csum_flags) with INET csum
) -> Vec<u8> {
    let mut parts = vec![
        nla_be32(NFTA_PAYLOAD_SREG, sreg),
        nla_be32(NFTA_PAYLOAD_BASE, base),
        nla_be32(NFTA_PAYLOAD_OFFSET, offset),
        nla_be32(NFTA_PAYLOAD_LEN, len),
    ];
    match csum {
        Some((coff, cflags)) => {
            parts.push(nla_be32(NFTA_PAYLOAD_CSUM_TYPE, NFT_PAYLOAD_CSUM_INET));
            parts.push(nla_be32(NFTA_PAYLOAD_CSUM_OFFSET, coff));
            parts.push(nla_be32(NFTA_PAYLOAD_CSUM_FLAGS, cflags));
        }
        None => {
            parts.push(nla_be32(NFTA_PAYLOAD_CSUM_TYPE, NFT_PAYLOAD_CSUM_NONE));
        }
    }
    expr("payload", &cat(&parts))
}

pub fn immediate_data(dreg: u32, value: &[u8]) -> Vec<u8> {
    let data = nla_nested(NFTA_IMMEDIATE_DATA, &nla(NFTA_DATA_VALUE, value));
    expr("immediate", &cat(&[nla_be32(NFTA_IMMEDIATE_DREG, dreg), data]))
}

pub fn verdict(code: u32, chain: Option<&str>) -> Vec<u8> {
    let mut v = nla_be32(NFTA_VERDICT_CODE, code);
    if let Some(c) = chain {
        v.extend_from_slice(&nla_str(NFTA_VERDICT_CHAIN, c));
    }
    let data = nla_nested(NFTA_IMMEDIATE_DATA, &nla_nested(NFTA_DATA_VERDICT, &v));
    expr("immediate", &cat(&[nla_be32(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT), data]))
}

pub fn lookup(set: &str, sreg: u32, dreg: Option<u32>) -> Vec<u8> {
    let mut parts = vec![nla_str(NFTA_LOOKUP_SET, set), nla_be32(NFTA_LOOKUP_SREG, sreg)];
    if let Some(d) = dreg {
        parts.push(nla_be32(NFTA_LOOKUP_DREG, d));
    }
    expr("lookup", &cat(&parts))
}

/// Inverted membership test: matches when `sreg`'s value is NOT a key of `set`/map.
pub fn lookup_inv(set: &str, sreg: u32) -> Vec<u8> {
    const NFT_LOOKUP_F_INV: u32 = 1;
    expr(
        "lookup",
        &cat(&[
            nla_str(NFTA_LOOKUP_SET, set),
            nla_be32(NFTA_LOOKUP_SREG, sreg),
            nla_be32(NFTA_LOOKUP_FLAGS, NFT_LOOKUP_F_INV),
        ]),
    )
}

pub fn dynset_update(set: &str, sreg_key: u32, timeout_ms: Option<u64>) -> Vec<u8> {
    let mut parts = vec![
        nla_str(NFTA_DYNSET_SET_NAME, set),
        nla_be32(NFTA_DYNSET_OP, NFT_DYNSET_OP_UPDATE),
        nla_be32(NFTA_DYNSET_SREG_KEY, sreg_key),
    ];
    if let Some(t) = timeout_ms {
        parts.push(nla_be64(NFTA_DYNSET_TIMEOUT, t));
    }
    expr("dynset", &cat(&parts))
}

pub fn log(group: u16, prefix: &str) -> Vec<u8> {
    expr("log", &cat(&[nla_be16(NFTA_LOG_GROUP, group), nla_str(NFTA_LOG_PREFIX, prefix)]))
}

pub fn fwd(dev_sreg: u32) -> Vec<u8> {
    expr("fwd", &nla_be32(NFTA_FWD_SREG_DEV, dev_sreg))
}
pub fn dup(dev_sreg: u32) -> Vec<u8> {
    expr("dup", &nla_be32(NFTA_DUP_SREG_DEV, dev_sreg))
}

// ---- message framing ----

fn nfgenmsg(family: u8, res_id_be: u16) -> [u8; 4] {
    let r = res_id_be.to_be_bytes();
    [family, 0 /*NFNETLINK_V0*/, r[0], r[1]]
}

/// Build a complete netlink message: nlmsghdr + nfgenmsg + attrs.
fn nl_msg(msg_type: u16, flags: u16, seq: u32, family: u8, res_id_be: u16, attrs: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&nfgenmsg(family, res_id_be));
    body.extend_from_slice(attrs);
    let total = 16 + body.len();
    let mut v = Vec::with_capacity(align4(total));
    v.extend_from_slice(&(total as u32).to_ne_bytes()); // nlmsg_len
    v.extend_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
    v.extend_from_slice(&flags.to_ne_bytes()); // nlmsg_flags
    v.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
    v.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
    v.extend_from_slice(&body);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

fn batch(begin: bool, seq: u32) -> Vec<u8> {
    let t = if begin { NFNL_MSG_BATCH_BEGIN } else { NFNL_MSG_BATCH_END };
    nl_msg(t, NLM_F_REQUEST, seq, 0 /*AF_UNSPEC*/, NFNL_SUBSYS_NFTABLES, &[])
}

/// One nft message inside a transaction (subsys NFTABLES). res_id = 0.
pub fn nft_message(msg: u16, extra_flags: u16, seq: u32, family: u8, attrs: &[u8]) -> Vec<u8> {
    let mtype = (NFNL_SUBSYS_NFTABLES << 8) | msg;
    nl_msg(mtype, NLM_F_REQUEST | NLM_F_ACK | extra_flags, seq, family, 0, attrs)
}

// ---- socket ----

pub struct NlSock {
    fd: OwnedFd,
    seq: u32,
}

impl NlSock {
    pub fn open() -> Result<NlSock> {
        // SAFETY: FFI socket() with constant args; on success the returned fd is fresh and
        // unowned, so OwnedFd takes sole ownership (closed on drop). Not built on failure.
        let raw =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_NETFILTER) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()).context("netlink socket");
        }
        // SAFETY: raw is a fresh owned fd (checked >= 0 above); OwnedFd takes ownership.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // bind with pid=0 (kernel assigns).
        // SAFETY: sockaddr_nl is repr(C) over integer/padding fields; all-zero is a valid
        // value. We then set nl_family. (No Default impl, and nl_pad is libc's Padding type.)
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: FFI bind. &sa is valid for the passed size; fd is owned/open; reads only.
        let r = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if r < 0 {
            return Err(std::io::Error::last_os_error()).context("netlink bind");
        }
        // 2s recv timeout so ack reads can't hang forever.
        let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
        let one: i32 = 1;
        // SAFETY: FFI setsockopt; each optval pointer is valid for the size passed and the
        // call only reads it. Return values are non-fatal (best-effort tuning), so ignored.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
            // NETLINK_EXT_ACK=11, NETLINK_CAP_ACK=12: descriptive errors, capped orig msg.
            libc::setsockopt(fd.as_raw_fd(), libc::SOL_NETLINK, 11, &one as *const _ as *const libc::c_void, 4);
            libc::setsockopt(fd.as_raw_fd(), libc::SOL_NETLINK, 12, &one as *const _ as *const libc::c_void, 4);
        }
        Ok(NlSock { fd, seq: 1 })
    }

    fn next_seq(&mut self) -> u32 {
        self.seq += 1;
        self.seq
    }

    fn send(&self, buf: &[u8]) -> Result<()> {
        let mut off = 0;
        while off < buf.len() {
            // SAFETY: FFI send; the pointer/len describe a valid sub-slice of `buf` and the
            // call only reads it. fd is owned/open.
            let n = unsafe {
                libc::send(self.fd.as_raw_fd(), buf[off..].as_ptr() as *const libc::c_void, buf.len() - off, 0)
            };
            if n < 0 {
                return Err(std::io::Error::last_os_error()).context("netlink send");
            }
            off += n as usize;
        }
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        // SAFETY: FFI recv; writes at most buf.len() bytes into the valid, exclusively
        // borrowed `buf`. fd is owned/open.
        let n = unsafe {
            libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error()).context("netlink recv");
        }
        Ok(n as usize)
    }

    /// Send a transaction (begin + messages + end) and verify all ACKs succeed.
    /// `messages` are pre-built nft messages (each with its own seq + NLM_F_ACK).
    pub fn transaction(&mut self, build: impl FnOnce(&mut TxnSeq) -> Vec<Vec<u8>>) -> Result<()> {
        let begin_seq = self.next_seq();
        let mut ts = TxnSeq { sock: self };
        let msgs = build(&mut ts);
        let end_seq = self.next_seq();

        let mut wire = batch(true, begin_seq);
        let mut acks_expected = 0usize;
        for m in &msgs {
            wire.extend_from_slice(m);
            acks_expected += 1;
        }
        wire.extend_from_slice(&batch(false, end_seq));
        self.send(&wire)?;

        // Read responses. Each acked inner message yields an NLMSG_ERROR (err==0 ok).
        let mut acks = 0usize;
        let mut rbuf = vec![0u8; 65536];
        while acks < acks_expected {
            let n = match self.recv(&mut rbuf) {
                Ok(n) => n,
                Err(_) => break, // timeout: assume remaining acks ok
            };
            let mut off = 0;
            while off + 16 <= n {
                let mlen = u32::from_ne_bytes(rbuf[off..off + 4].try_into().unwrap()) as usize;
                let mtype = u16::from_ne_bytes(rbuf[off + 4..off + 6].try_into().unwrap());
                if mlen < 16 || off + mlen > n {
                    break;
                }
                if mtype == NLMSG_ERROR {
                    let err = i32::from_ne_bytes(rbuf[off + 16..off + 20].try_into().unwrap());
                    if err != 0 {
                        // NLMSG_ERROR payload: int error; struct nlmsghdr orig
                        let (otype, oseq) = if off + 20 + 16 <= n {
                            let ot = u16::from_ne_bytes(rbuf[off + 20 + 4..off + 20 + 6].try_into().unwrap());
                            let os = u32::from_ne_bytes(rbuf[off + 20 + 8..off + 20 + 12].try_into().unwrap());
                            (ot & 0xff, os)
                        } else {
                            (0, 0)
                        };
                        // ext-ack TLVs after capped {error(4)+nlmsghdr(16)} => offset 20.
                        let mut extmsg = String::new();
                        let flags = u16::from_ne_bytes(rbuf[off + 6..off + 8].try_into().unwrap());
                        if flags & 0x200 != 0 {
                            // NLM_F_ACK_TLVS
                            for (t, v) in parse_attrs(&rbuf[off + 20..off + mlen]) {
                                if t == 1 {
                                    // NLMSGERR_ATTR_MSG
                                    let s = v.split(|b| *b == 0).next().unwrap_or(&[]);
                                    extmsg = String::from_utf8_lossy(s).into_owned();
                                }
                            }
                        }
                        bail!(
                            "nft transaction failed: {} ({}); nft_type={} seq={} extack={:?}",
                            err,
                            std::io::Error::from_raw_os_error(-err),
                            otype,
                            oseq,
                            extmsg
                        );
                    }
                    acks += 1;
                }
                off += align4(mlen);
            }
        }
        Ok(())
    }

    /// Dump set elements (keys). Returns each element's key bytes.
    pub fn dump_set_elems(&mut self, table: &str, set: &str, family: u8) -> Result<Vec<Vec<u8>>> {
        let seq = self.next_seq();
        let attrs = cat(&[
            nla_str(NFTA_SET_ELEM_LIST_TABLE, table),
            nla_str(NFTA_SET_ELEM_LIST_SET, set),
        ]);
        let mtype = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSETELEM;
        let msg = nl_msg(mtype, NLM_F_REQUEST | NLM_F_DUMP, seq, family, 0, &attrs);
        self.send(&msg)?;

        let mut out = Vec::new();
        let mut rbuf = vec![0u8; 65536];
        'outer: loop {
            let n = match self.recv(&mut rbuf) {
                Ok(n) => n,
                Err(_) => break,
            };
            let mut off = 0;
            while off + 16 <= n {
                let mlen = u32::from_ne_bytes(rbuf[off..off + 4].try_into().unwrap()) as usize;
                let mtype = u16::from_ne_bytes(rbuf[off + 4..off + 6].try_into().unwrap());
                if mlen < 16 || off + mlen > n {
                    break;
                }
                if mtype == NLMSG_DONE {
                    break 'outer;
                }
                if mtype == NLMSG_ERROR {
                    let err = i32::from_ne_bytes(rbuf[off + 16..off + 20].try_into().unwrap());
                    if err != 0 {
                        bail!("dump_set_elems error {}", err);
                    }
                    break 'outer;
                }
                // NEWSETELEM message: skip nfgenmsg(4), parse attrs for ELEM_LIST_ELEMENTS
                let abody = &rbuf[off + 20..off + mlen];
                parse_setelem_keys(abody, &mut out);
                off += align4(mlen);
            }
        }
        Ok(out)
    }
}

/// Hands out per-message sequence numbers within a transaction.
pub struct TxnSeq<'a> {
    sock: &'a mut NlSock,
}
impl TxnSeq<'_> {
    pub fn seq(&mut self) -> u32 {
        self.sock.next_seq()
    }
}

// ---- attribute parsing (for set element dump) ----

fn parse_attrs(buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= buf.len() {
        let len = u16::from_ne_bytes(buf[i..i + 2].try_into().unwrap()) as usize;
        let typ = u16::from_ne_bytes(buf[i + 2..i + 4].try_into().unwrap()) & 0x3fff;
        if len < 4 || i + len > buf.len() {
            break;
        }
        out.push((typ, &buf[i + 4..i + len]));
        i += align4(len);
    }
    out
}

fn parse_setelem_keys(abody: &[u8], out: &mut Vec<Vec<u8>>) {
    for (t, v) in parse_attrs(abody) {
        if t == NFTA_SET_ELEM_LIST_ELEMENTS {
            // nested list of NFTA_LIST_ELEM, each an element
            for (et, ev) in parse_attrs(v) {
                if et == NFTA_LIST_ELEM {
                    // element attrs: find NFTA_SET_ELEM_KEY -> NFTA_DATA_VALUE
                    for (kt, kv) in parse_attrs(ev) {
                        if kt == NFTA_SET_ELEM_KEY {
                            for (dt, dv) in parse_attrs(kv) {
                                if dt == NFTA_DATA_VALUE {
                                    out.push(dv.to_vec());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nla_alignment() {
        let a = nla(NFTA_TABLE_NAME, b"x");
        // len=5 -> padded to 8
        assert_eq!(a.len(), 8);
        assert_eq!(u16::from_ne_bytes([a[0], a[1]]), 5);
    }

    #[test]
    fn expr_roundtrips_name() {
        let e = meta_load(NFT_META_L4PROTO, NFT_REG_1);
        // nested LIST_ELEM containing EXPR_NAME "meta"
        assert!(e.windows(4).any(|w| w == b"meta"));
    }
}
