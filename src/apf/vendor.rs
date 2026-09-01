//! Qualcomm APF vendor command over a raw `NETLINK_GENERIC` socket.
//!
//! Same wire format `apf/lpc_ctl/lpc_ctl.c` proved on device, reimplemented here so
//! pbridge never shells out: resolve the `nl80211` family through `GENL_ID_CTRL`, then
//! send `NL80211_CMD_VENDOR` with QCA's vendor id and subcommand 83.
//!
//! `NL80211_ATTR_VENDOR_DATA` MUST carry `NLA_F_NESTED`. cfg80211's
//! `nl80211_vendor_check_policy` rejects the command outright ("expected nested data")
//! whenever the vendor command declares an `nla_policy`, which this one does — that is
//! why `iw vendor send` cannot drive it.

use anyhow::{bail, Context, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NETLINK_GENERIC: i32 = 16;
const GENL_ID_CTRL: u16 = 16;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const NLMSG_HDRLEN: usize = 16;
const GENL_HDRLEN: usize = 4;
const NLA_HDRLEN: usize = 4;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;

const NL80211_CMD_VENDOR: u8 = 103;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_VENDOR_ID: u16 = 195;
const NL80211_ATTR_VENDOR_SUBCMD: u16 = 196;
const NL80211_ATTR_VENDOR_DATA: u16 = 197;

const QCA_NL80211_VENDOR_ID: u32 = 0x0000_1374;
const QCA_SUBCMD_PACKET_FILTER: u32 = 83;

// enum set_reset_packet_filter (qcacld-3.0 core/hdd/src/wlan_hdd_apf.c)
const APF_WRITE: u32 = 3;
const APF_READ: u32 = 4;
const APF_ENABLE: u32 = 5;
const APF_DISABLE: u32 = 6;

// enum qca_wlan_vendor_attr_packet_filter
const APF_ATTR_SUBCMD: u16 = 1;
const APF_ATTR_PACKET_SIZE: u16 = 4;
const APF_ATTR_CURRENT_OFFSET: u16 = 5;
const APF_ATTR_PROGRAM: u16 = 6;
const APF_ATTR_PROG_LEN: u16 = 7;

/// `MAX_APF_MEMORY_LEN` (core/hdd/inc/wlan_hdd_apf.h): the driver's per-attribute cap.
const MAX_APF_MEMORY_LEN: usize = 4096;
const RECV_BUF: usize = 16 * 1024;

pub struct VendorSocket {
    fd: OwnedFd,
    seq: u32,
    family: u16,
}

impl VendorSocket {
    /// Open the socket and resolve the nl80211 family id (fails fast if cfg80211/the WLAN
    /// driver is not loaded, which is exactly when the watchdog cannot work).
    pub fn open() -> Result<Self> {
        // SAFETY: FFI socket() with constant args; on success the fd is fresh and unowned,
        // so OwnedFd takes sole ownership (closed on drop). Not constructed on failure.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_GENERIC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()).context("genetlink socket");
        }
        // SAFETY: raw is a fresh owned fd (checked >= 0 above); OwnedFd takes ownership.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: sockaddr_nl is repr(C) over integer/padding fields, so all-zero is a
        // valid value; we then set nl_family. (No Default impl for libc's padding type.)
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: FFI bind; &sa is valid for the size passed and the call only reads it.
        let r = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if r < 0 {
            return Err(std::io::Error::last_os_error()).context("genetlink bind");
        }
        // 2s recv timeout: an APF vendor command that never answers must not wedge the
        // core actor while the interpreter is disabled.
        let tv = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        // SAFETY: FFI setsockopt; optval is valid for the size passed and only read.
        // Best-effort tuning, so the return value is deliberately ignored.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
        }
        let mut s = VendorSocket {
            fd,
            seq: 1,
            family: 0,
        };
        s.family = s
            .resolve_family("nl80211")
            .context("resolve nl80211 genl family")?;
        Ok(s)
    }

    pub fn apf_disable(&mut self, ifindex: u32) -> Result<()> {
        let inner = nla_u32(APF_ATTR_SUBCMD, APF_DISABLE);
        self.vendor(ifindex, &inner, false).map(|_| ())
    }

    pub fn apf_enable(&mut self, ifindex: u32) -> Result<()> {
        let inner = nla_u32(APF_ATTR_SUBCMD, APF_ENABLE);
        self.vendor(ifindex, &inner, false).map(|_| ())
    }

    /// Read `length` bytes of APF work memory from `offset`. Requires the interpreter to
    /// be disabled (`hdd_apf_read_memory` refuses otherwise). The driver reassembles all
    /// firmware response events into one `APF_ATTR_PROGRAM` attribute, so one request is
    /// enough.
    pub fn apf_read(&mut self, ifindex: u32, length: usize, offset: u32) -> Result<Vec<u8>> {
        if length == 0 || length > MAX_APF_MEMORY_LEN {
            bail!("APF read length must be 1..={MAX_APF_MEMORY_LEN}, got {length}");
        }
        let mut inner = nla_u32(APF_ATTR_SUBCMD, APF_READ);
        inner.extend_from_slice(&nla_u32(APF_ATTR_PACKET_SIZE, length as u32));
        inner.extend_from_slice(&nla_u32(APF_ATTR_CURRENT_OFFSET, offset));
        let reply = self.vendor(ifindex, &inner, true)?;
        let program = extract_program(&reply, length)?;
        if program.is_empty() {
            bail!("no APF_PROGRAM attribute in the READ reply (is the interpreter still enabled?)");
        }
        if program.len() != length {
            bail!(
                "APF read returned {} of {length} requested bytes",
                program.len()
            );
        }
        Ok(program)
    }

    /// Write `program` into APF work memory at `offset`, declaring it as the new program
    /// length. Requires the interpreter to be disabled.
    pub fn apf_write(&mut self, ifindex: u32, program: &[u8], offset: u32) -> Result<()> {
        if program.is_empty() || program.len() > MAX_APF_MEMORY_LEN {
            bail!(
                "APF program must be 1..={MAX_APF_MEMORY_LEN} bytes, got {}",
                program.len()
            );
        }
        let mut inner = nla_u32(APF_ATTR_SUBCMD, APF_WRITE);
        inner.extend_from_slice(&nla_u32(APF_ATTR_PROG_LEN, program.len() as u32));
        inner.extend_from_slice(&nla_u32(APF_ATTR_CURRENT_OFFSET, offset));
        inner.extend_from_slice(&nla(APF_ATTR_PROGRAM, program));
        self.vendor(ifindex, &inner, false).map(|_| ())
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1).max(1);
        self.seq
    }

    fn resolve_family(&mut self, name: &str) -> Result<u16> {
        let mut payload = name.as_bytes().to_vec();
        payload.push(0);
        let attrs = nla(CTRL_ATTR_FAMILY_NAME, &payload);
        let seq = self.next_seq();
        let msg = genl_msg(
            GENL_ID_CTRL,
            NLM_F_REQUEST,
            seq,
            CTRL_CMD_GETFAMILY,
            1,
            &attrs,
        );
        self.send(&msg)?;
        let reply = self.recv_reply(seq, false, true)?;
        for (t, v) in top_attrs(&reply) {
            if t == CTRL_ATTR_FAMILY_ID && v.len() >= 2 {
                return Ok(u16::from_ne_bytes([v[0], v[1]]));
            }
        }
        bail!("GETFAMILY reply for {name:?} has no CTRL_ATTR_FAMILY_ID")
    }

    /// Send one QCA packet-filter vendor command and return the reply messages.
    fn vendor(&mut self, ifindex: u32, inner: &[u8], is_apf_read: bool) -> Result<Vec<u8>> {
        let mut attrs = nla_u32(NL80211_ATTR_IFINDEX, ifindex);
        attrs.extend_from_slice(&nla_u32(NL80211_ATTR_VENDOR_ID, QCA_NL80211_VENDOR_ID));
        attrs.extend_from_slice(&nla_u32(
            NL80211_ATTR_VENDOR_SUBCMD,
            QCA_SUBCMD_PACKET_FILTER,
        ));
        // The whole point: NLA_F_NESTED on VENDOR_DATA, or cfg80211 bails out before the
        // driver handler ever runs.
        attrs.extend_from_slice(&nla(NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED, inner));
        let seq = self.next_seq();
        let msg = genl_msg(
            self.family,
            NLM_F_REQUEST | NLM_F_ACK,
            seq,
            NL80211_CMD_VENDOR,
            0,
            &attrs,
        );
        self.send(&msg)?;
        self.recv_reply(seq, true, is_apf_read)
    }

    fn send(&self, buf: &[u8]) -> Result<()> {
        let mut off = 0;
        while off < buf.len() {
            // SAFETY: FFI send; pointer/len describe a valid sub-slice of `buf`, only read.
            let n = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    buf[off..].as_ptr() as *const libc::c_void,
                    buf.len() - off,
                    0,
                )
            };
            if n < 0 {
                return Err(std::io::Error::last_os_error()).context("genetlink send");
            }
            off += n as usize;
        }
        Ok(())
    }

    /// Read until the ACK / error / reply for `seq`, returning the concatenated non-error
    /// messages. An APF READ needs both its data reply and the ACK; an ACK-only command
    /// finishes at its ACK. A netlink error is surfaced with errno context.
    fn recv_reply(&self, seq: u32, need_ack: bool, need_data: bool) -> Result<Vec<u8>> {
        let mut collected = Vec::new();
        let mut buf = vec![0u8; RECV_BUF];
        let mut saw_ack = false;
        for _ in 0..16 {
            // SAFETY: FFI recv; writes at most buf.len() bytes into the exclusively
            // borrowed `buf`. fd is owned/open.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n < 0 {
                return Err(std::io::Error::last_os_error()).context("genetlink recv");
            }
            let n = n as usize;
            let mut off = 0;
            while off + NLMSG_HDRLEN <= n {
                let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                let mtype = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
                let mseq = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap());
                if len < NLMSG_HDRLEN || off + len > n {
                    bail!("truncated netlink message in reply");
                }
                if mseq != seq {
                    off += align4(len);
                    continue; // a stale/other reply on the same socket
                }
                match mtype {
                    NLMSG_ERROR => {
                        if off + 20 > n {
                            bail!("truncated NLMSG_ERROR");
                        }
                        let err = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                        if err != 0 {
                            return Err(std::io::Error::from_raw_os_error(-err))
                                .context("APF vendor command rejected by the kernel");
                        }
                        saw_ack = true;
                        if !need_ack || (!need_data || !collected.is_empty()) {
                            return Ok(collected);
                        }
                    }
                    NLMSG_DONE => {
                        if !needs_more_reply_data(
                            need_ack,
                            saw_ack,
                            need_data,
                            !collected.is_empty(),
                        ) {
                            return Ok(collected);
                        }
                        bail!(
                            "incomplete APF netlink multipart reply (ack={saw_ack}, data={})",
                            !collected.is_empty()
                        );
                    }
                    _ => {
                        collected.extend_from_slice(&buf[off..off + len]);
                        // A vendor reply arrives before the ACK; keep reading for it.
                    }
                }
                off += align4(len);
            }
            if !needs_more_reply_data(need_ack, saw_ack, need_data, !collected.is_empty()) {
                return Ok(collected);
            }
        }
        if !needs_more_reply_data(need_ack, saw_ack, need_data, !collected.is_empty()) {
            return Ok(collected);
        }
        bail!(
            "incomplete APF netlink reply after 16 datagrams (ack={saw_ack}, data={})",
            !collected.is_empty()
        )
    }
}

// ---- TLV encoding / decoding ----

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// True while a transaction still needs either its ACK or (for APF READ) its data reply.
/// Kept pure so the ACK-before-data ordering rule is unit-tested without a socket.
fn needs_more_reply_data(need_ack: bool, saw_ack: bool, need_data: bool, have_data: bool) -> bool {
    (need_ack && !saw_ack) || (need_data && !have_data)
}

/// One netlink attribute (TLV), 4-byte aligned. Header fields are native-endian.
fn nla(typ: u16, payload: &[u8]) -> Vec<u8> {
    let len = NLA_HDRLEN + payload.len();
    let mut v = Vec::with_capacity(align4(len));
    v.extend_from_slice(&(len as u16).to_ne_bytes());
    v.extend_from_slice(&typ.to_ne_bytes());
    v.extend_from_slice(payload);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

/// A u32 attribute. Netlink scalars are native-endian (unlike nftables' big-endian).
fn nla_u32(typ: u16, val: u32) -> Vec<u8> {
    nla(typ, &val.to_ne_bytes())
}

fn genl_msg(family: u16, flags: u16, seq: u32, cmd: u8, version: u8, attrs: &[u8]) -> Vec<u8> {
    let total = NLMSG_HDRLEN + GENL_HDRLEN + attrs.len();
    let mut v = Vec::with_capacity(align4(total));
    v.extend_from_slice(&(total as u32).to_ne_bytes()); // nlmsg_len
    v.extend_from_slice(&family.to_ne_bytes()); // nlmsg_type
    v.extend_from_slice(&flags.to_ne_bytes());
    v.extend_from_slice(&seq.to_ne_bytes());
    v.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid (kernel assigns)
    v.push(cmd); // genlmsghdr.cmd
    v.push(version);
    v.extend_from_slice(&0u16.to_ne_bytes()); // reserved
    v.extend_from_slice(attrs);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

/// Parse a flat attribute list. Stops at the first malformed entry (never panics, never
/// reads out of bounds), so a truncated reply yields the attributes seen so far.
pub(crate) fn parse_attrs(buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + NLA_HDRLEN <= buf.len() {
        let len = u16::from_ne_bytes(buf[i..i + 2].try_into().unwrap()) as usize;
        let typ = u16::from_ne_bytes(buf[i + 2..i + 4].try_into().unwrap()) & NLA_TYPE_MASK;
        if len < NLA_HDRLEN || i + len > buf.len() {
            break;
        }
        out.push((typ, &buf[i + NLA_HDRLEN..i + len]));
        i += align4(len);
    }
    out
}

/// Top-level attributes across every genl message in a reply buffer.
pub(crate) fn top_attrs(reply: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + NLMSG_HDRLEN + GENL_HDRLEN <= reply.len() {
        let len = u32::from_ne_bytes(reply[off..off + 4].try_into().unwrap()) as usize;
        if len < NLMSG_HDRLEN + GENL_HDRLEN || off + len > reply.len() {
            break;
        }
        let body = &reply[off + NLMSG_HDRLEN + GENL_HDRLEN..off + len];
        out.extend(parse_attrs(body));
        off += align4(len);
    }
    out
}

/// Concatenate the `APF_ATTR_PROGRAM` payload(s) nested inside `NL80211_ATTR_VENDOR_DATA`.
pub(crate) fn extract_program(reply: &[u8], cap: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for (t, v) in top_attrs(reply) {
        if t != NL80211_ATTR_VENDOR_DATA {
            continue;
        }
        for (it, iv) in parse_attrs(v) {
            if it == APF_ATTR_PROGRAM {
                if out.len() + iv.len() > cap {
                    bail!("APF READ reply carries more than the {cap} bytes requested");
                }
                out.extend_from_slice(iv);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_alignment_and_roundtrip() {
        let a = nla(APF_ATTR_PROGRAM, b"abc");
        assert_eq!(a.len(), 8, "3-byte payload pads 7 -> 8");
        assert_eq!(
            u16::from_ne_bytes([a[0], a[1]]),
            7,
            "nla_len excludes padding"
        );
        let parsed = parse_attrs(&a);
        assert_eq!(parsed, vec![(APF_ATTR_PROGRAM, &b"abc"[..])]);

        let u = nla_u32(APF_ATTR_SUBCMD, APF_READ);
        assert_eq!(u.len(), 8);
        assert_eq!(
            parse_attrs(&u),
            vec![(APF_ATTR_SUBCMD, &APF_READ.to_ne_bytes()[..])]
        );
    }

    #[test]
    fn nested_flag_is_masked_off_when_parsing() {
        let inner = nla_u32(APF_ATTR_SUBCMD, APF_READ);
        let outer = nla(NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED, &inner);
        // The flag must be on the wire...
        let raw = u16::from_ne_bytes([outer[2], outer[3]]);
        assert_eq!(raw & NLA_F_NESTED, NLA_F_NESTED);
        // ...and masked off when read back.
        assert_eq!(parse_attrs(&outer)[0].0, NL80211_ATTR_VENDOR_DATA);
    }

    /// Build a reply shaped like the driver's: genl header + nested vendor data.
    fn fake_reply(program: &[u8]) -> Vec<u8> {
        let inner = nla(APF_ATTR_PROGRAM, program);
        let attrs = nla(NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED, &inner);
        genl_msg(28, 0, 7, NL80211_CMD_VENDOR, 0, &attrs)
    }

    #[test]
    fn read_reply_program_extraction() {
        let prog: Vec<u8> = (0..250u32).map(|x| x as u8).collect();
        let got = extract_program(&fake_reply(&prog), 2048).unwrap();
        assert_eq!(got, prog);
    }

    #[test]
    fn read_reply_two_fragments_concatenate() {
        let a = nla(APF_ATTR_PROGRAM, &[1, 2, 3, 4]);
        let b = nla(APF_ATTR_PROGRAM, &[5, 6, 7, 8]);
        let mut inner = a;
        inner.extend_from_slice(&b);
        let attrs = nla(NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED, &inner);
        let reply = genl_msg(28, 0, 7, NL80211_CMD_VENDOR, 0, &attrs);
        assert_eq!(
            extract_program(&reply, 64).unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn ack_before_read_reply_must_not_complete_the_transaction() {
        // Some generic-netlink paths place the ACK in a separate datagram. READ needs
        // both conditions: treating the ACK as terminal would let the next command's
        // reply poison this transaction (or report an empty program).
        assert!(needs_more_reply_data(true, true, true, false));
        assert!(!needs_more_reply_data(true, true, true, true));
        assert!(!needs_more_reply_data(true, true, false, false)); // ACK-only command
        assert!(needs_more_reply_data(true, false, true, false)); // data before ACK
    }

    #[test]
    fn read_reply_over_cap_is_rejected() {
        let reply = fake_reply(&[0u8; 64]);
        assert!(
            extract_program(&reply, 32).is_err(),
            "must not overrun the caller's cap"
        );
    }

    #[test]
    fn truncated_reply_yields_no_program() {
        let full = fake_reply(&[9u8; 64]);
        let cut = &full[..full.len() / 2];
        // Truncation must be inert, never a panic and never a partial program passed off
        // as complete (apf_read length-checks the result).
        let got = extract_program(cut, 2048).unwrap();
        assert!(got.len() < 64);
    }

    #[test]
    fn unknown_and_missing_attributes_are_ignored() {
        let inner = nla_u32(9999 & NLA_TYPE_MASK, 1); // not APF_ATTR_PROGRAM
        let attrs = nla(NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED, &inner);
        let reply = genl_msg(28, 0, 7, NL80211_CMD_VENDOR, 0, &attrs);
        assert!(extract_program(&reply, 2048).unwrap().is_empty());
    }

    #[test]
    fn genl_header_layout() {
        let m = genl_msg(
            28,
            NLM_F_REQUEST | NLM_F_ACK,
            42,
            NL80211_CMD_VENDOR,
            0,
            &[],
        );
        assert_eq!(
            u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize,
            m.len()
        );
        assert_eq!(u16::from_ne_bytes(m[4..6].try_into().unwrap()), 28);
        assert_eq!(u32::from_ne_bytes(m[8..12].try_into().unwrap()), 42);
        assert_eq!(m[16], NL80211_CMD_VENDOR, "genlmsghdr.cmd follows nlmsghdr");
    }
}
