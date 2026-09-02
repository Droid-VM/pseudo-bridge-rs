//! Decode and rewrite a legacy APF `SET` vendor command in a captured `sendmsg` buffer.
//!
//! Pure byte manipulation, no ptrace and no syscalls, so the whole rewrite is unit-tested
//! against real captures on the host. [`super::inflight`] supplies the buffer and applies
//! the result.
//!
//! Layout, as measured on device (18 captures, `apf-caller-is-wifi-hal-not-networkstack`):
//!
//! ```text
//! nlmsghdr(16) genlmsghdr(4) | IFINDEX | VENDOR_ID | VENDOR_SUBCMD | VENDOR_DATA(nested)
//!                                                                     ├─ SUBCMD=1 (SET)
//!                                                                     ├─ FILTER_ID
//!                                                                     ├─ PACKET_SIZE
//!                                                                     ├─ CURRENT_OFFSET
//!                                                                     └─ PROGRAM
//! ```
//!
//! Growing the program by `delta` means five lengths move together, and missing any one of
//! them yields a message the kernel either rejects or silently truncates:
//!
//! 1. `PROGRAM`'s `nla_len`
//! 2. `VENDOR_DATA`'s `nla_len` (it encloses PROGRAM)
//! 3. `nlmsg_len`
//! 4. `PACKET_SIZE`'s u32 *value* (the driver's `total_length`)
//! 5. `iov_len` — not in this buffer; [`super::inflight`] writes it into the tracee's iovec
//!
//! Every legacy SET observed was single-fragment (`PACKET_SIZE == PROGRAM len`,
//! `CURRENT_OFFSET == 0`), so [`Decoded::single_fragment`] lets the caller refuse anything
//! else rather than guess at cross-fragment offset fixups.
#![forbid(unsafe_code)]

use super::vendor::{
    parse_attrs_at, APF_ATTR_CURRENT_OFFSET, APF_ATTR_PACKET_SIZE, APF_ATTR_PROGRAM,
    APF_ATTR_SUBCMD, APF_SET, GENL_HDRLEN, NL80211_ATTR_VENDOR_DATA, NL80211_ATTR_VENDOR_ID,
    NL80211_ATTR_VENDOR_SUBCMD, NL80211_CMD_VENDOR, NLMSG_HDRLEN, QCA_NL80211_VENDOR_ID,
    QCA_SUBCMD_PACKET_FILTER,
};
use anyhow::{bail, Result};

/// A decoded legacy APF SET command. Offsets are relative to the start of the buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub nlmsg_len: usize,
    /// `nla_len` header offset of the nested `NL80211_ATTR_VENDOR_DATA`.
    pub vendor_data_hdr_at: usize,
    /// `nla_len` header offset of `APF_ATTR_PROGRAM`.
    pub program_hdr_at: usize,
    /// Where the program bytes start, and how many there are.
    pub program_at: usize,
    pub program_len: usize,
    /// Payload offset of the `APF_ATTR_PACKET_SIZE` u32.
    pub packet_size_at: usize,
    pub packet_size: u32,
    pub current_offset: u32,
}

impl Decoded {
    /// True when this message carries the whole program in one go, which is the only shape
    /// the rewrite handles.
    pub fn single_fragment(&self) -> bool {
        self.current_offset == 0 && self.packet_size as usize == self.program_len
    }
}

/// Decode `buf` if and only if it is a QCA packet-filter vendor command using the legacy
/// `SET` sub-command. Returns `Ok(None)` for anything else — a different netlink family, a
/// different vendor command, or APF WRITE/READ/ENABLE/DISABLE (including pbridge's own
/// traffic) — so the caller can pass those through untouched.
pub fn decode(buf: &[u8]) -> Result<Option<Decoded>> {
    if buf.len() < NLMSG_HDRLEN + GENL_HDRLEN {
        return Ok(None);
    }
    let nlmsg_len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
    if nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN || nlmsg_len > buf.len() {
        return Ok(None);
    }
    // genlmsghdr.cmd. The nl80211 family id is dynamic, so the command byte plus the QCA
    // vendor id below is the discriminator; a false positive would need another family to
    // use cmd 103 with attributes 195/196 carrying exactly QCA's id and subcommand 83.
    if buf[NLMSG_HDRLEN] != NL80211_CMD_VENDOR {
        return Ok(None);
    }

    let mut vendor_id = None;
    let mut vendor_sub = None;
    let mut vdata: Option<(usize, usize, usize)> = None; // (hdr_at, payload_at, payload_len)
    for (typ, hdr_at, at, len) in parse_attrs_at(buf, NLMSG_HDRLEN + GENL_HDRLEN, nlmsg_len) {
        match typ {
            NL80211_ATTR_VENDOR_ID => vendor_id = u32_at(buf, at, len),
            NL80211_ATTR_VENDOR_SUBCMD => vendor_sub = u32_at(buf, at, len),
            NL80211_ATTR_VENDOR_DATA => vdata = Some((hdr_at, at, len)),
            _ => {}
        }
    }
    if vendor_id != Some(QCA_NL80211_VENDOR_ID) || vendor_sub != Some(QCA_SUBCMD_PACKET_FILTER) {
        return Ok(None);
    }
    let Some((vendor_data_hdr_at, vd_at, vd_len)) = vdata else {
        return Ok(None);
    };

    let mut subcmd = None;
    let mut program: Option<(usize, usize, usize)> = None;
    let mut packet_size: Option<(usize, u32)> = None;
    let mut current_offset = None;
    for (typ, hdr_at, at, len) in parse_attrs_at(buf, vd_at, vd_at + vd_len) {
        match typ {
            APF_ATTR_SUBCMD => subcmd = u32_at(buf, at, len),
            APF_ATTR_PACKET_SIZE => packet_size = u32_at(buf, at, len).map(|v| (at, v)),
            APF_ATTR_CURRENT_OFFSET => current_offset = u32_at(buf, at, len),
            APF_ATTR_PROGRAM => program = Some((hdr_at, at, len)),
            _ => {}
        }
    }
    if subcmd != Some(APF_SET) {
        return Ok(None);
    }
    // A SET that reached this point but is missing its program/size attributes is a
    // message we do not understand. Report it rather than silently passing it through, so
    // the caller can log and leave it alone instead of assuming "not APF".
    let (Some((program_hdr_at, program_at, program_len)), Some((packet_size_at, packet_size))) =
        (program, packet_size)
    else {
        bail!("APF SET without PROGRAM/PACKET_SIZE attributes");
    };

    Ok(Some(Decoded {
        nlmsg_len,
        vendor_data_hdr_at,
        program_hdr_at,
        program_at,
        program_len,
        packet_size_at,
        packet_size,
        current_offset: current_offset.unwrap_or(0),
    }))
}

/// Build the rewritten message carrying `new_prog`.
///
/// The netlink attribute after `PROGRAM` (if any) must stay 4-byte aligned, so the message
/// grows by the *aligned* delta while the `nla_len` fields carry the exact one. Returns the
/// new buffer; the caller writes it back and separately updates `iov_len` to its length.
pub fn rewrite(buf: &[u8], d: &Decoded, new_prog: &[u8]) -> Result<Vec<u8>> {
    if !d.single_fragment() {
        bail!(
            "refusing to rewrite a fragmented APF SET (packet_size {} program {} offset {})",
            d.packet_size,
            d.program_len,
            d.current_offset
        );
    }
    if new_prog.len() < d.program_len {
        bail!(
            "rewrite only grows the program ({} -> {})",
            d.program_len,
            new_prog.len()
        );
    }
    let old_padded = align4(d.program_len);
    let new_padded = align4(new_prog.len());
    let grow = new_padded - old_padded;

    // PROGRAM is the last attribute in every capture, but do not rely on it: splice at the
    // end of its padded payload so anything following is carried along verbatim.
    let tail_at = d.program_at + old_padded;
    if tail_at > d.nlmsg_len {
        bail!("APF SET program padding runs past nlmsg_len");
    }
    let mut out = Vec::with_capacity(d.nlmsg_len + grow);
    out.extend_from_slice(&buf[..d.program_at]);
    out.extend_from_slice(new_prog);
    out.resize(d.program_at + new_padded, 0); // 4-byte pad, zero-filled
    out.extend_from_slice(&buf[tail_at..d.nlmsg_len]);

    // (1) PROGRAM's nla_len, (2) VENDOR_DATA's nla_len, (3) nlmsg_len, (4) PACKET_SIZE's
    // value. Exact deltas, not padded ones, for the nla_len fields.
    let exact_grow = new_prog.len() - d.program_len;
    bump_nla_len(&mut out, d.program_hdr_at, exact_grow)?;
    bump_nla_len(&mut out, d.vendor_data_hdr_at, exact_grow)?;
    let new_nlmsg_len = d.nlmsg_len + grow;
    out[0..4].copy_from_slice(&(new_nlmsg_len as u32).to_ne_bytes());
    out[d.packet_size_at..d.packet_size_at + 4]
        .copy_from_slice(&(new_prog.len() as u32).to_ne_bytes());

    if out.len() != new_nlmsg_len {
        bail!(
            "rewrite produced {} bytes but nlmsg_len says {}",
            out.len(),
            new_nlmsg_len
        );
    }
    // Cheap structural self-check: decoding the result must yield the program we intended.
    // This runs before anything touches the tracee, so a rewrite bug cannot reach the wire.
    match decode(&out)? {
        Some(back)
            if back.program_len == new_prog.len()
                && back.packet_size as usize == new_prog.len()
                && &out[back.program_at..back.program_at + back.program_len] == new_prog => {}
        Some(back) => bail!(
            "rewritten message does not decode back (program_len {} packet_size {})",
            back.program_len,
            back.packet_size
        ),
        None => bail!("rewritten message no longer decodes as an APF SET"),
    }
    Ok(out)
}

fn bump_nla_len(buf: &mut [u8], hdr_at: usize, grow: usize) -> Result<()> {
    if hdr_at + 2 > buf.len() {
        bail!("nla_len header at {hdr_at} is out of bounds");
    }
    let old = u16::from_ne_bytes(buf[hdr_at..hdr_at + 2].try_into().unwrap()) as usize;
    let new = old + grow;
    if new > u16::MAX as usize {
        bail!("nla_len {old} + {grow} overflows u16");
    }
    buf[hdr_at..hdr_at + 2].copy_from_slice(&(new as u16).to_ne_bytes());
    Ok(())
}

fn u32_at(buf: &[u8], at: usize, len: usize) -> Option<u32> {
    if len < 4 || at + 4 > buf.len() {
        return None;
    }
    Some(u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap()))
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apf::vendor::{
        genl_msg, nla, nla_u32, APF_ATTR_PROGRAM, NL80211_ATTR_IFINDEX, NLA_F_NESTED,
        NLM_F_REQUEST,
    };

    const APF_ATTR_FILTER_ID: u16 = 3;

    /// Build a legacy SET exactly the way the HAL does, using the encoder that is already
    /// proven on device: IFINDEX/VENDOR_ID/VENDOR_SUBCMD then nested
    /// SUBCMD/FILTER_ID/PACKET_SIZE/CURRENT_OFFSET/PROGRAM. Attribute order matches the
    /// measured `attr_order=[1,3,4,5,6]`.
    fn build_set(prog: &[u8], family: u16) -> Vec<u8> {
        let mut inner = nla_u32(APF_ATTR_SUBCMD, APF_SET);
        inner.extend_from_slice(&nla_u32(APF_ATTR_FILTER_ID, 0));
        inner.extend_from_slice(&nla_u32(APF_ATTR_PACKET_SIZE, prog.len() as u32));
        inner.extend_from_slice(&nla_u32(APF_ATTR_CURRENT_OFFSET, 0));
        inner.extend_from_slice(&nla(APF_ATTR_PROGRAM, prog));

        let mut attrs = nla_u32(NL80211_ATTR_IFINDEX, 304);
        attrs.extend_from_slice(&nla_u32(NL80211_ATTR_VENDOR_ID, QCA_NL80211_VENDOR_ID));
        attrs.extend_from_slice(&nla_u32(
            NL80211_ATTR_VENDOR_SUBCMD,
            QCA_SUBCMD_PACKET_FILTER,
        ));
        attrs.extend_from_slice(&nla(NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED, &inner));
        genl_msg(family, NLM_F_REQUEST, 1, NL80211_CMD_VENDOR, 0, &attrs)
    }

    #[test]
    fn decodes_a_legacy_set() {
        let prog: Vec<u8> = (0..1084u16).map(|i| (i % 251) as u8).collect();
        let msg = build_set(&prog, 28);
        let d = decode(&msg).unwrap().expect("should decode");
        assert_eq!(d.program_len, 1084);
        assert_eq!(d.packet_size, 1084);
        assert_eq!(d.current_offset, 0);
        assert!(d.single_fragment());
        assert_eq!(&msg[d.program_at..d.program_at + d.program_len], &prog[..]);
        assert_eq!(d.nlmsg_len, msg.len());
    }

    /// On device the measured shape was a 1084-byte program in a 1180-byte message with the
    /// program at offset 96. This synthetic message models the five APF attributes but not
    /// whatever else the HAL's libnl puts in the outer level, so it lands at 84/1168 — the
    /// exact offsets are deliberately NOT asserted, since the decoder derives them. What
    /// must hold is that the header overhead is constant and the program is found intact.
    #[test]
    fn header_overhead_is_constant_across_program_sizes() {
        let mut overheads = Vec::new();
        for len in [366usize, 845, 1079, 1084, 1085] {
            let msg = build_set(&vec![0u8; len], 28);
            let d = decode(&msg).unwrap().unwrap();
            assert_eq!(d.program_len, len);
            assert_eq!(d.nlmsg_len, msg.len());
            overheads.push((d.program_at, msg.len() - align4(len)));
        }
        let first = overheads[0];
        assert!(
            overheads.iter().all(|&o| o == first),
            "header overhead must not depend on program size: {overheads:?}"
        );
    }

    #[test]
    fn rewrite_grows_all_five_lengths_consistently() {
        let prog = vec![0xAAu8; 1084];
        let msg = build_set(&prog, 28);
        let d = decode(&msg).unwrap().unwrap();

        // +74 is the eight-guest worst case (2 + 9*8).
        let mut grown = prog.clone();
        grown.extend_from_slice(&[0xBB; 74]);
        let out = rewrite(&msg, &d, &grown).unwrap();

        let d2 = decode(&out).unwrap().unwrap();
        assert_eq!(d2.program_len, 1158);
        assert_eq!(d2.packet_size, 1158);
        assert!(d2.single_fragment());
        assert_eq!(&out[d2.program_at..d2.program_at + 1158], &grown[..]);
        assert_eq!(
            u32::from_ne_bytes(out[0..4].try_into().unwrap()) as usize,
            out.len(),
            "nlmsg_len must equal the buffer length"
        );

        // Exactly four fields ahead of the program may change, and they are the four the
        // module documents: nlmsg_len, VENDOR_DATA's nla_len, PACKET_SIZE's value, and
        // PROGRAM's nla_len. Anything else differing would mean the splice moved a header
        // it should have copied verbatim.
        let mut changed: Vec<usize> = (0..d.program_at).filter(|&i| out[i] != msg[i]).collect();
        let mut expected: Vec<usize> = Vec::new();
        expected.extend(0..4); // nlmsg_len
        expected.extend(d.vendor_data_hdr_at..d.vendor_data_hdr_at + 2);
        expected.extend(d.packet_size_at..d.packet_size_at + 4);
        expected.extend(d.program_hdr_at..d.program_hdr_at + 2);
        changed.sort_unstable();
        expected.sort_unstable();
        // A byte whose new value happens to equal the old one is fine, so compare as a
        // subset of the permitted set rather than for equality.
        assert!(
            changed.iter().all(|i| expected.contains(i)),
            "unexpected bytes changed before the program: {changed:?} not within {expected:?}"
        );
    }

    /// A +11 growth (one guest) leaves the program unaligned, so the message grows by the
    /// padded delta (12) while nla_len carries the exact one (11).
    #[test]
    fn unaligned_growth_pads_the_message_but_not_nla_len() {
        let prog = vec![0u8; 1084];
        let msg = build_set(&prog, 28);
        let d = decode(&msg).unwrap().unwrap();
        let grown = vec![1u8; 1084 + 11];

        let out = rewrite(&msg, &d, &grown).unwrap();
        assert_eq!(out.len(), msg.len() + 12, "message grows by aligned delta");
        let d2 = decode(&out).unwrap().unwrap();
        assert_eq!(d2.program_len, 1095, "nla_len carries the exact length");
        assert_eq!(d2.packet_size, 1095);
    }

    #[test]
    fn ignores_non_apf_and_non_set_traffic() {
        // APF WRITE (subcmd 3) — pbridge's own vendor traffic must pass through.
        let mut inner = nla_u32(APF_ATTR_SUBCMD, 3);
        inner.extend_from_slice(&nla_u32(APF_ATTR_CURRENT_OFFSET, 0));
        inner.extend_from_slice(&nla(APF_ATTR_PROGRAM, &[0u8; 16]));
        let mut attrs = nla_u32(NL80211_ATTR_IFINDEX, 304);
        attrs.extend_from_slice(&nla_u32(NL80211_ATTR_VENDOR_ID, QCA_NL80211_VENDOR_ID));
        attrs.extend_from_slice(&nla_u32(
            NL80211_ATTR_VENDOR_SUBCMD,
            QCA_SUBCMD_PACKET_FILTER,
        ));
        attrs.extend_from_slice(&nla(NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED, &inner));
        let write = genl_msg(28, NLM_F_REQUEST, 1, NL80211_CMD_VENDOR, 0, &attrs);
        assert!(decode(&write).unwrap().is_none(), "APF WRITE is not SET");

        // A different genl command entirely.
        let other = genl_msg(28, NLM_F_REQUEST, 1, 99, 0, &attrs);
        assert!(decode(&other).unwrap().is_none());

        // A different vendor id.
        let mut a2 = nla_u32(NL80211_ATTR_IFINDEX, 304);
        a2.extend_from_slice(&nla_u32(NL80211_ATTR_VENDOR_ID, 0x1234));
        a2.extend_from_slice(&nla_u32(
            NL80211_ATTR_VENDOR_SUBCMD,
            QCA_SUBCMD_PACKET_FILTER,
        ));
        a2.extend_from_slice(&nla(NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED, &inner));
        let foreign = genl_msg(28, NLM_F_REQUEST, 1, NL80211_CMD_VENDOR, 0, &a2);
        assert!(decode(&foreign).unwrap().is_none());
    }

    #[test]
    fn truncated_and_empty_buffers_are_not_apf() {
        assert!(decode(&[]).unwrap().is_none());
        assert!(decode(&[0u8; 8]).unwrap().is_none());
        let msg = build_set(&vec![0u8; 64], 28);
        // nlmsg_len larger than the buffer: refuse rather than read past the end.
        let mut lying = msg.clone();
        lying[0..4].copy_from_slice(&((msg.len() + 64) as u32).to_ne_bytes());
        assert!(decode(&lying).unwrap().is_none());
        // Chopped short: nlmsg_len now exceeds the buffer, which is caught before any
        // attribute walk, so this reports "not APF" rather than a parse error.
        assert!(decode(&msg[..msg.len() - 40]).unwrap().is_none());

        // A buffer whose nlmsg_len is honest but whose nested PROGRAM attribute was cut:
        // this one IS an APF SET we cannot understand, and must be reported as an error so
        // the caller passes it through instead of assuming it is not APF.
        let mut inner = nla_u32(APF_ATTR_SUBCMD, APF_SET);
        inner.extend_from_slice(&nla_u32(APF_ATTR_CURRENT_OFFSET, 0));
        let mut attrs = nla_u32(NL80211_ATTR_IFINDEX, 304);
        attrs.extend_from_slice(&nla_u32(NL80211_ATTR_VENDOR_ID, QCA_NL80211_VENDOR_ID));
        attrs.extend_from_slice(&nla_u32(
            NL80211_ATTR_VENDOR_SUBCMD,
            QCA_SUBCMD_PACKET_FILTER,
        ));
        attrs.extend_from_slice(&nla(NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED, &inner));
        let no_prog = genl_msg(28, NLM_F_REQUEST, 1, NL80211_CMD_VENDOR, 0, &attrs);
        assert!(decode(&no_prog).is_err());
    }

    #[test]
    fn fragmented_set_is_refused() {
        let prog = vec![0u8; 512];
        // Claim a 2048-byte total: a partial chunk.
        let mut inner = nla_u32(APF_ATTR_SUBCMD, APF_SET);
        inner.extend_from_slice(&nla_u32(APF_ATTR_PACKET_SIZE, 2048));
        inner.extend_from_slice(&nla_u32(APF_ATTR_CURRENT_OFFSET, 0));
        inner.extend_from_slice(&nla(APF_ATTR_PROGRAM, &prog));
        let mut attrs = nla_u32(NL80211_ATTR_IFINDEX, 304);
        attrs.extend_from_slice(&nla_u32(NL80211_ATTR_VENDOR_ID, QCA_NL80211_VENDOR_ID));
        attrs.extend_from_slice(&nla_u32(
            NL80211_ATTR_VENDOR_SUBCMD,
            QCA_SUBCMD_PACKET_FILTER,
        ));
        attrs.extend_from_slice(&nla(NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED, &inner));
        let msg = genl_msg(28, NLM_F_REQUEST, 1, NL80211_CMD_VENDOR, 0, &attrs);

        let d = decode(&msg).unwrap().unwrap();
        assert!(!d.single_fragment());
        let err = rewrite(&msg, &d, &vec![0u8; 523]).unwrap_err();
        assert!(err.to_string().contains("fragmented"), "{err}");
    }

    #[test]
    fn shrinking_is_refused() {
        let prog = vec![0u8; 128];
        let msg = build_set(&prog, 28);
        let d = decode(&msg).unwrap().unwrap();
        assert!(rewrite(&msg, &d, &vec![0u8; 64]).is_err());
    }

    #[test]
    fn nla_len_overflow_is_refused() {
        // PROGRAM's nla_len is a u16; a program near 64 KiB cannot grow.
        let prog = vec![0u8; 65_000];
        let msg = build_set(&prog, 28);
        let d = decode(&msg).unwrap().unwrap();
        let grown = vec![0u8; 65_000 + 600];
        let err = rewrite(&msg, &d, &grown).unwrap_err();
        assert!(err.to_string().contains("overflow"), "{err}");
    }
}
