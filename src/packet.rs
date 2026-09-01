//! L3 packet parsing for the nft copy path (NFLOG delivers L3 payload + L2 header
//! separately). Pure functions over byte slices, plus the ICMPv6 checksum used to
//! repair ND packets before AF_PACKET reinject (ARCHITECTURE.md §userspace path).
//!
//! Parses untrusted on-wire bytes, so memory safety is critical: unsafe is forbidden
//! here — all access is bounds-checked slice indexing.
#![forbid(unsafe_code)]

use crate::types::{Mac, PktKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

pub const IPPROTO_ICMPV6: u8 = 58;

pub const ND_RS: u8 = 133;
pub const ND_NS: u8 = 135;
pub const ND_NA: u8 = 136;

fn be16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|s| u16::from_be_bytes([s[0], s[1]]))
}

/// Parse an ARP IPv4 sender protocol address (spa). Returns None for probes
/// (spa == 0) or malformed. ARP L3 layout: htype2 ptype2 hlen1 plen1 op2 sha6 spa4...
pub fn arp_spa(l3: &[u8]) -> Option<Ipv4Addr> {
    // require IPv4 over Ethernet
    let ptype = be16(l3, 2)?;
    if ptype != ETHERTYPE_IPV4 {
        return None;
    }
    let spa = l3.get(14..18)?;
    let a = Ipv4Addr::new(spa[0], spa[1], spa[2], spa[3]);
    if a.is_unspecified() {
        None
    } else {
        Some(a)
    }
}

/// Parse an Ethernet/IPv4 ARP request. The caller supplies the Ethernet source
/// separately; `arp_sha` is returned so it can reject inconsistent L2/L3 senders.
pub fn arp_request(l3: &[u8]) -> Option<(Mac, Ipv4Addr, Ipv4Addr)> {
    if l3.len() < 28
        || be16(l3, 0)? != 1
        || be16(l3, 2)? != ETHERTYPE_IPV4
        || l3.get(4..6)? != [6, 4]
        || be16(l3, 6)? != 1
    {
        return None;
    }
    let sha = Mac::from_slice(l3.get(8..14)?)?;
    let spa = l3.get(14..18)?;
    let tpa = l3.get(24..28)?;
    let requester_ip = Ipv4Addr::new(spa[0], spa[1], spa[2], spa[3]);
    if requester_ip.is_unspecified() {
        return None;
    }
    Some((
        sha,
        requester_ip,
        Ipv4Addr::new(tpa[0], tpa[1], tpa[2], tpa[3]),
    ))
}

/// IPv6 next header byte and source/destination addresses from an L3 IPv6 packet.
pub fn ipv6_src(l3: &[u8]) -> Option<Ipv6Addr> {
    let s = l3.get(8..24)?;
    let mut b = [0u8; 16];
    b.copy_from_slice(s);
    Some(Ipv6Addr::from(b))
}

pub fn ipv6_nexthdr(l3: &[u8]) -> Option<u8> {
    l3.get(6).copied()
}

/// ICMPv6 type, for ND packets (assumes no extension headers; next_header==58).
pub fn icmpv6_type(l3: &[u8]) -> Option<u8> {
    if ipv6_nexthdr(l3)? != IPPROTO_ICMPV6 {
        return None;
    }
    l3.get(40).copied()
}

/// ND target address (NS/NA) at icmpv6 offset 8 => L3 offset 48..64.
pub fn nd_target(l3: &[u8]) -> Option<Ipv6Addr> {
    let s = l3.get(48..64)?;
    let mut b = [0u8; 16];
    b.copy_from_slice(s);
    Some(Ipv6Addr::from(b))
}

/// Classify the L3 payload (given its ethertype) into a learn kind + the IP to
/// learn. mac comes from the L2 source separately. Returns None when nothing is
/// learnable (e.g. ARP probe, RS-from-::, non-ND ICMPv6, malformed).
pub fn classify_learn(ethertype: u16, l3: &[u8]) -> Option<(PktKind, IpAddr)> {
    match ethertype {
        ETHERTYPE_ARP => arp_spa(l3).map(|a| (PktKind::Arp, IpAddr::V4(a))),
        ETHERTYPE_IPV4 => {
            let s = l3.get(12..16)?;
            Some((PktKind::Ip, IpAddr::V4(Ipv4Addr::new(s[0], s[1], s[2], s[3]))))
        }
        ETHERTYPE_IPV6 => {
            let src = ipv6_src(l3)?;
            match icmpv6_type(l3) {
                Some(ND_NS) => {
                    if src.is_unspecified() {
                        // DAD NS: learn the claimed target.
                        nd_target(l3).map(|t| (PktKind::NdDad, IpAddr::V6(t)))
                    } else {
                        Some((PktKind::Nd, IpAddr::V6(src)))
                    }
                }
                Some(ND_NA) => {
                    // NA advertises the target address; learn that.
                    nd_target(l3).map(|t| (PktKind::Nd, IpAddr::V6(t)))
                }
                Some(ND_RS) => {
                    if src.is_unspecified() {
                        None // RS-from-:: has no SLLAO; nothing to learn
                    } else {
                        Some((PktKind::Nd, IpAddr::V6(src)))
                    }
                }
                _ => {
                    // plain IPv6 data: learn source.
                    Some((PktKind::Ip, IpAddr::V6(src)))
                }
            }
        }
        _ => None,
    }
}

/// Recompute the ICMPv6 checksum in-place over an IPv6 L3 payload. Used after the
/// kernel set the LLA (nft can't fix csum) and before AF_PACKET reinject.
/// Returns false if the buffer is too short / not ICMPv6.
pub fn fix_icmpv6_csum(l3: &mut [u8]) -> bool {
    if l3.len() < 44 || ipv6_nexthdr(l3) != Some(IPPROTO_ICMPV6) {
        return false;
    }
    // ICMPv6 payload length = total IPv6 payload length field (offset 4..6).
    let payload_len = match be16(l3, 4) {
        Some(n) => n as usize,
        None => return false,
    };
    let icmp_start = 40;
    if icmp_start + payload_len > l3.len() {
        return false;
    }
    // zero the existing csum (icmp offset 2..4 => l3 42..44)
    l3[42] = 0;
    l3[43] = 0;

    let mut sum: u32 = 0;
    // pseudo-header: src(16) + dst(16) + upper-layer-len(4) + zero(3) + next(1)
    for i in (8..40).step_by(2) {
        sum += u16::from_be_bytes([l3[i], l3[i + 1]]) as u32;
    }
    sum += (payload_len >> 16) as u32 & 0xffff;
    sum += payload_len as u32 & 0xffff;
    sum += IPPROTO_ICMPV6 as u32;

    // icmpv6 message
    let icmp = &l3[icmp_start..icmp_start + payload_len];
    let mut i = 0;
    while i + 1 < icmp.len() {
        sum += u16::from_be_bytes([icmp[i], icmp[i + 1]]) as u32;
        i += 2;
    }
    if i < icmp.len() {
        sum += (icmp[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    let csum = if csum == 0 { 0xffff } else { csum };
    let b = csum.to_be_bytes();
    l3[42] = b[0];
    l3[43] = b[1];
    true
}

/// Build a full Ethernet frame for reinjection: dst | HOSTMAC src | ethertype | l3.
pub fn build_frame(dst: Mac, src: Mac, ethertype: u16, l3: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + l3.len());
    f.extend_from_slice(dst.bytes());
    f.extend_from_slice(src.bytes());
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(l3);
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_parse() {
        // htype=1 ptype=0800 hlen=6 plen=4 op=1 sha=.. spa=10.0.0.5 ...
        let mut p = vec![0u8; 28];
        p[2] = 0x08;
        p[3] = 0x00; // ptype IPv4
        p[14..18].copy_from_slice(&[10, 0, 0, 5]);
        assert_eq!(arp_spa(&p), Some(Ipv4Addr::new(10, 0, 0, 5)));
        p[14..18].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(arp_spa(&p), None, "probe spa=0");
    }

    #[test]
    fn arp_request_parse_rejects_probes() {
        let mut p = vec![0u8; 28];
        p[1] = 1; // htype ethernet
        p[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        p[4..6].copy_from_slice(&[6, 4]);
        p[6..8].copy_from_slice(&1u16.to_be_bytes());
        p[8..14].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        p[14..18].copy_from_slice(&[10, 0, 0, 1]);
        p[24..28].copy_from_slice(&[10, 0, 0, 5]);
        assert_eq!(
            arp_request(&p),
            Some((
                Mac([2, 0, 0, 0, 0, 1]),
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 5),
            ))
        );
        p[14..18].copy_from_slice(&[0; 4]);
        assert_eq!(arp_request(&p), None, "ACD probe has no requester IP");
    }

    fn mk_ns(src_unspec: bool, target: [u8; 16]) -> Vec<u8> {
        let mut l3 = vec![0u8; 72];
        l3[0] = 0x60; // v6
        l3[6] = IPPROTO_ICMPV6;
        l3[4] = 0;
        l3[5] = 32; // payload len = 32 (icmpv6 hdr+target+option)
        if !src_unspec {
            l3[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        }
        l3[40] = ND_NS;
        l3[48..64].copy_from_slice(&target);
        // option SLLAO at icmp offset 24 => l3 64: type=1 len=1 mac
        l3[64] = 1;
        l3[65] = 1;
        l3
    }

    #[test]
    fn ns_learn_src_vs_target() {
        let tgt = [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
        let l3 = mk_ns(false, tgt);
        let (k, ip) = classify_learn(ETHERTYPE_IPV6, &l3).unwrap();
        assert_eq!(k, PktKind::Nd);
        assert_eq!(ip, "fe80::1".parse::<IpAddr>().unwrap(), "src learned");

        let l3 = mk_ns(true, tgt); // DAD
        let (k, ip) = classify_learn(ETHERTYPE_IPV6, &l3).unwrap();
        assert_eq!(k, PktKind::NdDad);
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::from(tgt)), "target learned for DAD");
    }

    #[test]
    fn icmpv6_csum_roundtrip() {
        // Build a minimal NS and check the csum verifies (sum over pseudo+msg == 0xffff).
        let tgt = [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
        let mut l3 = mk_ns(false, tgt);
        l3[24..40].copy_from_slice(&tgt); // dst = solicited node-ish, any
        assert!(fix_icmpv6_csum(&mut l3));
        // verify: recompute over the now-set csum should yield 0
        let payload_len = 32usize;
        let mut sum: u32 = 0;
        for i in (8..40).step_by(2) {
            sum += u16::from_be_bytes([l3[i], l3[i + 1]]) as u32;
        }
        sum += payload_len as u32 + IPPROTO_ICMPV6 as u32;
        let icmp = &l3[40..40 + payload_len];
        let mut i = 0;
        while i + 1 < icmp.len() {
            sum += u16::from_be_bytes([icmp[i], icmp[i + 1]]) as u32;
            i += 2;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(!(sum as u16), 0, "checksum verifies");
    }
}
