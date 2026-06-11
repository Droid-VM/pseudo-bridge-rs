//! Raw L2 send via AF_PACKET. Used for: nft-ND reinject (after fix_csum) and
//! per-entry broadcast on HOSTMAC change (gratuitous ARP / unsolicited NA), so the
//! upstream gateway re-caches guest-ip → new HOSTMAC. ARCHITECTURE.md §syncer.

use crate::packet::{ETHERTYPE_ARP, ETHERTYPE_IPV6, IPPROTO_ICMPV6, ND_NA};
use crate::types::Mac;
use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const ETH_P_ALL: u16 = 0x0003;

pub struct Injector {
    fd: OwnedFd,
    ifindex: u32,
}

impl Injector {
    pub fn new(ifindex: u32) -> Result<Self> {
        // SAFETY: socket() is an FFI call with constant, valid arguments. On success it
        // returns a fresh fd that nothing else owns, so wrapping it in OwnedFd takes sole
        // ownership (and closes it on drop). On failure (<0) we never build the OwnedFd.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                ETH_P_ALL.to_be() as i32,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()).context("AF_PACKET socket");
        }
        // SAFETY: raw is a fresh owned fd (checked >= 0 above); OwnedFd takes ownership.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Injector { fd, ifindex })
    }

    /// Send a complete Ethernet frame (incl. L2 header) out the bound interface.
    pub fn send_frame(&self, frame: &[u8]) -> Result<()> {
        // sockaddr_ll built as a plain (safe) struct literal — no mem::zeroed. dst mac is
        // the frame's first 6 bytes (informational; the kernel transmits the frame as-is).
        let mut dst = [0u8; 8];
        if frame.len() >= 6 {
            dst[..6].copy_from_slice(&frame[..6]);
        }
        let sa = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: self.ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: dst,
        };
        // SAFETY: FFI sendto. `frame`/`sa` are valid for the lengths passed (frame.len()
        // and size_of::<sockaddr_ll>()); the fd is owned and open. sendto only reads them.
        let ret = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &sa as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error()).context("AF_PACKET sendto");
        }
        Ok(())
    }

    pub fn send_garp(&self, ip: Ipv4Addr, hostmac: Mac) -> Result<()> {
        self.send_frame(&build_garp(ip, hostmac))
    }

    pub fn send_unsol_na(&self, ip: Ipv6Addr, hostmac: Mac) -> Result<()> {
        self.send_frame(&build_unsol_na(ip, hostmac))
    }
}

/// ARP request "who has `target`, tell `sender`@hostmac" (broadcast). Used by the
/// offload keepalive probe (injected on fwd0 → vmbr): a guest still holding `target`
/// replies, refreshing its entry's liveness (and the upstream's cache for it).
pub fn build_arp_request(target: Ipv4Addr, sender: Ipv4Addr, hostmac: Mac) -> Vec<u8> {
    let mut f = Vec::with_capacity(42);
    f.extend_from_slice(Mac::BROADCAST.bytes()); // dst
    f.extend_from_slice(hostmac.bytes()); // src
    f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    f.extend_from_slice(&1u16.to_be_bytes()); // htype ethernet
    f.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype IPv4
    f.push(6); // hlen
    f.push(4); // plen
    f.extend_from_slice(&1u16.to_be_bytes()); // op = request
    f.extend_from_slice(hostmac.bytes()); // sha
    f.extend_from_slice(&sender.octets()); // spa
    f.extend_from_slice(&[0u8; 6]); // tha (unknown)
    f.extend_from_slice(&target.octets()); // tpa
    f
}

/// Neighbor Solicitation for `target`, src=`src`@hostmac, to target's solicited-node
/// multicast, with SLLAO=hostmac. Offload keepalive probe (v6 counterpart of the ARP one).
pub fn build_ns(target: Ipv6Addr, src: Ipv6Addr, hostmac: Mac) -> Vec<u8> {
    let t = target.octets();
    let sol = Ipv6Addr::new(
        0xff02, 0, 0, 0, 0, 1, 0xff00 | t[13] as u16, (t[14] as u16) << 8 | t[15] as u16,
    );
    let dmac = Mac([0x33, 0x33, 0xff, t[13], t[14], t[15]]);
    // ICMPv6 NS: type(1) code(1) csum(2) reserved(4) target(16) + SLLAO(8) = 32 bytes
    let mut icmp = vec![0u8; 32];
    icmp[0] = 135; // NS
    icmp[8..24].copy_from_slice(&t); // target
    icmp[24] = 1; // option type SLLAO
    icmp[25] = 1; // length (8 bytes)
    icmp[26..32].copy_from_slice(hostmac.bytes());
    let mut l3 = vec![0u8; 40];
    l3[0] = 0x60; // version 6
    l3[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
    l3[6] = IPPROTO_ICMPV6;
    l3[7] = 255; // hop limit
    l3[8..24].copy_from_slice(&src.octets());
    l3[24..40].copy_from_slice(&sol.octets());
    l3.extend_from_slice(&icmp);
    crate::packet::fix_icmpv6_csum(&mut l3);
    crate::packet::build_frame(dmac, hostmac, ETHERTYPE_IPV6, &l3)
}

/// Unsolicited *unicast* ARP reply: "sender_ip is at hostmac", addressed to a specific
/// neighbour (L2 dst = target_mac). Linux peers set their cache entry to NUD_REACHABLE
/// on a unicast reply (arp.c: "Broadcast replies and request packets do not assert
/// neighbour reachability") — the core of the `--arp-keepalive` mechanism.
pub fn build_arp_reply(sender_ip: Ipv4Addr, hostmac: Mac, target_ip: Ipv4Addr, target_mac: Mac) -> Vec<u8> {
    let mut f = Vec::with_capacity(42);
    f.extend_from_slice(target_mac.bytes()); // dst (unicast -> PACKET_HOST at receiver)
    f.extend_from_slice(hostmac.bytes()); // src
    f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    f.extend_from_slice(&1u16.to_be_bytes()); // htype ethernet
    f.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype IPv4
    f.push(6); // hlen
    f.push(4); // plen
    f.extend_from_slice(&2u16.to_be_bytes()); // op = reply
    f.extend_from_slice(hostmac.bytes()); // sha
    f.extend_from_slice(&sender_ip.octets()); // spa
    f.extend_from_slice(target_mac.bytes()); // tha
    f.extend_from_slice(&target_ip.octets()); // tpa
    f
}

/// Gratuitous ARP reply: spa=tpa=ip, sha=hostmac, broadcast. Announces ip@hostmac.
pub fn build_garp(ip: Ipv4Addr, hostmac: Mac) -> Vec<u8> {
    let mut f = Vec::with_capacity(42);
    f.extend_from_slice(Mac::BROADCAST.bytes()); // dst
    f.extend_from_slice(hostmac.bytes()); // src
    f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    // ARP
    f.extend_from_slice(&1u16.to_be_bytes()); // htype ethernet
    f.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype IPv4
    f.push(6); // hlen
    f.push(4); // plen
    f.extend_from_slice(&2u16.to_be_bytes()); // op = reply (gratuitous)
    f.extend_from_slice(hostmac.bytes()); // sha
    f.extend_from_slice(&ip.octets()); // spa
    f.extend_from_slice(Mac::BROADCAST.bytes()); // tha
    f.extend_from_slice(&ip.octets()); // tpa
    f
}

/// Unsolicited NA with override flag, TLLAO=hostmac, target=ip, dst=ff02::1.
/// Announces ip@hostmac to all nodes.
pub fn build_unsol_na(ip: Ipv6Addr, hostmac: Mac) -> Vec<u8> {
    // ICMPv6 NA: type(1) code(1) csum(2) flags(4) target(16) + TLLAO(8) = 32 bytes
    let mut icmp = vec![0u8; 32];
    icmp[0] = ND_NA;
    icmp[1] = 0;
    // flags: override (0x20) + router(0)+solicited(0). byte 4 high bits.
    icmp[4] = 0x20;
    icmp[8..24].copy_from_slice(&ip.octets());
    icmp[24] = 2; // option type TLLAO
    icmp[25] = 1; // length (8 bytes)
    icmp[26..32].copy_from_slice(hostmac.bytes());

    let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    // IPv6 header (40) + icmp
    let mut l3 = vec![0u8; 40];
    l3[0] = 0x60; // version 6
    let plen = icmp.len() as u16;
    l3[4..6].copy_from_slice(&plen.to_be_bytes());
    l3[6] = IPPROTO_ICMPV6;
    l3[7] = 255; // hop limit
    l3[8..24].copy_from_slice(&ip.octets()); // src = the advertised address
    l3[24..40].copy_from_slice(&all_nodes.octets());
    l3.extend_from_slice(&icmp);
    crate::packet::fix_icmpv6_csum(&mut l3);

    // dst mac for ff02::1 = 33:33:00:00:00:01
    let dst = Mac([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
    crate::packet::build_frame(dst, hostmac, ETHERTYPE_IPV6, &l3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garp_shape() {
        let mac: Mac = "02:00:00:00:00:01".parse().unwrap();
        let f = build_garp(Ipv4Addr::new(10, 0, 0, 5), mac);
        assert_eq!(f.len(), 42);
        assert_eq!(&f[0..6], Mac::BROADCAST.bytes());
        assert_eq!(&f[6..12], mac.bytes());
        assert_eq!(&f[12..14], &ETHERTYPE_ARP.to_be_bytes());
        assert_eq!(&f[28..32], &[10, 0, 0, 5]); // spa
        assert_eq!(&f[38..42], &[10, 0, 0, 5]); // tpa
    }

    #[test]
    fn arp_reply_shape() {
        let hm: Mac = "02:00:00:00:00:01".parse().unwrap();
        let gw: Mac = "02:00:00:00:00:99".parse().unwrap();
        let f = build_arp_reply(
            Ipv4Addr::new(10, 0, 0, 5),
            hm,
            Ipv4Addr::new(10, 0, 0, 1),
            gw,
        );
        assert_eq!(f.len(), 42);
        assert_eq!(&f[0..6], gw.bytes(), "unicast to the neighbour");
        assert_eq!(&f[6..12], hm.bytes());
        assert_eq!(&f[20..22], &2u16.to_be_bytes(), "op reply");
        assert_eq!(&f[22..28], hm.bytes()); // sha
        assert_eq!(&f[28..32], &[10, 0, 0, 5]); // spa = guest
        assert_eq!(&f[32..38], gw.bytes()); // tha
        assert_eq!(&f[38..42], &[10, 0, 0, 1]); // tpa = neighbour
    }

    #[test]
    fn unsol_na_shape() {
        let mac: Mac = "02:00:00:00:00:01".parse().unwrap();
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let f = build_unsol_na(ip, mac);
        assert_eq!(&f[0..6], &[0x33, 0x33, 0, 0, 0, 1]);
        assert_eq!(&f[6..12], mac.bytes());
        assert_eq!(&f[12..14], &ETHERTYPE_IPV6.to_be_bytes());
        // icmp type at 14+40 = 54
        assert_eq!(f[54], ND_NA);
        // target at 54+8 = 62
        assert_eq!(&f[62..78], &ip.octets());
        // TLLAO mac at 54+26 = 80
        assert_eq!(&f[80..86], mac.bytes());
    }
}
