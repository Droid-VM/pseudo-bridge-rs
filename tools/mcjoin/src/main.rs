//! mcjoin — throwaway probe to confirm the pbridge v6 ND-resolution fix.
//!
//! Joins the solicited-node multicast group of one or more IPv6 addresses on a
//! given interface *at the IPv6 layer* (MCAST_JOIN_GROUP), then holds the
//! membership open until Ctrl-C. This is the one thing `ip link set allmulticast`
//! and `ip maddr add` (link-layer only) could NOT do: it creates a real MLD
//! membership (`inet6 ... users N` in `ip maddr show`), sends an MLD report, and
//! makes Android's APF / the Wi-Fi firmware pass the upstream gateway's NS.
//!
//!   mcjoin <iface> <addr-or-group> [addr-or-group ...]
//!
//! e.g.  mcjoin wlan0 2a0e:b107:1953:cd:4e:b6ff:fe5b:41e9
//!       -> joins ff02::1:ff5b:41e9 on wlan0 and waits.
//!
//! While it runs:  `ip maddr show dev wlan0`  should now list the group with an
//! `inet6 ... users` line, and  `tcpdump -enni wlan0 icmp6`  should show the
//! gateway's NS arriving. Ping from the guest -> replies should flow. Ctrl-C to
//! drop the memberships (kernel auto-leaves on socket close).

use std::ffi::CString;
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const IPV6_ADD_MEMBERSHIP: libc::c_int = 20; // = IPV6_JOIN_GROUP on Linux

/// Solicited-node multicast address: ff02::1:ffXX:XXXX from the low 24 bits.
fn solicited_node(a: &Ipv6Addr) -> Ipv6Addr {
    let o = a.octets();
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00 | o[13] as u16, (o[14] as u16) << 8 | o[15] as u16)
}

fn if_index(name: &str) -> u32 {
    if let Ok(n) = name.parse::<u32>() {
        return n;
    }
    let c = CString::new(name).unwrap();
    unsafe { libc::if_nametoindex(c.as_ptr()) }
}

fn join(fd: i32, ifindex: u32, group: &Ipv6Addr) -> std::io::Result<()> {
    let mut mreq: libc::ipv6_mreq = unsafe { std::mem::zeroed() };
    mreq.ipv6mr_multiaddr = libc::in6_addr { s6_addr: group.octets() };
    mreq.ipv6mr_interface = ifindex;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IPV6_ADD_MEMBERSHIP,
            &mreq as *const libc::ipv6_mreq as *const libc::c_void,
            std::mem::size_of::<libc::ipv6_mreq>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <iface> <addr-or-group> [addr-or-group ...]", args[0]);
        eprintln!("  joins each address's solicited-node group (or the group itself if");
        eprintln!("  already ff00::/8) on <iface> and holds it until Ctrl-C.");
        std::process::exit(2);
    }

    let iface = &args[1];
    let ifindex = if_index(iface);
    if ifindex == 0 {
        eprintln!("error: no such interface {iface:?}");
        std::process::exit(1);
    }

    // SAFETY: socket() with constant args; the fd is owned and only used for setsockopt.
    let raw = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if raw < 0 {
        eprintln!("error: socket: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }
    let fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut joined = 0usize;
    for a in &args[2..] {
        let addr: Ipv6Addr = match a.parse() {
            Ok(x) => x,
            Err(_) => {
                eprintln!("skip {a:?}: not an IPv6 address");
                continue;
            }
        };
        let group = if (addr.octets()[0]) == 0xff { addr } else { solicited_node(&addr) };
        match join(fd.as_raw_fd(), ifindex, &group) {
            Ok(()) => {
                println!("joined {group} on {iface} (if{ifindex})  [from {addr}]");
                joined += 1;
            }
            Err(e) if e.raw_os_error() == Some(libc::EADDRINUSE) => {
                println!("already a member of {group} on {iface}  [from {addr}]");
                joined += 1;
            }
            Err(e) => eprintln!("join {group} on {iface}: {e}"),
        }
    }

    if joined == 0 {
        eprintln!("nothing joined; exiting");
        std::process::exit(1);
    }

    println!();
    println!("holding {joined} membership(s). verify:  ip maddr show dev {iface}");
    println!("Ctrl-C to leave.");
    // Block forever holding the socket (and thus the memberships) open.
    loop {
        unsafe { libc::pause() };
    }
}
