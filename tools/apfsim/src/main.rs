//! apfsim — a userspace "upstream NIC with ARP/ND offload", for testing pbridge's
//! `--offload-workaround` faithfully.
//!
//! It sits between pbridge's up0 (the host-side tap, tap2) and the gateway (reached via
//! the upstream-side tap, tap1, which it bridges to a real upstream interface). It models
//! exactly the Android-APF behaviour that breaks v6 MAC-NAT:
//!
//!   tap2 -> tap1 (host -> upstream): enforce a single source MAC — drop any frame whose
//!                 src mac != tap2's mac (HOSTMAC). This is the Wi-Fi STA / src-mac port.
//!   tap1 -> tap2 (upstream -> host): ARP/ND **offload** — for an ARP-request or NS whose
//!                 *target* is an address currently configured on tap2, answer it directly
//!                 (ARP reply / NA, with HOSTMAC); for any *other* target, **drop** it
//!                 (APF's `DROPPED_ARP_OTHER_HOST` / `DROPPED_IPV6_NS_OTHER_HOST`).
//!                 Everything else is forwarded.
//!
//! pbridge's workaround installs each learned guest address onto up0 (=tap2); apfsim
//! detects tap2's address set live (polls), so with the workaround on the guest's address
//! is offload-answered (resolution works) and without it the guest's NS/ARP is dropped
//! (resolution fails) — the real failure, reproduced.
//!
//!   apfsim --upstream <ifname> [--up-tap tap1] [--host-tap tap2]

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::Command;
use std::sync::{Arc, Mutex};

const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

#[derive(Default, Clone)]
struct HostInfo {
    mac: [u8; 6],
    v4: HashSet<[u8; 4]>,
    v6: HashSet<[u8; 16]>,
}

fn tap_open(name: &str) -> OwnedFd {
    // SAFETY: open + ioctl on /dev/net/tun with a well-formed ifreq.
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        panic!("open /dev/net/tun: {}", std::io::Error::last_os_error());
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.bytes().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI;
    if unsafe { libc::ioctl(fd, TUNSETIFF as _, &ifr) } < 0 {
        panic!("TUNSETIFF {name}: {}", std::io::Error::last_os_error());
    }
    // non-blocking so we can drain each tap in a loop.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn ip(args: &[&str]) {
    let _ = Command::new("ip").args(args).status();
}

fn parse_mac(s: &str) -> [u8; 6] {
    let mut m = [0u8; 6];
    for (i, p) in s.trim().split(':').enumerate().take(6) {
        m[i] = u8::from_str_radix(p, 16).unwrap_or(0);
    }
    m
}

/// Read tap2's mac + configured v4/v6 addresses (so proxies appear live).
fn read_host_info(tap: &str) -> HostInfo {
    let mut hi = HostInfo::default();
    if let Ok(s) = std::fs::read_to_string(format!("/sys/class/net/{tap}/address")) {
        hi.mac = parse_mac(&s);
    }
    if let Ok(out) = Command::new("ip").args(["-o", "addr", "show", "dev", tap]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        let toks: Vec<&str> = text.split_whitespace().collect();
        for (i, t) in toks.iter().enumerate() {
            if *t == "inet" {
                if let Some(a) = toks.get(i + 1).and_then(|x| x.split('/').next()) {
                    if let Ok(v4) = a.parse::<Ipv4Addr>() {
                        hi.v4.insert(v4.octets());
                    }
                }
            } else if *t == "inet6" {
                if let Some(a) = toks.get(i + 1).and_then(|x| x.split('/').next()) {
                    if let Ok(v6) = a.parse::<Ipv6Addr>() {
                        hi.v6.insert(v6.octets());
                    }
                }
            }
        }
    }
    hi
}

fn write_frame(fd: RawFd, f: &[u8]) {
    unsafe {
        libc::write(fd, f.as_ptr() as *const libc::c_void, f.len());
    }
}

fn build_arp_reply(req: &[u8], mac: &[u8; 6]) -> Vec<u8> {
    let rm = &req[6..12]; // requester mac
    let rip = &req[28..32]; // requester ip (spa)
    let tip = &req[38..42]; // target ip (tpa) — one of ours
    let mut f = Vec::with_capacity(42);
    f.extend_from_slice(rm); // dst = requester
    f.extend_from_slice(mac); // src = HOSTMAC
    f.extend_from_slice(&[0x08, 0x06]); // ARP
    f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02]); // eth/ipv4, reply
    f.extend_from_slice(mac); // sha = HOSTMAC
    f.extend_from_slice(tip); // spa = the target they asked for
    f.extend_from_slice(rm); // tha
    f.extend_from_slice(rip); // tpa
    f
}

fn csum16(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for p in parts {
        let mut i = 0;
        while i + 1 < p.len() {
            sum += ((p[i] as u32) << 8) | p[i + 1] as u32;
            i += 2;
        }
        if p.len() % 2 == 1 {
            sum += (p[p.len() - 1] as u32) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_na(ns: &[u8], mac: &[u8; 6]) -> Option<Vec<u8>> {
    let sm = &ns[6..12]; // solicitor mac
    let sip = &ns[22..38]; // solicitor ip (ipv6 src)
    let tgt = &ns[62..78]; // ND target — one of ours
    if sip.iter().all(|&b| b == 0) {
        return None; // DAD NS (src ::) — don't answer
    }
    // ICMPv6 NA payload (32 bytes): type, code, csum, flags(4), target(16), TLLA(8).
    let mut icmp = vec![0u8; 32];
    icmp[0] = 136; // NA
    icmp[4] = 0x60; // solicited + override
    icmp[8..24].copy_from_slice(tgt);
    icmp[24] = 2; // TLLA
    icmp[25] = 1;
    icmp[26..32].copy_from_slice(mac);
    // pseudo-header: src(tgt) dst(sip) len(32) zeros(3) nh(58)
    let len = (icmp.len() as u32).to_be_bytes();
    let ph_tail = [0u8, 0, 0, 58u8];
    let c = csum16(&[tgt, sip, &len, &ph_tail, &icmp]);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());

    let mut f = Vec::with_capacity(86);
    f.extend_from_slice(sm); // dst = solicitor
    f.extend_from_slice(mac); // src = HOSTMAC
    f.extend_from_slice(&[0x86, 0xdd]);
    let mut l3 = vec![0u8; 40];
    l3[0] = 0x60;
    l3[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
    l3[6] = 58; // next header ICMPv6
    l3[7] = 255; // hop limit
    l3[8..24].copy_from_slice(tgt); // src = target
    l3[24..40].copy_from_slice(sip); // dst = solicitor
    f.extend_from_slice(&l3);
    f.extend_from_slice(&icmp);
    Some(f)
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let mut upstream = None;
    let mut up_tap = "tap1".to_string();
    let mut host_tap = "tap2".to_string();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--upstream" => {
                i += 1;
                upstream = argv.get(i).cloned();
            }
            "--up-tap" => {
                i += 1;
                up_tap = argv.get(i).cloned().unwrap_or(up_tap);
            }
            "--host-tap" => {
                i += 1;
                host_tap = argv.get(i).cloned().unwrap_or(host_tap);
            }
            _ => {}
        }
        i += 1;
    }
    let Some(upstream) = upstream else {
        eprintln!("usage: apfsim --upstream <ifname> [--up-tap tap1] [--host-tap tap2]");
        std::process::exit(2);
    };

    let up_fd = tap_open(&up_tap); // toward the gateway
    let host_fd = tap_open(&host_tap); // toward pbridge (= up0)

    // Bridge the upstream-side tap with the real upstream interface.
    ip(&["link", "set", &up_tap, "up"]);
    ip(&["link", "set", &host_tap, "up"]);
    ip(&["link", "add", "apfbr", "type", "bridge"]);
    ip(&["link", "set", "apfbr", "up"]);
    ip(&["link", "set", &up_tap, "master", "apfbr"]);
    ip(&["link", "set", &upstream, "master", "apfbr"]);
    ip(&["link", "set", &upstream, "up"]);

    let host_info = Arc::new(Mutex::new(read_host_info(&host_tap)));
    {
        // refresh tap2's mac + addresses every 500ms so installed proxies appear.
        let hi = host_info.clone();
        let tap = host_tap.clone();
        std::thread::spawn(move || loop {
            let fresh = read_host_info(&tap);
            *hi.lock().unwrap() = fresh;
            std::thread::sleep(std::time::Duration::from_millis(500));
        });
    }

    eprintln!(
        "apfsim: {up_tap}(upstream<-{upstream}) <-> {host_tap}(host/up0); offload + single-mac"
    );

    let up_raw = up_fd.as_raw_fd();
    let host_raw = host_fd.as_raw_fd();
    let mut fds = [
        libc::pollfd { fd: host_raw, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: up_raw, events: libc::POLLIN, revents: 0 },
    ];
    let mut buf = [0u8; 2048];
    loop {
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, 1000) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        // host -> upstream: single-MAC filter.
        if fds[0].revents & libc::POLLIN != 0 {
            drain(host_raw, &mut buf, |f| {
                let hi = host_info.lock().unwrap();
                if f.len() >= 12 && f[6..12] == hi.mac {
                    write_frame(up_raw, f); // src == HOSTMAC -> allowed
                }
                // else dropped (leak / spoof)
            });
        }
        // upstream -> host: ARP/ND offload.
        if fds[1].revents & libc::POLLIN != 0 {
            drain(up_raw, &mut buf, |f| {
                let hi = host_info.lock().unwrap();
                if let Some(action) = offload(f, &hi) {
                    match action {
                        Action::Answer(reply) => write_frame(up_raw, &reply),
                        Action::Drop => {}
                        Action::Forward => write_frame(host_raw, f),
                    }
                } else {
                    write_frame(host_raw, f);
                }
            });
        }
    }
}

enum Action {
    Answer(Vec<u8>),
    Drop,
    Forward,
}

/// Decide the offload action for an upstream->host frame. `None` == plain forward.
fn offload(f: &[u8], hi: &HostInfo) -> Option<Action> {
    if f.len() < 14 {
        return Some(Action::Forward);
    }
    let ethtype = u16::from_be_bytes([f[12], f[13]]);
    match ethtype {
        0x0806 if f.len() >= 42 => {
            let op = u16::from_be_bytes([f[20], f[21]]);
            if op != 1 {
                return Some(Action::Forward); // ARP reply etc.
            }
            let mut tpa = [0u8; 4];
            tpa.copy_from_slice(&f[38..42]);
            if hi.v4.contains(&tpa) {
                Some(Action::Answer(build_arp_reply(f, &hi.mac))) // offload
            } else {
                Some(Action::Drop) // ARP_OTHER_HOST
            }
        }
        0x86dd if f.len() >= 78 && f[20] == 58 && f[54] == 135 => {
            let mut tgt = [0u8; 16];
            tgt.copy_from_slice(&f[62..78]);
            let known = hi.v6.contains(&tgt);
            if std::env::var("APFSIM_DEBUG").is_ok() {
                eprintln!("NS target={} known={known} v6set={}", Ipv6Addr::from(tgt), hi.v6.len());
            }
            if known {
                match build_na(f, &hi.mac) {
                    Some(na) => Some(Action::Answer(na)), // offload
                    None => Some(Action::Forward),        // DAD NS
                }
            } else {
                Some(Action::Drop) // NS_OTHER_HOST
            }
        }
        _ => Some(Action::Forward),
    }
}

fn drain<F: FnMut(&[u8])>(fd: RawFd, buf: &mut [u8], mut f: F) {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break; // EAGAIN / closed
        }
        f(&buf[..n as usize]);
    }
}
