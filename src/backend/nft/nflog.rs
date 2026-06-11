//! nfnetlink_log reader (subsys NFNL_SUBSYS_ULOG=4, verified empirically). Binds the
//! configured group in COPY_PACKET mode and turns each logged packet into a CopyEvent.
//! NFULA_HWADDR = original guest src mac; NFULA_HWHEADER = full L2 header (ethertype at
//! bytes 12..14); NFULA_PAYLOAD = L3; NFULA_PREFIX "R" => reinject (ND drop path).

use crate::backend::{push_copy, CopyEvent};
use crate::types::Mac;
use anyhow::{Context, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

const NETLINK_NETFILTER: i32 = 12;
const NFNL_SUBSYS_ULOG: u16 = 4;
const NFULNL_MSG_CONFIG: u16 = 1;
const NFULNL_MSG_PACKET: u16 = 0;
const NFULA_CFG_CMD: u16 = 1;
const NFULA_CFG_MODE: u16 = 2;
const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_COPY_PACKET: u8 = 2;
const NFULA_HWADDR: u16 = 8;
const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;
const NFULA_HWHEADER: u16 = 16;
const NLM_F_REQUEST: u16 = 1;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn nlattr(typ: u16, payload: &[u8]) -> Vec<u8> {
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

fn config_msg(group: u16, seq: u32, attr: &[u8]) -> Vec<u8> {
    // nfgenmsg: family=AF_UNSPEC, version=0, res_id=htons(group)
    let mut body = vec![0u8, 0u8];
    body.extend_from_slice(&group.to_be_bytes());
    body.extend_from_slice(attr);
    let total = 16 + body.len();
    let mut v = Vec::with_capacity(align4(total));
    v.extend_from_slice(&(total as u32).to_ne_bytes());
    v.extend_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG).to_ne_bytes());
    v.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    v.extend_from_slice(&seq.to_ne_bytes());
    v.extend_from_slice(&0u32.to_ne_bytes());
    v.extend_from_slice(&body);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

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

pub fn spawn_reader(group: u16, stop: Arc<AtomicBool>, tx: Sender<CopyEvent>) -> Result<()> {
    // SAFETY: FFI socket() with constant args; the returned fd is fresh/unowned on success
    // so OwnedFd takes sole ownership (closed on drop). Not built on failure.
    let raw = unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_NETFILTER)
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error()).context("nflog socket");
    }
    // SAFETY: raw is a fresh owned fd (checked >= 0 above); OwnedFd takes ownership.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: sockaddr_nl is repr(C) over integer/padding fields; all-zero is valid. We then
    // set nl_family. (No Default impl, and nl_pad is libc's Padding type.)
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: FFI bind; &sa valid for the passed size; fd owned/open; reads only.
    if unsafe {
        libc::bind(fd.as_raw_fd(), &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32)
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("nflog bind");
    }
    // Enlarge rcvbuf; set 1s timeout so the thread can poll the stop flag.
    let bufsz: i32 = 1 << 20;
    // SAFETY: FFI setsockopt; each optval pointer is valid for its size and read-only.
    // Best-effort tuning, so the return values are intentionally ignored.
    unsafe {
        libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, &bufsz as *const _ as *const libc::c_void, 4);
        let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
        libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32);
    }

    // BIND group + COPY_PACKET mode
    let bind = config_msg(group, 1, &nlattr(NFULA_CFG_CMD, &[NFULNL_CFG_CMD_BIND]));
    send_all(&fd, &bind)?;
    let mut mode_payload = 0xffff_ffffu32.to_be_bytes().to_vec(); // copy_range
    mode_payload.push(NFULNL_COPY_PACKET);
    mode_payload.push(0); // pad
    let modemsg = config_msg(group, 2, &nlattr(NFULA_CFG_MODE, &mode_payload));
    send_all(&fd, &modemsg)?;

    std::thread::Builder::new()
        .name("nflog-reader".into())
        .spawn(move || {
            let mut buf = vec![0u8; 1 << 17];
            let mut dropped = 0u64;
            loop {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                // SAFETY: FFI recv; writes at most buf.len() bytes into the valid, owned
                // `buf`. fd is owned/open for the thread's lifetime.
                let n = unsafe {
                    libc::recv(fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                };
                if n <= 0 {
                    continue; // timeout / EINTR
                }
                let n = n as usize;
                let mut off = 0;
                while off + 16 <= n {
                    let mlen = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                    let mtype = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
                    if mlen < 16 || off + mlen > n {
                        break;
                    }
                    if (mtype >> 8) == NFNL_SUBSYS_ULOG && (mtype & 0xff) == NFULNL_MSG_PACKET {
                        // skip nfgenmsg (4 bytes) then attrs
                        if let Some(ev) = parse_packet(&buf[off + 20..off + mlen]) {
                            push_copy(&tx, ev, &mut dropped);
                        }
                    }
                    off += align4(mlen);
                }
            }
        })
        .context("spawn nflog thread")?;
    Ok(())
}

fn parse_packet(abody: &[u8]) -> Option<CopyEvent> {
    let mut hwaddr = None;
    let mut hwheader: Option<&[u8]> = None;
    let mut payload: Option<&[u8]> = None;
    let mut reinject = false;
    for (t, v) in parse_attrs(abody) {
        match t {
            NFULA_HWADDR => {
                // nfulnl_msg_packet_hw { __be16 hw_addrlen; __u16 _pad; __u8 hw_addr[8]; }
                if v.len() >= 10 {
                    hwaddr = Mac::from_slice(&v[4..10]);
                }
            }
            NFULA_HWHEADER => hwheader = Some(v),
            NFULA_PAYLOAD => payload = Some(v),
            NFULA_PREFIX => {
                reinject = v.first() == Some(&b'R');
            }
            _ => {}
        }
    }
    let payload = payload?;
    // ingress hooks deliver HWHEADER (L2) separately + PAYLOAD = L3.
    // egress hooks deliver no HWHEADER; PAYLOAD = full L2 frame.
    if let Some(hwheader) = hwheader {
        if hwheader.len() < 14 {
            return None;
        }
        let dst_mac = Mac::from_slice(&hwheader[0..6])?;
        let hwaddr = hwaddr.or_else(|| Mac::from_slice(&hwheader[6..12]))?;
        let ethertype = u16::from_be_bytes([hwheader[12], hwheader[13]]);
        Some(CopyEvent::Nflog { hwaddr, dst_mac, ethertype, l3: payload.to_vec(), reinject })
    } else {
        if payload.len() < 14 {
            return None;
        }
        let dst_mac = Mac::from_slice(&payload[0..6])?;
        let hwaddr = Mac::from_slice(&payload[6..12])?;
        let ethertype = u16::from_be_bytes([payload[12], payload[13]]);
        Some(CopyEvent::Nflog { hwaddr, dst_mac, ethertype, l3: payload[14..].to_vec(), reinject })
    }
}

fn send_all(fd: &OwnedFd, buf: &[u8]) -> Result<()> {
    // SAFETY: FFI send; pointer/len describe the valid `buf`, read-only; fd is owned/open.
    let n = unsafe { libc::send(fd.as_raw_fd(), buf.as_ptr() as *const libc::c_void, buf.len(), 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("nflog send");
    }
    Ok(())
}
