//! wifimc — throwaway probe: talk to wpa_supplicant's control socket and send a
//! raw command (default: a `PING` connectivity check). The point is to drive the
//! Wi-Fi driver's RX packet filter directly, which is what `WifiManager.MulticastLock`
//! does under the hood on almost every Android Wi-Fi HAL.
//!
//! To let the host RECEIVE multicast (so the upstream gateway's solicited-node NS
//! reaches us and the guest can be ND-resolved), the filter must be turned off:
//!
//!   wifimc wlan0                         # PING -> expect "PONG" (socket reachable)
//!   wifimc wlan0 DRIVER RXFILTER-STOP    # drop ALL rx filtering (receive everything)
//!   wifimc wlan0 DRIVER RXFILTER-REMOVE 3# drop only the IPv6-multicast filter
//!   wifimc -r 2 wlan0 DRIVER RXFILTER-STOP   # re-send every 2s (hold it off)
//!
//! Options:
//!   -p PATH   explicit control socket (full path, or a dir to which <iface> is added).
//!             default candidates: /data/vendor/wifi/wpa/sockets, /data/misc/wifi/sockets,
//!             /var/run/wpa_supplicant
//!   -r SECS   after the first send, repeat every SECS seconds until Ctrl-C.
//!
//! This is IPC over wpa_supplicant's documented control interface (like netlink),
//! not shelling out to a CLI. Throwaway — pbridge is untouched.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

const SUN_PATH_OFF: usize = 2; // offsetof(sockaddr_un, sun_path) on Linux (sa_family_t = u16)

fn sockaddr_un(path: &str) -> (libc::sockaddr_un, libc::socklen_t) {
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    // leading '@' => abstract namespace (first byte NUL).
    let (abstract_ns, body) =
        if let Some(rest) = path.strip_prefix('@') { (true, rest.as_bytes()) } else { (false, bytes) };
    let start = if abstract_ns { 1 } else { 0 };
    for (i, b) in body.iter().enumerate() {
        sa.sun_path[start + i] = *b as libc::c_char;
    }
    let len = SUN_PATH_OFF + start + body.len() + if abstract_ns { 0 } else { 1 };
    (sa, len as libc::socklen_t)
}

fn discover(iface: &str, explicit: Option<&str>) -> Option<String> {
    if let Some(p) = explicit {
        // a dir -> append iface; otherwise treat as the socket path itself.
        if Path::new(p).is_dir() {
            return Some(format!("{}/{}", p.trim_end_matches('/'), iface));
        }
        return Some(p.to_string());
    }
    for dir in [
        "/data/vendor/wifi/wpa/sockets",
        "/data/misc/wifi/sockets",
        "/var/run/wpa_supplicant",
    ] {
        let cand = format!("{dir}/{iface}");
        if Path::new(&cand).exists() {
            return Some(cand);
        }
    }
    None
}

/// Send one command, return the reply string (or an error).
///
/// Bind mode matters for the *reply*: by default we autobind an **abstract** socket,
/// which has no filesystem perms so wpa_supplicant (uid `wifi`) can always `sendto`
/// it — this is what worked on-device. `-b <dir>` instead binds a filesystem socket
/// in <dir> (wpa_ctrl convention); only useful if abstract is blocked, and note a
/// root-owned socket file there is NOT writable by wpa (DAC), so it usually fails.
fn request(server: &str, cmd: &str, bind_dir: Option<&str>, seq: u32) -> std::io::Result<String> {
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // cleanup guard for the filesystem-bind case (no-op for abstract).
    struct Unlink(Option<String>);
    impl Drop for Unlink {
        fn drop(&mut self) {
            if let Some(p) = &self.0 {
                let _ = std::fs::remove_file(p);
            }
        }
    }
    let _guard = match bind_dir {
        None => {
            // autobind an abstract address.
            let mut local: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            local.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let rc = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    &local as *const libc::sockaddr_un as *const libc::sockaddr,
                    SUN_PATH_OFF as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Unlink(None)
        }
        Some(dir) => {
            let pid = unsafe { libc::getpid() };
            let client_path = format!("{}/wifimc-{}-{}", dir.trim_end_matches('/'), pid, seq);
            let _ = std::fs::remove_file(&client_path);
            let (lsa, llen) = sockaddr_un(&client_path);
            let rc = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    &lsa as *const libc::sockaddr_un as *const libc::sockaddr,
                    llen,
                )
            };
            if rc < 0 {
                let e = std::io::Error::last_os_error();
                return Err(std::io::Error::new(e.kind(), format!("bind {client_path}: {e}")));
            }
            Unlink(Some(client_path))
        }
    };

    // 2s recv timeout.
    let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let (sa, salen) = sockaddr_un(server);
    let rc = unsafe {
        libc::connect(fd.as_raw_fd(), &sa as *const libc::sockaddr_un as *const libc::sockaddr, salen)
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let c = CString::new(cmd).unwrap();
    let n = unsafe { libc::send(fd.as_raw_fd(), c.as_ptr() as *const libc::c_void, cmd.len(), 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut buf = vec![0u8; 4096];
    let r = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(String::from_utf8_lossy(&buf[..r as usize]).trim_end().to_string())
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let mut explicit: Option<String> = None;
    let mut bind_override: Option<String> = None;
    let mut repeat: Option<u64> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-p" => {
                i += 1;
                explicit = argv.get(i).cloned();
            }
            "-b" => {
                i += 1;
                bind_override = argv.get(i).cloned();
            }
            "-r" => {
                i += 1;
                repeat = argv.get(i).and_then(|s| s.parse().ok());
            }
            "-h" | "--help" => {
                eprintln!("usage: wifimc [-p sock] [-b dir] [-r secs] <iface> [command words...]");
                eprintln!("  no command -> PING. e.g. wifimc wlan0 DRIVER RXFILTER-STOP");
                eprintln!("  -b dir : where to bind the client socket (default: wpa's socket dir)");
                std::process::exit(2);
            }
            _ => rest.push(argv[i].clone()),
        }
        i += 1;
    }
    if rest.is_empty() {
        eprintln!("usage: wifimc [-p sock] [-r secs] <iface> [command words...]");
        std::process::exit(2);
    }
    let iface = rest.remove(0);
    let cmd = if rest.is_empty() { "PING".to_string() } else { rest.join(" ") };

    let server = match discover(&iface, explicit.as_deref()) {
        Some(s) => s,
        None => {
            eprintln!("error: no wpa_supplicant control socket found for {iface}.");
            eprintln!("  try -p <dir-or-path>; look under /data/vendor/wifi/wpa/sockets etc.");
            std::process::exit(1);
        }
    };
    eprintln!("ctrl socket: {server}");
    eprintln!("bind       : {}", bind_override.as_deref().unwrap_or("abstract"));
    eprintln!("command    : {cmd}");

    let mut seq = 0u32;
    let mut send = || {
        seq += 1;
        match request(&server, &cmd, bind_override.as_deref(), seq) {
            Ok(reply) => {
                println!("<- {reply}");
                true
            }
            Err(e) => {
                eprintln!("error: {e}");
                false
            }
        }
    };

    if !send() {
        std::process::exit(1);
    }
    if let Some(secs) = repeat {
        eprintln!("holding (re-send every {secs}s); Ctrl-C to stop.");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            send();
        }
    }
}
