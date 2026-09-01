//! Backend abstraction: the kernel offload datapath (nft ruleset+sets / ebpf
//! progs+maps). The backend owns only the in-kernel rewrite/demux/copy state.
//! Link/addr/route + HOSTMAC derivation live in the syncer (it calls these).
//!
//! Both backends spawn a "copy reader" (NFLOG socket / BPF ringbuf) at init that
//! pushes `CopyEvent`s to the core over the provided channel.
//!
//! **Unsafe boundary**: all `unsafe` in this crate is confined to the external-I/O
//! leaves — `ebpf` (aya map POD impls + `poll`), `nft::wire` and `nft::nflog` (raw
//! `AF_NETLINK` sockets), and the top-level `afpacket` (raw `AF_PACKET` socket). Each
//! such block carries a `// SAFETY:` note. The control plane and core algorithm
//! (`core`, `state`, `packet`, `types`, `cli`, `netlink`) are `#![forbid(unsafe_code)]`,
//! and `nft` rule-encoding here builds plain `Vec<u8>` with no unsafe.

pub mod ebpf;
pub mod nft;

use crate::cli::Mode;
use crate::types::Mac;
use anyhow::Result;
use std::net::IpAddr;
use tokio::sync::mpsc::Sender;

/// Copy-queue depth (reader threads → core). Bounded on purpose: the kernel copy
/// path is already lossy (ringbuf overruns / NFLOG drops under pressure), so a full
/// queue is handled the same way — drop the event, the next packet re-learns. An
/// unbounded queue would let a guest cycling src addresses balloon memory, since
/// each *new* address costs the core several netlink round-trips to reconcile.
pub const COPY_QUEUE_DEPTH: usize = 1024;

/// Lossy enqueue for the copy readers (see COPY_QUEUE_DEPTH). `dropped` is a
/// per-reader counter; drops are logged at power-of-two counts to stay quiet.
pub(crate) fn push_copy(tx: &Sender<CopyEvent>, ev: CopyEvent, dropped: &mut u64) {
    use tokio::sync::mpsc::error::TrySendError;
    match tx.try_send(ev) {
        Ok(()) | Err(TrySendError::Closed(_)) => {} // closed = core shutting down
        Err(TrySendError::Full(_)) => {
            *dropped += 1;
            if dropped.is_power_of_two() {
                log::warn!("copy queue full: {dropped} copy events dropped so far (lossy by design)");
            }
        }
    }
}

/// A learn event surfaced from the kernel copy path.
#[derive(Debug)]
pub enum CopyEvent {
    /// ebpf: BPF already parsed the (ip, mac) tuple in-kernel.
    Learn { ip: IpAddr, mac: Mac },
    /// An upstream ARP request for an address in the current kernel demux map. The
    /// core validates it against its authoritative installed snapshot before replying.
    ArpRequest {
        guest_ip: std::net::Ipv4Addr,
        requester_ip: std::net::Ipv4Addr,
        requester_mac: Mac,
    },
    /// nft NFLOG: raw L3 payload + L2 metadata; parsed in the core. `reinject`
    /// (ND drop path) means the core must fix_csum + AF_PACKET send to up0.
    Nflog {
        hwaddr: Mac,
        dst_mac: Mac,
        ethertype: u16,
        l3: Vec<u8>,
        reinject: bool,
    },
}

/// Static config for a session (one up0-present lifetime).
#[derive(Clone, Debug)]
pub struct InitCfg {
    pub mode: Mode,
    pub up0: String,
    pub up0_ifindex: u32,
    /// fwd mode only.
    pub fwd0: Option<String>,
    pub fwd0_ifindex: Option<u32>,
    pub nflog_group: u16,
    pub timeout: u64,
    pub hostmac: Mac,
    pub brmac: Option<Mac>,
    pub host_ips: Vec<IpAddr>,
}

/// The kernel offload datapath. All methods are synchronous; the core calls them
/// from its async task (they do blocking netlink/bpf syscalls, which are fast).
pub trait Backend: Send {
    fn name(&self) -> &'static str;

    /// Install chains/progs + maps/sets, program HOSTMAC/BRMAC/host_ips, and spawn
    /// the copy reader (pushing to `copy_tx` via the lossy `push_copy`).
    fn init(&mut self, cfg: &InitCfg, copy_tx: Sender<CopyEvent>) -> Result<()>;

    /// Remove all kernel state for this session (back to uninitialized).
    fn teardown(&mut self) -> Result<()>;

    fn set_hostmac(&mut self, mac: Mac) -> Result<()>;
    fn set_brmac(&mut self, mac: Option<Mac>) -> Result<()>;
    fn set_host_ips(&mut self, ips: &[IpAddr]) -> Result<()>;

    /// Reconcile write: ip2mac[ip]=mac + valid(ip,mac) + seen=alive.
    fn write_entry(&mut self, ip: IpAddr, mac: Mac) -> Result<()>;
    /// Reconcile withdraw: remove ip2mac/valid/seen for ip (no-op if absent).
    fn withdraw_entry(&mut self, ip: IpAddr) -> Result<()>;

    /// Re-assert liveness for ip from the control plane (same effect as a datapath
    /// seen mark). Called when a keepalive probe is grace-skipped: the skip's safety
    /// must not hang on the remaining lifetime of a mark that may be almost a full
    /// period old — nft's seen is a kernel-clock timeout, so a control frame landing
    /// just after a flush leaves an arbitrarily thin margin, and any lateness of the
    /// aging timer then evicts a live guest (ebpf's mark-bit has no such race).
    fn refresh_seen(&mut self, ip: IpAddr) -> Result<()>;

    /// Aging: advance liveness and return the set of IPs still alive.
    fn flush(&mut self) -> Result<Vec<IpAddr>>;
}
