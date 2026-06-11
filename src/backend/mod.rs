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
use tokio::sync::mpsc::UnboundedSender;

/// A learn event surfaced from the kernel copy path.
#[derive(Debug)]
pub enum CopyEvent {
    /// ebpf: BPF already parsed the (ip, mac) tuple in-kernel.
    Learn { ip: IpAddr, mac: Mac },
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
    /// the copy reader (pushing to `copy_tx`).
    fn init(&mut self, cfg: &InitCfg, copy_tx: UnboundedSender<CopyEvent>) -> Result<()>;

    /// Remove all kernel state for this session (back to uninitialized).
    fn teardown(&mut self) -> Result<()>;

    fn set_hostmac(&mut self, mac: Mac) -> Result<()>;
    fn set_brmac(&mut self, mac: Option<Mac>) -> Result<()>;
    fn set_host_ips(&mut self, ips: &[IpAddr]) -> Result<()>;

    /// Reconcile write: ip2mac[ip]=mac + valid(ip,mac) + seen=alive.
    fn write_entry(&mut self, ip: IpAddr, mac: Mac) -> Result<()>;
    /// Reconcile withdraw: remove ip2mac/valid/seen for ip (no-op if absent).
    fn withdraw_entry(&mut self, ip: IpAddr) -> Result<()>;

    /// Aging: advance liveness and return the set of IPs still alive.
    fn flush(&mut self) -> Result<Vec<IpAddr>>;
}
