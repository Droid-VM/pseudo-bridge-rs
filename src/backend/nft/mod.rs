//! nft backend: programs the offload as an nf_tables `netdev` table via hand-rolled
//! netlink (see wire.rs), and reads the copy path from nfnetlink_log. Zero ebpf.
//!
//! The ruleset mirrors the CLI-validated /tmp/pb-*.nft and ARCHITECTURE.md tables.
//! HOSTMAC/BRMAC are baked into rule literals, so a HOSTMAC change rebuilds the
//! table and re-flashes all elements (the backend keeps a shadow of them).

mod nflog;
mod wire;

use super::{Backend, CopyEvent, InitCfg};
use crate::cli::Mode;
use crate::types::{Family, Mac};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use wire::*;

const TABLE: &str = "pbridge";
const CH_NDOUT: &str = "nd_out";
const CH_OUT: &str = "out";
const CH_IN: &str = "in";
const CH_GUARD: &str = "egress_guard";

// NFTA_SET_ID handles. Rules are created in the same atomic batch as their sets
// (see build_table), where a by-name set reference can't resolve yet — the kernel
// resolves same-batch references by id (wire::lookup / dynset_update send both).
const SID_IP2MAC4: u32 = 1;
const SID_IP2MAC6: u32 = 2;
const SID_VALID4: u32 = 3;
const SID_VALID6: u32 = 4;
const SID_HOST4: u32 = 5;
const SID_HOST6: u32 = 6;
const SID_SEEN4: u32 = 7;
const SID_SEEN6: u32 = 8;

// header offsets
const LL_DST: u32 = 0;
const LL_SRC: u32 = 6;
const V4_SADDR: u32 = 12;
const V4_DADDR: u32 = 16;
const V6_SADDR: u32 = 8;
const V6_DADDR: u32 = 24;
const ARP_OP: u32 = 6;
const ARP_SPA: u32 = 14;
const ARP_THA: u32 = 18;
const ARP_TPA: u32 = 24;
const TH_ICMP_TYPE: u32 = 0;
const TH_NSNA_OPT: u32 = 24; // option-type byte for NS/NA
const TH_NSNA_LLA: u32 = 26;
const TH_RS_OPT: u32 = 8;
const TH_RS_LLA: u32 = 10;
const TH_BOOTP_FLAGS: u32 = 18;
const TH_UDP_CSUM: u32 = 6;
const TH_ICMP_CSUM: u32 = 2; // ICMPv6 checksum, transport-relative
// ICMPv6 checksum as a NETWORK-header-relative offset (fixed 40B IPv6 header + 2;
// host-generated NS never carries extension headers). Used when a payload_set on the
// IPv6 header itself (pseudo-header field) must incrementally fix the ICMPv6 csum.
const V6_ICMP_CSUM_FROM_NET: u32 = 42;

const ETH_IP4: u16 = 0x0800;
const ETH_IP6: u16 = 0x86dd;
const ETH_ARP: u16 = 0x0806;
const L4_UDP: u8 = 17;
const L4_ICMPV6: u8 = 58;

const PKT_BROADCAST: u8 = 1;
const PKT_MULTICAST: u8 = 2;
const NFT_META_PKTTYPE_KEY: u32 = NFT_META_PKTTYPE;

pub struct NftBackend {
    cfg: Option<InitCfg>,
    hostmac: Mac,
    brmac: Option<Mac>,
    host4: HashSet<Ipv4Addr>,
    host6: HashSet<Ipv6Addr>,
    entries: HashMap<IpAddr, Mac>,
    sock: Option<NlSock>,
    reader_stop: Option<Arc<AtomicBool>>,
    /// Whether our table is currently installed (drives the atomic delete+create swap
    /// in rebuild vs a fresh build).
    table_installed: bool,
}

impl NftBackend {
    pub fn new() -> Self {
        NftBackend {
            cfg: None,
            hostmac: Mac::ZERO,
            brmac: None,
            host4: HashSet::new(),
            host6: HashSet::new(),
            entries: HashMap::new(),
            sock: None,
            reader_stop: None,
            table_installed: false,
        }
    }

    fn sock(&mut self) -> Result<&mut NlSock> {
        self.sock.as_mut().ok_or_else(|| anyhow::anyhow!("nft socket not open"))
    }

    fn cfg(&self) -> Result<&InitCfg> {
        self.cfg.as_ref().ok_or_else(|| anyhow::anyhow!("nft not initialized"))
    }

    /// Rebuild the table to the current literals (HOSTMAC/BRMAC/mode) and re-flash all
    /// shadow elements. The ruleset swap is a single atomic batch (delete-old + create-new
    /// commit together), so traffic never sees a missing or partially-installed ruleset —
    /// critical in direct mode, where a gap on the up0 egress hook would leak guest src
    /// macs upstream (case 13).
    fn rebuild(&mut self) -> Result<()> {
        if self.table_installed {
            // Atomic swap. If it fails (e.g. someone deleted our table externally, making
            // the in-batch DELTABLE abort the whole batch), fall back to a fresh build.
            if let Err(e) = self.build_table(true) {
                log::warn!("nft atomic rebuild failed ({e:#}); retrying as fresh build");
                self.table_installed = false;
            }
        }
        if !self.table_installed {
            self.delete_table_best_effort(); // clear any stale table (crashed run)
            self.build_table(false)?;
        }
        self.table_installed = true;
        // Re-flash shadow elements in follow-up transactions. The gap is fail-safe: with
        // the full ruleset in place, empty sets only mean OUT falls through to the else
        // row (which still normalizes src to HOSTMAC) and IN demux misses accept to the
        // host stack — no leak, just a brief demux outage until the elements land.
        let host4: Vec<Ipv4Addr> = self.host4.iter().copied().collect();
        let host6: Vec<Ipv6Addr> = self.host6.iter().copied().collect();
        for ip in host4 {
            self.add_host(IpAddr::V4(ip))?;
        }
        for ip in host6 {
            self.add_host(IpAddr::V6(ip))?;
        }
        let entries: Vec<(IpAddr, Mac)> = self.entries.iter().map(|(k, v)| (*k, *v)).collect();
        for (ip, mac) in entries {
            self.flash_entry(ip, mac)?;
        }
        Ok(())
    }

    fn delete_table_best_effort(&mut self) {
        if let Ok(sock) = self.sock() {
            let _ = sock.transaction(|ts| {
                let seq = ts.seq();
                vec![nft_message(
                    NFT_MSG_DELTABLE,
                    0,
                    seq,
                    NFPROTO_NETDEV,
                    &nla_str(NFTA_TABLE_NAME, TABLE),
                )]
            });
        }
    }

    /// Build the complete table — table + sets + chains + every rule — in ONE batch,
    /// optionally preceded by a delete of the old table (`replace`). nf_tables commits
    /// a batch atomically, so the datapath flips from the old ruleset to the new one
    /// with no window of missing/partial rules. Rule errors are pinpointed by the
    /// reported seq + extack instead of per-rule transactions.
    fn build_table(&mut self, replace: bool) -> Result<()> {
        let cfg = self.cfg()?.clone();
        let hostmac = self.hostmac;
        let brmac = self.brmac;
        let group = cfg.nflog_group;

        // Rules in final order (NLM_F_APPEND within the batch preserves it).
        let mut rules: Vec<(&str, Vec<Vec<u8>>)> = Vec::new();
        for r in nd_out_rules(hostmac, group) {
            rules.push((CH_NDOUT, r));
        }
        match cfg.mode {
            Mode::Fwd | Mode::FwdOffload => {
                let fwd0 = cfg.fwd0_ifindex.unwrap_or(0);
                let up0 = cfg.up0_ifindex;
                for r in out_rules_fwd(hostmac, brmac, group, up0) {
                    rules.push((CH_OUT, r));
                }
                for r in in_rules_fwd(hostmac, fwd0, group) {
                    rules.push((CH_IN, r));
                }
            }
            Mode::Direct => {
                for r in out_rules_direct(hostmac, group) {
                    rules.push((CH_OUT, r));
                }
                for r in in_rules_direct(hostmac, group) {
                    rules.push((CH_IN, r));
                }
            }
        }
        rules.push((CH_GUARD, guard_rule(hostmac)));
        // fwd: clone host-originated ARP-req/NS for unknown targets to fwd0 so silent guests
        // get discovered (after guard_rule so the clone carries the normalized HOSTMAC src).
        if matches!(cfg.mode, Mode::Fwd | Mode::FwdOffload) {
            let fwd0 = cfg.fwd0_ifindex.unwrap_or(0);
            for r in guard_host_demux(fwd0) {
                rules.push((CH_GUARD, r));
            }
            rules.push((CH_GUARD, guard_arp_discover(fwd0)));
            rules.push((CH_GUARD, guard_ns_discover(fwd0)));
        }

        let (out_hook, in_hook) = match cfg.mode {
            Mode::Fwd | Mode::FwdOffload => (NF_NETDEV_INGRESS, NF_NETDEV_INGRESS),
            Mode::Direct => (NF_NETDEV_EGRESS, NF_NETDEV_INGRESS),
        };
        let out_dev = match cfg.mode {
            Mode::Fwd | Mode::FwdOffload => cfg.fwd0.clone().unwrap_or_default(),
            Mode::Direct => cfg.up0.clone(),
        };

        let sock = self.sock.as_mut().ok_or_else(|| anyhow::anyhow!("no sock"))?;
        sock.transaction(|ts| {
            let mut msgs = Vec::new();
            if replace {
                msgs.push(nft_message(NFT_MSG_DELTABLE, 0, ts.seq(), NFPROTO_NETDEV, &nla_str(NFTA_TABLE_NAME, TABLE)));
            }
            msgs.push(nft_message(NFT_MSG_NEWTABLE, NLM_F_CREATE, ts.seq(), NFPROTO_NETDEV, &nla_str(NFTA_TABLE_NAME, TABLE)));
            msgs.push(set_msg(ts.seq(), "ip2mac4", DT_IP4, 4, SetKind::Map(6), SID_IP2MAC4));
            msgs.push(set_msg(ts.seq(), "ip2mac6", DT_IP6, 16, SetKind::Map(6), SID_IP2MAC6));
            msgs.push(set_msg(ts.seq(), "valid4", (DT_IP4 << 6) | DT_ETHER, 12, SetKind::Concat(&[4, 6]), SID_VALID4));
            msgs.push(set_msg(ts.seq(), "valid6", (DT_IP6 << 6) | DT_ETHER, 24, SetKind::Concat(&[16, 6]), SID_VALID6));
            msgs.push(set_msg(ts.seq(), "host4", DT_IP4, 4, SetKind::Plain, SID_HOST4));
            msgs.push(set_msg(ts.seq(), "host6", DT_IP6, 16, SetKind::Plain, SID_HOST6));
            msgs.push(set_msg(ts.seq(), "seen4", DT_IP4, 4, SetKind::Dynamic(cfg.timeout), SID_SEEN4));
            msgs.push(set_msg(ts.seq(), "seen6", DT_IP6, 16, SetKind::Dynamic(cfg.timeout), SID_SEEN6));
            msgs.push(chain_msg(ts.seq(), CH_NDOUT, None));
            msgs.push(chain_msg(ts.seq(), CH_OUT, Some(Hook { hooknum: out_hook, prio: -300, dev: &out_dev })));
            msgs.push(chain_msg(ts.seq(), CH_IN, Some(Hook { hooknum: in_hook, prio: -300, dev: &cfg.up0 })));
            msgs.push(chain_msg(ts.seq(), CH_GUARD, Some(Hook { hooknum: NF_NETDEV_EGRESS, prio: 0, dev: &cfg.up0 })));
            for (chain, exprs) in rules {
                msgs.push(rule_msg(ts.seq(), chain, exprs));
            }
            msgs
        })
    }

    fn add_host(&mut self, ip: IpAddr) -> Result<()> {
        let (set, key) = match ip {
            IpAddr::V4(a) => ("host4", a.octets().to_vec()),
            IpAddr::V6(a) => ("host6", a.octets().to_vec()),
        };
        let s = self.sock()?;
        s.transaction(|ts| vec![setelem_msg(ts.seq(), NFT_MSG_NEWSETELEM, set, &key, None, None)])
    }

    fn del_host(&mut self, ip: IpAddr) -> Result<()> {
        let (set, key) = match ip {
            IpAddr::V4(a) => ("host4", a.octets().to_vec()),
            IpAddr::V6(a) => ("host6", a.octets().to_vec()),
        };
        let s = self.sock()?;
        s.transaction(|ts| vec![setelem_msg(ts.seq(), NFT_MSG_DELSETELEM, set, &key, None, None)])
    }

    /// Add ip2mac + valid + seen elements for (ip, mac).
    fn flash_entry(&mut self, ip: IpAddr, mac: Mac) -> Result<()> {
        let timeout_ms = self.cfg()?.timeout * 1000;
        let s = self.sock()?;
        let m = mac.bytes().to_vec();
        match ip {
            IpAddr::V4(a) => {
                let k = a.octets().to_vec();
                let mut vk = k.clone();
                vk.extend_from_slice(&m);
                vk.extend_from_slice(&[0u8, 0u8]); // pad ether 6->8
                s.transaction(|ts| {
                    vec![
                        setelem_msg(ts.seq(), NFT_MSG_NEWSETELEM, "ip2mac4", &k, Some(&m), None),
                        setelem_msg(ts.seq(), NFT_MSG_NEWSETELEM, "valid4", &vk, None, None),
                        setelem_msg(ts.seq(), NFT_MSG_NEWSETELEM, "seen4", &k, None, Some(timeout_ms)),
                    ]
                })
            }
            IpAddr::V6(a) => {
                let k = a.octets().to_vec();
                let mut vk = k.clone();
                vk.extend_from_slice(&m);
                vk.extend_from_slice(&[0u8, 0u8]);
                s.transaction(|ts| {
                    vec![
                        setelem_msg(ts.seq(), NFT_MSG_NEWSETELEM, "ip2mac6", &k, Some(&m), None),
                        setelem_msg(ts.seq(), NFT_MSG_NEWSETELEM, "valid6", &vk, None, None),
                        setelem_msg(ts.seq(), NFT_MSG_NEWSETELEM, "seen6", &k, None, Some(timeout_ms)),
                    ]
                })
            }
        }
    }

    /// Refresh the `seen` element for ip with a fresh --timeout: control-plane analog
    /// of the datapath's `update @seen`. Netlink has no element-update op, so
    /// delete+add in two best-effort/strict steps: the DEL may hit an already-expired
    /// element (fine), and a datapath update racing between the two just means the
    /// mark is already fresh (the NEW's EEXIST is then harmless).
    fn touch_seen(&mut self, ip: IpAddr) -> Result<()> {
        let timeout_ms = self.cfg()?.timeout * 1000;
        let (seen, k) = match ip {
            IpAddr::V4(a) => ("seen4", a.octets().to_vec()),
            IpAddr::V6(a) => ("seen6", a.octets().to_vec()),
        };
        let s = self.sock()?;
        let _ = s.transaction(|ts| vec![setelem_msg(ts.seq(), NFT_MSG_DELSETELEM, seen, &k, None, None)]);
        let s = self.sock()?;
        s.transaction(|ts| {
            vec![setelem_msg(ts.seq(), NFT_MSG_NEWSETELEM, seen, &k, None, Some(timeout_ms))]
        })
    }

    fn unflash_entry(&mut self, ip: IpAddr, mac: Mac) -> Result<()> {
        let m = mac.bytes().to_vec();
        let (ip2mac, valid, seen, k) = match ip {
            IpAddr::V4(a) => ("ip2mac4", "valid4", "seen4", a.octets().to_vec()),
            IpAddr::V6(a) => ("ip2mac6", "valid6", "seen6", a.octets().to_vec()),
        };
        let mut vk = k.clone();
        vk.extend_from_slice(&m);
        vk.extend_from_slice(&[0u8, 0u8]); // pad ether 6->8
        // ip2mac + valid together (both present for a live entry). seen separately,
        // best-effort: the kernel may have already auto-expired it (timeout), and an
        // ENOENT there must not roll back the demux removals.
        let s = self.sock()?;
        s.transaction(|ts| {
            vec![
                setelem_msg(ts.seq(), NFT_MSG_DELSETELEM, ip2mac, &k, None, None),
                setelem_msg(ts.seq(), NFT_MSG_DELSETELEM, valid, &vk, None, None),
            ]
        })?;
        let s = self.sock()?;
        let _ = s.transaction(|ts| vec![setelem_msg(ts.seq(), NFT_MSG_DELSETELEM, seen, &k, None, None)]);
        Ok(())
    }
}

impl Backend for NftBackend {
    fn name(&self) -> &'static str {
        "nft"
    }

    fn init(
        &mut self,
        cfg: &InitCfg,
        copy_tx: Sender<CopyEvent>,
        apf_tx: Option<Sender<crate::backend::ApfExternalWrite>>,
    ) -> Result<()> {
        // The watchdog needs a BPF kprobe; the CLI rejects nft + watchdog up front, so
        // reaching here means the wiring is wrong rather than the configuration.
        if cfg.apf_watchdog || apf_tx.is_some() {
            anyhow::bail!("nft backend does not support the APF watchdog (needs -e ebpf)");
        }
        self.cfg = Some(cfg.clone());
        self.hostmac = cfg.hostmac;
        self.brmac = cfg.brmac;
        self.host4.clear();
        self.host6.clear();
        for ip in &cfg.host_ips {
            match ip {
                IpAddr::V4(a) => {
                    self.host4.insert(*a);
                }
                IpAddr::V6(a) => {
                    self.host6.insert(*a);
                }
            }
        }
        self.sock = Some(NlSock::open()?);
        self.table_installed = false; // fresh session: rebuild clears any stale table
        self.rebuild()?;
        // start NFLOG reader
        let stop = Arc::new(AtomicBool::new(false));
        nflog::spawn_reader(cfg.nflog_group, stop.clone(), copy_tx)?;
        self.reader_stop = Some(stop);
        Ok(())
    }

    fn teardown(&mut self) -> Result<()> {
        if let Some(stop) = self.reader_stop.take() {
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        self.delete_table_best_effort();
        self.table_installed = false;
        self.sock = None;
        self.cfg = None;
        Ok(())
    }

    fn set_hostmac(&mut self, mac: Mac) -> Result<()> {
        self.hostmac = mac;
        if let Some(c) = self.cfg.as_mut() {
            c.hostmac = mac;
        }
        self.rebuild()
    }

    fn set_brmac(&mut self, mac: Option<Mac>) -> Result<()> {
        self.brmac = mac;
        if let Some(c) = self.cfg.as_mut() {
            c.brmac = mac;
        }
        self.rebuild()
    }

    fn set_host_ips(&mut self, ips: &[IpAddr]) -> Result<()> {
        let mut new4 = HashSet::new();
        let mut new6 = HashSet::new();
        for ip in ips {
            match ip {
                IpAddr::V4(a) => {
                    new4.insert(*a);
                }
                IpAddr::V6(a) => {
                    new6.insert(*a);
                }
            }
        }
        let add4: Vec<Ipv4Addr> = new4.difference(&self.host4).copied().collect();
        let del4: Vec<Ipv4Addr> = self.host4.difference(&new4).copied().collect();
        let add6: Vec<Ipv6Addr> = new6.difference(&self.host6).copied().collect();
        let del6: Vec<Ipv6Addr> = self.host6.difference(&new6).copied().collect();
        for ip in add4 {
            self.host4.insert(ip);
            self.add_host(IpAddr::V4(ip))?;
        }
        for ip in del4 {
            self.host4.remove(&ip);
            self.del_host(IpAddr::V4(ip))?;
        }
        for ip in add6 {
            self.host6.insert(ip);
            self.add_host(IpAddr::V6(ip))?;
        }
        for ip in del6 {
            self.host6.remove(&ip);
            self.del_host(IpAddr::V6(ip))?;
        }
        Ok(())
    }

    fn write_entry(&mut self, ip: IpAddr, mac: Mac) -> Result<()> {
        if let Some(&old) = self.entries.get(&ip) {
            if old != mac {
                self.unflash_entry(ip, old)?;
            } else {
                // refresh seen only (idempotent)
            }
        }
        self.entries.insert(ip, mac);
        self.flash_entry(ip, mac)
    }

    fn withdraw_entry(&mut self, ip: IpAddr) -> Result<()> {
        if let Some(mac) = self.entries.remove(&ip) {
            self.unflash_entry(ip, mac)?;
        }
        Ok(())
    }

    fn refresh_seen(&mut self, ip: IpAddr) -> Result<()> {
        if !self.entries.contains_key(&ip) {
            return Ok(());
        }
        self.touch_seen(ip)
    }

    fn arm_probe(&mut self) -> Result<()> {
        // Remove the current timeout marks. A guest reply updates the dynamic set again;
        // flush() therefore reports only entries that answered this probe round.
        let seen4 = {
            let s = self.sock()?;
            s.dump_set_elems(TABLE, "seen4", NFPROTO_NETDEV)?
        };
        if !seen4.is_empty() {
            let s = self.sock()?;
            s.transaction(|ts| {
                seen4
                    .iter()
                    .map(|k| setelem_msg(ts.seq(), NFT_MSG_DELSETELEM, "seen4", k, None, None))
                    .collect()
            })?;
        }
        let seen6 = {
            let s = self.sock()?;
            s.dump_set_elems(TABLE, "seen6", NFPROTO_NETDEV)?
        };
        if !seen6.is_empty() {
            let s = self.sock()?;
            s.transaction(|ts| {
                seen6
                    .iter()
                    .map(|k| setelem_msg(ts.seq(), NFT_MSG_DELSETELEM, "seen6", k, None, None))
                    .collect()
            })?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<Vec<IpAddr>> {
        let mut alive = Vec::new();
        let s = self.sock()?;
        for k in s.dump_set_elems(TABLE, "seen4", NFPROTO_NETDEV)? {
            if k.len() >= 4 {
                alive.push(IpAddr::V4(Ipv4Addr::new(k[0], k[1], k[2], k[3])));
            }
        }
        let s = self.sock()?;
        for k in s.dump_set_elems(TABLE, "seen6", NFPROTO_NETDEV)? {
            if k.len() >= 16 {
                let mut b = [0u8; 16];
                b.copy_from_slice(&k[..16]);
                alive.push(IpAddr::V6(Ipv6Addr::from(b)));
            }
        }
        Ok(alive)
    }
}

// ===== rule builders =====

fn eth_gate(ethertype: u16) -> Vec<Vec<u8>> {
    vec![meta_load(NFT_META_PROTOCOL, NFT_REG_1), cmp(NFT_REG_1, NFT_CMP_EQ, &ethertype.to_be_bytes())]
}
fn l4_gate(proto: u8) -> Vec<Vec<u8>> {
    vec![meta_load(NFT_META_L4PROTO, NFT_REG_1), cmp(NFT_REG_1, NFT_CMP_EQ, &[proto])]
}
fn set_src_hostmac(hostmac: Mac) -> Vec<Vec<u8>> {
    vec![immediate_data(NFT_REG_1, hostmac.bytes()), payload_set(NFT_PAYLOAD_LL_HEADER, LL_SRC, 6, NFT_REG_1, None)]
}
fn term_fwd(ifindex: u32) -> Vec<Vec<u8>> {
    vec![immediate_data(NFT_REG_1, &ifindex.to_ne_bytes()), fwd(NFT_REG_1)]
}
fn term_dup(ifindex: u32) -> Vec<Vec<u8>> {
    vec![immediate_data(NFT_REG_1, &ifindex.to_ne_bytes()), dup(NFT_REG_1)]
}
fn term_accept() -> Vec<Vec<u8>> {
    vec![verdict(NF_ACCEPT, None)]
}

/// nd_out: NS/NA/RS rewrite LLA + mark seen + log "R" + drop. Shared by both modes.
fn nd_out_rules(hostmac: Mac, group: u16) -> Vec<Vec<Vec<u8>>> {
    let hm = hostmac.bytes().to_vec();
    let mk = |icmp_type: u8, check_src: bool, opt_off: u32, lla_off: u32| -> Vec<Vec<u8>> {
        let mut e = Vec::new();
        e.extend(eth_gate(ETH_IP6));
        e.extend(l4_gate(L4_ICMPV6));
        e.push(payload_load(NFT_PAYLOAD_TRANSPORT_HEADER, TH_ICMP_TYPE, 1, NFT_REG_1));
        e.push(cmp(NFT_REG_1, NFT_CMP_EQ, &[icmp_type]));
        if check_src {
            e.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, V6_SADDR, 16, NFT_REG_1));
            e.push(cmp(NFT_REG_1, NFT_CMP_NEQ, &[0u8; 16]));
        }
        // option-type guard
        let opt_val: u8 = if icmp_type == 136 { 2 } else { 1 };
        e.push(payload_load(NFT_PAYLOAD_TRANSPORT_HEADER, opt_off, 1, NFT_REG_1));
        e.push(cmp(NFT_REG_1, NFT_CMP_EQ, &[opt_val]));
        // lla != HOSTMAC
        e.push(payload_load(NFT_PAYLOAD_TRANSPORT_HEADER, lla_off, 6, NFT_REG_1));
        e.push(cmp(NFT_REG_1, NFT_CMP_NEQ, &hm));
        // set lla = HOSTMAC (no csum -> userspace fixes)
        e.push(immediate_data(NFT_REG_1, &hm));
        e.push(payload_set(NFT_PAYLOAD_TRANSPORT_HEADER, lla_off, 6, NFT_REG_1, None));
        // mark seen (ip6 saddr)
        e.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, V6_SADDR, 16, NFT_REG_1));
        e.push(dynset_update("seen6", SID_SEEN6, NFT_REG_1, None));
        e.push(log(group, "R"));
        e.push(verdict(NF_DROP, None));
        e
    };
    vec![
        mk(135, true, TH_NSNA_OPT, TH_NSNA_LLA),  // NS
        mk(136, false, TH_NSNA_OPT, TH_NSNA_LLA), // NA
        mk(133, true, TH_RS_OPT, TH_RS_LLA),      // RS
    ]
}

fn nd_dispatch() -> Vec<Vec<u8>> {
    let mut e = Vec::new();
    e.extend(eth_gate(ETH_IP6));
    e.extend(l4_gate(L4_ICMPV6));
    e.push(verdict(NFT_JUMP, Some(CH_NDOUT)));
    e
}

fn dhcp_rule(hostmac: Mac, term: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut e = Vec::new();
    e.extend(l4_gate(L4_UDP));
    // sport 68 dport 67 in one 4-byte cmp: [00,44,00,43]
    e.push(payload_load(NFT_PAYLOAD_TRANSPORT_HEADER, 0, 4, NFT_REG_1));
    e.push(cmp(NFT_REG_1, NFT_CMP_EQ, &[0x00, 0x44, 0x00, 0x43]));
    // BOOTP flags |= 0x8000
    e.push(immediate_data(NFT_REG_1, &0x8000u16.to_be_bytes()));
    e.push(payload_set(NFT_PAYLOAD_TRANSPORT_HEADER, TH_BOOTP_FLAGS, 2, NFT_REG_1, None));
    // udp csum = 0 (IPv4 optional). write literal 0, no csum fixup.
    e.push(immediate_data(NFT_REG_1, &[0u8, 0u8]));
    e.push(payload_set(NFT_PAYLOAD_TRANSPORT_HEADER, TH_UDP_CSUM, 2, NFT_REG_1, None));
    e.extend(set_src_hostmac(hostmac));
    e.extend(term);
    e
}

fn valid_rule(fam: Family, hostmac: Mac, term: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut e = Vec::new();
    let (eth, saddr, set, sid, seen, seen_sid) = match fam {
        Family::V4 => (ETH_IP4, V4_SADDR, "valid4", SID_VALID4, "seen4", SID_SEEN4),
        Family::V6 => (ETH_IP6, V6_SADDR, "valid6", SID_VALID6, "seen6", SID_SEEN6),
    };
    let slen = if fam == Family::V4 { 4 } else { 16 };
    e.extend(eth_gate(eth));
    // concat key: ip saddr -> reg1; ether saddr -> next register past field1.
    // v4 (4b) leaves field2 at byte offset 4 = REG32_01 (reg9); v6 (16b) fills
    // NFT_REG_1 so field2 starts at byte 16 = NFT_REG_2 (reg2). Mirrors nft.
    let field2 = if fam == Family::V4 { NFT_REG32_01 } else { NFT_REG_2 };
    e.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, saddr, slen, NFT_REG_1));
    e.push(payload_load(NFT_PAYLOAD_LL_HEADER, LL_SRC, 6, field2));
    e.push(lookup(set, sid, NFT_REG_1, None));
    // mark seen (reload ip saddr)
    e.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, saddr, slen, NFT_REG_1));
    e.push(dynset_update(seen, seen_sid, NFT_REG_1, None));
    e.extend(set_src_hostmac(hostmac));
    e.extend(term);
    e
}

fn arp_out_rule(hostmac: Mac, group: u16, term: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let hm = hostmac.bytes().to_vec();
    let mut e = Vec::new();
    e.extend(eth_gate(ETH_ARP));
    // arp sha = HOSTMAC (network header offset 8)
    e.push(immediate_data(NFT_REG_1, &hm));
    e.push(payload_set(NFT_PAYLOAD_NETWORK_HEADER, 8, 6, NFT_REG_1, None));
    // mark seen (arp spa)
    e.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, ARP_SPA, 4, NFT_REG_1));
    e.push(dynset_update("seen4", SID_SEEN4, NFT_REG_1, None));
    e.push(log(group, "L"));
    e.extend(set_src_hostmac(hostmac));
    e.extend(term);
    e
}

fn else_out_rule(hostmac: Mac, group: u16, term: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut e = vec![log(group, "L")];
    e.extend(set_src_hostmac(hostmac));
    e.extend(term);
    e
}

fn drop_src(mac: Mac) -> Vec<Vec<u8>> {
    vec![
        payload_load(NFT_PAYLOAD_LL_HEADER, LL_SRC, 6, NFT_REG_1),
        cmp(NFT_REG_1, NFT_CMP_EQ, mac.bytes()),
        verdict(NF_DROP, None),
    ]
}

fn out_rules_fwd(hostmac: Mac, brmac: Option<Mac>, group: u16, up0: u32) -> Vec<Vec<Vec<u8>>> {
    // Host-originated packets that the up0 egress demux redirected back to fwd0 carry
    // HOSTMAC as their source. Let only known guest destinations through; all other
    // HOSTMAC traffic is still rejected below so bridge flood copies cannot leak out.
    let mut rules = host_probe_fwd_allow(hostmac);
    rules.extend(host_to_guest_fwd_allow(hostmac));
    rules.push(drop_src(hostmac));
    if let Some(b) = brmac {
        rules.push(drop_src(b));
    }
    rules.push(dhcp_rule(hostmac, term_fwd(up0)));
    rules.push(nd_dispatch());
    rules.push(valid_rule(Family::V4, hostmac, term_fwd(up0)));
    rules.push(valid_rule(Family::V6, hostmac, term_fwd(up0)));
    rules.push(arp_out_rule(hostmac, group, term_fwd(up0)));
    rules.push(else_out_rule(hostmac, group, term_fwd(up0)));
    rules
}

/// Allow the anonymous ARP/NS copies made by the up0 discovery guard. They retain
/// HOSTMAC as their L2 source but are intentionally addressed to the guest bridge;
/// ordinary HOSTMAC flood copies still fall through to `drop_src` below.
fn host_probe_fwd_allow(hostmac: Mac) -> Vec<Vec<Vec<u8>>> {
    let mut rules = Vec::new();
    let mut arp = vec![payload_load(NFT_PAYLOAD_LL_HEADER, LL_SRC, 6, NFT_REG_1)];
    arp.push(cmp(NFT_REG_1, NFT_CMP_EQ, hostmac.bytes()));
    arp.extend(eth_gate(ETH_ARP));
    arp.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, ARP_OP, 2, NFT_REG_1));
    arp.push(cmp(NFT_REG_1, NFT_CMP_EQ, &1u16.to_be_bytes()));
    arp.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, ARP_SPA, 4, NFT_REG_1));
    arp.push(cmp(NFT_REG_1, NFT_CMP_EQ, &[0u8; 4]));
    arp.push(verdict(NF_ACCEPT, None));
    rules.push(arp);

    let mut ns = vec![payload_load(NFT_PAYLOAD_LL_HEADER, LL_SRC, 6, NFT_REG_1)];
    ns.push(cmp(NFT_REG_1, NFT_CMP_EQ, hostmac.bytes()));
    ns.extend(eth_gate(ETH_IP6));
    ns.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, V6_SADDR, 16, NFT_REG_1));
    ns.push(cmp(NFT_REG_1, NFT_CMP_EQ, &[0u8; 16]));
    ns.extend(l4_gate(L4_ICMPV6));
    ns.push(payload_load(NFT_PAYLOAD_TRANSPORT_HEADER, TH_ICMP_TYPE, 1, NFT_REG_1));
    ns.push(cmp(NFT_REG_1, NFT_CMP_EQ, &[135]));
    ns.push(verdict(NF_ACCEPT, None));
    rules.push(ns);
    rules
}

fn host_to_guest_fwd_allow(hostmac: Mac) -> Vec<Vec<Vec<u8>>> {
    let mut rules = Vec::new();
    for (eth, saddr, daddr, len, host, host_sid, map, map_sid) in [
        (ETH_IP4, V4_SADDR, V4_DADDR, 4u32, "host4", SID_HOST4, "ip2mac4", SID_IP2MAC4),
        (ETH_IP6, V6_SADDR, V6_DADDR, 16u32, "host6", SID_HOST6, "ip2mac6", SID_IP2MAC6),
    ] {
        let mut r = vec![payload_load(NFT_PAYLOAD_LL_HEADER, LL_SRC, 6, NFT_REG_1)];
        r.push(cmp(NFT_REG_1, NFT_CMP_EQ, hostmac.bytes()));
        r.extend(eth_gate(eth));
        r.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, saddr, len, NFT_REG_1));
        r.push(lookup(host, host_sid, NFT_REG_1, None));
        r.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, daddr, len, NFT_REG_1));
        r.push(lookup(map, map_sid, NFT_REG_1, Some(NFT_REG_1)));
        r.push(verdict(NF_ACCEPT, None));
        rules.push(r);
    }
    rules
}

fn out_rules_direct(hostmac: Mac, group: u16) -> Vec<Vec<Vec<u8>>> {
    // row1: src==HOSTMAC accept (host / reinject)
    let mut rules = vec![vec![
        payload_load(NFT_PAYLOAD_LL_HEADER, LL_SRC, 6, NFT_REG_1),
        cmp(NFT_REG_1, NFT_CMP_EQ, hostmac.bytes()),
        verdict(NF_ACCEPT, None),
    ]];
    rules.push(dhcp_rule(hostmac, term_accept()));
    rules.push(nd_dispatch());
    rules.push(valid_rule(Family::V4, hostmac, term_accept()));
    rules.push(valid_rule(Family::V6, hostmac, term_accept()));
    rules.push(arp_out_rule(hostmac, group, term_accept()));
    rules.push(else_out_rule(hostmac, group, term_accept()));
    rules
}

fn eth_dst_is(mac: Mac) -> Vec<Vec<u8>> {
    vec![payload_load(NFT_PAYLOAD_LL_HEADER, LL_DST, 6, NFT_REG_1), cmp(NFT_REG_1, NFT_CMP_EQ, mac.bytes())]
}

fn in_host_rules(hostmac: Mac) -> Vec<Vec<Vec<u8>>> {
    let mut rules = Vec::new();
    // ether daddr==HOSTMAC ip daddr @host4 accept
    let mut r = eth_dst_is(hostmac);
    r.extend(eth_gate(ETH_IP4));
    r.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, V4_DADDR, 4, NFT_REG_1));
    r.push(lookup("host4", SID_HOST4, NFT_REG_1, None));
    r.push(verdict(NF_ACCEPT, None));
    rules.push(r);
    // ether daddr==HOSTMAC ip6 daddr @host6 accept
    let mut r = eth_dst_is(hostmac);
    r.extend(eth_gate(ETH_IP6));
    r.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, V6_DADDR, 16, NFT_REG_1));
    r.push(lookup("host6", SID_HOST6, NFT_REG_1, None));
    r.push(verdict(NF_ACCEPT, None));
    rules.push(r);
    // arp tpa @host4 accept
    let mut r = eth_gate(ETH_ARP);
    r.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, ARP_TPA, 4, NFT_REG_1));
    r.push(lookup("host4", SID_HOST4, NFT_REG_1, None));
    r.push(verdict(NF_ACCEPT, None));
    rules.push(r);
    rules
}

fn in_demux_ip(fam: Family, hostmac: Mac, term: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let (eth, daddr, dlen, map, sid) = match fam {
        Family::V4 => (ETH_IP4, V4_DADDR, 4u32, "ip2mac4", SID_IP2MAC4),
        Family::V6 => (ETH_IP6, V6_DADDR, 16u32, "ip2mac6", SID_IP2MAC6),
    };
    let mut r = eth_dst_is(hostmac);
    r.extend(eth_gate(eth));
    r.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, daddr, dlen, NFT_REG_1));
    r.push(lookup(map, sid, NFT_REG_1, Some(NFT_REG_1))); // key reg1 -> mac reg1
    r.push(payload_set(NFT_PAYLOAD_LL_HEADER, LL_DST, 6, NFT_REG_1, None));
    r.extend(term);
    r
}

fn in_demux_arp(hostmac: Mac, term: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut r = eth_dst_is(hostmac);
    r.extend(eth_gate(ETH_ARP));
    r.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, ARP_TPA, 4, NFT_REG_1));
    r.push(lookup("ip2mac4", SID_IP2MAC4, NFT_REG_1, Some(NFT_REG_1)));
    // set arp tha + eth dst
    r.push(payload_set(NFT_PAYLOAD_NETWORK_HEADER, ARP_THA, 6, NFT_REG_1, None));
    r.push(payload_set(NFT_PAYLOAD_LL_HEADER, LL_DST, 6, NFT_REG_1, None));
    r.extend(term);
    r
}

fn in_arp_proxy_request(group: u16) -> Vec<Vec<u8>> {
    // Report only requests whose target has an installed demux entry. The original
    // request keeps flowing (and may still reach the guest); the userspace reply is
    // an additional fast proxy answer, not a new dependency on NFLOG delivery.
    let mut r = eth_gate(ETH_ARP);
    r.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, ARP_OP, 2, NFT_REG_1));
    r.push(cmp(NFT_REG_1, NFT_CMP_EQ, &1u16.to_be_bytes()));
    r.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, ARP_TPA, 4, NFT_REG_1));
    r.push(lookup("ip2mac4", SID_IP2MAC4, NFT_REG_1, None));
    r.push(log(group, "A"));
    r
}

fn in_rules_fwd(hostmac: Mac, fwd0: u32, group: u16) -> Vec<Vec<Vec<u8>>> {
    // Reflected self-frame guard FIRST: a Wi-Fi AP echoes the STA's own transmissions
    // back down (broadcasts at the next DTIM, unicast-to-own-mac via hairpin). Anything
    // arriving with src == HOSTMAC is such a copy; the bcast/mcast dup below would
    // re-inject it into the guest bridge (a reflected keepalive GARP then repoints the
    // host's own neighbour entry for a guest to HOSTMAC → host->guest black-hole), and
    // the demux would hand hairpinned replies back to guests. Drop them outright.
    let mut rules = vec![drop_src(hostmac)];
    rules.extend(in_host_rules(hostmac));
    rules.push(in_arp_proxy_request(group));
    // bcast/mcast dup
    rules.push({
        let mut r = vec![meta_load(NFT_META_PKTTYPE_KEY, NFT_REG_1), cmp(NFT_REG_1, NFT_CMP_EQ, &[PKT_BROADCAST])];
        r.extend(term_dup(fwd0));
        r
    });
    rules.push({
        let mut r = vec![meta_load(NFT_META_PKTTYPE_KEY, NFT_REG_1), cmp(NFT_REG_1, NFT_CMP_EQ, &[PKT_MULTICAST])];
        r.extend(term_dup(fwd0));
        r
    });
    rules.push(in_demux_ip(Family::V4, hostmac, term_fwd(fwd0)));
    rules.push(in_demux_ip(Family::V6, hostmac, term_fwd(fwd0)));
    rules.push(in_demux_arp(hostmac, term_fwd(fwd0)));
    // else: dst==HOSTMAC accept (to host stack)
    rules.push({
        let mut r = eth_dst_is(hostmac);
        r.push(verdict(NF_ACCEPT, None));
        r
    });
    rules
}

fn in_rules_direct(hostmac: Mac, group: u16) -> Vec<Vec<Vec<u8>>> {
    // same reflected self-frame guard as fwd (see in_rules_fwd) — in direct mode the
    // echoed copy would otherwise be flooded by the kernel bridge into the guest ports.
    let mut rules = vec![drop_src(hostmac)];
    rules.extend(in_host_rules(hostmac));
    rules.push(in_arp_proxy_request(group));
    rules.push(in_demux_ip(Family::V4, hostmac, term_accept()));
    rules.push(in_demux_ip(Family::V6, hostmac, term_accept()));
    rules.push(in_demux_arp(hostmac, term_accept()));
    rules
}

/// fwd-only discovery: clone a host-originated broadcast ARP-request whose sender IP isn't
/// a learned guest (i.e. host→unknown) to fwd0, so a silent guest replies and gets learned.
/// The up0 egress demux then handles any host packet queued while learning completed.
/// Clone, not redirect — the original still goes upstream (the gateway is still resolved).
///
/// The CLONE is ACD-ized first (spa=0.0.0.0, restored right after — `dup` snapshots the
/// packet's current state): it is delivered inside the guest bridge, where the host's L2
/// identity is the bridge mac, so a clone carrying "host-ip @ HOSTMAC" would repoint every
/// guest's neighbour entry for the host and their host-bound replies would detour out the
/// uplink. spa=0 gives receivers nothing to cache; the silent guest still defends (RFC
/// 5227) toward sha=HOSTMAC → its reply crosses fwd0 and is learned as before. Broadcast
/// requests only: a unicast NUD probe can't discover a silent guest anyway, and the kernel
/// falls back to broadcast resolution itself.
fn guard_arp_discover(fwd0: u32) -> Vec<Vec<u8>> {
    let mut e = eth_gate(ETH_ARP);
    e.push(payload_load(NFT_PAYLOAD_LL_HEADER, LL_DST, 6, NFT_REG_1));
    e.push(cmp(NFT_REG_1, NFT_CMP_EQ, &[0xffu8; 6])); // broadcast resolution only
    e.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, ARP_OP, 2, NFT_REG_1));
    e.push(cmp(NFT_REG_1, NFT_CMP_EQ, &1u16.to_be_bytes())); // request
    // sender IP into REG_3: it must survive the immediate/dup below (both use REG_1)
    // so the original spa can be restored for the wire copy.
    e.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, ARP_SPA, 4, NFT_REG_3));
    e.push(cmp(NFT_REG_3, NFT_CMP_NEQ, &[0u8; 4])); // not an ACD probe (spa != 0.0.0.0); v4 analog of NS's src != :: DAD guard. Else the guest's own RFC 5227 probe is cloned back over the bridge and read as a conflict -> the guest declines every offer.
    e.push(lookup_inv("ip2mac4", SID_IP2MAC4, NFT_REG_3)); // sender IP not a learned guest
    // ACD-ize → dup → restore (ARP has no checksum)
    e.push(immediate_data(NFT_REG_1, &[0u8; 4]));
    e.push(payload_set(NFT_PAYLOAD_NETWORK_HEADER, ARP_SPA, 4, NFT_REG_1, None));
    e.extend(term_dup(fwd0));
    e.push(payload_set(NFT_PAYLOAD_NETWORK_HEADER, ARP_SPA, 4, NFT_REG_3, None));
    e
}

/// fwd-only discovery: same as `guard_arp_discover` but for a host-originated NS — the
/// clone is DAD-ized (src=::, SLLAO type neutralized to unassigned 200 so receivers skip
/// it; a DAD NS must carry no *recognized* source-lladdr option) and restored after the
/// dup. Both edits are ICMPv6-checksum-covered (the source via the pseudo-header), fixed
/// incrementally by payload_set's inet-csum support. The defending guest answers a DAD NS
/// with an NA to ff02::1 (all-nodes), which floods across fwd0 and is learned as before.
/// Solicited-node multicast only (dst mac 33:33:*): unicast NUD probes are not cloned.
fn guard_ns_discover(fwd0: u32) -> Vec<Vec<u8>> {
    let mut e = eth_gate(ETH_IP6);
    e.extend(l4_gate(L4_ICMPV6));
    e.push(payload_load(NFT_PAYLOAD_LL_HEADER, LL_DST, 2, NFT_REG_1));
    e.push(cmp(NFT_REG_1, NFT_CMP_EQ, &[0x33u8, 0x33])); // v6 multicast mac (solicited-node)
    e.push(payload_load(NFT_PAYLOAD_TRANSPORT_HEADER, TH_ICMP_TYPE, 1, NFT_REG_1));
    e.push(cmp(NFT_REG_1, NFT_CMP_EQ, &[135])); // NS
    e.push(payload_load(NFT_PAYLOAD_TRANSPORT_HEADER, TH_NSNA_OPT, 1, NFT_REG_1));
    e.push(cmp(NFT_REG_1, NFT_CMP_EQ, &[1])); // first option is an SLLAO (host NS always has one)
    // source into REG_3 (survives the immediates/dup; used for match + restore)
    e.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, V6_SADDR, 16, NFT_REG_3));
    e.push(cmp(NFT_REG_3, NFT_CMP_NEQ, &[0u8; 16])); // not DAD (src != ::)
    e.push(lookup_inv("ip2mac6", SID_IP2MAC6, NFT_REG_3)); // source not a learned guest
    // DAD-ize → dup → restore, ICMPv6 csum incrementally fixed at each step
    e.push(immediate_data(NFT_REG_1, &[0u8; 16]));
    e.push(payload_set(NFT_PAYLOAD_NETWORK_HEADER, V6_SADDR, 16, NFT_REG_1, Some((V6_ICMP_CSUM_FROM_NET, 0))));
    e.push(immediate_data(NFT_REG_1, &[200u8]));
    e.push(payload_set(NFT_PAYLOAD_TRANSPORT_HEADER, TH_NSNA_OPT, 1, NFT_REG_1, Some((TH_ICMP_CSUM, 0))));
    e.extend(term_dup(fwd0));
    e.push(payload_set(NFT_PAYLOAD_NETWORK_HEADER, V6_SADDR, 16, NFT_REG_3, Some((V6_ICMP_CSUM_FROM_NET, 0))));
    e.push(immediate_data(NFT_REG_1, &[1u8]));
    e.push(payload_set(NFT_PAYLOAD_TRANSPORT_HEADER, TH_NSNA_OPT, 1, NFT_REG_1, Some((TH_ICMP_CSUM, 0))));
    e
}

fn guard_rule(hostmac: Mac) -> Vec<Vec<u8>> {
    vec![
        payload_load(NFT_PAYLOAD_LL_HEADER, LL_SRC, 6, NFT_REG_1),
        cmp(NFT_REG_1, NFT_CMP_NEQ, hostmac.bytes()),
        immediate_data(NFT_REG_1, hostmac.bytes()),
        payload_set(NFT_PAYLOAD_LL_HEADER, LL_SRC, 6, NFT_REG_1, None),
    ]
}

/// fwd-only host egress demux. A packet generated before the guest was learned may still
/// be queued on the connected up0 route after the control plane has installed the vmroute.
/// Once its neighbour is filled with HOSTMAC, rewrite the destination to the learned guest
/// MAC and send it to fwd0. Matching the source against host4/host6 excludes normal guest
/// traffic (which has already been MAC-NATed but retains its guest source IP).
fn guard_host_demux(fwd0: u32) -> Vec<Vec<Vec<u8>>> {
    let mut rules = Vec::new();
    for (eth, saddr, daddr, len, host, host_sid, map, map_sid) in [
        (ETH_IP4, V4_SADDR, V4_DADDR, 4u32, "host4", SID_HOST4, "ip2mac4", SID_IP2MAC4),
        (ETH_IP6, V6_SADDR, V6_DADDR, 16u32, "host6", SID_HOST6, "ip2mac6", SID_IP2MAC6),
    ] {
        let mut r = eth_gate(eth);
        r.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, saddr, len, NFT_REG_1));
        r.push(lookup(host, host_sid, NFT_REG_1, None));
        r.push(payload_load(NFT_PAYLOAD_NETWORK_HEADER, daddr, len, NFT_REG_1));
        r.push(lookup(map, map_sid, NFT_REG_1, Some(NFT_REG_1)));
        r.push(payload_set(NFT_PAYLOAD_LL_HEADER, LL_DST, 6, NFT_REG_1, None));
        r.extend(term_fwd(fwd0));
        rules.push(r);
    }
    rules
}

// ===== message assembly (pbridge-specific; table = TABLE) =====

struct Hook<'a> {
    hooknum: u32,
    prio: i32,
    dev: &'a str,
}

fn chain_msg(seq: u32, name: &str, hook: Option<Hook>) -> Vec<u8> {
    let mut attrs = cat(&[nla_str(NFTA_CHAIN_TABLE, TABLE), nla_str(NFTA_CHAIN_NAME, name)]);
    if let Some(h) = hook {
        let hook_nested = cat(&[
            nla_be32(NFTA_HOOK_HOOKNUM, h.hooknum),
            nla_be32(NFTA_HOOK_PRIORITY, h.prio as u32),
            nla_str(NFTA_HOOK_DEV, h.dev),
        ]);
        attrs.extend(nla_nested(NFTA_CHAIN_HOOK, &hook_nested));
        attrs.extend(nla_str(NFTA_CHAIN_TYPE, "filter"));
        attrs.extend(nla_be32(NFTA_CHAIN_POLICY, NF_ACCEPT));
    }
    nft_message(NFT_MSG_NEWCHAIN, NLM_F_CREATE, seq, NFPROTO_NETDEV, &attrs)
}

enum SetKind<'a> {
    Plain,
    Map(u32),
    Concat(&'a [u32]),
    Dynamic(u64),
}

// nft datatype cookies (for nft-list display + element validation): ipv4=7, ipv6=8,
// ether=9; concat = (field0<<6)|field1.
const DT_IP4: u32 = 7;
const DT_IP6: u32 = 8;
const DT_ETHER: u32 = 9;

fn set_msg(seq: u32, name: &str, key_type: u32, key_len: u32, kind: SetKind, set_id: u32) -> Vec<u8> {
    let mut attrs = cat(&[
        nla_str(NFTA_SET_TABLE, TABLE),
        nla_str(NFTA_SET_NAME, name),
        nla_be32(NFTA_SET_KEY_TYPE, key_type),
        nla_be32(NFTA_SET_KEY_LEN, key_len),
        nla_be32(NFTA_SET_ID, set_id),
    ]);
    match kind {
        SetKind::Plain => {}
        SetKind::Map(dlen) => {
            attrs.extend(nla_be32(NFTA_SET_FLAGS, NFT_SET_MAP));
            attrs.extend(nla_be32(NFTA_SET_DATA_TYPE, DT_ETHER));
            attrs.extend(nla_be32(NFTA_SET_DATA_LEN, dlen));
        }
        SetKind::Concat(fields) => {
            attrs.extend(nla_be32(NFTA_SET_FLAGS, NFT_SET_CONCAT));
            let mut concat = Vec::new();
            for &fl in fields {
                concat.extend(nla_nested(NFTA_LIST_ELEM, &nla_be32(NFTA_SET_FIELD_LEN, fl)));
            }
            attrs.extend(nla_nested(NFTA_SET_DESC, &nla_nested(NFTA_SET_DESC_CONCAT, &concat)));
        }
        SetKind::Dynamic(timeout_secs) => {
            attrs.extend(nla_be32(NFTA_SET_FLAGS, NFT_SET_EVAL | NFT_SET_TIMEOUT));
            attrs.extend(nla_be64(NFTA_SET_TIMEOUT, timeout_secs * 1000));
            attrs.extend(nla_nested(NFTA_SET_DESC, &nla_be32(NFTA_SET_DESC_SIZE, 65535)));
        }
    }
    nft_message(NFT_MSG_NEWSET, NLM_F_CREATE, seq, NFPROTO_NETDEV, &attrs)
}

fn rule_msg(seq: u32, chain: &str, exprs: Vec<Vec<u8>>) -> Vec<u8> {
    let blob = cat(&exprs);
    let attrs = cat(&[
        nla_str(NFTA_RULE_TABLE, TABLE),
        nla_str(NFTA_RULE_CHAIN, chain),
        nla_nested(NFTA_RULE_EXPRESSIONS, &blob),
    ]);
    nft_message(NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND, seq, NFPROTO_NETDEV, &attrs)
}

fn setelem_msg(
    seq: u32,
    msg: u16,
    set: &str,
    key: &[u8],
    data: Option<&[u8]>,
    timeout_ms: Option<u64>,
) -> Vec<u8> {
    let mut elem = nla_nested(NFTA_SET_ELEM_KEY, &nla(NFTA_DATA_VALUE, key));
    if let Some(d) = data {
        elem.extend(nla_nested(NFTA_SET_ELEM_DATA, &nla(NFTA_DATA_VALUE, d)));
    }
    if let Some(t) = timeout_ms {
        elem.extend(nla_be64(NFTA_SET_ELEM_TIMEOUT, t));
    }
    let list = nla_nested(NFTA_SET_ELEM_LIST_ELEMENTS, &nla_nested(NFTA_LIST_ELEM, &elem));
    let attrs = cat(&[
        nla_str(NFTA_SET_ELEM_LIST_TABLE, TABLE),
        nla_str(NFTA_SET_ELEM_LIST_SET, set),
        list,
    ]);
    let flags = if msg == NFT_MSG_NEWSETELEM { NLM_F_CREATE } else { 0 };
    nft_message(msg, flags, seq, NFPROTO_NETDEV, &attrs)
}
