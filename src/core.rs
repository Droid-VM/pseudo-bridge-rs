//! The core actor: owns `entries` (the single source of truth) and the derived
//! kernel-side snapshot, and is the only writer of kernel offload + routes.
//! Drives three event classes (ARCHITECTURE.md §syncer): copy packets (learn),
//! netlink link/addr changes (recompute+diff), and the aging timer.
#![forbid(unsafe_code)] // core algorithm: memory-safety is compiler-guaranteed here

use crate::afpacket::{build_arp_request, build_ns, Injector};
use crate::backend::{Backend, CopyEvent, InitCfg, COPY_QUEUE_DEPTH};
use crate::cli::{Cli, Engine, Mode};
use crate::netlink::{AddrInfo, Net};
use crate::packet::{build_frame, classify_learn, fix_icmpv6_csum, ETHERTYPE_IPV6};
use crate::state::Entries;
use crate::types::{family, is_learnable_unicast, is_link_local, Family, Mac};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc::{channel, Sender};

/// Derived kernel-side state (ARCHITECTURE.md §syncer recompute()).
#[derive(Clone, Debug, Default)]
struct Snap {
    up0_present: bool,
    up0_index: u32,
    br_index: Option<u32>,
    fwd0_index: Option<u32>,
    hostmac: Option<Mac>,
    brmac: Option<Mac>,
    host_ips: Vec<AddrInfo>,
    up0_addrs: Vec<AddrInfo>, // fwd mirror want
    br_addrs: Vec<AddrInfo>,  // fwd mirror have
    gw6: Vec<IpAddr>,         // default-route gateways (offload-workaround guard)
}

impl Snap {
    fn host_ip_set(&self) -> HashSet<IpAddr> {
        self.host_ips.iter().map(|a| a.ip).collect()
    }
}

/// A bridge's original state, saved on attach so we can restore it on detach:
/// its IPv6 knobs and its own (non-mirror) global addresses that we cleared.
struct SavedBrCfg {
    index: u32,
    addr_gen_mode: String,
    accept_ra: String,
    addrs: Vec<(IpAddr, u8)>,
}

pub struct Core {
    cli: Cli,
    net: Net,
    backend: Box<dyn Backend>,
    entries: Entries,
    snap: Snap,
    initialized: bool,
    injector: Option<Injector>,
    copy_tx: Sender<CopyEvent>,
    host_routes: HashSet<IpAddr>, // fwd: ips with a /32-/128 host route programmed
    mirrored_br: Option<u32>,     // fwd: bridge index we last mirrored up0's IPs onto
    saved_br_cfg: Option<SavedBrCfg>, // fwd: bridge IPv6 knobs to restore on detach
    nd_proxied: HashSet<IpAddr>,  // offload-workaround: guest addrs we installed on up0
    installed: HashMap<IpAddr, Mac>, // vmroutes currently programmed (for transition logging)
    fwd0_injector: Option<Injector>, // fwd: AF_PACKET on fwd0, for the offload keepalive probe
    aging_tick: u64,                 // counts aging ticks (probe/flush alternation in offload)
}

pub async fn run(cli: Cli) -> Result<()> {
    let net = Net::connect()?;
    let mut nl_rx = Net::monitor()?;
    // Bounded + lossy (see COPY_QUEUE_DEPTH): a learn flood degrades to dropped copies
    // (the next packet re-learns) instead of unbounded queue growth.
    let (copy_tx, mut copy_rx) = channel(COPY_QUEUE_DEPTH);

    let backend: Box<dyn Backend> = match cli.engine {
        Engine::Nft => Box::new(crate::backend::nft::NftBackend::new()),
        Engine::Ebpf => Box::new(crate::backend::ebpf::EbpfBackend::new()),
    };

    let timeout = cli.timeout;
    let entries = Entries::new(cli.max_cap);
    let mut core = Core {
        cli,
        net,
        backend,
        entries,
        snap: Snap::default(),
        initialized: false,
        injector: None,
        copy_tx,
        host_routes: HashSet::new(),
        mirrored_br: None,
        saved_br_cfg: None,
        nd_proxied: HashSet::new(),
        installed: HashMap::new(),
        fwd0_injector: None,
        aging_tick: 0,
    };
    if core.cli.offload_workaround.is_some() && !core.is_fwd() {
        log::warn!("--offload-workaround is set but mode is direct; ignoring (fwd-mode only)");
    }

    // Attempt initial session (up0 may already be present).
    if let Err(e) = core.on_netlink_change().await {
        log::warn!("initial sync error: {e:#}");
    }

    // Offload mode runs the aging timer at timeout/2 and alternates probe/flush (a probe
    // keeps silent-but-present proxied guests alive); otherwise it flushes once per timeout.
    let aging_secs = if core.offload_active() { (timeout / 2).max(1) } else { timeout.max(1) };
    let mut aging = tokio::time::interval(Duration::from_secs(aging_secs));
    // If the loop stalls past a period (e.g. a slow nft rebuild), don't fire make-up
    // ticks back-to-back: bursty flushes would halve the effective idle timeout.
    aging.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    aging.tick().await; // consume the immediate first tick

    // Both signal streams are created once, outside the loop: a stream buffers signals
    // that arrive while another select branch is being handled. (Calling ctrl_c() per
    // iteration would recreate the listener each time and could miss a SIGINT.)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    loop {
        tokio::select! {
            Some(ev) = copy_rx.recv() => {
                if let Err(e) = core.on_copy(ev).await { log::warn!("copy: {e:#}"); }
            }
            ch = nl_rx.recv() => {
                match ch {
                    Some(_) => {
                        // coalesce a burst of netlink events into one recompute
                        while nl_rx.try_recv().is_ok() {}
                        if let Err(e) = core.on_netlink_change().await { log::warn!("netlink: {e:#}"); }
                    }
                    None => {
                        // The multicast monitor died (e.g. socket overrun → ENOBUFS while
                        // the loop was busy). Without it we'd silently stop tracking
                        // HOSTMAC / addr / bridge changes, so rebuild it and resync; if
                        // that fails, exit and let the supervisor restart us clean.
                        log::error!("netlink monitor died; rebuilding");
                        match Net::monitor() {
                            Ok(rx) => {
                                nl_rx = rx;
                                if let Err(e) = core.on_netlink_change().await {
                                    log::warn!("netlink resync: {e:#}");
                                }
                            }
                            Err(e) => {
                                log::error!("netlink monitor rebuild failed: {e:#}; exiting");
                                break;
                            }
                        }
                    }
                }
            }
            _ = aging.tick() => {
                if let Err(e) = core.on_tick().await { log::warn!("aging: {e:#}"); }
            }
            _ = sigterm.recv() => { log::info!("SIGTERM"); break; }
            _ = sigint.recv() => { log::info!("SIGINT"); break; }
        }
    }

    log::info!("shutting down: teardown");
    let _ = core.teardown_session().await;
    Ok(())
}

impl Core {
    fn is_fwd(&self) -> bool {
        matches!(self.cli.mode, Mode::Fwd | Mode::FwdOffload)
    }

    /// Effective offload-workaround families (None = off). Active only in fwd-type modes;
    /// an explicit `--offload-workaround` wins, otherwise `fwd-with-offload` defaults to
    /// v4+v6 (the families that actually need it; v6ll is on-link only).
    fn offload_cfg(&self) -> Option<crate::cli::OffloadFamilies> {
        if !self.is_fwd() {
            return None;
        }
        self.cli.offload_workaround.or(match self.cli.mode {
            Mode::FwdOffload => {
                Some(crate::cli::OffloadFamilies { v4: true, v6: true, v6ll: false })
            }
            _ => None,
        })
    }

    /// Whether the offload workaround is active (drives the keepalive probe + faster aging).
    fn offload_active(&self) -> bool {
        self.offload_cfg().is_some()
    }

    async fn recompute(&self) -> Result<Snap> {
        let up0 = self.net.get_link_by_name(&self.cli.interface).await?;
        let Some(up0) = up0 else {
            return Ok(Snap::default()); // up0_present = false
        };

        // master (br) depends on mode.
        let master_index = if self.is_fwd() {
            match self.net.get_link_by_name(&self.cli.fwd1()).await? {
                Some(f) => f.master,
                None => None,
            }
        } else {
            up0.master
        };
        let br = match master_index {
            Some(idx) => self.net.get_link_by_index(idx).await?,
            None => None,
        };
        let br_present = br.is_some();
        let br_mac = br.as_ref().and_then(|b| b.mac);

        let hostmac = if !self.is_fwd() && br_present {
            br_mac.or(up0.mac)
        } else {
            up0.mac
        };
        let brmac = if self.is_fwd() && br_present { br_mac } else { None };

        let up0_addrs_all = self.net.get_addrs(up0.index).await?;
        // Offload-workaround proxy addresses we put on up0 carry the magic IFA_RT_PRIORITY
        // tag; they are guest addresses, NOT the host's, so they must be excluded from every
        // "host address" view (host-ip accept/skip, src selection, and the bridge mirror).
        let enabled = self.offload_cfg().is_some();
        let magic = self.cli.offload_workaround_magic;
        let is_proxy = |a: &AddrInfo| enabled && a.rt_priority == magic;
        // Mirror set = global + link-local. The host needs to be reachable at up0's
        // link-local on the bridge segment too (v6 ND), so fe80 is mirrored as well.
        // (No route is ever written for a mirrored address — routes are per learned
        // guest entry and skip link-local; see write_host_route.)
        let up0_mirror: Vec<AddrInfo> = up0_addrs_all
            .iter()
            .filter(|a| (a.global || is_link_local(&a.ip)) && !is_proxy(a))
            .cloned()
            .collect();
        let br_addrs = match br.as_ref() {
            Some(b) => self.net.get_addrs(b.index).await?,
            None => vec![],
        };

        // host_ips (accept / skip / src-selector) = global + link-local. The link-local
        // addresses MUST be in here: they feed the kernel host4/host6 accept sets and the
        // reconcile host-wins skip — without them a guest could claim the host's own fe80
        // (learnable!) and have unicast-to-host-LL traffic (router NUD probes, unicast RA)
        // demuxed away from the host. select_src is unaffected (an fe80/64 never contains
        // a routable vm-ip, and LL guest entries never get a host route anyway).
        let host_ips = if self.is_fwd() {
            up0_mirror.clone()
        } else if br_present {
            br_addrs
                .iter()
                .filter(|a| a.global || is_link_local(&a.ip))
                .cloned()
                .collect()
        } else {
            vec![]
        };

        let fwd0_index = if self.is_fwd() {
            self.net.get_link_by_name(&self.cli.fwd0()).await?.map(|l| l.index)
        } else {
            None
        };

        // Default gateways — only needed (and only queried) when the offload workaround
        // is active, to keep us from ever proxy-claiming the upstream router's address.
        let gw6 = if enabled { self.net.default_gw6().await } else { vec![] };

        Ok(Snap {
            up0_present: true,
            up0_index: up0.index,
            br_index: br.as_ref().map(|b| b.index),
            fwd0_index,
            hostmac,
            brmac,
            host_ips,
            up0_addrs: up0_mirror,
            br_addrs,
            gw6,
        })
    }

    /// netlink → recompute + diff (level-triggered).
    async fn on_netlink_change(&mut self) -> Result<()> {
        let new = self.recompute().await?;
        let old = std::mem::replace(&mut self.snap, new.clone());

        match (old.up0_present, new.up0_present) {
            (true, false) => {
                log::info!("up0 gone → teardown");
                self.teardown_session().await?;
                return Ok(());
            }
            (false, true) | (false, false) if new.up0_present && !self.initialized => {
                log::info!("up0 present → init session");
                self.init_session().await?;
                return Ok(());
            }
            (false, false) => return Ok(()),
            _ => {}
        }

        if !self.initialized {
            if new.up0_present {
                self.init_session().await?;
            }
            return Ok(());
        }

        // session active: apply field diffs
        let hostmac_changed = old.hostmac != new.hostmac;
        let brmac_changed = old.brmac != new.brmac;
        let hostips_changed = old.host_ip_set() != new.host_ip_set();
        let br_changed = old.br_index != new.br_index || old.fwd0_index != new.fwd0_index;

        if br_changed && old.br_index != new.br_index {
            let what = match (old.br_index, new.br_index) {
                (None, Some(b)) => format!("attached (idx {b})"),
                (Some(a), None) => format!("detached (was idx {a})"),
                (Some(a), Some(b)) => format!("changed (idx {a} -> {b})"),
                (None, None) => unreachable!(),
            };
            log::info!("host-side: bridge {what}");
        }

        if hostmac_changed {
            if let Some(m) = new.hostmac {
                log::info!("host-side: HOSTMAC -> {m}");
                self.backend.set_hostmac(m)?;
                self.broadcast_hostmac(m);
            }
        }
        if brmac_changed {
            let s = new.brmac.map(|m| m.to_string()).unwrap_or_else(|| "none".into());
            log::info!("host-side: BRMAC -> {s}");
            self.backend.set_brmac(new.brmac)?;
        }
        if hostips_changed {
            let ips: Vec<IpAddr> = new.host_ips.iter().map(|a| a.ip).collect();
            log::info!("host-side: host IPs -> {ips:?}");
            self.backend.set_host_ips(&ips)?;
        }
        // fwd: we pin only up0; the bridge is whatever the user enslaves fwd1 into, and
        // they may attach / change / detach it at any time (br = fwd1.master, tracked via
        // netlink). On a bridge change/detach, drop the host routes that pointed at the
        // old bridge; reconcile_all below re-adds them via the new one (if any). The
        // mirror (reconcile_mirror) self-cleans the previous bridge — see mirrored_br.
        if self.is_fwd() && br_changed {
            self.withdraw_all_host_routes().await;
        }
        if self.is_fwd() && (hostips_changed || br_changed) {
            if self.snap.br_index.is_some() {
                self.ensure_vmroute_rules().await?;
            }
            self.reconcile_mirror().await?;
        }
        if hostmac_changed || hostips_changed || br_changed {
            self.reconcile_all().await?;
        }
        Ok(())
    }

    async fn init_session(&mut self) -> Result<()> {
        let snap = self.recompute().await?;
        if !snap.up0_present {
            return Ok(());
        }
        let Some(hostmac) = snap.hostmac else {
            log::warn!("up0 has no mac yet; deferring init");
            return Ok(());
        };

        // fwd mode: create the veth pair fwd0╌fwd1 and bring both ends up. We never
        // touch a bridge — the only interface we pin is up0. The operator (or whatever
        // brought up the VM bridge) enslaves fwd1 into it whenever; we track fwd1.master
        // dynamically via netlink (attach / change / detach all handled).
        let mut fwd0_index = None;
        if self.is_fwd() {
            let fwd0 = self.cli.fwd0();
            let fwd1 = self.cli.fwd1();
            self.net.create_veth(&fwd0, &fwd1).await?;
            // fwd0/fwd1 are pure L2 transport — they must not own addresses or run ND.
            // Disable auto link-local generation + RA acceptance *before* bringing them
            // up so no fe80 is ever created; they just pass frames.
            if let Some(f0) = self.net.get_link_by_name(&fwd0).await? {
                self.disable_dev_autoconf(&fwd0, f0.index).await;
            }
            if let Some(f1) = self.net.get_link_by_name(&fwd1).await? {
                self.disable_dev_autoconf(&fwd1, f1.index).await;
            }
            if let Some(f0) = self.net.get_link_by_name(&fwd0).await? {
                self.net.link_set_up(f0.index).await?;
            }
            if let Some(f1) = self.net.get_link_by_name(&fwd1).await? {
                self.net.link_set_up(f1.index).await?;
            }
            fwd0_index = self.net.get_link_by_name(&fwd0).await?.map(|l| l.index);
            if fwd0_index.is_none() {
                anyhow::bail!("fwd mode: could not create/resolve fwd0 {}", fwd0);
            }
        }

        // recompute again to pick up fwd0's index / any master already present.
        let snap = self.recompute().await?;
        let hostmac = snap.hostmac.unwrap_or(hostmac);

        let cfg = InitCfg {
            mode: self.cli.mode,
            up0: self.cli.interface.clone(),
            up0_ifindex: snap.up0_index,
            fwd0: if self.is_fwd() { Some(self.cli.fwd0()) } else { None },
            fwd0_ifindex: fwd0_index,
            nflog_group: self.cli.nflog_group,
            timeout: self.cli.timeout,
            hostmac,
            brmac: snap.brmac,
            host_ips: snap.host_ips.iter().map(|a| a.ip).collect(),
        };

        self.injector = Some(Injector::new(snap.up0_index)?);
        // fwd + offload: an injector on fwd0 for the keepalive probe (toward the vmbr).
        self.fwd0_injector = match fwd0_index {
            Some(idx) if self.offload_active() => Some(Injector::new(idx)?),
            _ => None,
        };
        self.backend.init(&cfg, self.copy_tx.clone())?;
        self.initialized = true;
        self.snap = snap;

        // fwd: add ip rules (idempotent) + mirror up0 IPs to br.
        if self.is_fwd() {
            self.ensure_vmroute_rules().await?;
            self.reconcile_mirror().await?;
        }

        self.reconcile_all().await?;
        log::info!("{} backend running", self.backend.name());
        Ok(())
    }

    async fn teardown_session(&mut self) -> Result<()> {
        if !self.initialized {
            return Ok(());
        }
        log::info!("teardown session ({} vmroutes dropped)", self.installed.len());
        // withdraw host routes + unmirror the bridge we put up0's IPs on
        self.withdraw_all_host_routes().await;
        self.remove_vmroute_rules().await;
        self.unproxy_all().await;
        self.installed.clear(); // kernel state wiped; re-init logs fresh vmroute adds
        if let Some(br) = self.mirrored_br.take() {
            self.clean_mirror_from(br).await;
            self.restore_bridge_cfg(br).await;
        }
        let _ = self.backend.teardown();
        // fwd: remove veth (deletes the pair)
        if self.is_fwd() {
            let _ = self.net.link_del_by_name(&self.cli.fwd0()).await;
        }
        self.injector = None;
        self.fwd0_injector = None;
        self.initialized = false;
        Ok(())
    }

    fn broadcast_hostmac(&self, hostmac: Mac) {
        let Some(inj) = &self.injector else { return };
        for (ip, _e) in self.entries.iter() {
            match ip {
                IpAddr::V4(a) => {
                    let _ = inj.send_garp(*a, hostmac);
                }
                IpAddr::V6(a) => {
                    let _ = inj.send_unsol_na(*a, hostmac);
                }
            }
        }
    }

    // ---- copy path / learn ----

    async fn on_copy(&mut self, ev: CopyEvent) -> Result<()> {
        match ev {
            CopyEvent::Learn { ip, mac } => self.do_learn(ip, mac).await,
            CopyEvent::Nflog { hwaddr, dst_mac, ethertype, mut l3, reinject } => {
                // Learn FIRST: with the entry already flashed into ip2mac, the reinjected
                // ND hits the up0-egress discovery-dup rule as a *known* source and isn't
                // echoed back into the vm bridge (the dedup there is an ip2mac lookup).
                let learned = match classify_learn(ethertype, &l3) {
                    Some((_kind, ip)) => self.do_learn(ip, hwaddr).await,
                    None => Ok(()),
                };
                if reinject {
                    if ethertype == ETHERTYPE_IPV6 {
                        fix_icmpv6_csum(&mut l3);
                    }
                    if let (Some(inj), Some(hm)) = (&self.injector, self.snap.hostmac) {
                        let frame = build_frame(dst_mac, hm, ethertype, &l3);
                        let _ = inj.send_frame(&frame);
                    }
                }
                learned
            }
        }
    }

    async fn do_learn(&mut self, ip: IpAddr, mac: Mac) -> Result<()> {
        if !is_learnable_unicast(&ip) {
            return Ok(());
        }
        let res = self.entries.learn(ip, mac);
        for ip in res.changed {
            self.reconcile(ip).await?;
        }
        Ok(())
    }

    // ---- reconcile ----

    async fn reconcile(&mut self, ip: IpAddr) -> Result<()> {
        let e = self.entries.get(&ip).copied();
        let host_ips = self.snap.host_ip_set();
        let skip = match e {
            None => true,
            Some(e) => host_ips.contains(&ip) || Some(e.mac) == self.snap.hostmac,
        };
        if skip {
            self.backend.withdraw_entry(ip)?;
            self.withdraw_host_route(ip).await;
            self.unproxy_addr(ip).await;
            if self.installed.remove(&ip).is_some() {
                let reason = if e.is_none() { "expired/evicted" } else { "host-owned" };
                log::info!("vmroute del {ip} ({reason})");
            }
        } else {
            let mac = e.unwrap().mac;
            self.backend.write_entry(ip, mac)?;
            self.write_host_route(ip).await?;
            self.proxy_addr(ip).await;
            match self.installed.insert(ip, mac) {
                None => log::info!("vmroute add {ip} -> {mac}{}", self.vmroute_detail(ip)),
                Some(old) if old != mac => log::info!("vmroute update {ip} {old} -> {mac}"),
                Some(_) => {} // idempotent re-reconcile, nothing changed
            }
        }
        Ok(())
    }

    /// A short suffix for the vmroute-add log describing what kernel state backs it
    /// (the fwd host route and/or the offload-workaround proxy address), for visibility.
    fn vmroute_detail(&self, ip: IpAddr) -> String {
        let mut parts = Vec::new();
        if self.host_routes.contains(&ip) {
            let plen = if family(&ip) == Family::V4 { 32 } else { 128 };
            let table = self.cli.vmroute_table.0.unwrap_or(0);
            parts.push(format!("route /{plen}@table{table}"));
        }
        if self.nd_proxied.contains(&ip) {
            parts.push(format!("proxy@up0(metric {})", self.cli.offload_workaround_magic));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!(" [{}]", parts.join(", "))
        }
    }

    // ---- offload workaround: install learned guest addrs on up0 (fwd, APF) ----

    /// Whether `ip`'s family is selected by the effective offload config (see `offload_cfg`).
    fn offload_family_selected(&self, ip: IpAddr) -> bool {
        let Some(f) = self.offload_cfg() else {
            return false;
        };
        match ip {
            IpAddr::V4(_) => f.v4,
            IpAddr::V6(_) if is_link_local(&ip) => f.v6ll,
            IpAddr::V6(_) => f.v6,
        }
    }

    /// Guard: only proxy an address that sits in one of the host's own on-link prefixes
    /// (so we never claim something off-segment), and never the default gateway. v6
    /// link-local is on-link by definition, so it skips the prefix test.
    fn offload_eligible(&self, ip: IpAddr) -> bool {
        if self.snap.gw6.contains(&ip) {
            return false;
        }
        if is_link_local(&ip) {
            return true;
        }
        self.snap.host_ips.iter().any(|h| subnet_contains(h.ip, h.plen, ip))
    }

    async fn proxy_addr(&mut self, ip: IpAddr) {
        if !self.offload_family_selected(ip) || !self.offload_eligible(ip) {
            return;
        }
        let up0 = self.snap.up0_index;
        if up0 == 0 {
            return;
        }
        let plen = if family(&ip) == Family::V4 { 32 } else { 128 };
        if !self.nd_proxied.contains(&ip) {
            let magic = self.cli.offload_workaround_magic;
            let (nodad, deprecated) =
                if family(&ip) == Family::V4 { (false, false) } else { (true, true) };
            if let Err(e) =
                self.net.addr_add_tagged(up0, ip, plen, true, nodad, Some(magic), deprecated).await
            {
                log::warn!("offload-proxy add {ip}: {e:#}");
                return;
            }
            self.nd_proxied.insert(ip);
            log::debug!("offload-proxy + {ip} on up0 (metric {magic})");
        }
        // Drop the kernel's auto `local <ip>` route so host-originated traffic to the guest
        // forwards via the vmroute (the address stays assigned, so the upstream offload still
        // answers ND/ARP; external traffic is stolen by the ingress demux before routing).
        // v6's local route is inserted slightly after the addr-add returns, so this runs on
        // every reconcile pass for a proxied addr (idempotent) — the NEWADDR event triggers a
        // follow-up reconcile by which point the route exists.
        let _ = self.net.del_local_route(ip, plen).await;
    }

    async fn unproxy_addr(&mut self, ip: IpAddr) {
        if !self.nd_proxied.remove(&ip) {
            return;
        }
        // Deleting our /32 or /128 never touches a host's same-IP /prefix (the kernel
        // matches prefix length on delete), so this is safe even on a host-wins conflict.
        let plen = if family(&ip) == Family::V4 { 32 } else { 128 };
        let _ = self.net.addr_del(self.snap.up0_index, ip, plen).await;
        log::debug!("offload-proxy - {ip}");
    }

    async fn unproxy_all(&mut self) {
        for ip in std::mem::take(&mut self.nd_proxied) {
            let plen = if family(&ip) == Family::V4 { 32 } else { 128 };
            let _ = self.net.addr_del(self.snap.up0_index, ip, plen).await;
        }
    }

    async fn reconcile_all(&mut self) -> Result<()> {
        for ip in self.entries.ips() {
            self.reconcile(ip).await?;
        }
        Ok(())
    }

    async fn on_tick(&mut self) -> Result<()> {
        if !self.initialized {
            // A failed init (e.g. transient nft error) is otherwise only retried on the
            // next netlink event — which may never come if the topology is stable. Use
            // the tick as a retry heartbeat; on_netlink_change inits if up0 is present.
            return self.on_netlink_change().await;
        }
        self.aging_tick = self.aging_tick.wrapping_add(1);
        // Offload keepalive: the timer runs at timeout/2 and alternates probe/flush. On a
        // probe tick we solicit every proxied guest (ARP/NS via fwd0); a still-present guest
        // replies → seen refreshed (in OUT) → it survives the flush half a period later, so a
        // silent-but-present VM keeps its proxy and stays reachable. A released VM never
        // replies → seen expires → evicted on the flush (~timeout after it goes away).
        if self.offload_active() && self.aging_tick % 2 == 1 {
            self.probe();
            return Ok(());
        }
        let alive: HashSet<IpAddr> = self.backend.flush()?.into_iter().collect();
        let dead: Vec<IpAddr> =
            self.entries.ips().into_iter().filter(|ip| !alive.contains(ip)).collect();
        for ip in dead {
            self.entries.remove(&ip);
            self.reconcile(ip).await?; // entry gone → withdraw
        }
        Ok(())
    }

    /// Solicit every proxied guest on fwd0 (toward the vmbr): ARP-request for v4, NS for v6.
    /// A present guest's reply enters fwd0-ingress (OUT path) and refreshes its `seen` (and,
    /// MAC-NAT'd upstream, the gateway's neighbour cache too). Sender = a host IP of the same
    /// family so the guest answers on-link.
    fn probe(&self) {
        let Some(inj) = &self.fwd0_injector else { return };
        let Some(hostmac) = self.snap.hostmac else { return };
        let host_v4 = self.snap.host_ips.iter().find_map(|a| match a.ip {
            IpAddr::V4(v) if !is_link_local(&a.ip) => Some(v),
            _ => None,
        });
        let host_v6 = self.snap.host_ips.iter().find_map(|a| match a.ip {
            IpAddr::V6(v) if a.global => Some(v),
            _ => None,
        });
        for ip in &self.nd_proxied {
            match ip {
                IpAddr::V4(g) => {
                    if let Some(s) = host_v4 {
                        let _ = inj.send_frame(&build_arp_request(*g, s, hostmac));
                    }
                }
                IpAddr::V6(g) => {
                    if let Some(s) = host_v6 {
                        let _ = inj.send_frame(&build_ns(*g, s, hostmac));
                    }
                }
            }
        }
    }

    // ---- fwd host routes ----

    async fn write_host_route(&mut self, ip: IpAddr) -> Result<()> {
        if !self.is_fwd() {
            return Ok(());
        }
        // vmroute table disabled (-1) → don't write any host route.
        let Some(table) = self.cli.vmroute_table.0 else { return Ok(()) };
        let Some(br_index) = self.snap.br_index else { return Ok(()) };
        // link-local: ip2mac only (for ND demux), no /32-/128 route (scope link, not
        // routable). Applies to both the v6 fe80 and v4 169.254 cases.
        if is_link_local(&ip) {
            return Ok(());
        }
        let plen = if family(&ip) == Family::V4 { 32 } else { 128 };
        let src = select_src(ip, &self.snap.host_ips);
        self.net.route_add(ip, plen, br_index, src, table).await?;
        self.host_routes.insert(ip);
        Ok(())
    }

    async fn withdraw_host_route(&mut self, ip: IpAddr) {
        if self.host_routes.remove(&ip) {
            if let Some(table) = self.cli.vmroute_table.0 {
                let plen = if family(&ip) == Family::V4 { 32 } else { 128 };
                let _ = self.net.route_del(ip, plen, table).await;
            }
        }
    }

    async fn withdraw_all_host_routes(&mut self) {
        let Some(table) = self.cli.vmroute_table.0 else {
            self.host_routes.clear();
            return;
        };
        for ip in std::mem::take(&mut self.host_routes) {
            let plen = if family(&ip) == Family::V4 { 32 } else { 128 };
            let _ = self.net.route_del(ip, plen, table).await;
        }
    }

    /// Add the `iif lo lookup <vmroute-table>` rules (v4+v6) iff both a table and a rule
    /// priority are configured (defaults: table 200, prio 11000; either set to -1 skips —
    /// e.g. no rule is needed if the table is one that's already consulted). Idempotent.
    async fn ensure_vmroute_rules(&self) -> Result<()> {
        if let (Some(table), Some(prio)) = (self.cli.vmroute_table.0, self.cli.vmroute_rule.0) {
            self.net.rule_add(false, table, prio).await?;
            self.net.rule_add(true, table, prio).await?;
        }
        Ok(())
    }

    async fn remove_vmroute_rules(&self) {
        if let (Some(table), Some(prio)) = (self.cli.vmroute_table.0, self.cli.vmroute_rule.0) {
            let _ = self.net.rule_del(false, table, prio).await;
            let _ = self.net.rule_del(true, table, prio).await;
        }
    }

    // ---- fwd mirror: up0 IPs → br (noprefixroute, nodad) ----

    /// Remove the addresses we mirrored onto a (now-former) bridge. The mirror only ever
    /// adds noprefixroute global addrs, so deleting those reverses it without touching the
    /// user's own addresses or the bridge's automatic link-local.
    async fn br_name(&self, index: u32) -> Option<String> {
        self.net.get_link_by_index(index).await.ok().flatten().map(|l| l.name)
    }

    /// Make a device a pure L2 transport: no auto link-local, no RA processing, and
    /// drop any auto-LL it already has. Used for fwd0/fwd1 (they only forward frames).
    async fn disable_dev_autoconf(&self, name: &str, index: u32) {
        write_ipv6_conf(name, "addr_gen_mode", "1"); // none — no auto link-local
        write_ipv6_conf(name, "accept_ra", "0");
        if let Ok(addrs) = self.net.get_addrs(index).await {
            for a in addrs.iter().filter(|a| is_link_local(&a.ip) && !a.noprefixroute) {
                let _ = self.net.addr_del(index, a.ip, a.plen).await;
            }
        }
    }

    /// On bridge attach: stop the bridge auto-generating its own link-local and accepting
    /// RAs, and drop the auto-LL it already made — so its only addresses are the mirrored
    /// up0 ones. That way the VM (bridge segment) and external neighbours (upstream) see
    /// the *same* host IP. Originals are saved for restore on detach.
    async fn apply_bridge_cfg(&mut self, br_index: u32) {
        let Some(name) = self.br_name(br_index).await else { return };
        let agm = read_ipv6_conf(&name, "addr_gen_mode").unwrap_or_else(|| "0".into());
        let ara = read_ipv6_conf(&name, "accept_ra").unwrap_or_else(|| "1".into());
        write_ipv6_conf(&name, "addr_gen_mode", "1"); // none — no auto link-local
        write_ipv6_conf(&name, "accept_ra", "0");
        // Clear the bridge to a clean slate before mirroring: delete every address that
        // ISN'T ours (anything not noprefixroute — its auto LL + any user/stale IP). Those
        // would otherwise add competing connected routes and make the VM see host IPs that
        // don't match the upstream. reconcile_mirror then puts only up0's mirrored IPs on.
        // Save the global ones so detach can put them back.
        let mut saved = Vec::new();
        if let Ok(addrs) = self.net.get_addrs(br_index).await {
            for a in addrs.iter().filter(|a| !a.noprefixroute) {
                if a.global {
                    saved.push((a.ip, a.plen));
                }
                let _ = self.net.addr_del(br_index, a.ip, a.plen).await;
            }
        }
        log::info!(
            "bridge {name}: mirror-only (addr_gen_mode=1 accept_ra=0; cleared {} own addr)",
            saved.len()
        );
        self.saved_br_cfg =
            Some(SavedBrCfg { index: br_index, addr_gen_mode: agm, accept_ra: ara, addrs: saved });
    }

    /// On bridge detach/change/teardown: restore the bridge's original IPv6 knobs.
    async fn restore_bridge_cfg(&mut self, br_index: u32) {
        let Some(cfg) = self.saved_br_cfg.take() else { return };
        if cfg.index != br_index {
            self.saved_br_cfg = Some(cfg);
            return;
        }
        if let Some(name) = self.br_name(br_index).await {
            write_ipv6_conf(&name, "addr_gen_mode", &cfg.addr_gen_mode);
            write_ipv6_conf(&name, "accept_ra", &cfg.accept_ra);
            // put back the bridge's own addresses we cleared on attach (as normal addrs).
            for (ip, plen) in &cfg.addrs {
                let _ = self.net.addr_add(br_index, *ip, *plen, false, false).await;
            }
            log::info!(
                "bridge {name}: restored addr_gen_mode={} accept_ra={} + {} addr",
                cfg.addr_gen_mode,
                cfg.accept_ra,
                cfg.addrs.len()
            );
        } else {
            // bridge was deleted outright (e.g. `ip link del`) — nothing to restore,
            // its sysctls went with it. Drop the saved config and carry on.
            log::debug!("bridge idx {br_index} gone before restore; nothing to do");
        }
    }

    async fn clean_mirror_from(&self, br_index: u32) {
        if let Ok(addrs) = self.net.get_addrs(br_index).await {
            for a in addrs
                .iter()
                .filter(|a| a.noprefixroute && (a.global || is_link_local(&a.ip)))
            {
                let _ = self.net.addr_del(br_index, a.ip, a.plen).await;
            }
        }
    }

    /// Mirror up0's IPs onto the current bridge (= fwd1.master). If that bridge changed
    /// or went away since last time, unmirror the previous one first. `mirrored_br`
    /// remembers where the mirror lives so detach/teardown can clean it.
    async fn reconcile_mirror(&mut self) -> Result<()> {
        let target = if self.is_fwd() { self.snap.br_index } else { None };
        if self.mirrored_br != target {
            if let Some(old) = self.mirrored_br {
                self.clean_mirror_from(old).await;
                self.restore_bridge_cfg(old).await;
            }
            self.mirrored_br = None;
        }
        let Some(br_index) = target else { return Ok(()) };
        if self.mirrored_br.is_none() {
            // first mirror onto this bridge: make it mirror-only addressed.
            self.apply_bridge_cfg(br_index).await;
        }
        let want: HashSet<(IpAddr, u8)> =
            self.snap.up0_addrs.iter().map(|a| (a.ip, a.plen)).collect();
        // Our mirrored addrs are the noprefixroute global + link-local ones. The bridge's
        // OWN auto link-local is NOT noprefixroute, so it's excluded here → never touched.
        let have: HashSet<(IpAddr, u8)> = self
            .snap
            .br_addrs
            .iter()
            .filter(|a| a.noprefixroute && (a.global || is_link_local(&a.ip)))
            .map(|a| (a.ip, a.plen))
            .collect();
        for (ip, plen) in want.difference(&have) {
            self.net.addr_add(br_index, *ip, *plen, true, true).await?;
        }
        for (ip, plen) in have.difference(&want) {
            self.net.addr_del(br_index, *ip, *plen).await?;
        }
        self.mirrored_br = Some(br_index);
        Ok(())
    }
}

// ---- per-interface IPv6 sysctls via procfs (writing /proc/sys is not "shelling out") ----

fn ipv6_conf_path(iface: &str, key: &str) -> String {
    format!("/proc/sys/net/ipv6/conf/{iface}/{key}")
}
fn read_ipv6_conf(iface: &str, key: &str) -> Option<String> {
    std::fs::read_to_string(ipv6_conf_path(iface, key)).ok().map(|s| s.trim().to_string())
}
fn write_ipv6_conf(iface: &str, key: &str, val: &str) {
    if let Err(e) = std::fs::write(ipv6_conf_path(iface, key), val) {
        log::debug!("write {iface}/{key}={val}: {e}");
    }
}

/// Per-entry src selector (ARCHITECTURE.md host→VM 路由): most-precise subnet
/// containing vm-ip; tie → numerically smallest IP; none → None (kernel chooses).
fn select_src(vm: IpAddr, host: &[AddrInfo]) -> Option<IpAddr> {
    let mut best: Option<(u8, IpAddr)> = None;
    for a in host {
        if family(&a.ip) != family(&vm) {
            continue;
        }
        if !subnet_contains(a.ip, a.plen, vm) {
            continue;
        }
        let cand = (a.plen, a.ip);
        best = Some(match best {
            None => cand,
            Some(b) => {
                if cand.0 > b.0 || (cand.0 == b.0 && ip_lt(cand.1, b.1)) {
                    cand
                } else {
                    b
                }
            }
        });
    }
    best.map(|(_, ip)| ip)
}

fn ip_lt(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(x), IpAddr::V4(y)) => u32::from(x) < u32::from(y),
        (IpAddr::V6(x), IpAddr::V6(y)) => u128::from(x) < u128::from(y),
        _ => false,
    }
}

fn subnet_contains(net: IpAddr, plen: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            if plen > 32 {
                return false;
            }
            let mask = if plen == 0 { 0 } else { u32::MAX << (32 - plen) };
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            if plen > 128 {
                return false;
            }
            let mask = if plen == 0 { 0 } else { u128::MAX << (128 - plen) };
            (u128::from(n) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ai(ip: &str, plen: u8) -> AddrInfo {
        AddrInfo { ip: ip.parse().unwrap(), plen, global: true, noprefixroute: false, rt_priority: 0 }
    }

    #[test]
    fn src_select_most_precise() {
        let host = vec![ai("10.0.0.2", 24), ai("10.0.5.1", 16)];
        // vm 10.0.0.9 in both 10.0.0.0/24 and 10.0.0.0/16 -> pick /24 (more precise)
        let s = select_src("10.0.0.9".parse().unwrap(), &host);
        assert_eq!(s, Some("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn src_select_tie_smallest() {
        let host = vec![ai("10.0.0.50", 24), ai("10.0.0.20", 24)];
        let s = select_src("10.0.0.9".parse().unwrap(), &host);
        assert_eq!(s, Some("10.0.0.20".parse().unwrap()), "tie -> smallest");
    }

    #[test]
    fn src_select_none_when_no_subnet() {
        let host = vec![ai("10.0.0.2", 24)];
        let s = select_src("192.168.1.1".parse().unwrap(), &host);
        assert_eq!(s, None);
    }

    #[test]
    fn subnet_contains_v6() {
        assert!(subnet_contains(
            "2001:db8::1".parse().unwrap(),
            64,
            "2001:db8::99".parse().unwrap()
        ));
        assert!(!subnet_contains(
            "2001:db8:1::1".parse().unwrap(),
            64,
            "2001:db8:2::1".parse().unwrap()
        ));
    }
}
