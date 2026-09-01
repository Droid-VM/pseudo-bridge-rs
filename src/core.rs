//! The core actor: owns `entries` (the single source of truth) and the derived
//! kernel-side snapshot, and is the only writer of kernel offload + routes.
//! Drives three event classes (ARCHITECTURE.md §syncer): copy packets (learn),
//! netlink link/addr changes (recompute+diff), and the aging timer.
#![forbid(unsafe_code)] // core algorithm: memory-safety is compiler-guaranteed here

use crate::afpacket::{
    build_arp_probe, build_arp_reply, build_arp_request, build_ns_dad, Injector,
};
use crate::apf::{self, VendorSocket};
use crate::backend::{
    ApfExternalWrite, Backend, CopyEvent, InitCfg, APF_QUEUE_DEPTH, COPY_QUEUE_DEPTH,
};
use crate::cli::{Cli, Engine, Mode};
use crate::netlink::{AddrInfo, Net};
use crate::packet::{build_frame, classify_learn, fix_icmpv6_csum, ETHERTYPE_IPV6};
use crate::state::Entries;
use crate::types::{family, is_learnable_unicast, is_link_local, Family, Mac};
use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
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
    apf_tx: Option<Sender<ApfExternalWrite>>,
    host_routes: HashSet<IpAddr>, // fwd: ips with a /32-/128 host route programmed
    mirrored_br: Option<u32>,     // fwd: bridge index we last mirrored up0's IPs onto
    saved_br_cfg: Option<SavedBrCfg>, // fwd: bridge IPv6 knobs to restore on detach
    nd_proxied: HashSet<IpAddr>,  // offload-workaround: guest addrs we installed on up0
    installed: HashMap<IpAddr, Mac>, // vmroutes currently programmed (for transition logging)
    /// Neighbours written by pbridge, keyed by (ifindex, guest IP) with the expected MAC.
    /// The expected value lets withdrawal avoid deleting a user replacement.
    host_neighs: HashMap<(u32, IpAddr), Mac>,
    probe_injector: Option<Injector>, // guest-facing AF_PACKET device for aging probes
    aging_tick: u64,                 // counts aging ticks (probe/flush alternation)
    skip_flush_once: bool,            // probe send failure: preserve entries for one tick
    keepalive_tick: u64,              // counts --arp-keepalive ticks (GARP every Nth)
    apf: Option<ApfWatchdog>,         // --apf-watchdog-guest state (ebpf only)
    apf_discovery_ticks: u64, // cold-start ticks since an explicit APF guest was last unresolved
}

/// APF watchdog state. Present iff `--apf-watchdog-guest` was given; the vendor socket is
/// opened lazily at session init (it needs the driver loaded) and dropped at teardown.
struct ApfWatchdog {
    guests: Vec<Ipv4Addr>,
    sock: Option<VendorSocket>,
    ifindex: u32,
    /// Consecutive failures, for the retry backoff.
    failures: u32,
}

/// Retry backoff after a failed transaction. A failure is usually "the firmware/driver is
/// busy or the program is unfamiliar", so back off instead of hammering disable/enable.
const APF_BACKOFF_SECS: [u64; 5] = [1, 2, 5, 10, 30];

/// Explicit watchdog guests have no MAC at cold start, so they cannot be pre-filled into
/// `ip2mac`. Ask them to defend their IPv4 address on the guest bridge instead. A short
/// burst makes the first inbound packet work without waiting for natural guest traffic;
/// then back off to avoid waking a missing VM forever.
const APF_DISCOVERY_FAST_TICKS: u64 = 5;
const APF_DISCOVERY_SLOW_EVERY: u64 = 30;

fn apf_discovery_due(tick: u64) -> bool {
    tick <= APF_DISCOVERY_FAST_TICKS || tick.is_multiple_of(APF_DISCOVERY_SLOW_EVERY)
}

/// --arp-keepalive sends the GARP broadcast only every Nth tick (unicast replies go
/// every tick): broadcasts wake every powersaving client on the WLAN, so be polite.
const GARP_EVERY: u64 = 3;

pub async fn run(cli: Cli) -> Result<()> {
    // Reject an unsupported combination before touching the kernel.
    let apf_guests = crate::cli::validate_apf_watchdog(&cli).map_err(|e| anyhow!(e))?;

    let net = Net::connect()?;
    let mut nl_rx = Net::monitor()?;
    // Bounded + lossy (see COPY_QUEUE_DEPTH): a learn flood degrades to dropped copies
    // (the next packet re-learns) instead of unbounded queue growth.
    let (copy_tx, mut copy_rx) = channel(COPY_QUEUE_DEPTH);
    // Depth-1, coalescing, NOT lossy (see ApfExternalWrite). Only created when the
    // watchdog is on, so the ebpf session is otherwise unchanged.
    let (apf_tx_raw, mut apf_rx) = channel::<ApfExternalWrite>(APF_QUEUE_DEPTH);
    let apf_tx = (!apf_guests.is_empty()).then_some(apf_tx_raw);

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
        apf_tx: apf_tx.clone(),
        host_routes: HashSet::new(),
        mirrored_br: None,
        saved_br_cfg: None,
        nd_proxied: HashSet::new(),
        installed: HashMap::new(),
        host_neighs: HashMap::new(),
        probe_injector: None,
        aging_tick: 0,
        skip_flush_once: false,
        keepalive_tick: 0,
        apf: (!apf_guests.is_empty()).then(|| ApfWatchdog {
            guests: apf_guests.clone(),
            sock: None,
            ifindex: 0,
            failures: 0,
        }),
        apf_discovery_ticks: 0,
    };
    if !apf_guests.is_empty() {
        log::info!(
            "apf-watchdog: enabled for {} guest(s) {:?}, debounce {}ms",
            apf_guests.len(),
            apf_guests,
            core.cli.apf_watchdog_debounce_ms
        );
    }
    if core.cli.offload_workaround.is_some() && !core.is_fwd() {
        log::warn!("--offload-workaround is set but mode is direct; ignoring (fwd-mode only)");
    }

    // Attempt initial session (up0 may already be present).
    if let Err(e) = core.on_netlink_change().await {
        log::warn!("initial sync error: {e:#}");
    }

    // Every aging cycle first probes guests, then flushes liveness on the next tick. A
    // reply marks the entry alive in the datapath; an unanswered probe is removed by the
    // following flush. Half-period ticks put the probe immediately before the aging
    // decision while allowing a silent-but-present guest to defend its address first.
    let aging_secs = (timeout / 2).max(1);
    let mut aging = tokio::time::interval(Duration::from_secs(aging_secs));
    // If the loop stalls past a period (e.g. a slow nft rebuild), don't fire make-up
    // ticks back-to-back: bursty flushes would halve the effective idle timeout.
    aging.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    aging.tick().await; // consume the immediate first tick

    // --arp-keepalive timer (inert unless enabled; the select arm is gated below).
    let ka_enabled = core.cli.arp_keepalive > 0;
    let mut keepalive = tokio::time::interval(Duration::from_secs(core.cli.arp_keepalive.max(1)));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await; // consume the immediate first tick

    // Both signal streams are created once, outside the loop: a stream buffers signals
    // that arrive while another select branch is being handled. (Calling ctrl_c() per
    // iteration would recreate the listener each time and could miss a SIGINT.)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    // APF watchdog timer: a single armed deadline that serves both roles. A kprobe event
    // sets it to now+debounce, coalescing the several vendor commands NetworkStack issues
    // for one logical update; a failed transaction sets it to now+backoff. Events arriving
    // during a transaction are still queued (the depth-1 channel holds one), so the next
    // loop iteration re-arms and runs again — that is the "repatch once more if it was
    // overwritten mid-transaction" requirement, without a second timer.
    let apf_debounce = Duration::from_millis(core.cli.apf_watchdog_debounce_ms);
    let apf_enabled = core.apf.is_some();
    let mut apf_deadline: Option<tokio::time::Instant> = None;

    // Cold-start discovery for explicitly configured APF guests. This is separate from
    // the normal aging interval: a default 30 s aging tick would leave a restart's first
    // inbound packet black-holed for far too long. The tick only emits anonymous ARP
    // probes for configured-but-unlearned IPv4s; it never scans or trusts an address.
    let mut apf_discovery = tokio::time::interval(Duration::from_secs(1));
    apf_discovery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    apf_discovery.tick().await; // consume interval's immediate first tick

    loop {
        // A disarmed timer must never fire; park it far out and gate the arm on the flag.
        let apf_sleep = tokio::time::sleep_until(
            apf_deadline.unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600)),
        );
        tokio::pin!(apf_sleep);

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
            _ = keepalive.tick(), if ka_enabled => {
                if let Err(e) = core.on_arp_keepalive().await { log::warn!("arp-keepalive: {e:#}"); }
            }
            _ = apf_discovery.tick(), if apf_enabled => {
                if let Err(e) = core.on_apf_discovery_tick() {
                    log::warn!("apf-watchdog discovery: {e:#}");
                }
            }
            ev = apf_rx.recv(), if apf_enabled => {
                match ev {
                    Some(ev) => {
                        log::debug!(
                            "apf-watchdog: external APF vendor command from tgid {} — repatch in {}ms",
                            ev.tgid, apf_debounce.as_millis()
                        );
                        apf_deadline = Some(tokio::time::Instant::now() + apf_debounce);
                    }
                    None => {
                        // The ringbuf reader is gone (backend torn down): nothing can
                        // notify us any more, so cancel any pending retry.
                        apf_deadline = None;
                    }
                }
            }
            _ = &mut apf_sleep, if apf_enabled && apf_deadline.is_some() => {
                // Disarm first: the transaction is inline, and on success nothing re-arms.
                // A failure returns its backoff; an event that arrived meanwhile is still
                // in the depth-1 channel and re-arms on the next iteration.
                apf_deadline = core.apf_repatch("external APF write").await
                    .map(|backoff| tokio::time::Instant::now() + backoff);
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
            Mode::FwdOffload => Some(crate::cli::OffloadFamilies {
                v4: true,
                v6: true,
                v6ll: false,
            }),
            _ => None,
        })
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

        if br_changed {
            let probe_ifindex = if self.is_fwd() { new.fwd0_index } else { new.br_index };
            self.probe_injector = probe_ifindex.map(Injector::new).transpose()?;
            if let Some(old_br) = old.br_index {
                self.withdraw_host_neighs_on(old_br).await;
            }
        }

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

    /// --bridge convenience: enslave `dev` into the named bridge, once, at session
    /// init — and nothing more. The syncer's dynamic master tracking is unaffected:
    /// the operator can detach / re-attach / swap bridges afterwards and pbridge
    /// follows via netlink as usual. Best-effort: a missing bridge (or dev) only warns.
    async fn ensure_bridge(&self, dev: &str) {
        let Some(br_name) = &self.cli.bridge else {
            return;
        };
        let br = match self.net.get_link_by_name(br_name).await {
            Ok(Some(b)) => b,
            _ => {
                log::warn!("--bridge {br_name}: no such link; not enslaving {dev} (attach manually)");
                return;
            }
        };
        let Ok(Some(d)) = self.net.get_link_by_name(dev).await else {
            return;
        };
        if d.master == Some(br.index) {
            return; // already there
        }
        match self.net.link_set_master(d.index, br.index).await {
            Ok(()) => log::info!("--bridge: enslaved {dev} into {br_name}"),
            Err(e) => log::warn!("--bridge: enslave {dev} into {br_name}: {e:#}"),
        }
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
            apf_watchdog: self.apf.is_some(),
        };

        self.injector = Some(Injector::new(snap.up0_index)?);
        // Aging probes are injected on the guest-facing side: fwd0 enters the operator's
        // bridge in fwd mode; the bridge master is the correct ingress in direct mode.
        let probe_ifindex = if self.is_fwd() { fwd0_index } else { snap.br_index };
        self.probe_injector = probe_ifindex.map(Injector::new).transpose()?;
        self.backend
            .init(&cfg, self.copy_tx.clone(), self.apf_tx.clone())?;
        self.initialized = true;
        self.snap = snap;

        // APF watchdog: only now, with the backend loaded (so the kprobe is armed and its
        // events can reach us) and up0's ifindex known. The first repatch runs immediately
        // — the live program is whatever NetworkStack installed before we started.
        self.apf_session_start().await;

        // --bridge: enslave the guest-facing port only now, AFTER the hooks are live —
        // otherwise (direct especially) there's a window where the kernel bridge floods
        // unrewritten guest frames out up0. The resulting netlink change flows through
        // the same dynamic attach path as an operator enslave (BRMAC/HOSTMAC/mirror).
        let guest_port =
            if self.is_fwd() { self.cli.fwd1() } else { self.cli.interface.clone() };
        self.ensure_bridge(&guest_port).await;

        // fwd: add ip rules (idempotent) + mirror up0 IPs to br.
        if self.is_fwd() {
            self.ensure_vmroute_rules().await?;
            self.reconcile_mirror().await?;
        }

        self.reconcile_all().await?;
        // The normal aging probe only iterates `installed`, which is intentionally empty
        // after a stateless restart. Explicit APF guests need one discovery ARP now that
        // hooks and (in fwd mode) the guest-facing bridge path are all live.
        self.apf_discovery_ticks = 0;
        if let Err(e) = self.probe_apf_watchdog_guests() {
            log::warn!("apf-watchdog initial guest discovery: {e:#}");
        }
        log::info!("{} backend running", self.backend.name());
        Ok(())
    }

    async fn teardown_session(&mut self) -> Result<()> {
        if !self.initialized {
            return Ok(());
        }
        log::info!(
            "teardown session ({} vmroutes dropped)",
            self.installed.len()
        );
        // Stop the watchdog BEFORE dropping the backend: disarming the kprobe first means
        // the teardown's own vendor traffic (and anyone else's) can't queue one last
        // repatch against an interface that is going away.
        self.apf_session_stop();
        // withdraw host routes + unmirror the bridge we put up0's IPs on
        self.withdraw_all_host_routes().await;
        self.remove_vmroute_rules().await;
        self.unproxy_all().await;
        self.withdraw_all_host_neighs().await;
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
        self.probe_injector = None;
        self.skip_flush_once = false;
        self.apf_discovery_ticks = 0;
        self.initialized = false;
        Ok(())
    }

    // ---- APF watchdog ----

    /// Session init: open the vendor socket, pin up0's ifindex, and do the first repatch.
    /// A failure is logged, not fatal — the next external APF write retries. (Arming the
    /// kprobe already failed hard in `backend.init` if the driver has no APF path at all.)
    async fn apf_session_start(&mut self) {
        let Some(wd) = &mut self.apf else { return };
        wd.ifindex = self.snap.up0_index;
        wd.failures = 0;
        match VendorSocket::open() {
            Ok(s) => wd.sock = Some(s),
            Err(e) => {
                log::error!("apf-watchdog: cannot open the nl80211 vendor socket: {e:#}");
                return;
            }
        }
        log::info!("apf-watchdog: session up on ifindex {}", wd.ifindex);
        self.apf_repatch("session init").await;
    }

    /// Session teardown: drop the socket so no repatch can run against a dead interface.
    /// The kprobe itself goes away with the `Ebpf` object when the backend is dropped.
    fn apf_session_stop(&mut self) {
        if let Some(wd) = &mut self.apf {
            if wd.sock.take().is_some() {
                log::info!("apf-watchdog: session down");
            }
            wd.ifindex = 0;
            wd.failures = 0;
        }
    }

    /// Run one repatch transaction. Returns the backoff to wait before retrying, or None
    /// when there is nothing to retry.
    async fn apf_repatch(&mut self, reason: &str) -> Option<Duration> {
        if !self.initialized {
            return None;
        }
        let Some(wd) = &mut self.apf else { return None };
        let (Some(sock), ifindex) = (wd.sock.as_mut(), wd.ifindex) else {
            return None;
        };
        if ifindex == 0 {
            return None;
        }
        let guests = wd.guests.clone();
        // Blocking, but bounded: the four vendor commands measured ~42 ms total on device,
        // and the socket has a 2s recv timeout. Running it inline keeps the core actor the
        // single writer — no lock, no concurrent transaction, no half-applied program.
        let result = apf::repatch(sock, ifindex, &guests);
        match result {
            Ok(apf::Outcome::Patched {
                stock_len,
                patched_len,
                guests,
            }) => {
                wd.failures = 0;
                log::info!(
                    "apf-watchdog: repatched after {reason}: {stock_len} -> {patched_len} bytes, \
                     {guests} guest(s) passed, readback verified"
                );
                None
            }
            Ok(apf::Outcome::AlreadyPatched { len }) => {
                wd.failures = 0;
                log::debug!(
                    "apf-watchdog: {reason}: live {len}-byte program already carries our rules"
                );
                None
            }
            Err(e) => {
                wd.failures = wd.failures.saturating_add(1);
                let idx = (wd.failures as usize - 1).min(APF_BACKOFF_SECS.len() - 1);
                let backoff = Duration::from_secs(APF_BACKOFF_SECS[idx]);
                log::warn!(
                    "apf-watchdog: repatch after {reason} failed (attempt {}): {e:#}; APF left \
                     enabled with the firmware's own program, retrying in {}s",
                    wd.failures,
                    backoff.as_secs()
                );
                Some(backoff)
            }
        }
    }

    /// Cold-start discovery for explicit `--apf-watchdog-guest` IPv4s. It uses the same
    /// anonymous RFC 5227 ARP probe as aging (`spa=0.0.0.0`, L2 broadcast): this asks a
    /// live guest to defend its address, and the guest's real ARP reply passes through the
    /// normal OUT hook to establish the authoritative `(IP, MAC)` binding. We never insert
    /// a static/guessed MAC into `ip2mac`, and we never scan addresses the operator did not
    /// explicitly name.
    fn probe_apf_watchdog_guests(&self) -> Result<usize> {
        if !self.initialized {
            return Ok(0);
        }
        let Some(wd) = &self.apf else { return Ok(0) };
        let Some(inj) = &self.probe_injector else {
            return Ok(0);
        };
        let Some(hostmac) = self.snap.hostmac else {
            return Ok(0);
        };
        let mut sent = 0;
        for guest in &wd.guests {
            if self.entries.get(&IpAddr::V4(*guest)).is_some() {
                continue;
            }
            inj.send_frame(&build_arp_probe(*guest, hostmac))?;
            sent += 1;
        }
        if sent != 0 {
            log::debug!("apf-watchdog: sent {sent} cold-start ARP discovery probe(s)");
        }
        Ok(sent)
    }

    /// First five seconds after a restart probe once per second. Thereafter keep a small
    /// 30-second heartbeat for an explicit guest that was offline at session start. A
    /// learned entry exits this path immediately and uses the ordinary aging probe instead.
    fn on_apf_discovery_tick(&mut self) -> Result<()> {
        if !self.initialized || self.apf.is_none() {
            return Ok(());
        }
        self.apf_discovery_ticks = self.apf_discovery_ticks.wrapping_add(1);
        if apf_discovery_due(self.apf_discovery_ticks) {
            self.probe_apf_watchdog_guests()?;
        }
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
            CopyEvent::ArpRequest {
                guest_ip,
                requester_ip,
                requester_mac,
            } => self.on_arp_request(guest_ip, requester_ip, requester_mac),
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

    /// Reply to an upstream request for an installed guest IPv4 address. The backend
    /// filters for its current demux map; check `installed` again because this event
    /// crosses an asynchronous, lossy queue and may arrive after withdrawal.
    fn on_arp_request(
        &self,
        guest_ip: Ipv4Addr,
        requester_ip: Ipv4Addr,
        requester_mac: Mac,
    ) -> Result<()> {
        if !self.installed.contains_key(&IpAddr::V4(guest_ip)) {
            return Ok(());
        }
        let (Some(inj), Some(hostmac)) = (&self.injector, self.snap.hostmac) else {
            return Ok(());
        };
        inj.send_frame(&build_arp_reply(guest_ip, hostmac, requester_ip, requester_mac))?;
        log::debug!("arp-proxy: {guest_ip} is-at {hostmac} -> {requester_ip} ({requester_mac})");
        Ok(())
    }

    async fn do_learn(&mut self, ip: IpAddr, mac: Mac) -> Result<()> {
        if !is_learnable_unicast(&ip) {
            return Ok(());
        }
        let res = self.entries.learn(ip, mac);
        let changed = res.changed;
        for ip in changed.iter().copied() {
            self.reconcile(ip).await?;
        }
        // A datapath re-learn is a cheap opportunity to repair a neighbour entry that a
        // host kernel may have garbage-collected while the guest entry stayed alive.
        if changed.is_empty() {
            if let Some(guest_mac) = self.entries.get(&ip).map(|e| e.mac) {
                self.reconcile_host_neighs(ip, guest_mac).await;
            }
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
            self.withdraw_host_neigh(ip).await;
            self.unproxy_addr(ip).await;
            if self.installed.remove(&ip).is_some() {
                let reason = if e.is_none() { "expired/evicted" } else { "host-owned" };
                log::info!("vmroute del {ip} ({reason})");
            }
        } else {
            let mac = e.unwrap().mac;
            self.backend.write_entry(ip, mac)?;
            self.write_host_route(ip).await?;
            self.reconcile_host_neighs(ip, mac).await;
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
        let fresh = !self.nd_proxied.contains(&ip);
        if fresh {
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
        //
        // The kernel inserts that local route ASYNCHRONOUSLY (addrconf work), and whether it
        // lands before our delete is a kernel-version coin toss: on 6.17 the sub-ms delete
        // races AHEAD of the insert, the ESRCH looks like success, and the surviving local
        // route blackholes host->guest v6 (and eats the host's replies for guest->host)
        // until teardown — nothing retriggers a reconcile for a proxy addr (its NEWADDR is
        // magic-metric and diffs empty). So on a fresh install, retry until a delete actually
        // matches (Ok(true)); the loop exits on the first hit, typically iteration 0-1.
        // Non-fresh reconciles keep the single best-effort pass (their route is long gone).
        let mut deleted = self.net.del_local_route(ip, plen).await.unwrap_or(false);
        if fresh {
            let mut tries = 0;
            while !deleted && tries < 50 {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                deleted = self.net.del_local_route(ip, plen).await.unwrap_or(false);
                tries += 1;
            }
            if deleted {
                log::debug!("offload-proxy {ip}: local route deleted (try {tries})");
            } else {
                log::warn!(
                    "offload-proxy {ip}: local route never appeared within 1s — \
                     host->guest may be shadowed by local delivery"
                );
            }
        }
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

    /// Keep both sides of fwd-mode host resolution warm. While a guest is first being
    /// learned, Linux may still have selected the connected up0 route and queue the first
    /// packet behind an ARP/ND lookup there. Mapping that neighbour to HOSTMAC lets the
    /// up0 egress demux redirect the queued packet into fwd0; the bridge-side entry uses
    /// the real guest MAC for subsequent vmroute traffic.
    async fn reconcile_host_neighs(&mut self, ip: IpAddr, guest_mac: Mac) {
        if !self.is_fwd() {
            return;
        }
        let hostmac = match self.snap.hostmac {
            Some(m) => m,
            None => return,
        };
        let mut want = Vec::with_capacity(2);
        if self.snap.up0_index != 0 {
            want.push((self.snap.up0_index, hostmac));
        }
        if let Some(br) = self.snap.br_index {
            want.push((br, guest_mac));
        }
        for (ifindex, mac) in want {
            match self.net.neighbour_replace(ifindex, ip, mac).await {
                Ok(()) => {
                    self.host_neighs.insert((ifindex, ip), mac);
                }
                Err(e) => log::debug!("host-neigh + {ip} on ifindex {ifindex}: {e:#}"),
            }
        }
    }

    async fn withdraw_host_neigh(&mut self, ip: IpAddr) {
        let keys: Vec<((u32, IpAddr), Mac)> = self
            .host_neighs
            .iter()
            .filter_map(|(key, mac)| (key.1 == ip).then_some((*key, *mac)))
            .collect();
        for ((ifindex, ip), expected) in keys {
            let _ = self.net.neighbour_del_if(ifindex, ip, expected).await;
            self.host_neighs.remove(&(ifindex, ip));
        }
    }

    async fn withdraw_host_neighs_on(&mut self, ifindex: u32) {
        let keys: Vec<((u32, IpAddr), Mac)> = self
            .host_neighs
            .iter()
            .filter_map(|(key, mac)| (key.0 == ifindex).then_some((*key, *mac)))
            .collect();
        for ((idx, ip), expected) in keys {
            let _ = self.net.neighbour_del_if(idx, ip, expected).await;
            self.host_neighs.remove(&(idx, ip));
        }
    }

    async fn withdraw_all_host_neighs(&mut self) {
        let keys: Vec<((u32, IpAddr), Mac)> = self.host_neighs.iter().map(|(k, m)| (*k, *m)).collect();
        for ((ifindex, ip), expected) in keys {
            let _ = self.net.neighbour_del_if(ifindex, ip, expected).await;
        }
        self.host_neighs.clear();
    }

    async fn on_tick(&mut self) -> Result<()> {
        if !self.initialized {
            // A failed init (e.g. transient nft error) is otherwise only retried on the
            // next netlink event — which may never come if the topology is stable. Use
            // the tick as a retry heartbeat; on_netlink_change inits if up0 is present.
            return self.on_netlink_change().await;
        }
        self.aging_tick = self.aging_tick.wrapping_add(1);
        // The probe tick precedes the flush tick. A guest that is still present replies with
        // ARP/NA, and the existing OUT datapath marks its seen entry immediately. A guest
        // that does not reply is absent from the next flush result and is withdrawn.
        if self.aging_tick % 2 == 1 {
            if let Err(e) = self.probe() {
                // A failed probe is not evidence that the guest is gone. probe() restores
                // the liveness marks it can and this flag prevents the next tick from
                // flushing the round with an incomplete set of requests.
                self.skip_flush_once = true;
                return Err(e);
            }
            return Ok(());
        }
        if self.skip_flush_once {
            self.skip_flush_once = false;
            log::warn!("aging: skipping flush after incomplete probe round");
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

    /// --arp-keepalive tick: refresh upstream v4 neighbour caches from OUR side so peers
    /// never need to ARP-request a guest address. Wi-Fi firmware ARP offload (e.g.
    /// Qualcomm WMI_SET_ARP_NS_OFFLOAD) holds a single IPv4 slot — in powersave it
    /// answers only for the host's primary v4 and drops ARP requests for everything
    /// else, so inbound resolution of guest IPs is ~dead while the chip sleeps. Outbound
    /// frames are unaffected, so we push instead of waiting to be asked:
    ///   - unicast ARP reply (spa=guest, sha=HOSTMAC) to every v4 neighbour on up0 —
    ///     Linux sets a unicast reply to NUD_REACHABLE (broadcast replies/requests
    ///     don't assert reachability), so the entry never decays into probing;
    ///   - GARP broadcast every GARP_EVERY ticks — best-effort STALE refresh for LAN
    ///     peers that aren't in up0's neighbour table (they only talk to the VM);
    ///   - the HOST's own v4s are advertised alongside the guests: the firmware
    ///     repopulates its single slot from up0's address list on every change, and
    ///     with guest /32 proxies installed it can land on a proxy instead of the
    ///     host primary — then powersave eats ARP requests for the HOST itself
    ///     (outbound still works, so it presents as "LAN peers can't ping the
    ///     phone" while the phone browses fine). Same correct mapping the host
    ///     would answer with anyway, so pushing it is harmless;
    ///   - a gateway absent from the neighbour table (GC'd on an idle host) is
    ///     re-solicited from a host address; the next tick covers it.
    async fn on_arp_keepalive(&mut self) -> Result<()> {
        if !self.initialized {
            return Ok(());
        }
        let guests: Vec<Ipv4Addr> = self
            .installed
            .keys()
            .filter_map(|ip| match ip {
                IpAddr::V4(g) => Some(*g),
                _ => None,
            })
            .collect();
        if guests.is_empty() {
            return Ok(());
        }
        self.keepalive_tick = self.keepalive_tick.wrapping_add(1);
        let garp_tick = self.keepalive_tick.is_multiple_of(GARP_EVERY);
        let Some(hostmac) = self.snap.hostmac else {
            return Ok(());
        };

        // Neighbours resolving to HOSTMAC (host's own addrs, MAC-NAT'd guests) are "us",
        // not peers — neighbours_v4 filters them out during the scan.
        let neigh = self.net.neighbours_v4(self.snap.up0_index, hostmac).await;
        let have: HashSet<Ipv4Addr> = neigh.iter().map(|(ip, _)| *ip).collect();
        let missing_gws: Vec<Ipv4Addr> = self
            .net
            .default_gw4()
            .await
            .into_iter()
            .filter(|gw| !have.contains(gw))
            .collect();
        let host_v4s: Vec<Ipv4Addr> = self
            .snap
            .host_ips
            .iter()
            .filter_map(|a| match a.ip {
                IpAddr::V4(v) if !is_link_local(&a.ip) => Some(v),
                _ => None,
            })
            .collect();

        let Some(inj) = &self.injector else {
            return Ok(());
        };
        for gw in missing_gws {
            if let Some(src) = host_v4s.first() {
                let _ = inj.send_frame(&build_arp_request(gw, *src, hostmac));
            }
        }
        // Host v4s first: if the firmware slot got stolen by a proxy, the host's own
        // reachability is what's on the line. Reply-form frames only (op=2) — the
        // discovery dup clones op==request, so none of these re-enter the vmbr; the
        // reflected copies (src==HOSTMAC) die on the IN guard.
        for g in host_v4s.iter().chain(guests.iter()) {
            for (nip, nmac) in &neigh {
                let _ = inj.send_frame(&build_arp_reply(*g, hostmac, *nip, *nmac));
            }
            if garp_tick {
                let _ = inj.send_garp(*g, hostmac);
            }
        }
        log::debug!(
            "arp-keepalive: {} guest + {} host v4 x {} neighbours{}",
            guests.len(),
            host_v4s.len(),
            neigh.len(),
            if garp_tick { " + garp" } else { "" }
        );
        Ok(())
    }

    /// Solicit every installed guest on the guest-facing bridge: an RFC 5227 ACD probe
    /// (spa=0.0.0.0) for v4, a DAD-style NS (src=::, no SLLAO) for v6. A present guest
    /// defends its address; the reply enters the OUT path and refreshes its `seen`. The
    /// probes are deliberately ADDRESS-ANONYMOUS: this frame is delivered inside the
    /// guest bridge, where the host's L2 identity is the bridge mac — a
    /// probe with sender = host-ip @ HOSTMAC would repoint every guest's neighbour
    /// entry for the host to HOSTMAC, and the guests' host-bound traffic would then be
    /// MAC-NAT'd out the uplink instead of delivered locally (host<->VM black-holes
    /// until the guest re-ARPs). spa=0 / src=:: give receivers nothing to cache, while
    /// still soliciting the defense reply needed to keep the entry alive (see afpacket builders).
    ///
    /// DAD-conflict grace: a guest that JUST produced a control frame is skipped. Its
    /// v6 DAD NS is itself a learn event (target-learned → proxied within ms), so the
    /// address may still be TENTATIVE on the guest when the next probe tick fires —
    /// and receiving someone else's DAD-form NS for a tentative address is, per RFC
    /// 4862, a duplicate: the guest would abort the address (observed as SLAAC leases
    /// dying under load). A skip re-asserts `seen` from the control plane instead
    /// (backend.refresh_seen — see the skip branch below for why the control frame's
    /// own datapath mark is not enough on nft).
    ///
    /// The grace MUST NOT exceed the flush→probe offset (= the aging tick, timeout/2):
    /// probes fire midway between flushes, so with grace ≤ that offset a skipped probe
    /// implies the control frame came AFTER the previous flush. A longer grace can
    /// align as flush → (skipped probe) → flush and age out a silent-but-present
    /// guest.
    fn probe(&mut self) -> Result<()> {
        let Some(inj) = &self.probe_injector else {
            return Ok(());
        };
        let Some(hostmac) = self.snap.hostmac else {
            return Ok(());
        };
        if self.installed.is_empty() {
            return Ok(());
        }
        self.backend.arm_probe()?;
        let aging_secs = (self.cli.timeout / 2).max(1); // same period the timer uses
        let grace = Duration::from_secs(aging_secs.min(5)); // 5s covers any DAD window
        let ips: Vec<IpAddr> = self.installed.keys().copied().collect();
        let mut send_failed = false;
        for ip in &ips {
            if self
                .entries
                .get(ip)
                .is_some_and(|e| e.last_ctrl.elapsed() < grace)
            {
                // Possibly mid-DAD/ACD — don't solicit. But don't lean on the control
                // frame's own seen mark either: on nft that mark is a kernel-clock
                // timeout, and a frame that landed just after a flush leaves it with
                // an arbitrarily thin margin over the NEXT flush — any lateness of
                // this (tokio) timer then evicts a live guest (the parallel-suite
                // "silent proxies survive"/"vm1->host 100%" intermittents). Re-assert
                // it from the control plane: skip ⇒ seen fresh, margin a full period.
                if let Err(e) = self.backend.refresh_seen(*ip) {
                    log::debug!("probe skip refresh_seen {ip}: {e:#}");
                }
                continue;
            }
            match ip {
                IpAddr::V4(g) => {
                    if let Err(e) = inj.send_frame(&build_arp_probe(*g, hostmac)) {
                        log::warn!("aging probe send {ip}: {e:#}");
                        send_failed = true;
                    }
                }
                IpAddr::V6(g) => {
                    if let Err(e) = inj.send_frame(&build_ns_dad(*g, hostmac)) {
                        log::warn!("aging probe send {ip}: {e:#}");
                        send_failed = true;
                    }
                }
            }
        }
        if send_failed {
            // arm_probe() cleared every mark. Keep this round conservative: a send error
            // must never turn into an eviction, and the following flush is skipped by
            // on_tick(). Re-assert all entries so a later recovery starts with live state.
            for ip in ips {
                if let Err(e) = self.backend.refresh_seen(ip) {
                    log::warn!("aging probe restore seen {ip}: {e:#}");
                }
            }
            return Err(anyhow!("one or more aging probes failed"));
        }
        Ok(())
    }

    // ---- fwd host routes ----

    async fn write_host_route(&mut self, ip: IpAddr) -> Result<()> {
        if !self.is_fwd() {
            return Ok(());
        }
        // vmroute table disabled (-1) → don't write any host route.
        let Some(table) = self.cli.vmroute_table.0 else {
            return Ok(());
        };
        let Some(br_index) = self.snap.br_index else {
            return Ok(());
        };
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
        let Some(name) = self.br_name(br_index).await else {
            return;
        };
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
        let Some(cfg) = self.saved_br_cfg.take() else {
            return;
        };
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
        let Some(br_index) = target else {
            return Ok(());
        };
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
        AddrInfo {
            ip: ip.parse().unwrap(),
            plen,
            global: true,
            noprefixroute: false,
            rt_priority: 0,
        }
    }

    #[test]
    fn apf_discovery_schedule_is_bounded() {
        for tick in 1..=APF_DISCOVERY_FAST_TICKS {
            assert!(apf_discovery_due(tick), "fast tick {tick} must probe");
        }
        assert!(!apf_discovery_due(APF_DISCOVERY_FAST_TICKS + 1));
        assert!(!apf_discovery_due(APF_DISCOVERY_SLOW_EVERY - 1));
        assert!(apf_discovery_due(APF_DISCOVERY_SLOW_EVERY));
        assert!(apf_discovery_due(APF_DISCOVERY_SLOW_EVERY * 2));
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
