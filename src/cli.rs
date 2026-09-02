//! Command-line interface. Flags mirror ARCHITECTURE.md §cli 參數.
#![forbid(unsafe_code)]

use clap::{Parser, ValueEnum};
use std::net::Ipv4Addr;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Engine {
    /// nftables offload (pure netlink, no ebpf). For linux containers w/ NF_TABLES.
    Nft,
    /// ebpf offload (tc clsact, no nftables). For Android GKI.
    Ebpf,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// up0 itself joins a bridge; kernel bridge forwards. Hooks: up0 egress + ingress.
    Direct,
    /// up0 can't bridge (e.g. wlan0 STA); pbridge makes a veth pair fwd0╌fwd1 (and
    /// brings both up) and forwards between up0 and fwd0. The operator enslaves fwd1
    /// into the VM bridge; pbridge tracks fwd1.master dynamically (it only pins up0).
    /// Hooks: fwd0 ingress + up0 ingress.
    Fwd,
    /// Like `fwd`, but with the ND/ARP offload workaround on by default: each learned
    /// guest v4+v6 address is also installed onto up0 so an aggressive upstream offload
    /// (e.g. Android Wi-Fi APF) answers ARP/NS for it with HOSTMAC. Equivalent to
    /// `-m fwd --offload-workaround v4,v6`; an explicit `--offload-workaround` overrides
    /// the families. See §ND/ARP offload 繞道.
    #[value(name = "fwd-with-offload")]
    FwdOffload,
}

/// A routing-table id or rule priority that may also be "skip". Parsed from:
///   `-1`     → None (skip writing the route/rule entirely)
///   a number → that exact id/priority
///   a name   → looked up (builtin unspec/default/main/local + /etc/iproute2/rt_tables);
///              an unknown name is an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteTarget(pub Option<u32>);

impl std::str::FromStr for RouteTarget {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let t = s.trim();
        if t == "-1" {
            return Ok(RouteTarget(None));
        }
        if let Ok(n) = t.parse::<u32>() {
            return Ok(RouteTarget(Some(n)));
        }
        for (name, id) in [("unspec", 0u32), ("default", 253), ("main", 254), ("local", 255)] {
            if name == t {
                return Ok(RouteTarget(Some(id)));
            }
        }
        if let Ok(content) = std::fs::read_to_string("/etc/iproute2/rt_tables") {
            for line in content.lines() {
                let line = line.split('#').next().unwrap_or("").trim();
                let mut it = line.split_whitespace();
                if let (Some(id), Some(name)) = (it.next(), it.next()) {
                    if name == t {
                        if let Ok(n) = id.parse::<u32>() {
                            return Ok(RouteTarget(Some(n)));
                        }
                    }
                }
            }
        }
        Err(format!("unknown table/rule name {s:?} (use -1, a number, or an rt_tables name)"))
    }
}

/// Which learned-address families the offload workaround installs onto up0.
/// v4 = guest IPv4, v6 = guest IPv6 global, v6ll = guest IPv6 link-local.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct OffloadFamilies {
    pub v4: bool,
    pub v6: bool,
    pub v6ll: bool,
}

impl std::str::FromStr for OffloadFamilies {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let mut f = OffloadFamilies::default();
        for tok in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
            match tok {
                "v4" => f.v4 = true,
                "v6" => f.v6 = true,
                "v6ll" => f.v6ll = true,
                other => return Err(format!("unknown family {other:?} (want v4,v6,v6ll)")),
            }
        }
        if !f.v4 && !f.v6 && !f.v6ll {
            return Err("offload-workaround needs at least one of v4,v6,v6ll".into());
        }
        Ok(f)
    }
}

/// entry capacity limits: v4_per_mac, v6_per_mac, v4_global, v6_global.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MaxCap {
    pub v4_per_mac: u32,
    pub v6_per_mac: u32,
    pub v4_global: u32,
    pub v6_global: u32,
}

impl Default for MaxCap {
    fn default() -> Self {
        MaxCap { v4_per_mac: 16, v6_per_mac: 64, v4_global: 256, v6_global: 1024 }
    }
}

impl std::str::FromStr for MaxCap {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let p: Vec<&str> = s.split(',').map(|x| x.trim()).collect();
        if p.len() != 4 {
            return Err(format!("expected 4 comma-separated values, got {}", p.len()));
        }
        let n = |x: &str| x.parse::<u32>().map_err(|e| format!("bad number {x:?}: {e}"));
        Ok(MaxCap {
            v4_per_mac: n(p[0])?,
            v6_per_mac: n(p[1])?,
            v4_global: n(p[2])?,
            v6_global: n(p[3])?,
        })
    }
}

#[derive(Parser, Debug, Clone)]
#[command(name = "pbridge", version, disable_version_flag = true,
          about = "pseudo-bridge MAC-NAT offload")]
pub struct Cli {
    /// Print version and exit.
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    pub version: Option<bool>,

    /// Upstream interface (up0).
    #[arg(short = 'i', long = "interface")]
    pub interface: String,

    /// Offload engine.
    #[arg(short = 'e', long = "offload-engine", value_enum)]
    pub engine: Engine,

    /// Topology mode.
    #[arg(short = 'm', long = "mode", value_enum)]
    pub mode: Mode,

    /// Convenience: at session init, enslave the guest-facing port (direct: up0,
    /// fwd: fwd1) into this existing bridge — and do NOTHING else with it. The syncer
    /// keeps tracking the bridge dynamically via up0.master / fwd1.master, so the
    /// operator may still detach / re-attach / swap / delete bridges at any time;
    /// pbridge never fights that. A missing bridge is a warning, not an error (attach
    /// manually later). Re-applied on re-init (e.g. up0 disappeared and came back —
    /// in fwd mode the veth pair is recreated then, so it would otherwise sit
    /// bridge-less until the operator re-attaches).
    #[arg(short = 'b', long = "bridge")]
    pub bridge: Option<String>,

    /// Log filter: a level (error|warn|info|debug|trace) or an env_logger filter
    /// string (e.g. `pbridge=debug`). The RUST_LOG env var, if set, overrides this.
    #[arg(long = "loglevel", default_value = "info")]
    pub loglevel: String,

    /// fwd mode veth name (fwd0). Default: {ifname[:12]}-if
    #[arg(long = "fwd-device-if")]
    pub fwd_device_if: Option<String>,

    /// fwd mode veth name (fwd1). Default: {ifname[:12]}-br
    #[arg(long = "fwd-device-br")]
    pub fwd_device_br: Option<String>,

    /// nft NFLOG group.
    #[arg(long = "nflog-group", default_value_t = 32123)]
    pub nflog_group: u16,

    /// entry aging base interval in seconds; pbridge probes guests at timeout/2 and flushes
    /// liveness on the next tick, removing only entries that did not answer.
    #[arg(long = "timeout", default_value_t = 30)]
    pub timeout: u64,

    /// entry caps: v4_per_mac,v6_per_mac,v4_global,v6_global
    #[arg(long = "max-cap", default_value = "16,64,256,1024")]
    pub max_cap: MaxCap,

    /// Offload-workaround families (fwd mode only): comma list of `v4,v6,v6ll`. For each
    /// listed family the syncer installs every learned guest (vmroute) address of that
    /// family onto up0 (v4 `/32`, v6/v6ll `/128`; noprefixroute, nodad, deprecated,
    /// metric=<magic>), so a host with an aggressive ND/ARP offload (e.g. Android APF,
    /// which drops NS/ARP whose target isn't a *local* address) answers the gateway on the
    /// guest's behalf with HOSTMAC. The magic-metric tag keeps these addresses
    /// distinguishable from the host's real ones (excluded from host-ip detection and the
    /// bridge mirror). Off unless set; inert in direct mode. e.g. `--offload-workaround v6`.
    #[arg(long = "offload-workaround")]
    pub offload_workaround: Option<OffloadFamilies>,

    /// Magic IFA_RT_PRIORITY tag for the offload-workaround proxy addresses (see above).
    /// Accepts decimal or 0x-hex.
    #[arg(long = "offload-workaround-magic", value_parser = parse_magic, default_value_t = 4243672773)]
    pub offload_workaround_magic: u32,

    /// Periodic ARP keepalive interval in seconds (0 = off). Every interval, for each
    /// learned guest IPv4, send a unicast ARP reply (spa=guest, sha=HOSTMAC) to every v4
    /// neighbour on up0, plus a periodic gratuitous ARP broadcast. Keeps upstream
    /// neighbour caches REACHABLE from our (outbound) side, so peers never need to
    /// ARP-request the guest — works around Wi-Fi firmware ARP offload that only answers
    /// for a single IPv4 (e.g. Qualcomm WMI_SET_ARP_NS_OFFLOAD) and drops other ARP
    /// requests in powersave. Recommended on Android Wi-Fi: 10.
    #[arg(long = "arp-keepalive", default_value_t = 0)]
    pub arp_keepalive: u64,

    /// Routing table for the per-guest vmroutes (host → guest; external traffic never hits
    /// routing — it's redirected by the datapath into the bridge and switched). Used with the
    /// `iif lo` rule below so only locally-originated traffic consults it; use a *dedicated*
    /// table (not `local`/`main`). `-1` skips writing vmroutes; a number is that table; a name
    /// resolves via rt_tables. Default `200`.
    #[arg(long = "vmroute-table", default_value = "200")]
    pub vmroute_table: RouteTarget,

    /// ip-rule priority for the `iif lo lookup <vmroute-table>` rule (only locally-originated
    /// traffic consults the table). `-1` skips the rule (e.g. if you point `--vmroute-table` at
    /// a table that's already consulted, like `local`); a number is the priority. Default `11000`.
    #[arg(long = "vmroute-rule", default_value = "11000")]
    pub vmroute_rule: RouteTarget,

    /// APF watchdog (Android/Qualcomm, `-e ebpf` only): automatically maintain the
    /// firmware ICMP-echo PASS list from DHCPACK leases observed for guests behind
    /// pbridge. Mutually exclusive with `--apf-watchdog-guest`, which is the fixed,
    /// operator-supplied allow-list mode.
    #[arg(long = "apf-watchdog", conflicts_with = "apf_watchdog_guest")]
    pub apf_watchdog: bool,

    /// APF watchdog (Android/Qualcomm, `-e ebpf` only; repeatable, max 8 IPv4): keep an
    /// "ICMP echo request to this guest → PASS" rule alive in the Wi-Fi firmware's APF
    /// program. The Xiaomi vendor APF drops ALL inbound IPv4 ICMP echo requests
    /// (`DROPPED_ICMP_ECHO`), and NetworkStack regenerates the program on Doze / RA /
    /// address / multicast / keepalive changes, so a hand-installed patch is short-lived.
    /// With this flag pbridge kprobes the driver's single APF vendor-command entry point,
    /// and after every *external* install (its own writes are filtered by TGID in-kernel)
    /// re-reads the firmware's APF work memory, re-inserts the pass rules for these
    /// addresses, writes it back and verifies it byte-for-byte.
    ///
    /// Fixed list on purpose: it widens the host's inbound ICMP surface, so the operator
    /// names the addresses instead of pbridge deriving them from the (aging, churning)
    /// learn table. Empty = feature off.
    #[arg(long = "apf-watchdog-guest", value_name = "IPV4")]
    pub apf_watchdog_guest: Vec<Ipv4Addr>,

    /// Debounce window (ms) for coalescing one NetworkStack APF update's several vendor
    /// commands into a single repatch transaction.
    #[arg(long = "apf-watchdog-debounce-ms", default_value_t = 200)]
    pub apf_watchdog_debounce_ms: u64,

    /// How to keep the APF pass rules alive. Only meaningful together with
    /// `--apf-watchdog`/`--apf-watchdog-guest`; the two methods are mutually exclusive.
    ///
    /// `watchdog` (default) repairs the program *after* NetworkStack installs it.
    /// `inflight` rewrites it *before* the kernel sees it, which removes the repair
    /// window but cannot fix an install it declines to patch. See [`ApfMethod`].
    #[arg(long = "apf-method", value_enum, default_value_t = ApfMethod::Watchdog)]
    pub apf_method: ApfMethod,
}

/// Which mechanism maintains the APF pass rules. Mutually exclusive: each has a failure mode
/// the other does not, so running both would double-patch and confuse the "already ours"
/// detection.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ApfMethod {
    /// React after the fact. A BPF kprobe on the driver's APF vendor-command entry point
    /// notices an external install, then pbridge runs
    /// `disable → read → patch → write → read back → enable` against the firmware's work
    /// memory.
    ///
    /// Trade-off: there is a live window — the debounce plus one transaction — where the
    /// unpatched program runs. In exchange it repairs *any* install it can parse, whatever
    /// shape it arrives in, and it proves the result by reading the program back out of the
    /// firmware.
    Watchdog,
    /// Intercept and rewrite in flight. ptrace the Wi-Fi HAL (the process that actually
    /// issues the vendor command — NetworkStack only computes the bytes and passes them down
    /// via AIDL), stop it at `sendmsg` entry, and patch the program inside its own buffer.
    ///
    /// Trade-off: no window at all, and no firmware readback either — correctness rests on
    /// the offline-verified patcher plus a readback of the tracee's buffer. It declines
    /// anything it cannot patch safely (a fragmented install, no headroom in the HAL's
    /// buffer, a program with no drop site) and lets the stock program through, so those
    /// installs go unpatched entirely rather than being repaired late.
    ///
    /// Works with either address mode. With `--apf-watchdog` the tracer reads whichever
    /// DHCP-derived set is current when an install arrives; a lease change also triggers one
    /// repatch transaction so the already-installed program picks up the new address instead
    /// of waiting for NetworkStack's next install.
    ///
    /// Needs CAP_SYS_PTRACE and permission to ptrace the `hal_wifi_default` domain. Uses
    /// PTRACE_SEIZE, so if pbridge dies the kernel resumes the HAL rather than leaving it
    /// stopped.
    Inflight,
}

/// Max APF watchdog guest addresses. Each costs 9 program bytes (a `jeq r0,<ip>,PASS`)
/// plus 2 for the shared `ldw r0,[30]`; the patcher also refuses to exceed the debugbuf.
pub const APF_WATCHDOG_MAX_GUESTS: usize = 8;

/// APF watchdog guest source. `Dhcp` only trusts DHCPACKs observed on the guest-facing
/// segment; `Fixed` is the explicit operator allow-list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApfWatchdogMode {
    Off,
    Dhcp,
    Fixed(Vec<Ipv4Addr>),
}

/// Validate the parsed CLI beyond what clap can express per-arg.
pub fn validate_apf_watchdog(cli: &Cli) -> Result<ApfWatchdogMode, String> {
    if !cli.apf_watchdog && cli.apf_watchdog_guest.is_empty() {
        return Ok(ApfWatchdogMode::Off);
    }
    if cli.engine != Engine::Ebpf {
        return Err(
            "--apf-watchdog/--apf-watchdog-guest needs -e ebpf: overwrite detection is a BPF \
             kprobe on the driver's APF vendor command, and there is no polling fallback"
                .into(),
        );
    }
    if cli.apf_watchdog {
        return Ok(ApfWatchdogMode::Dhcp);
    }
    let mut seen = std::collections::BTreeSet::new();
    for ip in &cli.apf_watchdog_guest {
        if !seen.insert(*ip) {
            return Err(format!("--apf-watchdog-guest {ip}: duplicate address"));
        }
    }
    if seen.len() > APF_WATCHDOG_MAX_GUESTS {
        return Err(format!(
            "--apf-watchdog-guest: {} addresses given, at most {APF_WATCHDOG_MAX_GUESTS} supported",
            seen.len()
        ));
    }
    // Sorted: the patcher emits one jeq per address in this order, so the generated
    // program (and therefore the readback compare) is independent of CLI argument order.
    Ok(ApfWatchdogMode::Fixed(seen.into_iter().collect()))
}

/// The APF feature resolved into "which method, over which addresses".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApfPlan {
    Off,
    /// Kprobe plus repatch transactions. Carries the watchdog's own mode, which may derive
    /// addresses from DHCP.
    Watchdog(ApfWatchdogMode),
    /// ptrace the Wi-Fi HAL. Carries the same address mode as the watchdog: a DHCP-derived
    /// list works here too, because observing a lease is asynchronous — the tracer reads
    /// whatever set is current when an install arrives, and a lease change corrects the
    /// already-installed program through one repatch transaction.
    Inflight(ApfWatchdogMode),
}

/// Resolve `--apf-method` against the address configuration.
pub fn validate_apf_plan(cli: &Cli) -> Result<ApfPlan, String> {
    let mode = validate_apf_watchdog(cli)?;
    if mode == ApfWatchdogMode::Off {
        // A method without any addresses is not an error, just nothing to do — but say so,
        // because "I passed --apf-method inflight and nothing happened" is otherwise silent.
        if cli.apf_method != ApfMethod::Watchdog {
            return Err(
                "--apf-method inflight has no effect without --apf-watchdog or \
                 --apf-watchdog-guest"
                    .into(),
            );
        }
        return Ok(ApfPlan::Off);
    }
    match cli.apf_method {
        ApfMethod::Watchdog => Ok(ApfPlan::Watchdog(mode)),
        ApfMethod::Inflight => Ok(ApfPlan::Inflight(mode)),
    }
}

/// Parse a u32 magic value as decimal or 0x-prefixed hex.
fn parse_magic(s: &str) -> Result<u32, String> {
    let t = s.trim();
    let r = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(h, 16)
    } else {
        t.parse::<u32>()
    };
    match r {
        Ok(0) => Err("magic value must be non-zero".into()),
        Ok(v) => Ok(v),
        Err(e) => Err(format!("bad magic value {s:?}: {e}")),
    }
}

impl Cli {
    pub fn fwd0(&self) -> String {
        self.fwd_device_if.clone().unwrap_or_else(|| {
            let s: String = self.interface.chars().take(12).collect();
            format!("{s}-if")
        })
    }
    pub fn fwd1(&self) -> String {
        self.fwd_device_br.clone().unwrap_or_else(|| {
            let s: String = self.interface.chars().take(12).collect();
            format!("{s}-br")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maxcap_parse() {
        let m: MaxCap = "1,2,3,4".parse().unwrap();
        assert_eq!(m, MaxCap { v4_per_mac: 1, v6_per_mac: 2, v4_global: 3, v6_global: 4 });
        assert!("1,2,3".parse::<MaxCap>().is_err());
        assert!("a,2,3,4".parse::<MaxCap>().is_err());
    }

    #[test]
    fn fwd_defaults() {
        let cli = Cli {
            version: None,
            interface: "wlan0verylongname".into(),
            engine: Engine::Ebpf,
            mode: Mode::Fwd,
            bridge: None,
            loglevel: "info".into(),
            fwd_device_if: None,
            fwd_device_br: None,
            nflog_group: 32123,
            timeout: 30,
            max_cap: MaxCap::default(),
            offload_workaround: None,
            offload_workaround_magic: 4243672773,
            arp_keepalive: 0,
            vmroute_table: RouteTarget(Some(200)),
            vmroute_rule: RouteTarget(Some(11000)),
            apf_watchdog: false,
            apf_watchdog_guest: vec![],
            apf_watchdog_debounce_ms: 200,
            apf_method: ApfMethod::Watchdog,
        };
        assert_eq!(cli.fwd0(), "wlan0verylon-if");
        assert_eq!(cli.fwd1(), "wlan0verylon-br");
    }

    fn parse_args(extra: &[&str]) -> Result<Cli, clap::Error> {
        let mut argv = vec![
            "pbridge",
            "-i",
            "wlan0",
            "-e",
            "ebpf",
            "-m",
            "fwd-with-offload",
        ];
        argv.extend_from_slice(extra);
        Cli::try_parse_from(argv)
    }

    #[test]
    fn apf_watchdog_off_by_default() {
        let cli = parse_args(&[]).unwrap();
        assert!(cli.apf_watchdog_guest.is_empty());
        assert_eq!(validate_apf_watchdog(&cli), Ok(ApfWatchdogMode::Off));
    }

    #[test]
    fn apf_watchdog_rejects_ipv6() {
        assert!(parse_args(&["--apf-watchdog-guest", "fe80::1"]).is_err());
        assert!(parse_args(&["--apf-watchdog-guest", "not-an-ip"]).is_err());
    }

    #[test]
    fn apf_watchdog_sorts_and_rejects_duplicates() {
        let cli = parse_args(&[
            "--apf-watchdog-guest",
            "192.168.1.204",
            "--apf-watchdog-guest",
            "192.168.1.7",
        ])
        .unwrap();
        assert_eq!(
            validate_apf_watchdog(&cli),
            Ok(ApfWatchdogMode::Fixed(vec![
                Ipv4Addr::new(192, 168, 1, 7),
                Ipv4Addr::new(192, 168, 1, 204)
            ]))
        );

        let dup = parse_args(&[
            "--apf-watchdog-guest",
            "192.168.1.204",
            "--apf-watchdog-guest",
            "192.168.1.204",
        ])
        .unwrap();
        assert!(validate_apf_watchdog(&dup).is_err());
    }

    #[test]
    fn apf_watchdog_guest_cap() {
        let mut eight = Vec::new();
        for n in 1..=8u8 {
            eight.push("--apf-watchdog-guest".to_string());
            eight.push(format!("10.0.0.{n}"));
        }
        let refs: Vec<&str> = eight.iter().map(|s| s.as_str()).collect();
        let cli = parse_args(&refs).unwrap();
        assert_eq!(
            validate_apf_watchdog(&cli).map(|v| match v {
                ApfWatchdogMode::Fixed(v) => v.len(),
                _ => 0,
            }),
            Ok(8)
        );

        let mut nine = eight.clone();
        nine.push("--apf-watchdog-guest".into());
        nine.push("10.0.0.9".into());
        let refs: Vec<&str> = nine.iter().map(|s| s.as_str()).collect();
        let cli = parse_args(&refs).unwrap();
        assert!(
            validate_apf_watchdog(&cli).is_err(),
            "9th address must be rejected"
        );
    }

    #[test]
    fn apf_watchdog_auto_mode() {
        let cli = parse_args(&["--apf-watchdog"]).unwrap();
        assert_eq!(validate_apf_watchdog(&cli), Ok(ApfWatchdogMode::Dhcp));
        assert!(parse_args(&["--apf-watchdog", "--apf-watchdog-guest", "192.168.1.204"]).is_err());
    }

    #[test]
    fn apf_method_defaults_to_watchdog_and_off_means_off() {
        let cli = parse_args(&[]).unwrap();
        assert_eq!(cli.apf_method, ApfMethod::Watchdog);
        assert_eq!(validate_apf_plan(&cli), Ok(ApfPlan::Off));
    }

    #[test]
    fn apf_method_selects_between_the_two_mechanisms() {
        let wd = parse_args(&["--apf-watchdog-guest", "192.168.1.204"]).unwrap();
        assert_eq!(
            validate_apf_plan(&wd),
            Ok(ApfPlan::Watchdog(ApfWatchdogMode::Fixed(vec![
                "192.168.1.204".parse().unwrap()
            ])))
        );

        let inf = parse_args(&[
            "--apf-method",
            "inflight",
            "--apf-watchdog-guest",
            "192.168.1.204",
        ])
        .unwrap();
        assert_eq!(
            validate_apf_plan(&inf),
            Ok(ApfPlan::Inflight(ApfWatchdogMode::Fixed(vec![
                "192.168.1.204".parse().unwrap()
            ])))
        );
    }

    /// DHCP-derived addresses work with either method: observing a lease is asynchronous, so
    /// the in-flight tracer can read an updated set without ever blocking a syscall.
    #[test]
    fn apf_method_inflight_accepts_dhcp_mode() {
        let cli = parse_args(&["--apf-method", "inflight", "--apf-watchdog"]).unwrap();
        assert_eq!(
            validate_apf_plan(&cli),
            Ok(ApfPlan::Inflight(ApfWatchdogMode::Dhcp))
        );
    }

    /// The two methods must never both be live: they would double-patch, and each one's
    /// "already carries our rules" check would see the other's work.
    #[test]
    fn apf_plan_is_exactly_one_mechanism() {
        for args in [
            vec!["--apf-watchdog-guest", "192.168.1.204"],
            vec![
                "--apf-method",
                "inflight",
                "--apf-watchdog-guest",
                "192.168.1.204",
            ],
            vec!["--apf-watchdog"],
        ] {
            let cli = parse_args(&args).unwrap();
            let plan = validate_apf_plan(&cli).unwrap();
            let watchdog_live = matches!(plan, ApfPlan::Watchdog(_));
            let inflight_live = matches!(plan, ApfPlan::Inflight(_));
            assert!(
                watchdog_live ^ inflight_live,
                "exactly one mechanism must be live for {args:?}, got {plan:?}"
            );
        }
    }

    /// A method with no address configuration at all is rejected rather than silently doing
    /// nothing — the failure mode it prevents is "I passed the flag and saw no effect".
    #[test]
    fn apf_method_inflight_needs_some_address_source() {
        let bare = parse_args(&["--apf-method", "inflight"]).unwrap();
        let err = validate_apf_plan(&bare).expect_err("must reject a bare method");
        assert!(err.contains("no effect"), "{err}");
    }

    #[test]
    fn apf_method_inflight_returns_the_sorted_guest_list() {
        let cli = parse_args(&[
            "--apf-method",
            "inflight",
            "--apf-watchdog-guest",
            "192.168.1.204",
            "--apf-watchdog-guest",
            "192.168.1.153",
        ])
        .unwrap();
        assert_eq!(
            validate_apf_plan(&cli),
            Ok(ApfPlan::Inflight(ApfWatchdogMode::Fixed(vec![
                "192.168.1.153".parse().unwrap(),
                "192.168.1.204".parse().unwrap()
            ]))),
            "addresses must come back sorted, like the watchdog's"
        );
    }

    #[test]
    fn apf_method_inflight_rejects_nft_engine() {
        let mut cli = parse_args(&[
            "--apf-method",
            "inflight",
            "--apf-watchdog-guest",
            "192.168.1.204",
        ])
        .unwrap();
        cli.engine = Engine::Nft;
        assert!(validate_apf_plan(&cli).is_err());
    }

    #[test]
    fn apf_watchdog_requires_ebpf() {
        let cli = Cli::try_parse_from([
            "pbridge",
            "-i",
            "wlan0",
            "-e",
            "nft",
            "-m",
            "fwd",
            "--apf-watchdog",
        ])
        .unwrap();
        let err = validate_apf_watchdog(&cli).unwrap_err();
        assert!(err.contains("-e ebpf"), "{err}");
    }

    #[test]
    fn magic_parse() {
        assert_eq!(parse_magic("0x70627269"), Ok(0x7062_7269));
        assert_eq!(parse_magic("1885434217"), Ok(1885434217));
        assert!(parse_magic("0").is_err());
        assert!(parse_magic("xyz").is_err());
    }

    #[test]
    fn route_target_parse() {
        assert_eq!("-1".parse::<RouteTarget>(), Ok(RouteTarget(None)));
        assert_eq!("200".parse::<RouteTarget>(), Ok(RouteTarget(Some(200))));
        assert_eq!("local".parse::<RouteTarget>(), Ok(RouteTarget(Some(255))));
        assert_eq!("main".parse::<RouteTarget>(), Ok(RouteTarget(Some(254))));
        assert!("nope-no-such-table".parse::<RouteTarget>().is_err());
    }

    #[test]
    fn families_parse() {
        let f: OffloadFamilies = "v6".parse().unwrap();
        assert_eq!(f, OffloadFamilies { v4: false, v6: true, v6ll: false });
        let f: OffloadFamilies = "v4, v6 ,v6ll".parse().unwrap();
        assert_eq!(f, OffloadFamilies { v4: true, v6: true, v6ll: true });
        assert!("".parse::<OffloadFamilies>().is_err());
        assert!("v5".parse::<OffloadFamilies>().is_err());
    }
}
