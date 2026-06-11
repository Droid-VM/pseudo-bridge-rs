//! Command-line interface. Flags mirror ARCHITECTURE.md §cli 參數.
#![forbid(unsafe_code)]

use clap::{Parser, ValueEnum};

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
#[command(name = "pbridge", version, about = "pseudo-bridge MAC-NAT offload")]
pub struct Cli {
    /// Upstream interface (up0).
    #[arg(short = 'i', long = "interface")]
    pub interface: String,

    /// Offload engine.
    #[arg(short = 'e', long = "offload-engine", value_enum)]
    pub engine: Engine,

    /// Topology mode.
    #[arg(short = 'm', long = "mode", value_enum)]
    pub mode: Mode,

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

    /// entry idle aging seconds.
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
            interface: "wlan0verylongname".into(),
            engine: Engine::Ebpf,
            mode: Mode::Fwd,
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
        };
        assert_eq!(cli.fwd0(), "wlan0verylon-if");
        assert_eq!(cli.fwd1(), "wlan0verylon-br");
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
