//! rtnetlink wrapper: link/addr/route/rule operations + a multicast monitor.
//! The syncer uses this for everything topology-related (no shelling out to `ip`).
//! All netlink I/O goes through the safe `rtnetlink` crate — no raw unsafe here.
#![forbid(unsafe_code)]

use crate::types::Mac;
use anyhow::{Context, Result};
use futures::stream::TryStreamExt;
use netlink_packet_route::address::{AddressAttribute, AddressMessage, AddressScope};
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use netlink_packet_route::route::{RouteProtocol, RouteScope, RouteType};
use netlink_packet_route::rule::RuleAction;
use netlink_packet_route::AddressFamily;
use rtnetlink::{
    Handle, LinkUnspec, LinkVeth, MulticastGroup, RouteMessageBuilder,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[allow(dead_code)] // name/present are part of the faithful link model; not all read
#[derive(Clone, Debug)]
pub struct LinkInfo {
    pub index: u32,
    pub name: String,
    pub mac: Option<Mac>,
    pub master: Option<u32>,
    pub present: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrInfo {
    pub ip: IpAddr,
    pub plen: u8,
    pub global: bool,
    pub noprefixroute: bool,
    /// IFA_RT_PRIORITY (the address "metric"). pbridge tags its own ND-offload proxy
    /// addresses with a magic value here so they're unambiguously distinguishable from
    /// the host's real addresses (which carry 0). 0 if unset.
    pub rt_priority: u32,
}

/// A monitor signal: a link or address message arrived. The core recomputes on any
/// relevant change (level-triggered); the carried metadata documents what moved.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum NlChange {
    Link { index: u32, name: Option<String> },
    Addr { index: u32 },
}

pub struct Net {
    handle: Handle,
}

impl Net {
    /// Spawn the request connection.
    pub fn connect() -> Result<Net> {
        let (conn, handle, _messages) = rtnetlink::new_connection().context("netlink connect")?;
        tokio::spawn(conn);
        Ok(Net { handle })
    }

    /// Spawn the multicast monitor; returns a receiver of change signals.
    pub fn monitor() -> Result<tokio::sync::mpsc::UnboundedReceiver<NlChange>> {
        let groups = [
            MulticastGroup::Link,
            MulticastGroup::Ipv4Ifaddr,
            MulticastGroup::Ipv6Ifaddr,
        ];
        let (conn, _handle, mut messages) =
            rtnetlink::new_multicast_connection(&groups).context("netlink monitor connect")?;
        tokio::spawn(conn);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            use futures::StreamExt;
            use netlink_packet_route::RouteNetlinkMessage as Rnm;
            use rtnetlink::packet_core::NetlinkPayload;
            while let Some((msg, _addr)) = messages.next().await {
                if let NetlinkPayload::InnerMessage(inner) = msg.payload {
                    let change = match inner {
                        Rnm::NewLink(l) | Rnm::DelLink(l) => {
                            let name = l.attributes.iter().find_map(|a| match a {
                                LinkAttribute::IfName(n) => Some(n.clone()),
                                _ => None,
                            });
                            Some(NlChange::Link { index: l.header.index, name })
                        }
                        Rnm::NewAddress(a) | Rnm::DelAddress(a) => Some(NlChange::Addr {
                            index: a.header.index,
                        }),
                        _ => None,
                    };
                    if let Some(c) = change {
                        if tx.send(c).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(rx)
    }

    fn link_from_msg(m: &LinkMessage) -> LinkInfo {
        let mut name = String::new();
        let mut mac = None;
        let mut master = None;
        for a in &m.attributes {
            match a {
                LinkAttribute::IfName(n) => name = n.clone(),
                LinkAttribute::Address(bytes) => mac = Mac::from_slice(bytes),
                LinkAttribute::Controller(idx) => master = Some(*idx),
                _ => {}
            }
        }
        LinkInfo { index: m.header.index, name, mac, master, present: true }
    }

    pub async fn get_link_by_name(&self, name: &str) -> Result<Option<LinkInfo>> {
        let mut s = self.handle.link().get().match_name(name.to_string()).execute();
        match s.try_next().await {
            Ok(Some(m)) => Ok(Some(Self::link_from_msg(&m))),
            Ok(None) => Ok(None),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ENODEV => Ok(None),
            Err(e) => Err(e).context("get_link_by_name"),
        }
    }

    pub async fn get_link_by_index(&self, index: u32) -> Result<Option<LinkInfo>> {
        let mut s = self.handle.link().get().match_index(index).execute();
        match s.try_next().await {
            Ok(Some(m)) => Ok(Some(Self::link_from_msg(&m))),
            Ok(None) => Ok(None),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ENODEV => Ok(None),
            Err(e) => Err(e).context("get_link_by_index"),
        }
    }

    pub async fn get_addrs(&self, index: u32) -> Result<Vec<AddrInfo>> {
        let mut s = self.handle.address().get().set_link_index_filter(index).execute();
        let mut out = Vec::new();
        while let Some(m) = s.try_next().await.context("get_addrs")? {
            out.push(Self::addr_from_msg(&m));
        }
        Ok(out)
    }

    fn addr_from_msg(m: &AddressMessage) -> AddrInfo {
        let plen = m.header.prefix_len;
        let global = m.header.scope == AddressScope::Universe;
        let mut noprefixroute = false;
        let mut rt_priority = 0u32;
        let mut ip: Option<IpAddr> = None;
        for a in &m.attributes {
            match a {
                // IFA_ADDRESS is the peer for p2p; IFA_LOCAL is our address. For
                // normal links they're equal; prefer Local, fall back to Address.
                AddressAttribute::Local(x) => ip = Some(*x),
                AddressAttribute::Address(x) => {
                    if ip.is_none() {
                        ip = Some(*x);
                    }
                }
                AddressAttribute::Flags(f) => {
                    use netlink_packet_route::address::AddressFlags;
                    noprefixroute = f.contains(AddressFlags::Noprefixroute);
                }
                AddressAttribute::RoutePriority(p) => rt_priority = *p,
                _ => {}
            }
        }
        AddrInfo {
            ip: ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            plen,
            global,
            noprefixroute,
            rt_priority,
        }
    }

    pub async fn link_set_up(&self, index: u32) -> Result<()> {
        let msg = LinkUnspec::new_with_index(index).up().build();
        self.handle.link().set(msg).execute().await.context("link_set_up")
    }

    /// Enslave a link into a bridge (`ip link set <dev> master <br>`).
    pub async fn link_set_master(&self, index: u32, master: u32) -> Result<()> {
        let msg = LinkUnspec::new_with_index(index).controller(master).build();
        self.handle.link().set(msg).execute().await.context("link_set_master")
    }

    /// Create a veth pair (idempotent: ignores EEXIST).
    pub async fn create_veth(&self, a: &str, b: &str) -> Result<()> {
        match self
            .handle
            .link()
            .add(LinkVeth::new(a, b).build())
            .execute()
            .await
        {
            Ok(()) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::EEXIST => Ok(()),
            Err(e) => Err(e).context("create_veth"),
        }
    }

    pub async fn link_del_by_name(&self, name: &str) -> Result<()> {
        if let Some(l) = self.get_link_by_name(name).await? {
            match self.handle.link().del(l.index).execute().await {
                Ok(()) => Ok(()),
                Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ENODEV => Ok(()),
                Err(e) => Err(e).context("link_del"),
            }
        } else {
            Ok(())
        }
    }

    pub async fn addr_add(
        &self,
        index: u32,
        ip: IpAddr,
        plen: u8,
        noprefixroute: bool,
        nodad: bool,
    ) -> Result<()> {
        self.addr_add_tagged(index, ip, plen, noprefixroute, nodad, None, false).await
    }

    /// Like `addr_add` but optionally tags the address with `metric` (IFA_RT_PRIORITY,
    /// the magic marker) and/or marks it `deprecated` (preferred_lft 0, so the host never
    /// source-selects it). Used for the ND-offload proxy addresses on up0.
    #[allow(clippy::too_many_arguments)]
    pub async fn addr_add_tagged(
        &self,
        index: u32,
        ip: IpAddr,
        plen: u8,
        noprefixroute: bool,
        nodad: bool,
        metric: Option<u32>,
        deprecated: bool,
    ) -> Result<()> {
        use netlink_packet_route::address::{AddressFlags, CacheInfo};
        let mut req = self.handle.address().add(index, ip, plen);
        if noprefixroute || nodad {
            let mut flags = AddressFlags::empty();
            if noprefixroute {
                flags |= AddressFlags::Noprefixroute;
            }
            if nodad {
                flags |= AddressFlags::Nodad;
            }
            req.message_mut().attributes.push(AddressAttribute::Flags(flags));
        }
        if let Some(m) = metric {
            req.message_mut().attributes.push(AddressAttribute::RoutePriority(m));
        }
        if deprecated {
            // preferred_lft = 0 → deprecated; valid_lft = forever (permanent).
            // CacheInfo is #[non_exhaustive]; build from default then set fields.
            let mut ci = CacheInfo::default();
            ci.ifa_preferred = 0;
            ci.ifa_valid = u32::MAX;
            req.message_mut().attributes.push(AddressAttribute::CacheInfo(ci));
        }
        match req.execute().await {
            Ok(()) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::EEXIST => Ok(()),
            Err(e) => Err(e).context("addr_add"),
        }
    }

    pub async fn addr_del(&self, index: u32, ip: IpAddr, plen: u8) -> Result<()> {
        // Build a matching AddressMessage to delete.
        let mut msg = AddressMessage::default();
        msg.header.index = index;
        msg.header.prefix_len = plen;
        msg.header.family = match ip {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };
        msg.attributes.push(AddressAttribute::Address(ip));
        match self.handle.address().del(msg).execute().await {
            Ok(()) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(e))
                if e.raw_code() == -libc::ENOENT || e.raw_code() == -libc::EADDRNOTAVAIL =>
            {
                Ok(())
            }
            Err(e) => Err(e).context("addr_del"),
        }
    }

    /// Add a host->VM route in `table`: dst/plen via oif, prefsrc=src (scope link).
    pub async fn route_add(
        &self,
        dst: IpAddr,
        plen: u8,
        oif: u32,
        src: Option<IpAddr>,
        table: u32,
    ) -> Result<()> {
        let msg = match dst {
            IpAddr::V4(d) => {
                let mut b = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(d, plen)
                    .output_interface(oif)
                    .table_id(table)
                    .scope(RouteScope::Link)
                    .protocol(RouteProtocol::Static);
                if let Some(IpAddr::V4(s)) = src {
                    b = b.pref_source(s);
                }
                b.build()
            }
            IpAddr::V6(d) => {
                let mut b = RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(d, plen)
                    .output_interface(oif)
                    .table_id(table)
                    .scope(RouteScope::Link)
                    .protocol(RouteProtocol::Static);
                if let Some(IpAddr::V6(s)) = src {
                    b = b.pref_source(s);
                }
                b.build()
            }
        };
        match self.handle.route().add(msg).replace().execute().await {
            Ok(()) => Ok(()),
            Err(e) => Err(e).context("route_add"),
        }
    }

    pub async fn route_del(&self, dst: IpAddr, plen: u8, table: u32) -> Result<()> {
        // The route we add is scope=link/proto=static, but the builder defaults to
        // scope=universe — and the kernel matches DELROUTE on scope, so a scope-less
        // delete silently misses (ESRCH) and the route leaks. Wildcard scope (NoWhere)
        // + proto (Unspec) like `ip route del` does, so dst+table is enough to match.
        let msg = match dst {
            IpAddr::V4(d) => RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(d, plen)
                .table_id(table)
                .scope(RouteScope::NoWhere)
                .protocol(RouteProtocol::Unspec)
                .build(),
            IpAddr::V6(d) => RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(d, plen)
                .table_id(table)
                .scope(RouteScope::NoWhere)
                .protocol(RouteProtocol::Unspec)
                .build(),
        };
        match self.handle.route().del(msg).execute().await {
            Ok(()) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ESRCH => Ok(()),
            Err(e) => Err(e).context("route_del"),
        }
    }

    /// Delete the kernel's auto `local <ip> dev <oif>` route (table `local`/255, type
    /// RTN_LOCAL) that address assignment creates. Used for offload-workaround proxy
    /// addresses: dropping it lets host-originated traffic to a guest forward via the
    /// vmroute instead of being delivered locally, while the address stays assigned (so the
    /// upstream ND/ARP offload still answers for it). Idempotent.
    ///
    /// Returns whether a route was actually deleted: `Ok(false)` = nothing matched (ESRCH/
    /// ENOENT). The caller MUST treat false as "the insert hasn't landed yet", not success —
    /// the kernel inserts the local route for a fresh address asynchronously, and on some
    /// kernels (observed: 6.17; 7.0 wins the race) it lands AFTER the RTM_NEWADDR ack, so a
    /// single fire-and-forget delete leaves the route shadowing the vmroute forever.
    pub async fn del_local_route(&self, ip: IpAddr, plen: u8) -> Result<bool> {
        const RT_TABLE_LOCAL: u32 = 255;
        // Match the kernel's local route: type=local in table local. The builder defaults
        // scope=Universe/proto=Static, but the route is scope=host/proto=kernel — so wildcard
        // both (NoWhere scope + Unspec proto) or the delete won't match. No oif filter: the
        // v6 local route can live on `lo`, and a /128 has exactly one local route anyway.
        let msg = match ip {
            IpAddr::V4(d) => RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(d, plen)
                .table_id(RT_TABLE_LOCAL)
                .kind(RouteType::Local)
                .scope(RouteScope::NoWhere)
                .protocol(RouteProtocol::Unspec)
                .build(),
            IpAddr::V6(d) => RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(d, plen)
                .table_id(RT_TABLE_LOCAL)
                .kind(RouteType::Local)
                .scope(RouteScope::NoWhere)
                .protocol(RouteProtocol::Unspec)
                .build(),
        };
        match self.handle.route().del(msg).execute().await {
            Ok(()) => Ok(true),
            Err(rtnetlink::Error::NetlinkError(e))
                if e.raw_code() == -libc::ESRCH || e.raw_code() == -libc::ENOENT =>
            {
                Ok(false)
            }
            Err(e) => Err(e).context("del_local_route"),
        }
    }

    /// IPv4 default-route gateway addresses (next-hops of 0.0.0.0/0). Used by the
    /// ARP keepalive to make sure the gateway is always covered even if its neighbour
    /// entry was garbage-collected. Best-effort: returns empty on any error.
    pub async fn default_gw4(&self) -> Vec<Ipv4Addr> {
        use netlink_packet_route::route::RouteAddress;
        let msg = RouteMessageBuilder::<Ipv4Addr>::new().build();
        let mut s = self.handle.route().get(msg).execute();
        let mut out = Vec::new();
        while let Ok(Some(m)) = s.try_next().await {
            if m.header.destination_prefix_length != 0 {
                continue; // only 0.0.0.0/0 (default)
            }
            for a in &m.attributes {
                if let netlink_packet_route::route::RouteAttribute::Gateway(RouteAddress::Inet(g)) =
                    a
                {
                    out.push(*g);
                }
            }
        }
        out
    }

    /// Usable IPv4 neighbours on `ifindex`: entries with a link-layer address in a
    /// not-failed state (REACHABLE/STALE/DELAY/PROBE/PERMANENT). These are the ARP
    /// keepalive targets. Entries whose lladdr == `exclude_lladdr` (HOSTMAC) are
    /// filtered out during the scan: anything resolving to our own mac — host
    /// addresses, MAC-NAT'd guests — is "us", not a peer to refresh.
    /// Best-effort: returns empty on any error.
    pub async fn neighbours_v4(&self, ifindex: u32, exclude_lladdr: Mac) -> Vec<(Ipv4Addr, Mac)> {
        use netlink_packet_route::neighbour::{
            NeighbourAddress, NeighbourAttribute, NeighbourState,
        };
        let mut s = self
            .handle
            .neighbours()
            .get()
            .set_family(rtnetlink::IpVersion::V4)
            .execute();
        let mut out = Vec::new();
        while let Ok(Some(m)) = s.try_next().await {
            if m.header.ifindex != ifindex {
                continue;
            }
            let usable = matches!(
                m.header.state,
                NeighbourState::Reachable
                    | NeighbourState::Stale
                    | NeighbourState::Delay
                    | NeighbourState::Probe
                    | NeighbourState::Permanent
            );
            if !usable {
                continue;
            }
            let mut ip = None;
            let mut mac = None;
            for a in &m.attributes {
                match a {
                    NeighbourAttribute::Destination(NeighbourAddress::Inet(d)) => ip = Some(*d),
                    NeighbourAttribute::LinkLayerAddress(b) => mac = Mac::from_slice(b),
                    _ => {}
                }
            }
            if let (Some(ip), Some(mac)) = (ip, mac) {
                if mac != exclude_lladdr
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
                    && !ip.is_unspecified()
                {
                    out.push((ip, mac));
                }
            }
        }
        out
    }

    /// Install a host-side neighbour entry. The entry is deliberately REACHABLE rather
    /// than a kernel-resolved INCOMPLETE entry: fwd-mode host traffic initially follows
    /// up0 while the guest is being learned, and the egress demux then sends frames with
    /// this HOSTMAC mapping into fwd0.
    pub async fn neighbour_replace(&self, ifindex: u32, ip: IpAddr, mac: Mac) -> Result<()> {
        use netlink_packet_route::neighbour::NeighbourState;
        self.handle
            .neighbours()
            .add(ifindex, ip)
            .link_layer_address(mac.bytes())
            .state(NeighbourState::Reachable)
            .replace()
            .execute()
            .await
            .context("neighbour_replace")
    }

    /// Read the current link-layer address for one neighbour. Best-effort callers use this
    /// before deleting an entry so a user-replaced neighbour is never removed by pbridge.
    pub async fn neighbour_lladdr(&self, ifindex: u32, ip: IpAddr) -> Option<Mac> {
        use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute};
        let family = match ip {
            IpAddr::V4(_) => rtnetlink::IpVersion::V4,
            IpAddr::V6(_) => rtnetlink::IpVersion::V6,
        };
        let mut s = self.handle.neighbours().get().set_family(family).execute();
        while let Ok(Some(m)) = s.try_next().await {
            if m.header.ifindex != ifindex {
                continue;
            }
            let mut dst = None;
            let mut mac = None;
            for a in &m.attributes {
                match a {
                    NeighbourAttribute::Destination(NeighbourAddress::Inet(v)) => {
                        dst = Some(IpAddr::V4(*v));
                    }
                    NeighbourAttribute::Destination(NeighbourAddress::Inet6(v)) => {
                        dst = Some(IpAddr::V6(*v));
                    }
                    NeighbourAttribute::LinkLayerAddress(b) => mac = Mac::from_slice(b),
                    _ => {}
                }
            }
            if dst == Some(ip) {
                return mac;
            }
        }
        None
    }

    /// Delete a neighbour only when it still has the MAC pbridge installed. This protects
    /// a user-created/replaced entry at the same IP from a later guest withdrawal.
    pub async fn neighbour_del_if(&self, ifindex: u32, ip: IpAddr, expected: Mac) -> Result<bool> {
        use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage};
        if self.neighbour_lladdr(ifindex, ip).await != Some(expected) {
            return Ok(false);
        }
        let mut msg = NeighbourMessage::default();
        msg.header.ifindex = ifindex;
        msg.header.family = match ip {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };
        msg.attributes.push(NeighbourAttribute::Destination(match ip {
            IpAddr::V4(v) => NeighbourAddress::Inet(v),
            IpAddr::V6(v) => NeighbourAddress::Inet6(v),
        }));
        match self.handle.neighbours().del(msg).execute().await {
            Ok(()) => Ok(true),
            Err(rtnetlink::Error::NetlinkError(e))
                if e.raw_code() == -libc::ENOENT || e.raw_code() == -libc::ESRCH =>
            {
                Ok(false)
            }
            Err(e) => Err(e).context("neighbour_del"),
        }
    }

    /// IPv6 default-route gateway addresses (next-hops of ::/0). Used by the
    /// ND-offload proxy guard to never claim the upstream router's own address.
    /// Best-effort: returns empty on any error.
    pub async fn default_gw6(&self) -> Vec<IpAddr> {
        use netlink_packet_route::route::RouteAddress;
        let msg = RouteMessageBuilder::<Ipv6Addr>::new().build();
        let mut s = self.handle.route().get(msg).execute();
        let mut out = Vec::new();
        while let Ok(Some(m)) = s.try_next().await {
            if m.header.destination_prefix_length != 0 {
                continue; // only ::/0 (default)
            }
            for a in &m.attributes {
                if let netlink_packet_route::route::RouteAttribute::Gateway(RouteAddress::Inet6(g)) =
                    a
                {
                    out.push(IpAddr::V6(*g));
                }
            }
        }
        out
    }

    /// Add an ip rule `iif lo lookup <table>` at `prio` for the given family (idempotent).
    /// Scoped to `iif lo` — i.e. only **locally-originated** traffic (host → guest) consults
    /// the vmroute table; external traffic never hits routing (it's redirected by the
    /// ebpf/nft datapath into the bridge and switched).
    pub async fn rule_add(&self, v6: bool, table: u32, prio: u32) -> Result<()> {
        let req = self
            .handle
            .rule()
            .add()
            .input_interface("lo".to_string())
            .table_id(table)
            .priority(prio)
            .action(RuleAction::ToTable);
        let res = if v6 {
            req.v6().execute().await
        } else {
            req.v4().execute().await
        };
        match res {
            Ok(()) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::EEXIST => Ok(()),
            Err(e) => Err(e).context("rule_add"),
        }
    }

    /// Remove the `iif lo lookup <table>` rule at `prio` (idempotent).
    pub async fn rule_del(&self, v6: bool, table: u32, prio: u32) -> Result<()> {
        let base = self
            .handle
            .rule()
            .add()
            .input_interface("lo".to_string())
            .table_id(table)
            .priority(prio)
            .action(RuleAction::ToTable);
        let msg = if v6 {
            base.v6().message_mut().clone()
        } else {
            base.v4().message_mut().clone()
        };
        match self.handle.rule().del(msg).execute().await {
            Ok(()) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(e))
                if e.raw_code() == -libc::ENOENT || e.raw_code() == -libc::ESRCH =>
            {
                Ok(())
            }
            Err(e) => Err(e).context("rule_del"),
        }
    }
}

