//! Entry store: the single source of truth (`entries`) plus admission/caps/FIFO
//! eviction. Mirrors ARCHITECTURE.md §userspace path `learn` / `evict_oldest`.
//!
//! `createat` is a monotonic sequence counter (not wall clock): it only orders
//! FIFO eviction, and a counter gives strict ordering with no ties. Liveness
//! aging is independent (kernel `seen`), so wall time isn't needed here.
#![forbid(unsafe_code)]

use crate::cli::MaxCap;
use crate::types::{family, Family, Mac};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub mac: Mac,
    pub createat: u64,
    /// When this ip last produced a control-plane copy (ARP/ND learn event, including
    /// no-op re-learns). The offload keepalive probe consults it: a guest whose DAD NS
    /// just arrived is mid-DAD, and probing it with our DAD-form NS within that window
    /// reads as an address conflict (RFC 4862) — the guest would abort the address.
    pub last_ctrl: Instant,
}

pub struct Entries {
    map: HashMap<IpAddr, Entry>,
    seq: u64,
    cap: MaxCap,
}

/// Outcome of a learn() call: every IP that changed and therefore needs reconcile —
/// the new/updated ip plus any evicted victims (reconcile withdraws those, since
/// they're no longer in the store).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LearnResult {
    pub changed: Vec<IpAddr>,
}

impl Entries {
    pub fn new(cap: MaxCap) -> Self {
        Entries { map: HashMap::new(), seq: 0, cap }
    }

    pub fn get(&self, ip: &IpAddr) -> Option<&Entry> {
        self.map.get(ip)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&IpAddr, &Entry)> {
        self.map.iter()
    }

    pub fn ips(&self) -> Vec<IpAddr> {
        self.map.keys().copied().collect()
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn cap_per_mac(&self, fam: Family) -> u32 {
        match fam {
            Family::V4 => self.cap.v4_per_mac,
            Family::V6 => self.cap.v6_per_mac,
        }
    }
    fn cap_global(&self, fam: Family) -> u32 {
        match fam {
            Family::V4 => self.cap.v4_global,
            Family::V6 => self.cap.v6_global,
        }
    }

    fn per_mac_count(&self, fam: Family, mac: Mac) -> u32 {
        self.map
            .iter()
            .filter(|(ip, e)| family(ip) == fam && e.mac == mac)
            .count() as u32
    }
    fn global_count(&self, fam: Family) -> u32 {
        self.map.iter().filter(|(ip, _)| family(ip) == fam).count() as u32
    }

    /// FIFO victim: smallest createat among entries of `fam` (and matching
    /// `scope_mac` if Some). Returns the IP to evict.
    fn evict_oldest(&mut self, fam: Family, scope_mac: Option<Mac>) -> Option<IpAddr> {
        let victim = self
            .map
            .iter()
            .filter(|(ip, e)| {
                family(ip) == fam && scope_mac.map(|m| e.mac == m).unwrap_or(true)
            })
            .min_by_key(|(_, e)| e.createat)
            .map(|(ip, _)| *ip);
        if let Some(ip) = victim {
            self.map.remove(&ip);
        }
        victim
    }

    /// learn(ip, mac) per §userspace path. Returns the set of IPs that changed
    /// and must be reconciled (the new/updated ip plus any evicted victims).
    pub fn learn(&mut self, ip: IpAddr, mac: Mac) -> LearnResult {
        let mut res = LearnResult::default();
        if let Some(e) = self.map.get_mut(&ip) {
            e.last_ctrl = Instant::now(); // control-plane activity even when a no-op
            if e.mac == mac {
                return res; // known, no-op (liveness handled by kernel seen)
            }
            // op2: ip's mac changed (createat unchanged).
            e.mac = mac;
            res.changed.push(ip);
            return res;
        }
        // op1: new entry — admission via caps (FIFO evict if over).
        let fam = family(&ip);
        if self.per_mac_count(fam, mac) >= self.cap_per_mac(fam) {
            if let Some(v) = self.evict_oldest(fam, Some(mac)) {
                res.changed.push(v);
            }
        }
        if self.global_count(fam) >= self.cap_global(fam) {
            if let Some(v) = self.evict_oldest(fam, None) {
                res.changed.push(v);
            }
        }
        let createat = self.next_seq();
        self.map.insert(ip, Entry { mac, createat, last_ctrl: Instant::now() });
        res.changed.push(ip);
        res
    }

    /// Remove an IP (aging). Returns true if it existed.
    pub fn remove(&mut self, ip: &IpAddr) -> bool {
        self.map.remove(ip).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn mac(s: &str) -> Mac {
        s.parse().unwrap()
    }

    fn small_cap() -> MaxCap {
        MaxCap { v4_per_mac: 2, v6_per_mac: 2, v4_global: 3, v6_global: 3 }
    }

    #[test]
    fn learn_new_and_noop() {
        let mut e = Entries::new(MaxCap::default());
        let r = e.learn(ip("10.0.0.5"), mac("02:0:0:0:0:1"));
        assert_eq!(r.changed, vec![ip("10.0.0.5")]);
        let r = e.learn(ip("10.0.0.5"), mac("02:0:0:0:0:1"));
        assert!(r.changed.is_empty(), "same mac is a no-op");
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn learn_replace_mac() {
        let mut e = Entries::new(MaxCap::default());
        e.learn(ip("10.0.0.5"), mac("02:0:0:0:0:1"));
        let r = e.learn(ip("10.0.0.5"), mac("02:0:0:0:0:2"));
        assert_eq!(r.changed, vec![ip("10.0.0.5")]);
        assert_eq!(e.get(&ip("10.0.0.5")).unwrap().mac, mac("02:0:0:0:0:2"));
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn per_mac_fifo_evict() {
        let mut e = Entries::new(small_cap());
        let m = mac("02:0:0:0:0:1");
        e.learn(ip("10.0.0.1"), m); // oldest
        e.learn(ip("10.0.0.2"), m);
        // third for same mac -> evict oldest (10.0.0.1)
        let r = e.learn(ip("10.0.0.3"), m);
        assert!(r.changed.contains(&ip("10.0.0.3")));
        assert!(r.changed.contains(&ip("10.0.0.1")), "oldest evicted");
        assert!(e.get(&ip("10.0.0.1")).is_none());
        assert_eq!(e.len(), 2);
    }

    #[test]
    fn per_mac_isolation() {
        // guest A filling its cap does not evict guest B's entries.
        let mut e = Entries::new(small_cap());
        let a = mac("02:0:0:0:0:a");
        let b = mac("02:0:0:0:0:b");
        e.learn(ip("10.0.0.1"), b); // B's entry, oldest globally
        e.learn(ip("10.0.0.2"), a);
        e.learn(ip("10.0.0.3"), a);
        // A over per-mac cap -> evicts A's oldest (10.0.0.2), but global cap (3)
        // is also hit so global oldest (10.0.0.1, B) would go too. Use bigger
        // global to isolate the per-mac behaviour:
        let mut e = Entries::new(MaxCap { v4_per_mac: 2, v6_per_mac: 2, v4_global: 100, v6_global: 100 });
        e.learn(ip("10.0.0.1"), b);
        e.learn(ip("10.0.0.2"), a);
        e.learn(ip("10.0.0.3"), a);
        let r = e.learn(ip("10.0.0.4"), a);
        assert!(r.changed.contains(&ip("10.0.0.2")), "A oldest evicted");
        assert!(e.get(&ip("10.0.0.1")).is_some(), "B untouched");
    }

    #[test]
    fn global_fifo_evict() {
        let mut e = Entries::new(MaxCap { v4_per_mac: 100, v6_per_mac: 100, v4_global: 2, v6_global: 2 });
        let m = mac("02:0:0:0:0:1");
        e.learn(ip("10.0.0.1"), m);
        e.learn(ip("10.0.0.2"), m);
        let r = e.learn(ip("10.0.0.3"), m);
        assert!(r.changed.contains(&ip("10.0.0.1")), "global oldest evicted");
        assert_eq!(e.global_count(Family::V4), 2);
    }

    #[test]
    fn families_independent() {
        let mut e = Entries::new(MaxCap { v4_per_mac: 1, v6_per_mac: 1, v4_global: 1, v6_global: 1 });
        let m = mac("02:0:0:0:0:1");
        e.learn(ip("10.0.0.1"), m);
        e.learn(ip("fe80::1"), m);
        assert_eq!(e.len(), 2, "v4 and v6 caps independent");
    }
}
