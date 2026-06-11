//! Core value types: MAC, IP family helpers, learn tuples.
#![forbid(unsafe_code)]

use std::fmt;
use std::net::IpAddr;

pub const ETH_ALEN: usize = 6;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Mac(pub [u8; ETH_ALEN]);

impl Mac {
    pub const ZERO: Mac = Mac([0u8; ETH_ALEN]);
    pub const BROADCAST: Mac = Mac([0xff; ETH_ALEN]);

    pub fn from_slice(s: &[u8]) -> Option<Mac> {
        if s.len() < ETH_ALEN {
            return None;
        }
        let mut m = [0u8; ETH_ALEN];
        m.copy_from_slice(&s[..ETH_ALEN]);
        Some(Mac(m))
    }

    pub fn bytes(&self) -> &[u8; ETH_ALEN] {
        &self.0
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mac({self})")
    }
}

impl std::str::FromStr for Mac {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != ETH_ALEN {
            return Err(format!("bad mac {s:?}"));
        }
        let mut m = [0u8; ETH_ALEN];
        for (i, p) in parts.iter().enumerate() {
            m[i] = u8::from_str_radix(p, 16).map_err(|e| format!("bad mac octet {p:?}: {e}"))?;
        }
        Ok(Mac(m))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

pub fn family(ip: &IpAddr) -> Family {
    match ip {
        IpAddr::V4(_) => Family::V4,
        IpAddr::V6(_) => Family::V6,
    }
}

/// Unicast & routable for learning purposes. Excludes multicast (224/4, ff00::/8),
/// unspecified (0.0.0.0, ::), and loopback. Link-local fe80::/10 unicast IS learnable
/// (guest LL needed for ND demux); v4 link-local 169.254/16 also unicast-learnable.
pub fn is_learnable_unicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !a.is_multicast() && !a.is_unspecified() && !a.is_loopback() && !a.is_broadcast()
        }
        IpAddr::V6(a) => !a.is_multicast() && !a.is_unspecified() && !a.is_loopback(),
    }
}

/// Link-local: fe80::/10 (v6) or 169.254/16 (v4). Scope-link, not routable.
pub fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(a) => (a.segments()[0] & 0xffc0) == 0xfe80,
        IpAddr::V4(a) => {
            let o = a.octets();
            o[0] == 169 && o[1] == 254
        }
    }
}

/// What kind of copy packet we received (for the learn switch).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PktKind {
    Arp,
    /// Neighbor Discovery (NS/NA/RS), source != ::
    Nd,
    /// ND with src == :: (DAD NS) — learn from target.
    NdDad,
    Ip,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn mac_roundtrip() {
        let m: Mac = "02:00:00:0a:bb:cc".parse().unwrap();
        assert_eq!(m.to_string(), "02:00:00:0a:bb:cc");
        assert_eq!("ff:ff:ff:ff:ff:ff".parse::<Mac>().unwrap(), Mac::BROADCAST);
    }

    #[test]
    fn learnable() {
        assert!(is_learnable_unicast(&"10.0.0.5".parse().unwrap()));
        assert!(is_learnable_unicast(&"fe80::1".parse().unwrap()));
        assert!(!is_learnable_unicast(&"0.0.0.0".parse().unwrap()));
        assert!(!is_learnable_unicast(&"::".parse().unwrap()));
        assert!(!is_learnable_unicast(&"224.0.0.1".parse().unwrap()));
        assert!(!is_learnable_unicast(&"ff02::1".parse().unwrap()));
        assert!(!is_learnable_unicast(&IpAddr::V4(Ipv4Addr::BROADCAST)));
    }
}
