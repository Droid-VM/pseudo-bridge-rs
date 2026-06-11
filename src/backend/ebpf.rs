//! ebpf backend: loads the BPF datapath (build.rs object) with aya, attaches tc
//! programs, manages maps, and reads learn tuples from a ringbuf. Zero nft.

use super::{Backend, CopyEvent, InitCfg};
use crate::cli::Mode;
use crate::types::Mac;
use anyhow::{anyhow, Context, Result};
use aya::maps::{Array, HashMap as AyaHashMap, MapData, RingBuf};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{Ebpf, EbpfLoader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

// include_bytes! yields alignment-1 data, but ELF parsing needs 8-byte alignment.
#[repr(align(8))]
struct Aligned<T: ?Sized>(T);
static ALIGNED_OBJ: &Aligned<[u8]> =
    &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/pbridge.bpf.o")));
fn bpf_obj() -> &'static [u8] {
    &ALIGNED_OBJ.0
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Cfg {
    hostmac: [u8; 6],
    brmac: [u8; 6],
    has_brmac: u8,
    pad: [u8; 3],
    up0_ifx: u32,
    fwd0_ifx: u32,
}
// SAFETY: aya::Pod requires a `#[repr(C)]` type that is valid for any bit pattern and has
// no padding (it's byte-copied to/from BPF map memory). Cfg holds only u8/array/u32 fields,
// and the explicit `pad: [u8; 3]` aligns `up0_ifx` so there is no implicit padding.
unsafe impl aya::Pod for Cfg {}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct In6 {
    a: [u8; 16],
}
// SAFETY: a single `[u8; 16]` field — any bit pattern is valid, no padding.
unsafe impl aya::Pod for In6 {}

#[repr(C)]
#[derive(Clone, Copy)]
struct MacV {
    a: [u8; 6],
}
// SAFETY: a single `[u8; 6]` field — any bit pattern is valid, no padding.
unsafe impl aya::Pod for MacV {}

fn v4key(a: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(a.octets())
}
fn v4from(k: u32) -> Ipv4Addr {
    Ipv4Addr::from(k.to_ne_bytes())
}

pub struct EbpfBackend {
    ebpf: Option<Ebpf>,
    cfg: Option<InitCfg>,
    cur: Cfg,
    reader_stop: Option<Arc<AtomicBool>>,
}

impl EbpfBackend {
    pub fn new() -> Self {
        EbpfBackend {
            ebpf: None,
            cfg: None,
            cur: Cfg { hostmac: [0; 6], brmac: [0; 6], has_brmac: 0, pad: [0; 3], up0_ifx: 0, fwd0_ifx: 0 },
            reader_stop: None,
        }
    }

    fn ebpf(&mut self) -> Result<&mut Ebpf> {
        self.ebpf.as_mut().ok_or_else(|| anyhow!("ebpf not loaded"))
    }

    fn write_cfg(&mut self) -> Result<()> {
        let cur = self.cur;
        let map = self.ebpf()?.map_mut("config").ok_or_else(|| anyhow!("no config map"))?;
        let mut arr: Array<&mut MapData, Cfg> = Array::try_from(map)?;
        arr.set(0, cur, 0)?;
        Ok(())
    }
}

impl Backend for EbpfBackend {
    fn name(&self) -> &'static str {
        "ebpf"
    }

    fn init(&mut self, cfg: &InitCfg, copy_tx: UnboundedSender<CopyEvent>) -> Result<()> {
        let mut ebpf = EbpfLoader::new().load(bpf_obj()).context("load bpf object")?;

        self.cur = Cfg {
            hostmac: cfg.hostmac.0,
            brmac: cfg.brmac.map(|m| m.0).unwrap_or([0; 6]),
            has_brmac: cfg.brmac.is_some() as u8,
            pad: [0; 3],
            up0_ifx: cfg.up0_ifindex,
            fwd0_ifx: cfg.fwd0_ifindex.unwrap_or(0),
        };

        // config map
        {
            let map = ebpf.map_mut("config").ok_or_else(|| anyhow!("no config map"))?;
            let mut arr: Array<&mut MapData, Cfg> = Array::try_from(map)?;
            arr.set(0, self.cur, 0)?;
        }

        // attach programs per mode (TCX on kernel >= 6.6)
        let attach = |ebpf: &mut Ebpf, name: &str, iface: &str, ty: TcAttachType| -> Result<()> {
            let _ = tc::qdisc_add_clsact(iface); // harmless for TCX; needed for netlink fallback
            let p: &mut SchedClassifier =
                ebpf.program_mut(name).ok_or_else(|| anyhow!("no prog {name}"))?.try_into()?;
            p.load().with_context(|| format!("load {name}"))?;
            p.attach(iface, ty).with_context(|| format!("attach {name} to {iface}"))?;
            Ok(())
        };

        match cfg.mode {
            Mode::Fwd | Mode::FwdOffload => {
                let fwd0 = cfg.fwd0.clone().ok_or_else(|| anyhow!("fwd mode needs fwd0"))?;
                attach(&mut ebpf, "fwd_out", &fwd0, TcAttachType::Ingress)?;
                attach(&mut ebpf, "fwd_in", &cfg.up0, TcAttachType::Ingress)?;
                attach(&mut ebpf, "egress_guard", &cfg.up0, TcAttachType::Egress)?;
            }
            Mode::Direct => {
                attach(&mut ebpf, "direct_out", &cfg.up0, TcAttachType::Egress)?;
                attach(&mut ebpf, "direct_in", &cfg.up0, TcAttachType::Ingress)?;
            }
        }

        // host maps
        self.ebpf = Some(ebpf);
        self.cfg = Some(cfg.clone());
        self.set_host_ips(&cfg.host_ips)?;

        // ringbuf reader thread
        let ring_map = self.ebpf()?.take_map("events").ok_or_else(|| anyhow!("no events map"))?;
        let ring: RingBuf<MapData> = RingBuf::try_from(ring_map)?;
        let stop = Arc::new(AtomicBool::new(false));
        spawn_ringbuf_reader(ring, stop.clone(), copy_tx);
        self.reader_stop = Some(stop);
        Ok(())
    }

    fn teardown(&mut self) -> Result<()> {
        if let Some(s) = self.reader_stop.take() {
            s.store(true, Ordering::SeqCst);
        }
        self.ebpf = None; // drops programs -> detaches
        self.cfg = None;
        Ok(())
    }

    fn set_hostmac(&mut self, mac: Mac) -> Result<()> {
        self.cur.hostmac = mac.0;
        self.write_cfg()
    }

    fn set_brmac(&mut self, mac: Option<Mac>) -> Result<()> {
        self.cur.brmac = mac.map(|m| m.0).unwrap_or([0; 6]);
        self.cur.has_brmac = mac.is_some() as u8;
        self.write_cfg()
    }

    fn set_host_ips(&mut self, ips: &[IpAddr]) -> Result<()> {
        // rewrite host4/host6 to match `ips`.
        let want4: std::collections::HashSet<u32> =
            ips.iter().filter_map(|ip| if let IpAddr::V4(a) = ip { Some(v4key(*a)) } else { None }).collect();
        let want6: std::collections::HashSet<In6> =
            ips.iter().filter_map(|ip| if let IpAddr::V6(a) = ip { Some(In6 { a: a.octets() }) } else { None }).collect();
        {
            let map = self.ebpf()?.map_mut("host4").ok_or_else(|| anyhow!("no host4"))?;
            let mut h: AyaHashMap<&mut MapData, u32, u8> = AyaHashMap::try_from(map)?;
            let have: Vec<u32> = h.keys().filter_map(|k| k.ok()).collect();
            for k in &have {
                if !want4.contains(k) {
                    let _ = h.remove(k);
                }
            }
            for k in &want4 {
                let _ = h.insert(k, 1u8, 0);
            }
        }
        {
            let map = self.ebpf()?.map_mut("host6").ok_or_else(|| anyhow!("no host6"))?;
            let mut h: AyaHashMap<&mut MapData, In6, u8> = AyaHashMap::try_from(map)?;
            let have: Vec<In6> = h.keys().filter_map(|k| k.ok()).collect();
            for k in &have {
                if !want6.contains(k) {
                    let _ = h.remove(k);
                }
            }
            for k in &want6 {
                let _ = h.insert(k, 1u8, 0);
            }
        }
        Ok(())
    }

    fn write_entry(&mut self, ip: IpAddr, mac: Mac) -> Result<()> {
        match ip {
            IpAddr::V4(a) => {
                let k = v4key(a);
                {
                    let map = self.ebpf()?.map_mut("ip2mac4").ok_or_else(|| anyhow!("no ip2mac4"))?;
                    let mut m: AyaHashMap<&mut MapData, u32, MacV> = AyaHashMap::try_from(map)?;
                    m.insert(k, MacV { a: mac.0 }, 0)?;
                }
                let map = self.ebpf()?.map_mut("seen4").ok_or_else(|| anyhow!("no seen4"))?;
                let mut s: AyaHashMap<&mut MapData, u32, u8> = AyaHashMap::try_from(map)?;
                s.insert(k, 1u8, 0)?;
            }
            IpAddr::V6(a) => {
                let k = In6 { a: a.octets() };
                {
                    let map = self.ebpf()?.map_mut("ip2mac6").ok_or_else(|| anyhow!("no ip2mac6"))?;
                    let mut m: AyaHashMap<&mut MapData, In6, MacV> = AyaHashMap::try_from(map)?;
                    m.insert(k, MacV { a: mac.0 }, 0)?;
                }
                let map = self.ebpf()?.map_mut("seen6").ok_or_else(|| anyhow!("no seen6"))?;
                let mut s: AyaHashMap<&mut MapData, In6, u8> = AyaHashMap::try_from(map)?;
                s.insert(k, 1u8, 0)?;
            }
        }
        Ok(())
    }

    fn withdraw_entry(&mut self, ip: IpAddr) -> Result<()> {
        match ip {
            IpAddr::V4(a) => {
                let k = v4key(a);
                if let Some(map) = self.ebpf()?.map_mut("ip2mac4") {
                    let mut m: AyaHashMap<&mut MapData, u32, MacV> = AyaHashMap::try_from(map)?;
                    let _ = m.remove(&k);
                }
                if let Some(map) = self.ebpf()?.map_mut("seen4") {
                    let mut s: AyaHashMap<&mut MapData, u32, u8> = AyaHashMap::try_from(map)?;
                    let _ = s.remove(&k);
                }
            }
            IpAddr::V6(a) => {
                let k = In6 { a: a.octets() };
                if let Some(map) = self.ebpf()?.map_mut("ip2mac6") {
                    let mut m: AyaHashMap<&mut MapData, In6, MacV> = AyaHashMap::try_from(map)?;
                    let _ = m.remove(&k);
                }
                if let Some(map) = self.ebpf()?.map_mut("seen6") {
                    let mut s: AyaHashMap<&mut MapData, In6, u8> = AyaHashMap::try_from(map)?;
                    let _ = s.remove(&k);
                }
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<Vec<IpAddr>> {
        let mut alive = Vec::new();
        // seen4 second-chance
        {
            let map = self.ebpf()?.map_mut("seen4").ok_or_else(|| anyhow!("no seen4"))?;
            let mut s: AyaHashMap<&mut MapData, u32, u8> = AyaHashMap::try_from(map)?;
            let keys: Vec<u32> = s.keys().filter_map(|k| k.ok()).collect();
            for k in keys {
                match s.get(&k, 0) {
                    Ok(1) => {
                        let _ = s.insert(k, 0u8, 0);
                        alive.push(IpAddr::V4(v4from(k)));
                    }
                    _ => {
                        let _ = s.remove(&k);
                    }
                }
            }
        }
        {
            let map = self.ebpf()?.map_mut("seen6").ok_or_else(|| anyhow!("no seen6"))?;
            let mut s: AyaHashMap<&mut MapData, In6, u8> = AyaHashMap::try_from(map)?;
            let keys: Vec<In6> = s.keys().filter_map(|k| k.ok()).collect();
            for k in keys {
                match s.get(&k, 0) {
                    Ok(1) => {
                        let _ = s.insert(k, 0u8, 0);
                        alive.push(IpAddr::V6(Ipv6Addr::from(k.a)));
                    }
                    _ => {
                        let _ = s.remove(&k);
                    }
                }
            }
        }
        Ok(alive)
    }
}

fn spawn_ringbuf_reader(mut ring: RingBuf<MapData>, stop: Arc<AtomicBool>, tx: UnboundedSender<CopyEvent>) {
    std::thread::Builder::new()
        .name("ringbuf-reader".into())
        .spawn(move || {
            let fd = ring.as_raw_fd();
            loop {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
                // SAFETY: FFI poll over a 1-element array (`&mut pfd`, nfds=1); the fd is the
                // ring buffer's, valid for the thread's lifetime. poll only reads/writes pfd.
                let r = unsafe { libc::poll(&mut pfd, 1, 1000) };
                if r <= 0 {
                    continue;
                }
                while let Some(item) = ring.next() {
                    let d: &[u8] = &item;
                    if d.len() < 24 {
                        continue;
                    }
                    let Some(mac) = Mac::from_slice(&d[0..6]) else { continue };
                    let fam = d[6];
                    let ip = if fam == 4 {
                        IpAddr::V4(Ipv4Addr::new(d[8], d[9], d[10], d[11]))
                    } else {
                        let mut b = [0u8; 16];
                        b.copy_from_slice(&d[8..24]);
                        IpAddr::V6(Ipv6Addr::from(b))
                    };
                    let _ = tx.send(CopyEvent::Learn { ip, mac });
                }
            }
        })
        .expect("spawn ringbuf reader");
}

#[cfg(test)]
mod parse_test {
    #[test]
    fn bpf_obj_parses() {
        match aya::Ebpf::load(super::bpf_obj()) {
            Ok(_) => println!("PARSE OK"),
            Err(e) => println!("PARSE ERR: {e:?}"),
        }
    }
}
