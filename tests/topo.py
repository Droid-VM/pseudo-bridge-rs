"""Layer 2 — topology + upstream simulation.

   gw ns                        phone ns                              vm ns x3
   wanport ──veth── real_up0 ─[apfbr]─ helper_out ║upsim║ up0 ── pbridge
   (gw IPs, dnsmasq)            upsim (always in path):                  │
                                 out: log+drop non-HOSTMAC (leak det.)   │
                                 in : per --mode sim              vmport/up0
                                                                      [vmbr] ── vmpN ── vmN:eth0

upsim modes: portsec (inbound untouched) | apf (ARP/NS offload over all up0 addrs)
| qcom (offload over primary v4 + all v6 — the powersave single-v4-slot firmware).
The Wi-Fi sims (apf/qcom) also run with --reflect: a real AP echoes the STA's own
broadcasts back down (next DTIM) and hairpins unicast-to-own-mac — confirmed on
device, and the path by which pbridge's own GARPs/probes can re-enter up0 ingress
and poison neighbour caches unless dropped there. portsec models a wired port (no
echo).
"""

import subprocess
import time
from pathlib import Path

from common import (
    GW4, GW6, HMAC, HOST4, HOST6, LEAK_LOG, NEIGH1_4, NEIGH1_6, NEIGH2_4, NEIGH2_6,
    NS_ALL, UPSIM, VM1_4, VM1_6, VM2_4, VM2_6, sh, sh_ok, spawn, until_ok,
)


class Topo:
    def __init__(self, sim: str, mode: str):
        assert sim in ("portsec", "apf", "qcom")
        self.sim = sim
        self.mode = mode  # pbridge mode (direct places IPs on vmbr)
        self.upsim: subprocess.Popen | None = None

    def up(self):
        for n in NS_ALL:
            sh("ip", "netns", "add", n, check=True)
        # The wan segment is a real bridge in the gw ns modelling a home network: the
        # router (gw), two household devices (neigh1/neigh2), and the phone's uplink
        # (wanport<->real_up0) all share one L2 segment. The phone's single-MAC /
        # offload constraints live only on real_up0<->up0 (upsim); the gw<->neigh links
        # are ordinary. neigh1/neigh2 are NOT behind the MAC-NAT.
        sh("ip", "-n", "gw", "link", "add", "wanbr", "type", "bridge", check=True)
        sh("ip", "-n", "gw", "link", "set", "wanbr", "up")
        sh("ip", "-n", "gw", "link", "set", "lo", "up")
        sh("ip", "link", "add", "wanport", "netns", "gw", "type", "veth",
           "peer", "name", "real_up0", "netns", "phone", check=True)
        sh("ip", "-n", "gw", "link", "set", "wanport", "master", "wanbr")
        sh("ip", "-n", "gw", "link", "set", "wanport", "up")
        # gw's own addresses live on the bridge
        sh("ip", "-n", "gw", "addr", "add", f"{GW4}/24", "dev", "wanbr")
        sh("ip", "-n", "gw", "addr", "add", f"{GW6}/64", "dev", "wanbr", "nodad")
        # household devices on the wan segment
        for nsname, n4, n6, link in (
            ("neigh1", NEIGH1_4, NEIGH1_6, "n1"),
            ("neigh2", NEIGH2_4, NEIGH2_6, "n2"),
        ):
            sh("ip", "link", "add", link, "netns", "gw", "type", "veth",
               "peer", "name", "eth0", "netns", nsname, check=True)
            sh("ip", "-n", "gw", "link", "set", link, "master", "wanbr")
            sh("ip", "-n", "gw", "link", "set", link, "up")
            sh("ip", "-n", nsname, "addr", "add", f"{n4}/24", "dev", "eth0")
            sh("ip", "-n", nsname, "addr", "add", f"{n6}/64", "dev", "eth0", "nodad")
            sh("ip", "-n", nsname, "link", "set", "eth0", "up")
            sh("ip", "-n", nsname, "link", "set", "lo", "up")
        # learning-switch model: honor GARP/unsolicited-NA at once (a real AP re-learns
        # from the source mac; a Linux gw would otherwise hold stale entries to NUD timeout)
        sh("sysctl", "-q", "net.ipv4.conf.all.arp_accept=1",
           "net.ipv4.conf.default.arp_accept=1", ns="gw")
        # phone ns: every interface is v6-DISABLED by default — the plumbing (real_up0,
        # upsim's apfbr + tap ports, vm bridge ports) is pure L2 transport, and its
        # auto-LL MLD chatter (src = random port macs) would otherwise enter the helper
        # and trip the leak detector. Interfaces that genuinely need v6 (up0, vmbr)
        # are re-enabled explicitly below, deterministically before they come up.
        sh("sysctl", "-q", "net.ipv4.conf.all.rp_filter=0",
           "net.ipv4.conf.default.rp_filter=0", "net.ipv4.conf.all.forwarding=1",
           "net.ipv6.conf.all.forwarding=1",
           "net.ipv6.conf.default.disable_ipv6=1",
           "net.ipv6.conf.real_up0.disable_ipv6=1", ns="phone")
        sh("ip", "-n", "phone", "link", "set", "real_up0", "up")

        # the upstream simulator — always in the path. Wi-Fi sims get the AP echo.
        LEAK_LOG.write_text("")
        reflect = ("--reflect",) if self.sim in ("apf", "qcom") else ()
        self.upsim = spawn(str(UPSIM), "--upstream", "real_up0",
                           "--up-tap", "helper_out", "--host-tap", "up0",
                           "--mode", self.sim, "--leak-log", str(LEAK_LOG),
                           *reflect, ns="phone", log="/tmp/upsim.log")
        if not until_ok(5, lambda: sh_ok("ip", "-n", "phone", "link", "show", "up0")):
            try:
                why = Path("/tmp/upsim.log").read_text()[-300:]
            except OSError:
                why = "(no upsim.log)"
            raise RuntimeError(f"upsim taps did not appear; upsim.log:\n{why}")
        # up0 is the phone's real interface: it DOES speak v6. Order matters — upsim
        # already brought the tap up (v6-less thanks to the ns default), so set the
        # mac FIRST, then re-enable v6: enabling v6 on an up interface fires DAD/MLD
        # immediately, and doing it pre-mac would emit them with the tap's random mac.
        sh("ip", "-n", "phone", "link", "set", "up0", "address", HMAC)
        sh("sysctl", "-q", "net.ipv6.conf.up0.disable_ipv6=0", ns="phone")
        sh("ip", "-n", "phone", "link", "set", "up0", "up")

        # vm bridge (operator-owned; pbridge -b enslaves the guest-facing port).
        # vmbr speaks v6 (direct: host IPs live here; fwd: mirror target + BRMAC case).
        # Same ordering rule: fix the mac (direct) before enabling v6 / bringing it up.
        sh("ip", "-n", "phone", "link", "add", "vmbr", "type", "bridge", check=True)
        if self.mode == "direct":
            # direct: vmbr mac = up0 mac so HOSTMAC matches the enforced port mac
            sh("ip", "-n", "phone", "link", "set", "vmbr", "address", HMAC)
        sh("sysctl", "-q", "net.ipv6.conf.vmbr.disable_ipv6=0", ns="phone")
        sh("ip", "-n", "phone", "link", "set", "vmbr", "up")
        host_dev = "vmbr" if self.mode == "direct" else "up0"
        sh("ip", "-n", "phone", "addr", "add", f"{HOST4}/24", "dev", host_dev)
        sh("ip", "-n", "phone", "addr", "add", f"{HOST6}/64", "dev", host_dev, "nodad")
        # default routes via the gw, like a real phone (DHCP/RA would install them).
        # --arp-keepalive's gateway re-solicitation depends on default_gw4().
        sh("ip", "-n", "phone", "route", "add", "default", "via", GW4, "dev", host_dev)
        sh("ip", "-n", "phone", "-6", "route", "add", "default", "via", GW6, "dev", host_dev)

        # VMs: veth vmpN(phone, in vmbr) ── eth0(vmN). vm3 stays down/unaddressed —
        # the silent-vm and dhcp cases manage it themselves.
        for i, vm in enumerate(("vm1", "vm2", "vm3"), 1):
            sh("ip", "link", "add", f"vmp{i}", "netns", "phone", "type", "veth",
               "peer", "name", "eth0", "netns", vm, check=True)
            sh("ip", "-n", "phone", "link", "set", f"vmp{i}", "master", "vmbr")
            sh("ip", "-n", "phone", "link", "set", f"vmp{i}", "up")
            sh("ip", "-n", vm, "link", "set", "lo", "up")
        sh("ip", "-n", "vm1", "addr", "add", f"{VM1_4}/24", "dev", "eth0")
        sh("ip", "-n", "vm1", "addr", "add", f"{VM1_6}/64", "dev", "eth0", "nodad")
        sh("ip", "-n", "vm2", "addr", "add", f"{VM2_4}/24", "dev", "eth0")
        sh("ip", "-n", "vm2", "addr", "add", f"{VM2_6}/64", "dev", "eth0", "nodad")
        sh("ip", "-n", "vm1", "link", "set", "eth0", "up")
        sh("ip", "-n", "vm2", "link", "set", "eth0", "up")

    def down(self):
        if self.upsim:
            self.upsim.kill()
            self.upsim.wait()
            self.upsim = None
        for n in NS_ALL:
            sh("ip", "netns", "del", n)

    def set_hostmac(self, mac: str):
        """Change HOSTMAC: up0's mac (and vmbr's in direct, where HOSTMAC = vmbr mac).
        No gw neigh flush here — in reality the gateway's ARP cache survives an AP
        FDB re-learn; what re-points it is pbridge's per-entry GARP/unsolicited-NA
        broadcast (which the gw honors: arp_accept=1 + tha==sha garp)."""
        sh("ip", "-n", "phone", "link", "set", "up0", "address", mac)
        if self.mode == "direct":
            sh("ip", "-n", "phone", "link", "set", "vmbr", "address", mac)
        time.sleep(1.2)  # upsim refreshes its offload addr set every 500ms

    @staticmethod
    def flush_gw_neigh():
        sh("ip", "-n", "gw", "neigh", "flush", "dev", "wanbr")
        sh("ip", "-n", "gw", "-6", "neigh", "flush", "dev", "wanbr")

    @staticmethod
    def gw_neigh(ip: str) -> str:
        """The gw's neighbour entry line for `ip` ('' if none)."""
        r = sh("ip", "-n", "gw", "neigh", "show", "dev", "wanbr", ip)
        return r.stdout.strip()

    @staticmethod
    def mac_of(ns: str, dev: str = "eth0") -> str:
        out = sh("ip", "-n", ns, "-br", "link", "show", dev).stdout.split()
        return out[2] if len(out) > 2 else ""

    @staticmethod
    def neigh_lladdr(viewer_ns: str, ip: str) -> str:
        """`ip`'s resolved lladdr as seen from `viewer_ns` ('' if unresolved)."""
        r = sh("ip", "-n", viewer_ns, "neigh", "show", ip)
        toks = r.stdout.split()
        return toks[toks.index("lladdr") + 1] if "lladdr" in toks else ""
