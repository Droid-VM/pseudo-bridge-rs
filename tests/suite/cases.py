"""Layer 4 — the cases. This is the suite's durable asset: each case declares what it
needs (a predicate over the unit's sim/mode/engine) and asserts via helpers that raise
`Fail` with the reason. Cases run IN ORDER within one unit (one topology + one pbridge),
so state-mutating cases sit near the end and lifecycle cases (which restart pbridge)
are last before the leak guard.

Registration order == execution order.
"""

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from common import (
    GW4, GW6, HANDOVER_4, HANDOVER_6, MAGIC, NEIGH1_4, NEIGH2_4,
    VM1_4, VM1_6, VM2_4, VM2_6, VM3_4, VM3_6,
    Fail, expect, expect_no_ping, expect_ping, leak_count, ping, sh, sh_ok, until_ok,
)
from pb import PB_TIMEOUT, Pbridge
from topo import Topo


@dataclass
class Ctx:
    env: str
    sim: str
    mode: str
    engine: str
    topo: Topo
    pb: Pbridge
    leak_baseline: int = 0
    notes: list = field(default_factory=list)


@dataclass
class Case:
    name: str
    fn: object
    requires: object  # Ctx -> bool
    desc: str


CASES: list[Case] = []


def case(requires=lambda c: True, desc=""):
    def deco(fn):
        CASES.append(Case(fn.__name__, fn, requires, desc))
        return fn
    return deco


def offloaded(c: Ctx) -> bool:
    return c.mode == "fwd-with-offload"


def v4_actively_resolvable(c: Ctx) -> bool:
    """Can the gw ACTIVELY (re)resolve an arbitrary guest v4 (no passive ARP-request to
    learn from)? portsec: no inbound filter. apf+offloaded: the v4 proxy on up0 is
    offload-answered. NOT qcom-offloaded (its single v4 slot rejects the magic-metric
    proxy), NOT any plain fwd under apf/qcom (no proxy at all) — those need a guest
    re-ARP or --arp-keepalive, which is the whole point of those workarounds."""
    return c.sim == "portsec" or (c.sim == "apf" and offloaded(c))


def proxies(pattern: str) -> int:
    """Count offload-workaround proxy addresses on up0 matching `pattern`."""
    out = sh("ip", "-n", "phone", "-o", "addr", "show", "dev", "up0").stdout
    return sum(1 for l in out.splitlines() if f"metric {MAGIC}" in l and pattern in l)


def ping_all(ns: str, dst: str, count: int = 3) -> bool:
    """100% ping success (plain ping exits 0 on ANY reply)."""
    r = sh("ping", f"-c{count}", "-W1", dst, ns=ns)
    return r.returncode == 0 and " 0% packet loss" in r.stdout


def vmroute_present(ip: str) -> bool:
    """Is there a per-guest vmroute for `ip` (fwd /32-/128, default table 200)?"""
    out = sh("ip", "route", "show", "table", "200", ns="phone").stdout
    return ip in out


# ---------------------------------------------------------------- basics

@case(desc="guest v4 -> gw (ARP rewrite + demux)")
def conn_v4(c: Ctx):
    expect_ping("vm1", GW4, "vm1 v4 ping gw")


# apf/qcom drop the gw's NS for a guest address unless the offload-workaround put it
# on up0 — under plain fwd, v6 there is broken BY DESIGN (offload_workaround_off
# asserts exactly that), so plain v6 connectivity applies elsewhere only.
@case(requires=lambda c: c.sim == "portsec" or offloaded(c),
      desc="guest v6 -> gw (ND rewrite + csum + demux)")
def conn_v6(c: Ctx):
    expect_ping("vm1", GW6, "vm1 v6 ping gw")


@case(desc="phone's own traffic unaffected (host_ips early-accept)")
def host_coexist(c: Ctx):
    expect_ping("phone", GW4, "phone v4 -> gw", budget=10)
    expect_ping("phone", GW6, "phone v6 -> gw", budget=10)


@case(desc="phone -> VM (fwd: vmroute + mirror; direct: on-link)")
def host_to_vm(c: Ctx):
    expect_ping("phone", VM1_4, "phone -> vm1 v4")
    expect_ping("phone", VM1_6, "phone -> vm1 v6")


@case(desc="two guests, isolation, vm<->vm stays off the wan")
def multi_guest(c: Ctx):
    expect_ping("vm2", GW4, "vm2 v4 -> gw")
    expect_ping("vm1", VM2_4, "vm1 <-> vm2 over the bridge", budget=10)
    # established vm1<->vm2 must not traverse the wan port
    cap = subprocess.Popen(
        ["ip", "netns", "exec", "gw", "timeout", "3", "tcpdump", "-i", "wanport",
         "-n", f"host {VM2_4}"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    time.sleep(0.3)
    ping("vm1", VM2_4, count=2)
    out, _ = cap.communicate()
    expect(VM2_4 not in out, "vm1<->vm2 traffic leaked onto the wan")


@case(desc="wan household coexistence: gw + two neighbours + a guest all reachable")
def neigh_coexist(c: Ctx):
    # the wan segment has the router and two ordinary devices (not behind the MAC-NAT)
    expect_ping("gw", NEIGH1_4, "gw -> neigh1", budget=10)
    expect_ping("gw", NEIGH2_4, "gw -> neigh2", budget=10)
    # a guest reaches a wan neighbour through the MAC-NAT (same path as guest->gw)
    expect_ping("vm1", NEIGH1_4, "vm1 -> neigh1 (v4, through MAC-NAT)")


# ---------------------------------------------------------------- silent VM / DHCP

@case(requires=lambda c: c.mode != "direct",
      desc="phone -> silent VM: discovery dup learns it, vmroute appears (fwd)")
def silent_vm(c: Ctx):
    sh("ip", "-n", "vm3", "addr", "add", f"{VM3_4}/24", "dev", "eth0")
    sh("ip", "-n", "vm3", "addr", "add", f"{VM3_6}/64", "dev", "eth0", "nodad")
    sh("ip", "-n", "vm3", "link", "set", "eth0", "up")
    # vm3 never initiates; connectivity comes up "on retry" via the discovery dup. v6
    # is slower (ND + solicited-node), and under parallel CPU saturation the discovery
    # round-trip stretches — generous budgets keep it an eventual-success assertion.
    expect_ping("phone", VM3_4, "phone -> silent vm3 v4", budget=30)
    expect_ping("phone", VM3_6, "phone -> silent vm3 v6", budget=30)


@case(requires=lambda c: shutil.which("dnsmasq") and shutil.which("busybox"),
      desc="DHCPv4 lease via dnsmasq/udhcpc (broadcast-flag + csum0 rewrite)")
def dhcp_v4(c: Ctx):
    sh("ip", "-n", "vm3", "addr", "flush", "dev", "eth0")
    sh("ip", "-n", "vm3", "link", "set", "eth0", "up")
    # The lease file MUST live in the unit-private /tmp: `unshare --mount` gives each
    # unit its own /tmp + /run/netns but /var is SHARED, so dnsmasq's default
    # /var/lib/misc/dnsmasq.leases would be common to all parallel units — they'd
    # accumulate each other's leases and exhaust the small range ("no address
    # available"). --dhcp-authoritative + --no-ping keep allocation fast and decisive.
    dns = subprocess.Popen(
        ["ip", "netns", "exec", "gw", "dnsmasq", "--no-daemon", "--interface=wanbr",
         "--bind-interfaces", "--port=0", "--no-ping", "--dhcp-authoritative",
         "--dhcp-leasefile=/tmp/dnsmasq.leases",
         "--dhcp-range=10.0.0.100,10.0.0.150,255.255.255.0,12h"],
        stdout=open("/tmp/dnsmasq.log", "w"), stderr=subprocess.STDOUT)
    try:
        time.sleep(1.5)  # let dnsmasq bind before soliciting
        script = Path("/tmp/udhcpc.sh")
        script.write_text(
            '#!/bin/sh\ncase "$1" in bound|renew) '
            'ip addr add "$ip/${mask:-24}" dev "$interface" 2>/dev/null; '
            'echo "$ip" >/tmp/dhcp-lease;; esac\nexit 0\n')
        script.chmod(0o755)
        lease = Path("/tmp/dhcp-lease")
        lease.unlink(missing_ok=True)
        # udhcpc's own retries (-t 6, -T 2) ride out a transiently busy handshake; the
        # lease file being private means a clean range every run, so this rarely retries.
        sh("busybox", "udhcpc", "-i", "eth0", "-s", str(script),
           "-n", "-q", "-t", "6", "-T", "2", ns="vm3")
        expect(lease.exists() and lease.read_text().strip(),
               "no DHCPv4 lease (see /tmp/dnsmasq.log)")
        ip = lease.read_text().strip()
        expect_ping("vm3", GW4, f"leased ip {ip} pings gw", budget=10, src=ip)
    finally:
        dns.kill()
        dns.wait()


# ---------------------------------------------------------------- mutations

@case(desc="guest mac change: relearned, traffic continues")
def mac_change(c: Ctx):
    sh("ip", "-n", "vm1", "link", "set", "eth0", "address", "02:00:00:00:0c:01")
    expect_ping("vm1", GW4, "vm1 reaches gw after mac change")


@case(desc="HOSTMAC change: ruleset re-pointed, per-entry GARP/NA, new src on wire")
def hostmac_change(c: Ctx):
    expect(leak_count() == c.leak_baseline,
           f"leaks before HOSTMAC change ({leak_count()} != {c.leak_baseline})")
    new = "02:00:00:00:0a:bb"
    c.topo.set_hostmac(new)  # settles ~1.2s (upsim re-reads the mac) + gw neigh flush
    # frames sent inside the settle window were legitimately dropped: re-baseline
    c.leak_baseline = leak_count()
    expect_ping("vm1", GW4, "vm1 reaches gw after HOSTMAC change")
    cap = subprocess.Popen(
        ["ip", "netns", "exec", "gw", "timeout", "3", "tcpdump", "-i", "wanport",
         "-e", "-n", "icmp"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    time.sleep(0.3)
    ping("vm1", GW4, count=3)
    out, _ = cap.communicate()
    expect(new in out.lower(), "wire shows the new HOSTMAC as src")


# A brand-new guest IP only appears in IP packets (the guest already has the gw
# resolved, so it doesn't re-ARP), so the gw has to ACTIVELY resolve it — which only
# works where that's possible (see v4_actively_resolvable). Elsewhere it's broken by
# design: exactly what offload-workaround / arp-keepalive exist for.
@case(requires=v4_actively_resolvable,
      desc="guest adds an IP: learned, usable")
def ip_change(c: Ctx):
    sh("ip", "-n", "vm1", "addr", "add", "10.0.0.55/24", "dev", "eth0")
    try:
        expect_ping("vm1", GW4, "vm1's new ip reaches gw", src="10.0.0.55")
    finally:
        sh("ip", "-n", "vm1", "addr", "del", "10.0.0.55/24", "dev", "eth0")


# After the entry ages out and the guest goes quiet, reconnecting means the gw must
# re-resolve the (still-cached-on-the-guest) guest v4 — same active-resolution
# requirement as ip_change. The aging+relearn logic itself is fully covered under
# portsec; under apf/qcom the reconnect is sim-governed (proxy / keepalive territory).
@case(requires=v4_actively_resolvable,
      desc="idle > timeout: entry ages out then re-learns and reconnects")
def timeout_relearn(c: Ctx):
    time.sleep(2 * PB_TIMEOUT + 2)
    expect_ping("vm1", GW4, "vm1 reconnects after idle period")


@case(desc="engine isolation: nft uses 0 ebpf (wrapper), ebpf uses 0 nftables")
def engine_isolation(c: Ctx):
    if c.engine == "ebpf":
        expect(not Pbridge.nft_table_present(), "ebpf engine must not create nft tables")
    else:
        expect(bool(c.pb.wrap), "nft engine must run under the bpf-block wrapper (lxc env)")


# ---------------------------------------------------------------- offload workaround

@case(requires=lambda c: c.sim == "apf" and c.mode == "fwd",
      desc="workaround OFF under APF: gw cannot resolve a guest (v4+v6 dead)")
def offload_workaround_off(c: Ctx):
    expect_ping("vm1", GW4, "guest learned (one outbound flow)")
    c.topo.flush_gw_neigh()
    expect_no_ping("gw", VM1_4, "gw -> guest v4 with APF and no workaround")
    expect_no_ping("gw", VM1_6, "gw -> guest v6 with APF and no workaround")


@case(requires=lambda c: c.sim == "apf" and offloaded(c),
      desc="workaround ON under APF: proxies installed, gw -> guest works (v4+v6)")
def offload_workaround_on(c: Ctx):
    expect_ping("vm1", GW4, "learn vm1 v4")
    expect_ping("vm1", GW6, "learn vm1 v6")
    expect(until_ok(8, lambda: proxies(VM1_4) and proxies(VM1_6)),
           "proxy addrs (magic metric) installed on up0")
    c.topo.flush_gw_neigh()
    expect_ping("gw", VM1_4, "gw -> guest v4 via APF offload answer", budget=10)
    expect_ping("gw", VM1_6, "gw -> guest v6 via APF offload answer", budget=10)


@case(requires=lambda c: c.sim == "apf" and offloaded(c),
      desc="offload keepalive: silent-but-present guest keeps its proxy; released guest evicted")
def offload_keepalive(c: Ctx):
    expect_ping("vm1", GW4, "learn vm1 v4")
    expect_ping("vm1", GW6, "learn vm1 v6")
    expect(until_ok(8, lambda: proxies(VM1_4) and proxies(VM1_6)), "proxies installed")
    time.sleep(2.5 * PB_TIMEOUT + 1)  # silent but still holding the IPs
    expect(proxies(VM1_4) and proxies(VM1_6),
           "silent-but-present proxies survive (probe keepalive)")
    sh("ip", "-n", "vm1", "addr", "flush", "dev", "eth0")  # guest releases its IPs
    try:
        expect(until_ok(2.5 * PB_TIMEOUT + 4, lambda: not proxies(VM1_4) and not proxies(VM1_6)),
               "released guest's proxies evicted")
    finally:  # restore vm1 for the cases after us
        sh("ip", "-n", "vm1", "addr", "add", f"{VM1_4}/24", "dev", "eth0")
        sh("ip", "-n", "vm1", "addr", "add", f"{VM1_6}/64", "dev", "eth0", "nodad")


# ------------------------------------------------- qcom firmware / arp-keepalive
# Lifecycle cases: they restart pbridge with different flags; broken MUST run before
# hold (ordered registration). They model the real device: the firmware answers ARP
# only for the host's primary v4, and the guest has a warm gw cache (permanent neigh,
# i.e. it is not re-ARPing right now).

def _gw_mac() -> str:
    out = sh("ip", "-n", "gw", "-br", "link", "show", "wanbr").stdout.split()
    return out[2] if len(out) > 2 else ""


@case(requires=lambda c: c.sim == "qcom" and offloaded(c),
      desc="qcom single-v4-slot: without --arp-keepalive the gw entry dies")
def arp_keepalive_broken(c: Ctx):
    # fast NUD decay on the gw
    sh("sysctl", "-q", "net.ipv4.neigh.wanbr.base_reachable_time_ms=3000",
       "net.ipv4.neigh.wanbr.delay_first_probe_time=1",
       "net.ipv4.neigh.wanbr.retrans_time_ms=200",
       "net.ipv4.neigh.wanbr.ucast_solicit=2",
       "net.ipv4.neigh.wanbr.mcast_solicit=2", ns="gw")
    expect_ping("vm1", GW4, "learn vm1 v4 first")
    sh("ip", "-n", "vm1", "neigh", "replace", GW4, "lladdr", _gw_mac(),
       "dev", "eth0", "nud", "permanent")
    c.topo.flush_gw_neigh()
    expect_no_ping("vm1", GW4, "vm1 -> gw v4 while gw can't resolve vm1 (qcom drop)")
    entry = c.topo.gw_neigh(VM1_4)
    expect(("FAILED" in entry) or ("INCOMPLETE" in entry) or entry == "",
           f"gw entry for vm1 is dead (got: {entry!r})")


@case(requires=lambda c: c.sim == "qcom" and offloaded(c),
      desc="--arp-keepalive: unicast replies hold the gw entry REACHABLE through silence")
def arp_keepalive_hold(c: Ctx):
    expect(c.pb.restart("--arp-keepalive", "2"), "pbridge restarts with --arp-keepalive 2")
    expect(until_ok(15, lambda: ping("vm1", GW4)),
           "vm1 -> gw recovers once keepalive resolves the gw's dead entry")
    # The keepalive's unicast replies target the gw's entry in up0's neighbour table —
    # which exists because the phone itself is online (VM silent != phone silent). Keep
    # a light phone<->gw background flow during vm1's silence to model that, then assert
    # the gw never loses vm1: it stays REACHABLE (re-asserted each keepalive tick;
    # reachable decay is random in [1.5,4.5]s vs the 2s period, so check eventually) and
    # NEVER falls into probing/FAILED.
    end = time.monotonic() + 10
    worst_ok = True
    while time.monotonic() < end:
        ping("phone", GW4)  # phone is online
        e = c.topo.gw_neigh(VM1_4)
        if "FAILED" in e or "INCOMPLETE" in e or e == "":
            worst_ok = False
            break
        time.sleep(1)
    expect(worst_ok, f"gw entry for vm1 never died during silence (last: {c.topo.gw_neigh(VM1_4)!r})")
    expect(until_ok(4, lambda: "REACHABLE" in c.topo.gw_neigh(VM1_4)),
           "gw entry re-asserted REACHABLE within one keepalive period")
    expect(ping_all("gw", VM1_4), "gw -> vm1 at 100% while vm1 stays silent")


# ---------------------------------------------------------- IP handover (release)

@case(requires=lambda c: c.mode != "direct",
      desc="VM releases an IP, a wan neighbour takes it over: timeout withdraws every "
           "trace (demux/proxy/vmroute) so phone, gw AND vm2 all reach the new owner")
def ip_handover(c: Ctx):
    X4, X6 = HANDOVER_4, HANDOVER_6
    # vm3 briefly owns X; learning it installs the demux entry, the vmroute, and (when
    # offloaded) the proxy address on up0.
    sh("ip", "-n", "vm3", "addr", "flush", "dev", "eth0")
    sh("ip", "-n", "vm3", "addr", "add", f"{X4}/24", "dev", "eth0")
    sh("ip", "-n", "vm3", "addr", "add", f"{X6}/64", "dev", "eth0", "nodad")
    sh("ip", "-n", "vm3", "link", "set", "eth0", "up")
    expect_ping("vm3", GW4, "vm3 learns X (v4)")
    if c.sim != "qcom":
        expect_ping("vm3", GW6, "vm3 learns X (v6)")
    if offloaded(c):
        expect(until_ok(8, lambda: proxies(X4)), "X proxied onto up0 while vm3 owns it")
    expect(until_ok(8, lambda: vmroute_present(X4)), "vmroute for X present while vm3 owns it")

    # vm3 releases X and stays silent — the entry must age out.
    sh("ip", "-n", "vm3", "addr", "flush", "dev", "eth0")
    if offloaded(c):
        expect(until_ok(2.5 * PB_TIMEOUT + 2,
                        lambda: not proxies(X4) and not proxies(X6)),
               "proxy addrs removed from up0 after release")
    else:
        time.sleep(2 * PB_TIMEOUT + 2)
    expect(until_ok(PB_TIMEOUT, lambda: not vmroute_present(X4)),
           "stale vmroute for X withdrawn after release")

    # a wan neighbour takes X over (secondary on its eth0).
    sh("ip", "-n", "neigh1", "addr", "add", f"{X4}/24", "dev", "eth0")
    sh("ip", "-n", "neigh1", "addr", "add", f"{X6}/64", "dev", "eth0", "nodad")
    nmac = c.topo.mac_of("neigh1")
    try:
        # phone (the host itself), gw (upstream), and vm2 (another guest) must all reach
        # the NEW owner and resolve X to neigh1's mac — never a stale vm3 entry, and
        # never the phone (HOSTMAC), which a leftover up0 proxy would cause.
        for viewer in ("phone", "gw", "vm2"):
            sh("ip", "-n", viewer, "neigh", "flush", "all")
            expect_ping(viewer, X4, f"{viewer} -> X (now neigh1) after handover", budget=15)
            lladdr = c.topo.neigh_lladdr(viewer, X4).lower()
            expect(lladdr == nmac.lower(),
                   f"{viewer} resolves X to neigh1 {nmac}, not stale/HOSTMAC (got {lladdr!r})")
    finally:
        sh("ip", "-n", "neigh1", "addr", "del", f"{X4}/24", "dev", "eth0")
        sh("ip", "-n", "neigh1", "addr", "del", f"{X6}/64", "dev", "eth0")


# ---------------------------------------------------------------- final guard

@case(desc="leak guard: upsim saw zero foreign-src frames (whole unit)")
def leak_guard(c: Ctx):
    n = leak_count()
    expect(n == c.leak_baseline,
           f"{n - c.leak_baseline} foreign-src frame(s) hit the upstream port (see upsim leak log)")
