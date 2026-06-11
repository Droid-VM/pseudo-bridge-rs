# pseudo-bridge (pbridge)

Share a **single-MAC upstream** — a Wi-Fi STA interface, or a switch port that pins one
source MAC — among **multiple VMs/guests at L2**, like macOS's pseudo-bridge / MAC-NAT.

A normal bridge can't do this: the upstream only ever accepts frames from one MAC.
pbridge rewrites every outbound guest frame to the host's MAC (`HOSTMAC`) and
demultiplexes inbound frames back to the right guest by **destination IP**. Guests keep
their own MACs, DHCP/SLAAC, and mutual L2 visibility; the upstream only ever sees one
MAC.

```
        upstream wire (one MAC allowed)
  gateway ════════ up0 @ HOSTMAC
                    │   IN : dst-ip → guest-mac demux (in-kernel)
                    │   OUT: src-mac → HOSTMAC      (in-kernel)
                   fwd0 ╌ fwd1 ──[ your bridge ]──┬── tap VM1 (mac A)
                   (veth pair, fwd mode)          ├── tap VM2 (mac B)
                                                  └── ...
```

- **Datapath is 100% in-kernel** — `nftables` (netdev hooks) or `eBPF` (tc/TCX), your
  choice per environment. Userspace is a small Rust control plane: it *learns*
  guest `ip → mac` bindings from a lossy copy path (NFLOG / BPF ringbuf), enforces
  per-MAC/global caps with FIFO eviction, ages idle entries, and reconciles state into
  the kernel. Data packets never enter userspace (one exception: nft can't fix ICMPv6
  checksums, so ND packets take a fix-and-reinject detour).
- **No shell-outs, ever.** No `ip`, `nft`, `tc`, `brctl`, `bpftool`. Everything is
  netlink (rtnetlink + hand-rolled nf_tables wire) and BPF syscalls (aya). This is what
  makes it work on Android, where none of those binaries are guaranteed.
- **Static binaries** (musl): one for x86-64 linux, one for aarch64 Android (bionic).
  The BPF object is architecture-independent and embedded in both.

Full design — every rule table, state machine, and tradeoff: **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Engines × modes

|             | `-e nft`                              | `-e ebpf`                        |
|-------------|----------------------------------------|----------------------------------|
| works on    | linux with `NF_TABLES` (containers: no bpf() needed — proven under a bpf-blocking seccomp wrapper) | Android stock GKI ≥ 6.6 (no nftables needed), any linux with TCX |
| kernel min  | 5.16 (netdev **egress** hook, used by `direct` and the egress guard) | 6.6 (TCX; `CONFIG_NET_XGRESS` — GKI 6.6 has it) |
| ND rewrite  | kernel sets LLA, **userspace** fixes csum + reinjects | fully in-kernel (`bpf_l4_csum_replace`) |

| mode | when | hooks |
|------|------|-------|
| `direct` | up0 is a normal port that *can* join a bridge (wired, but the switch pins src-mac) | up0 egress (OUT) + up0 ingress (IN); kernel bridge forwards |
| `fwd` | up0 **can't** be bridged (Wi-Fi STA / `IFF_DONT_BRIDGE`) | pbridge creates veth `fwd0╌fwd1`, hooks fwd0 ingress (OUT) + up0 ingress (IN), forwards itself; `fwd1` goes into your VM bridge |
| `fwd-with-offload` | `fwd` on Android Wi-Fi | = `fwd` + `--offload-workaround v4,v6` on by default (see below) |

**pbridge pins only `up0`.** The bridge is discovered dynamically (`up0.master` /
`fwd1.master`): attach, swap, or detach it at any time and pbridge follows — HOSTMAC,
host-IP mirror, and host→VM routes all re-point automatically. `-b <bridge>` is a pure
convenience that does the *initial* enslave for you (once per session init, nothing
more — manual rebinds are never fought).

## Quick start

```sh
./build.sh                 # → dist/pbridge-linux-x64 + dist/pbridge-android-arm64 (static)
./build.sh host            # quick debug build (./target/debug/pbridge)

# Android Wi-Fi STA (root, e.g. KernelSU), VM bridge vmbr already exists:
pbridge -i wlan0 -e ebpf -m fwd-with-offload -b vmbr --arp-keepalive 10

# linux container with nftables but no bpf permission:
pbridge -i eth0 -e nft -m direct -b br0
```

Run as root (needs `CAP_NET_ADMIN` + raw sockets; ebpf additionally `bpf()`).
Teardown is automatic and complete on SIGINT/SIGTERM or when up0 disappears; everything
re-initializes when it comes back.

## CLI

| flag | default | what |
|------|---------|------|
| `-i, --interface` | — | upstream interface (`up0`) |
| `-e, --offload-engine` | — | `nft` \| `ebpf` |
| `-m, --mode` | — | `direct` \| `fwd` \| `fwd-with-offload` |
| `-b, --bridge` | — | enslave the guest-facing port (direct: up0, fwd: fwd1) into this existing bridge at session init — its only job; discovery stays dynamic |
| `--fwd-device-if/-br` | `{if}-if` / `{if}-br` | veth names in fwd mode |
| `--timeout` | 30 | entry idle aging (seconds) |
| `--max-cap` | `16,64,256,1024` | caps: v4/mac, v6/mac, v4 global, v6 global (FIFO evict) |
| `--nflog-group` | 32123 | NFLOG group (nft engine) |
| `--offload-workaround` | off | install learned guest addrs on up0 (`v4,v6,v6ll` subset) so an aggressive firmware filter (Android **APF**) answers ARP/NS for them; fwd-only |
| `--offload-workaround-magic` | 4243672773 | `IFA_RT_PRIORITY` tag marking those proxy addresses as ours |
| `--arp-keepalive` | 0 (off) | seconds; push-refresh upstream v4 neighbour caches (see below). Recommended on Android Wi-Fi: 10 |
| `--vmroute-table` / `--vmroute-rule` | 200 / 11000 | table + `iif lo` rule priority for host→VM `/32`·`/128` routes (fwd); `-1` disables |
| `--loglevel` | info | env_logger filter (`RUST_LOG` overrides) |

## Android Wi-Fi: two firmware fights you must know about

1. **APF drops ARP/NS for non-local addresses** (`DROPPED_ARP_OTHER_HOST`): the
   gateway can never resolve a guest IP. `fwd-with-offload` installs every learned
   guest address onto up0 (tagged, `noprefixroute`, deprecated, local-route removed) so
   the firmware itself answers with HOSTMAC. v6 would otherwise hard-fail; v4 would
   flap.
2. **The firmware's native ARP offload holds ONE IPv4 slot**
   (`WMI_SET_ARP_NS_OFFLOAD`, Qualcomm): in powersave it answers ARP only for the
   host's primary v4 and drops requests for everything else (~99% observed loss) —
   guest v4 flaps INCOMPLETE/FAILED on the gateway. v6 NS offload has multiple slots
   and is fine. `--arp-keepalive N` flips the problem around: outbound frames are
   unaffected by powersave, so pbridge periodically sends each v4 neighbour a *unicast*
   ARP reply per guest (unicast replies assert `NUD_REACHABLE` on Linux; GARP alone
   only gets STALE) plus an occasional GARP. Peers then never need to ARP-request a
   guest at all — at a tiny fraction of the power cost of disabling powersave.

## Tests

```sh
sudo tests/run_all_test.py                      # EVERYTHING in parallel (~1.5 min): matrix split
                                                #   per config + func scripts per engine + cargo test,
                                                #   each in its own mount+net namespace; summary at the end
bash tests/finaltest/matrix.sh                  # linux: mode(direct,fwd,fwd-with-offload) × engine(nft,ebpf), 16 cases each
bash tests/finaltest/smoke.sh fwd ebpf          # 1-guest quick check
bash tests/finaltest/func-arp-keepalive.sh      # firmware single-v4-slot simulation (case 18)
cargo test                                      # pure-logic unit tests

sudo bash tests/setup-artifacts.sh              # fetch GKI 6.6 Image + Alpine arm64 + redroid
sudo bash tests/finaltest/run-android.sh        # the same matrix on a REAL Android GKI kernel (QEMU)
sudo bash tests/finaltest/run-redroid-pbridge.sh # binary smoke under redroid (bionic)
```

The nft configs run under a **bpf()-blocking seccomp wrapper** — passing proves the nft
path needs zero ebpf (the container scenario). The matrix asserts, per config:
DHCPv4/v6 + SLAAC, ARP/ND rewrite correctness (incl. checksum), **zero foreign src-MAC
on the wire** (tcpdump-verified, and still held when the learn path is killed), host
coexistence, host→VM routing, multi-guest isolation, guest MAC/IP change, HOSTMAC
change (gratuitous ARP / unsolicited NA), idle aging, silent-VM discovery, offload
keepalive, and engine isolation.

| validated | direct | fwd | fwd-with-offload |
|---|---|---|---|
| x64 nft (bpf-blocked) | 16/16 | 16/16 | 16/16 |
| x64 ebpf | 16/16 | 16/16 | 16/16 |
| aarch64 ebpf @ real GKI 6.6 (QEMU) | 16/16 | 16/16 | — |

## Layout

    src/core.rs         the actor: owns entries + derived state, sole kernel writer
                        (reconcile, bridge mirror, vmroutes, proxy addrs, keepalives)
    src/state.rs        entry store: learn, caps, FIFO eviction
    src/packet.rs       L3 parsing + ICMPv6 checksum (nft copy path)
    src/afpacket.rs     raw L2 inject: ND reinject, GARP/NA, ARP keepalive frames
    src/netlink.rs      rtnetlink: link/addr/route/rule/neigh + multicast monitor
    src/backend/ebpf.rs aya: load + TCX attach + maps + ringbuf reader
    src/backend/nft/    hand-rolled nf_tables netlink (wire.rs), ruleset (mod.rs),
                        NFLOG reader (nflog.rs); table swaps are one atomic batch
    bpf/pbridge.bpf.c   the BPF datapath (one arch-independent object)
    tests/finaltest/    matrix + smoke + func scripts + Android/QEMU/redroid harness
    tests/poc/          kernel-capability proofs the design rests on
