# pseudo-bridge (pbridge)

Multi-guest MAC-NAT over a single-MAC upstream (Wi-Fi STA, or a switch that pins
src-mac), à la macOS pseudo-bridge. Lets several VM/guests share one upstream port
that only accepts a single MAC. Control plane in Rust; datapath offloaded to the
kernel via **nftables** (netdev) or **ebpf** (tc). Design: [ARCHITECTURE.md](ARCHITECTURE.md).

The product **never shells out** to `ip`/`nft`/`tc`/`bpftool` — everything is netlink
(rtnetlink + hand-rolled nf_tables) or BPF syscalls (aya), so it runs on Android where
those binaries aren't guaranteed. Binaries are static (musl) and run under glibc, musl,
or bionic.

## Layout

    src/cli.rs        CLI (-i/-e/-m/-fi/-fb/--nflog-group/--timeout/--max-cap)
    src/types.rs      Mac, IP family, packet-kind
    src/state.rs      entries store + per-mac/global FIFO caps
    src/packet.rs     L3 parse + ICMPv6 checksum (nft copy path)
    src/afpacket.rs   raw L2 send: ND reinject, gratuitous ARP / unsolicited NA
    src/netlink.rs    rtnetlink link/addr/route/rule + multicast monitor
    src/core.rs       the actor: entries (truth) + syncer (recompute/diff/reconcile/
                      mirror/routes) + packet processor + aging
    src/backend/      Backend trait + two engines:
      nft/wire.rs       hand-rolled nf_tables netlink encoder (zero libnftnl)
      nft/nflog.rs      nfnetlink_log reader (copy path)
      nft/mod.rs        ruleset + set/map elements + flush
      ebpf.rs           aya loader: tc(TCX) attach, maps, ringbuf, second-chance flush
    bpf/pbridge.bpf.c BPF datapath (one arch-independent object, build.rs compiles it)

## Build

    ./build.sh                # both static targets -> dist/pbridge-{linux-x64,android-arm64}
    ./build.sh x64            # just x86_64-musl
    ./build.sh arm64          # just aarch64-musl
    ./build.sh host           # quick host debug build (./target/debug/pbridge)

Needs `clang` (build.rs compiles the BPF object). aarch64 links with the bundled
`rust-lld`; no external cross toolchain required.

## Run

    pbridge -i wlan0 -e ebpf -m fwd       # Android GKI (STA upstream)
    pbridge -i eth0  -e nft  -m direct    # linux container

**pbridge pins only `up0`.** `fwd` mode: up0 can't bridge → pbridge makes a veth pair
`fwd0╌fwd1` and forwards between up0 and fwd0; **you** enslave `fwd1` into the VM bridge
(`brctl addif yourbr <if>-br` or `ip link set <if>-br master yourbr`). `direct` mode:
**you** enslave up0 into a bridge. Either way pbridge tracks the bridge (`fwd1.master` /
`up0.master`) dynamically — attach, change, or detach it at any time and it follows
(HOSTMAC, host-IP mirror, and host→VM routes all re-point automatically).

## Test

    # x64 functional matrix: mode(direct,fwd) x engine(nft,ebpf), ~15 cases each.
    # nft runs under a bpf-blocking seccomp wrapper (proves the nft path uses 0 ebpf).
    bash tests/finaltest/matrix.sh

    # aarch64 ebpf on a REAL Android GKI 6.6 kernel under QEMU (TCG):
    sudo bash tests/setup-artifacts.sh             # fetch GKI Image + Alpine arm64 + redroid
    sudo bash tests/finaltest/run-android.sh       # ENV=android matrix (ebpf only; GKI has no nft)
    sudo bash tests/finaltest/run-redroid-pbridge.sh  # pbridge runs under redroid (bionic) on GKI

    cargo test                                     # pure-logic unit tests

## Validated

| env × engine        | direct        | fwd           |
|---------------------|---------------|---------------|
| x64 nft (bpf-blocked) | ✅ 16/16     | ✅ 16/16      |
| x64 ebpf            | ✅ 16/16      | ✅ 16/16      |
| aarch64 ebpf @ GKI 6.6 (QEMU) | ✅ 16/16 | ✅ 16/16  |

Cases cover: ARP/ND connectivity (v4+v6), zero src-mac leak on the wire, host
coexistence, host→VM routing (fwd /32-/128 + mirror; direct on-link), multi-guest
isolation, guest MAC change, HOSTMAC change (gratuitous ARP / unsolicited NA), guest
IP change, idle timeout + relearn, and engine isolation (nft uses 0 ebpf, ebpf uses 0
nft). redroid15 (bionic) on GKI: the binary starts. See ARCHITECTURE.md §驗證.
