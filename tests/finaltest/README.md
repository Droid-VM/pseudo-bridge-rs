# tests/finaltest — pbridge test harness

Functional matrix + Android (GKI/QEMU) + redroid smoke for the pbridge implementation.
Test scripts may freely use `ip`/`nft`/`tc`/`tcpdump` (the **product** doesn't — see
ARCHITECTURE.md — but the harness can).

## Scripts

| script | what |
|---|---|
| `smoke.sh MODE ENGINE` | one-guest quick check (v4+v6 reach gw, no src-mac leak) |
| `matrix.sh` | full matrix: mode(direct,fwd) × engine — ~15 cases each. `ENV=linux` (default) runs nft+ebpf; `ENV=android` runs ebpf only |
| `noebpf.c` → `noebpf` | seccomp wrapper that blocks `bpf()`. matrix.sh runs the **nft** engine under it → proves the nft path makes zero bpf() calls ("no ebpf permission") |
| `../../build.sh` | build static `dist/pbridge-linux-x64` + `dist/pbridge-android-arm64` (build-targets.sh is a shim to it) |
| `run-android.sh` | boot GKI 6.6 + Alpine arm64 under QEMU, run `ENV=android` matrix (ebpf) |
| `run-redroid-pbridge.sh` | boot GKI 6.6 + redroid15 (bionic) under QEMU, run the pbridge binary |
| `setup-artifacts.sh` (in `tests/`) | fetch + boot-verify GKI Image / Alpine / redroid (idempotent) |

## Topology (per matrix config)

    ns up (gw 10.0.0.1 / fd00::1)  ──u0╌up0──  ns hostns (pbridge)  ──gbr╌g1eth──  ns g1
      single-MAC enforce (tc flower)              br0; g1,g2 on br0                  ns g2
    fwd   : pbridge makes mt-if/mt-br (pins only up0); the harness enslaves mt-br into br0
            after startup (= operator's job; pbridge tracks mt-br.master). hooks fwd0-ingress + up0-ingress.
    direct: up0 enslaved in br0, IP on br0; hooks up0-egress + up0-ingress.

The upstream "only one MAC" rule is `tc flower src_mac <HOSTMAC> accept / matchall drop`
(no nft, so it works on stock GKI too; where flower is absent the on-wire no-leak
capture still proves correctness). The gateway sets `arp_accept=1` and its neigh is
flushed on a HOSTMAC change to model a learning switch (a Linux host otherwise keeps a
REACHABLE neigh until NUD times out — pbridge's gratuitous ARP is correct regardless).

## Quick start

    cargo build                                    # ./target/debug/pbridge
    bash matrix.sh                                 # x64 nft + ebpf, both modes
    ./build.sh                                     # from repo root (build-targets.sh is a shim)
    sudo bash ../setup-artifacts.sh
    sudo bash run-android.sh                       # aarch64 ebpf on real GKI 6.6 (QEMU/TCG)
    sudo bash run-redroid-pbridge.sh              # pbridge under redroid bionic on GKI

## Results (validated)

    x64 nft  (bpf-blocked) : direct 16/16, fwd 16/16
    x64 ebpf               : direct 16/16, fwd 16/16
    aarch64 ebpf @ GKI 6.6 : direct 16/16, fwd 16/16    (QEMU TCG)
    redroid15 + GKI 6.6    : pbridge starts (PBRIDGE_REDROID_RUN_OK)

## GKI 6.6 config notes (android15-6.6.102, the pinned kernel)

Has: `BPF_SYSCALL`, `DEBUG_INFO_BTF`, `NET_XGRESS` (TCX), `NET_CLS_MATCHALL`,
`NETFILTER_NETLINK_LOG`, `BRIDGE`, `VETH`. Lacks: `NF_TABLES` (so nft is x64-only) and
`NET_CLS_FLOWER` (so the upstream filter is skipped on GKI; no-leak capture still runs).

`unpack_boot.py` (Android boot.img → raw Image), `android-init.sh` (matrix rdinit),
`rd-init` / `rd-pb-init` (redroid initramfs inits) are helpers used by the above.
The rest of this directory's history (android16-6.12 era audits) is superseded.
