"""Layer 1 — environments: where a unit executes and with what constraints.

An env contributes: which engines are available, and how pbridge is wrapped.
(`gki` is dispatched to the QEMU executor by run.py; inside the guest the suite
runs exactly like `local` — the env object still describes its constraints.)
"""

from dataclasses import dataclass, field

from common import NOEBPF


@dataclass(frozen=True)
class Env:
    name: str
    engines: tuple[str, ...]
    pb_wrap: tuple[str, ...] = field(default=())  # prefix argv for the pbridge launch
    executor: str = "host"  # host | qemu


ENVS = {
    # plain x64 host with bpf available — the ebpf-engine environment
    "local": Env("local", engines=("ebpf",)),
    # linux container without bpf(): pbridge under the seccomp wrapper, nft only.
    # passing proves the nft path needs zero ebpf.
    "lxc": Env("lxc", engines=("nft",), pb_wrap=(str(NOEBPF),)),
    # aarch64 Android GKI in QEMU: ebpf only (stock GKI has no NF_TABLES)
    "gki": Env("gki", engines=("ebpf",), executor="qemu"),
}
