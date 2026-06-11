#!/usr/bin/env python3
"""Run the pbridge test suite in parallel and summarize the results.

Every unit runs in its own mount+net namespace (unshare) with a private /tmp and a
private /run/netns, so the fixed names the scripts use everywhere (netns up/hostns/
g1/g2, /tmp/pb-*.log, nft table "pbridge", NFLOG groups) can't collide across
parallel units. nf_tables/NFLOG state is per-netns; BPF map/prog fds are per-process
— nothing else is shared.

Units (the parallelization grain):
  - matrix.sh split per config: mode(direct,fwd,fwd-with-offload) x engine(nft,ebpf)
    (matrix.sh honors MODES=/ENGINES= for exactly this)
  - each func-*.sh split per engine (they honor ENGINES=)
  - cargo test (no namespace needed)

Usage:
  sudo tests/run_all_test.py                 # everything, default parallelism
  sudo tests/run_all_test.py -j 4            # cap parallelism
  sudo tests/run_all_test.py --only matrix   # substring filter
  tests/run_all_test.py --list               # show units and exit

A unit's verdict is its exit code (every harness script exits non-zero on failure;
output can legitimately contain the word FAILED, e.g. a neigh state in an ok-line).
Full per-unit output lands in the log directory printed at the end.
"""

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FT = "tests/finaltest"

# live units, for Ctrl-C: each runs in its own session (own pgid), so killing our
# group would NOT reach them — they must be killed individually.
RUNNING = {}
RUNNING_LOCK = threading.Lock()

# Inside the unshared mount+net namespace: private /tmp (per-unit pb logs/captures),
# private /run/netns (per-unit `ip netns` names), loopback up, then the unit command.
WRAP = (
    "mount -t tmpfs tmpfs /tmp && "
    "mkdir -p /run/netns && mount -t tmpfs tmpfs /run/netns && "
    'ip link set lo up && exec "$@"'
)

FUNC_SCRIPTS = (
    "func-silent-vm",
    "func-offload-workaround",
    "func-offload-keepalive",
    "func-arp-keepalive",
)


def build_units():
    """(name, argv, extra_env, isolate) in rough longest-first order so the slowest
    units start immediately and don't tail the run."""
    units = []
    for mode in ("direct", "fwd", "fwd-with-offload"):
        for eng in ("nft", "ebpf"):
            units.append(
                (
                    f"matrix:{mode}x{eng}",
                    ["bash", f"{FT}/matrix.sh"],
                    {"MODES": mode, "ENGINES": eng},
                    True,
                )
            )
    for script in FUNC_SCRIPTS:
        for eng in ("nft", "ebpf"):
            units.append(
                (f"{script}:{eng}", ["bash", f"{FT}/{script}.sh"], {"ENGINES": eng}, True)
            )
    units.append(("cargo-test", ["cargo", "test", "--quiet"], {}, False))
    return units


def run_once(name, argv, extra_env, isolate, timeout):
    if isolate:
        argv = [
            "unshare", "--mount", "--net", "--fork", "--kill-child",
            "bash", "-c", WRAP, "wrap",
        ] + argv
    env = dict(os.environ, **extra_env)
    # start_new_session: the unit gets its own process group so a timeout/Ctrl-C can
    # kill the whole tree (pbridge, tcpdump, sleeps) and not just the shell.
    proc = subprocess.Popen(
        argv, cwd=ROOT, env=env, start_new_session=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    with RUNNING_LOCK:
        RUNNING[name] = proc
    try:
        out, _ = proc.communicate(timeout=timeout)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        out, _ = proc.communicate()
        out = (out or "") + f"\n*** TIMEOUT after {timeout}s (killed) ***\n"
        rc = -1
    finally:
        with RUNNING_LOCK:
            RUNNING.pop(name, None)
    return rc, out or ""


def run_unit(name, argv, extra_env, isolate, timeout, log_dir, retry):
    t0 = time.monotonic()
    log = log_dir / f"{name.replace(':', '_').replace('/', '_')}.log"
    attempts = 0
    rc, out = -1, ""
    while attempts <= retry:
        attempts += 1
        rc, chunk = run_once(name, argv, extra_env, isolate, timeout)
        out += ("" if attempts == 1 else f"\n*** retry {attempts - 1} ***\n") + chunk
        if rc == 0:
            break
    log.write_text(out)
    return name, rc == 0, rc, time.monotonic() - t0, attempts


def prebuild():
    """Build everything units depend on, once, before going parallel."""
    print("prebuild: cargo build (pbridge) ...", flush=True)
    subprocess.run(["cargo", "build"], cwd=ROOT, check=True)
    apfsim = ROOT / "tools/apfsim/target/x86_64-unknown-linux-musl/release/apfsim"
    if not apfsim.exists():
        print("prebuild: cargo build (apfsim, musl) ...", flush=True)
        subprocess.run(
            ["cargo", "build", "--release", "--target", "x86_64-unknown-linux-musl"],
            cwd=ROOT / "tools/apfsim", check=True,
        )
    noebpf = ROOT / FT / "noebpf"
    if not noebpf.exists():
        print("prebuild: cc noebpf ...", flush=True)
        subprocess.run(
            ["cc", "-O2", "-o", str(noebpf), str(ROOT / FT / "noebpf.c"), "-lseccomp"],
            check=True,
        )


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-j", "--jobs", type=int, default=6, help="parallel units (default 6)")
    ap.add_argument("--only", default="", help="run only units whose name contains this substring")
    ap.add_argument("--timeout", type=int, default=900, help="per-unit timeout seconds (default 900)")
    ap.add_argument("--retry", type=int, default=1,
                    help="re-run a failed unit up to N times (default 1); retried passes are marked")
    ap.add_argument("--list", action="store_true", help="list units and exit")
    args = ap.parse_args()

    units = [u for u in build_units() if args.only in u[0]]
    if args.list:
        for name, argv, env, isolate in units:
            envs = " ".join(f"{k}={v}" for k, v in env.items())
            print(f"{name:34} {envs} {' '.join(argv)}{'' if isolate else '   (no netns isolation)'}")
        return 0
    if not units:
        print(f"no units match --only {args.only!r}")
        return 2
    if os.geteuid() != 0:
        print("must run as root (unshare + netns + tc + bpf)")
        return 2

    prebuild()
    log_dir = Path(f"/tmp/pbridge-run-all-{time.strftime('%Y%m%d-%H%M%S')}")
    log_dir.mkdir(parents=True)

    t0 = time.monotonic()
    results = {}
    print(f"running {len(units)} units, -j {args.jobs}, logs: {log_dir}", flush=True)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futs = {
            pool.submit(run_unit, n, a, e, i, args.timeout, log_dir, args.retry): n
            for n, a, e, i in units
        }
        done = 0
        try:
            for fut in as_completed(futs):
                name, ok, rc, dur, attempts = fut.result()
                results[name] = (ok, rc, dur, attempts)
                done += 1
                mark = "PASS" if ok else "FAIL"
                note = f" (attempt {attempts})" if attempts > 1 else ""
                print(f"[{done:2}/{len(units)}] {mark}  {name:34} {dur:6.1f}s{note}", flush=True)
        except KeyboardInterrupt:
            print("\ninterrupted — killing running units")
            for fut in futs:
                fut.cancel()
            with RUNNING_LOCK:
                for proc in RUNNING.values():
                    # each unit is its own session leader; unshare --kill-child
                    # then reaps the namespaced tree underneath it.
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            raise

    wall = time.monotonic() - t0
    failed = [n for n, (ok, *_rest) in results.items() if not ok]
    print("\n================ SUMMARY ================")
    for name, _, _, _ in units:
        ok, rc, dur, attempts = results[name]
        mark = ("PASS" if attempts == 1 else f"PASS (retry {attempts - 1})") if ok else f"FAIL (rc={rc})"
        print(f"  {mark:14} {name:34} {dur:6.1f}s")
    print("=========================================")
    print(f"{len(units)} units: {len(units) - len(failed)} pass, {len(failed)} fail; wall {wall:.0f}s; logs {log_dir}")
    if failed:
        for n in failed:
            print(f"  see {log_dir}/{n.replace(':', '_')}.log")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
