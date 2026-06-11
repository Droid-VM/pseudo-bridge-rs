#!/usr/bin/env python3
"""pbridge suite orchestrator: expand env × sim × mode × engine into units, run them
in parallel (each inside its own mount+net namespace — fixed ns names never collide),
and aggregate per-case results.

  units = env(engine constraint) × sim(mode constraint):
    sim portsec: direct, fwd, fwd-with-offload
    sim apf    : fwd, fwd-with-offload
    sim qcom   : fwd-with-offload
  envs: local (ebpf) + lxc (nft under the bpf-blocking wrapper) -> 12 host units.
  gki (aarch64 GKI in one long-lived QEMU) is enumerated with --gki; its executor
  dispatches into the guest where the same suite.py runs (same isolation inside).

  sudo tests/suite/run.py                # all host units
  sudo tests/suite/run.py -j 4 --only qcom
  tests/suite/run.py --list
"""

import argparse
import os
import re
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

SIM_MODES = {
    "portsec": ("direct", "fwd", "fwd-with-offload"),
    "apf": ("fwd", "fwd-with-offload"),
    "qcom": ("fwd-with-offload",),
}
ENV_ENGINES = {"local": ("ebpf",), "lxc": ("nft",), "gki": ("ebpf",)}

WRAP = (
    "mount -t tmpfs tmpfs /tmp && "
    "mkdir -p /run/netns && mount -t tmpfs tmpfs /run/netns && "
    'ip link set lo up && exec "$@"'
)

# unshare invocation. Overridable so the GKI guest (busybox unshare, no --kill-child)
# can use the basic flags; the host default uses util-linux for tighter child cleanup.
UNSHARE = os.environ.get(
    "SUITE_UNSHARE", "unshare --mount --net --fork --kill-child").split()

RUNNING = {}
RUNNING_LOCK = threading.Lock()
RESULT_RX = re.compile(r"^(ok|fail|skip) (\S+)")


def build_units(with_gki: bool):
    units = []
    envs = ["local", "lxc"] + (["gki"] if with_gki else [])
    for env in envs:
        for engine in ENV_ENGINES[env]:
            for sim, modes in SIM_MODES.items():
                for mode in modes:
                    units.append((f"{env}/{engine}/{sim}/{mode}", env, sim, mode, engine))
    return units


def run_unit(name, env, sim, mode, engine, timeout, log_dir, retry):
    # gki units don't come through here — they run in one QEMU boot via the batch
    # executor (gki_run.run_gki), launched separately in main().
    argv = [
        *UNSHARE, "bash", "-c", WRAP, "wrap",
        sys.executable, str(HERE / "suite.py"),
        "--env", env, "--sim", sim, "--mode", mode, "--engine", engine,
    ]
    t0 = time.monotonic()
    out_all = ""
    attempts = 0
    rc = -1
    while attempts <= retry:
        attempts += 1
        proc = subprocess.Popen(argv, cwd=ROOT, start_new_session=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        with RUNNING_LOCK:
            RUNNING[name] = proc
        try:
            out, _ = proc.communicate(timeout=timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            out, _ = proc.communicate()
            out = (out or "") + f"\n*** TIMEOUT after {timeout}s ***\n"
            rc = -1
        finally:
            with RUNNING_LOCK:
                RUNNING.pop(name, None)
        out_all += ("" if attempts == 1 else f"\n*** retry {attempts - 1} ***\n") + (out or "")
        if rc == 0:
            break
    (log_dir / f"{name.replace('/', '_')}.log").write_text(out_all)
    cases = {}
    for line in out_all.splitlines():
        m = RESULT_RX.match(line)
        if m:
            cases[m.group(2)] = m.group(1)  # last attempt wins
    return name, rc == 0, "", time.monotonic() - t0, cases


def gki_guest(jobs: int) -> int:
    """Run inside the GKI guest: every gki unit in parallel, each in its own
    unshare --mount --net (GKI has netns + mount ns), bracketed by @@UNIT markers on
    the console for the host (gki_run._parse) to demux. Same run_unit/unshare path as
    the host side — the guest is just another executor."""
    units = [(f"gki/ebpf/{sim}/{mode}", "gki", sim, mode, "ebpf")
             for sim, modes in SIM_MODES.items() for mode in modes]
    log_dir = Path("/tmp/gki-guest-logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    print("@@GKI_START", flush=True)
    rc = 0
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futs = {pool.submit(run_unit, n, e, s, m, g, 900, log_dir, 0): n
                for n, e, s, m, g in units}
        for fut in as_completed(futs):
            name, ok, _note, _dur, cases = fut.result()
            print(f"@@UNIT {name}", flush=True)
            for cn, st in cases.items():
                print(f"{st} {cn}", flush=True)
                if st == "fail":
                    rc = 1
            if not cases:
                print("fail unit-start", flush=True)
                rc = 1
            if not ok:  # dump the unit log to the console for post-mortem
                logf = log_dir / f"{name.replace('/', '_')}.log"
                print("@@LOG-BEGIN", flush=True)
                try:
                    for ln in logf.read_text().splitlines()[-40:]:
                        print(f"| {ln}", flush=True)
                except OSError:
                    print("| (no log)", flush=True)
                print("@@LOG-END", flush=True)
            print("@@UNITEND", flush=True)
    print("@@GKI_COMPLETE", flush=True)
    return rc


def prebuild():
    print("prebuild: cargo build (pbridge) ...", flush=True)
    subprocess.run(["cargo", "build"], cwd=ROOT, check=True)
    upsim = ROOT / "tools/upsim/target/x86_64-unknown-linux-musl/release/upsim"
    if not upsim.exists():
        print("prebuild: cargo build (upsim, musl) ...", flush=True)
        subprocess.run(["cargo", "build", "--release", "--target",
                        "x86_64-unknown-linux-musl"], cwd=ROOT / "tools/upsim", check=True)
    noebpf = ROOT / "tests/finaltest/noebpf"
    if not noebpf.exists():
        subprocess.run(["cc", "-O2", "-o", str(noebpf),
                        str(ROOT / "tests/finaltest/noebpf.c"), "-lseccomp"], check=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-j", "--jobs", type=int, default=6)
    ap.add_argument("--only", default="", help="substring filter on unit names")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--retry", type=int, default=1)
    ap.add_argument("--gki", action="store_true", help="include gki (QEMU) units")
    ap.add_argument("--gki-guest", action="store_true",
                    help="(inside the GKI guest) run gki units in parallel with console markers")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.gki_guest:
        return gki_guest(args.jobs)

    units = [u for u in build_units(args.gki) if args.only in u[0]]
    if args.list:
        for name, *_ in units:
            print(name)
        return 0
    if not units:
        print(f"no units match --only {args.only!r}")
        return 2
    if os.geteuid() != 0:
        print("must run as root (unshare + netns + tc + bpf)")
        return 2

    host_units = [u for u in units if u[1] != "gki"]
    gki_units = [u for u in units if u[1] == "gki"]

    prebuild()
    log_dir = Path(f"/tmp/pbridge-suite-{time.strftime('%Y%m%d-%H%M%S')}")
    log_dir.mkdir(parents=True)
    print(f"running {len(host_units)} host units (-j {args.jobs})"
          f"{f' + {len(gki_units)} gki units (1 QEMU boot)' if gki_units else ''}; "
          f"logs: {log_dir}", flush=True)

    t0 = time.monotonic()
    results = {}

    # The gki matrix runs in one QEMU boot AFTER the host pool finishes, not alongside
    # it: a -j host pool saturates every core, and the aarch64 guest under TCG needs its
    # vCPU threads to make progress — running them concurrently starves qemu so hard it
    # can't even boot within the timeout. Sequential keeps total wall acceptable (host
    # ~minutes, then the guest on a quiet machine) and makes the guest reliable.
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futs = {pool.submit(run_unit, n, e, s, m, g, args.timeout, log_dir, args.retry): n
                for n, e, s, m, g in host_units}
        done = 0
        try:
            for fut in as_completed(futs):
                name, ok, note, dur, cases = fut.result()
                results[name] = (ok, dur, cases, note)
                done += 1
                nf = sum(1 for v in cases.values() if v == "fail")
                no = sum(1 for v in cases.values() if v == "ok")
                ns = sum(1 for v in cases.values() if v == "skip")
                print(f"[{done:2}/{len(host_units)}] {'PASS' if ok else 'FAIL'}  {name:36} "
                      f"{dur:6.1f}s  ({no} ok, {nf} fail, {ns} skip)", flush=True)
        except KeyboardInterrupt:
            print("\ninterrupted — killing running units")
            for fut in futs:
                fut.cancel()
            with RUNNING_LOCK:
                for proc in RUNNING.values():
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            raise

    if gki_units:
        import gki_run
        print("gki: booting QEMU + running the matrix on the now-quiet machine "
              "(TCG, slow) ...", flush=True)
        try:
            gki_res, complete, gki_log = gki_run.run_gki(max(args.timeout * 3, 2400))
        except Exception as e:
            print(f"gki: executor crashed: {e}", flush=True)
            gki_res, complete, gki_log = {}, False, "?"
        note = "" if complete else "guest did not complete"
        for name, *_ in gki_units:
            ok, cases = gki_res.get(name, (False, {}))
            results[name] = (ok, 0.0, cases, note if not cases else "")
            nf = sum(1 for v in cases.values() if v == "fail")
            no = sum(1 for v in cases.values() if v == "ok")
            ns = sum(1 for v in cases.values() if v == "skip")
            print(f"[gki] {'PASS' if ok else 'FAIL'}  {name:36}   ({no} ok, {nf} fail, {ns} skip)",
                  flush=True)
        print(f"gki console log: {gki_log}", flush=True)

    wall = time.monotonic() - t0
    failed_units = [n for n, (ok, *_r) in results.items() if not ok]
    print("\n================== per-case summary ==================")
    all_cases = []
    for name, (_, _, cases, _) in results.items():
        for cn in cases:
            if cn not in all_cases:
                all_cases.append(cn)
    for cn in all_cases:
        st = [v.get(cn) for _, _, v, _ in results.values()]
        no, nf, ns = st.count("ok"), st.count("fail"), st.count("skip")
        mark = "PASS" if nf == 0 else "FAIL"
        print(f"  {mark}  {cn:26} {no:2} ok, {nf} fail, {ns} skip")
    print("======================================================")
    if failed_units:
        print("failed units:")
        for n in failed_units:
            print(f"  {n}  (log: {log_dir}/{n.replace('/', '_')}.log)")
            for cn, st in results[n][2].items():
                if st == "fail":
                    print(f"      fail: {cn}")
            if results[n][3]:
                print(f"      note: {results[n][3]}")
    print(f"{len(units)} units: {len(units) - len(failed_units)} pass, "
          f"{len(failed_units)} fail; wall {wall:.0f}s; logs {log_dir}")
    return 1 if failed_units else 0


if __name__ == "__main__":
    sys.exit(main())
