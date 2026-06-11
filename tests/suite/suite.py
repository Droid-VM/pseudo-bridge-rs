#!/usr/bin/env python3
"""Run ONE unit — (env, sim, mode, engine) — against one topology + one pbridge:
filter the case registry by each case's `requires`, execute in registration order,
print one line per case. Importable by run.py (same process protocol either way).

  suite.py --env lxc --sim qcom --mode fwd-with-offload --engine nft [--only conn]
"""

import argparse
import sys
import time
import traceback

from cases import CASES, Ctx
from common import Fail
from envs import ENVS
from pb import Pbridge
from topo import Topo


def run_unit(env: str, sim: str, mode: str, engine: str, only: str = "") -> list[tuple]:
    """Returns [(case, status, detail, seconds)]; status in ok|fail|skip."""
    e = ENVS[env]
    topo = Topo(sim, mode)
    pb = Pbridge(mode, engine, wrap=e.pb_wrap)
    ctx = Ctx(env=env, sim=sim, mode=mode, engine=engine, topo=topo, pb=pb)
    results = []
    try:
        topo.up()
        if not pb.start():
            import pb as pbmod
            try:
                tail = Path(pbmod.PB_LOG).read_text()[-600:]
            except OSError:
                tail = "(no pbridge log)"
            try:
                up = Path("/tmp/upsim.log").read_text()[-200:]
            except OSError:
                up = ""
            return [("unit-start", "fail",
                     f"pbridge did not start:\n{tail}\n--upsim--\n{up}", 0.0)]
        for c in CASES:
            if only and only not in c.name:
                continue
            if not c.requires(ctx):
                results.append((c.name, "skip", "", 0.0))
                continue
            t0 = time.monotonic()
            try:
                c.fn(ctx)
                results.append((c.name, "ok", "", time.monotonic() - t0))
            except Fail as f:
                results.append((c.name, "fail", str(f), time.monotonic() - t0))
            except Exception:
                results.append((c.name, "fail", traceback.format_exc(limit=3),
                                time.monotonic() - t0))
    finally:
        pb.stop()
        topo.down()
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", required=True, choices=list(ENVS))
    ap.add_argument("--sim", required=True, choices=["portsec", "apf", "qcom"])
    ap.add_argument("--mode", required=True,
                    choices=["direct", "fwd", "fwd-with-offload"])
    ap.add_argument("--engine", required=True, choices=["nft", "ebpf"])
    ap.add_argument("--only", default="", help="substring filter on case names")
    args = ap.parse_args()

    results = run_unit(args.env, args.sim, args.mode, args.engine, args.only)
    rc = 0
    for name, status, detail, dur in results:
        line = f"{status} {name} ({dur:.1f}s)"
        if status == "fail":
            rc = 1
            line += f" - {detail.strip().splitlines()[-1] if detail else ''}"
        print(line, flush=True)
        if status == "fail" and detail and "\n" in detail:
            for ln in detail.strip().splitlines():
                print(f"#   {ln}")
    n_ok = sum(1 for r in results if r[1] == "ok")
    n_fail = sum(1 for r in results if r[1] == "fail")
    n_skip = sum(1 for r in results if r[1] == "skip")
    print(f"# unit {args.env}/{args.sim}/{args.mode}/{args.engine}: "
          f"{n_ok} ok, {n_fail} fail, {n_skip} skip")
    return rc


if __name__ == "__main__":
    sys.exit(main())
