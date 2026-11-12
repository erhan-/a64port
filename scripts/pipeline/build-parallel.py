#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Memory-aware parallel unit compiler for a64port generated C.

Peak RSS for one generated translation unit is ~134x its C source size
(measured here on GCC 16: 30.4 MB -> 3.97 GB). A flat `-P 12` would OOM-kill
cc1; a flat `-P 4` would idle 28 of 32 threads on the long tail of small units.
So schedule largest-first against a *memory* budget, not a process count.

Two modes:
  * scan mode   : <emitted-dir> [--rt DIR] [--define -DFOO]  -> compiles src/*.c
  * manifest    : --manifest FILE   (lines: src<TAB>obj<TAB>extra cflags)
                  used for the multi-module build, where each module needs its
                  own -D renames and its own -I paths.

Objects land at the same path/name as tools/recomp/build-guest.sh uses
(".obj-<cc>-<opt>/<stem>.o"), so build-guest.sh later reuses them as cache.
"""
import argparse
import os
import subprocess
import sys
import time


def main():
    # "--opt -O1" / "-I -X" style values must not be read as option names.
    argv = [sys.argv[0]]
    i = 1
    while i < len(sys.argv):
        a = sys.argv[i]
        if a in ("--opt", "--cc", "--obj", "--rt", "--log", "--status", "--manifest") and \
                i + 1 < len(sys.argv) and sys.argv[i + 1].startswith("-"):
            argv.append(a + "=" + sys.argv[i + 1])
            i += 2
            continue
        argv.append(a)
        i += 1

    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", nargs="?", default=None)
    ap.add_argument("--obj", required=True)
    ap.add_argument("--rt", default=None, help="runtime dir (for -I in scan mode)")
    ap.add_argument("--manifest", default=None,
                    help="lines: src<TAB>obj<TAB>extra cflags")
    ap.add_argument("--define", action="append", default=[],
                    help="extra -D flag for every unit (repeatable)")
    ap.add_argument("--cc", default="clang")
    ap.add_argument("--opt", default="-O1")
    ap.add_argument("--mem-gb", type=float, default=50.0)
    ap.add_argument("--jobs-max", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--rss-factor", type=float, default=140.0)
    ap.add_argument("--status", default=None)
    ap.add_argument("--log", default=None)
    a = ap.parse_args(argv[1:])

    obj = os.path.abspath(a.obj)
    outdir = os.path.abspath(a.outdir) if a.outdir else None
    os.makedirs(obj, exist_ok=True)
    logf = open(a.log, "a", buffering=1) if a.log else None

    def emit(line):
        print(line, flush=True)
        if logf:
            logf.write(line + "\n")

    # ---- unit list -------------------------------------------------------
    units = []          # (size, src, obj, extra_flags)
    if a.manifest:
        for line in open(a.manifest):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            p = line.split("\t")
            extra = p[2].split() if len(p) > 2 and p[2] else []
            units.append((os.path.getsize(p[0]), p[0], p[1], extra))
    else:
        for f in sorted(os.listdir(os.path.join(outdir, "src"))):
            if not f.endswith(".c"):
                continue
            src = os.path.join(outdir, "src", f)
            units.append((os.path.getsize(src), src,
                          os.path.join(obj, f[:-2] + ".o"), []))
    units.sort(key=lambda t: -t[0])

    total = len(units)
    budget_mb = a.mem_gb * 1024.0

    def est_mb(sz):
        return max(64.0, sz / 1048576.0 * a.rss_factor)

    base = ["-std=c11", a.opt, "-g", "-D_GNU_SOURCE", "-ffp-contract=off",
            "-fno-fast-math", "-foptimize-sibling-calls"]
    if outdir:
        base += [f"-I{outdir}", f"-I{os.path.join(outdir, 'a64port')}"]
    if a.rt:
        base += [f"-I{os.path.abspath(a.rt)}"]
    base += a.define

    t0 = time.time()
    done = cached = failed = 0
    running = {}
    peak_jobs = peak_est = 0.0
    times = {}

    def status_line():
        cur = sum(v[2] for v in running.values())
        return (f"{done + cached}/{total} done ({cached} cached)  running={len(running)}  "
                f"est={cur / 1024:.1f}GB  jobs_peak={int(peak_jobs)}  "
                f"mem_peak={peak_est / 1024:.1f}GB  elapsed={time.time() - t0:.0f}s")

    def write_status():
        if a.status:
            open(a.status, "w").write(status_line() + "\n")

    emit(f"build-parallel: {total} units, budget {a.mem_gb:.0f}GB, "
         f"jobs_max {a.jobs_max}, opt {a.opt}")
    emit(f"  obj dir {obj}")

    pending = list(units)
    while pending or running:
        while pending and len(running) < a.jobs_max:
            sz, src, o, extra = pending[0]
            e = est_mb(sz)
            cur = sum(v[2] for v in running.values())
            if running and cur + e > budget_mb:
                break
            pending.pop(0)
            if os.path.exists(o) and os.path.getmtime(o) > os.path.getmtime(src):
                cached += 1
                continue
            err = open(o + ".stderr", "wb")
            p = subprocess.Popen([a.cc] + base + extra + ["-c", src, "-o", o],
                                 stderr=err, stdout=subprocess.DEVNULL)
            running[p.pid] = (src, o, e, time.time(), p, err)
            if len(running) > peak_jobs:
                peak_jobs = len(running)
            tot = sum(v[2] for v in running.values())
            if tot > peak_est:
                peak_est = tot

        for pid in list(running):
            src, o, e, st, p, err = running[pid]
            if p.poll() is None:
                continue
            err.close()
            dt = time.time() - st
            del running[pid]
            stem = os.path.basename(src)
            times[stem] = dt
            if p.returncode != 0:
                failed += 1
                emit(f"[{time.time() - t0:7.1f}s] FAIL {stem} rc={p.returncode}")
                try:
                    for ln in open(o + ".stderr").read().splitlines()[:15]:
                        emit("      " + ln)
                except OSError:
                    pass
            else:
                done += 1
                if os.path.exists(o + ".stderr"):
                    os.unlink(o + ".stderr")
                emit(f"[{time.time() - t0:7.1f}s] ok {done + cached:3d}/{total} "
                     f"run={len(running):2d} {dt:6.1f}s {stem}")

        if failed:
            emit("aborting: a unit failed to compile")
            for _, _, _, _, p, err in running.values():
                p.kill()
            return 1

        write_status()
        if running or pending:
            time.sleep(0.4)

    wall = time.time() - t0
    emit("")
    emit(f"units complete: {done} compiled + {cached} cached = {done + cached}/{total} "
         f"in {wall:.0f}s wall")
    emit(f"peak concurrent compiles: {int(peak_jobs)} (est peak memory {peak_est / 1024:.1f} GB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
