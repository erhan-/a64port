#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""guest-hot.py - rank the guest functions an application spends the most time in.

The multi host has a flat sampling profiler (host_loader.c, A64PORT_PROF=1):
a thread samples every guest thread's PC every 10 ms and, every 250 ms, prints
the window's top 30 as

    [prof] t=... N busy samples, M idle/parked, L lost
    [prof]     1234   4.5%  pc=0x3fde29818 libX11

Each sample is `module` + a module-relative address, so the raw lines already
answer "which module".  They do not answer "which function", which is what you
need before writing a native leaf.  This script closes that gap:

  * aggregate the windowed top-30 rows (self-time by construction),
  * snap every PC to the function that contains it using the module's
    .eh_frame FDE ranges (`readelf -wf`), and
  * print the hottest functions as `module+0xSTART`, with the share of all
    attributed samples and the function's code size.

That list is the input for hand leaves: pick a hot, self-contained
leaf, port it from source, replace it with --native-leaf, verify byte-exactly.

Usage:
  scripts/guest-hot.py <run.log> [--rootfs DIR] [--top N] [--dumps N]

<run.log> is a log from a run with A64PORT_PROF=1 (any run of the
host binary with that variable set).  --rootfs defaults to rootfs/ next to this repository.
"""

from __future__ import annotations

import argparse
import bisect
import glob
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

HEADER_RE = re.compile(r"\[prof\]\s+t=[\d.]+\s+(\d+) busy samples,\s+(\d+) idle/parked,\s+(\d+) lost")
ROW_RE = re.compile(r"\[prof\]\s+(\d+)\s+([\d.]+)%\s+pc=0x([0-9a-f]+)\s+(\S+)")
# The profiler samples absolute guest PCs; map each module back to its load base.
BASE_EXE_RE = re.compile(r"exe @(0x[0-9a-f]+)")
BASE_INTERP_RE = re.compile(r"interp @(0x[0-9a-f]+)")
BASE_MAP_RE = re.compile(r"\[a64port\]\s+(\S+)\s+mapped at (0x[0-9a-f]+)")

# Modules whose ELF is not simply usr/lib/<name>.so*.
ELF_SPECIAL = {
    "app": ["usr/bin/myapp"],
    "ld": ["usr/lib/ld-linux-aarch64.so.1", "usr/lib/ld-*.so*", "lib/ld-*.so*"],
    "libstdcxx": ["usr/lib/libstdc++.so*", "usr/lib/aarch64-linux-gnu/libstdc++.so*"],
    "libgcc_s": ["usr/lib/libgcc_s.so*", "usr/lib/aarch64-linux-gnu/libgcc_s.so*"],
}

def load_profile() -> dict:
    """The application profile (apps/<app>/profile.json): A64PORT_PROFILE, else the one in A64PORT_APP_DIR (default: the only directory under apps/)."""
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    app = os.environ.get("A64PORT_APP_DIR")
    if not app:                                   # the only directory under apps/, if there is exactly one
        apps = os.path.join(root, "apps")
        subs = [os.path.join(apps, n) for n in sorted(os.listdir(apps))] if os.path.isdir(apps) else []
        subs = [x for x in subs if os.path.isdir(x)]
        app = subs[0] if len(subs) == 1 else ""
    p = os.environ.get("A64PORT_PROFILE") or os.path.join(app, "profile.json")
    try:
        import json
        return json.load(open(p))
    except Exception:
        return {}


def profile_paths() -> dict:
    """module name -> ELF path relative to the rootfs, as the profile lists them (what gen_mods.py uses)."""
    prof = load_profile()
    out = {}
    if prof.get("exe"):
        out[prof.get("module", "exe")] = prof["exe"]
    if prof.get("interp"):
        out["ld"] = prof["interp"]
    for mod, f in prof.get("dsos", []):
        out[mod] = os.path.join(prof.get("dso_dir", "usr/lib"), f)
    return out


_FDE_CACHE: dict[str, list[tuple[int, int]]] = {}
_ELF_CACHE: dict[str, str | None] = {}


def find_elf(rootfs: str, module: str) -> str | None:
    """Locate the guest ELF backing a profiler module name."""
    if module in _ELF_CACHE:
        return _ELF_CACHE[module]
    listed = profile_paths().get(module)
    if listed and os.path.isfile(os.path.join(rootfs, listed)):
        _ELF_CACHE[module] = os.path.join(rootfs, listed)
        return _ELF_CACHE[module]
    pats = ELF_SPECIAL.get(module)
    if pats is None:
        pats = [f"usr/lib/{module}.so*", f"usr/lib/aarch64-linux-gnu/{module}.so*",
                f"lib/{module}.so*"]
    hit = None
    for pat in pats:
        for cand in sorted(glob.glob(os.path.join(rootfs, pat))):
            if os.path.isfile(cand) and not os.path.islink(cand):
                hit = cand
                break
            if hit is None and os.path.exists(cand):
                hit = cand
        if hit:
            break
    _ELF_CACHE[module] = hit
    return hit


def fde_ranges(elf: str) -> list[tuple[int, int]]:
    """(start, end) for every .eh_frame FDE, sorted by start.

    readelf prints one `pc=START..END` per FDE; that pair *is* the function
    (the FDE covers the whole function), which is exactly the granularity we
    want and needs no symbol table (the guest libs are stripped)."""
    if elf in _FDE_CACHE:
        return _FDE_CACHE[elf]
    out: list[tuple[int, int]] = []
    try:
        txt = subprocess.run(["readelf", "-wf", elf], capture_output=True,
                             text=True, timeout=120).stdout
    except Exception:
        txt = ""
    for m in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", txt):
        a, b = int(m.group(1), 16), int(m.group(2), 16)
        if b > a:
            out.append((a, b))
    out.sort()
    _FDE_CACHE[elf] = out
    return out


def snap(elf: str, off: int) -> int:
    """Function start containing module-relative offset `off` (or off itself)."""
    rng = fde_ranges(elf)
    if not rng:
        return off
    i = bisect.bisect_right(rng, (off, 1 << 62)) - 1
    if i >= 0 and rng[i][0] <= off < rng[i][1]:
        return rng[i][0]
    return off


# ── "can this function be replaced by a native leaf?" ────────────────────────
# A native leaf is emitted in place of a whole block, with no way to call back
# into translated code except by setting c->pc to another block. So the cheap,
# decisive test is what the function's body contains:
#
#   bl/blr  a call to another guest function. Not automatically fatal, but the
#           callee has to be reimplemented or handed back, so it is not a
#           drop-in leaf.
#   br      an indirect branch (tail call or jump table) -- same problem, harder.
#   svc     a syscall: would need the shim's device/fd emulation.
#   ldxr..  exclusives/atomics: implementable with host __atomic_* IF every
#           address involved is in the arena (a near-NULL guest access that livelocked
#           a refcount CAS was exactly this assumption failing).
#   mrs/msr system registers: needs shim state.
_OBJDUMP_CACHE: dict[str, list[tuple[int, str]]] = {}
CALL_MN = {"bl", "blr"}
INDIRECT_MN = {"br"}
ATOMIC_MN = {
    "ldaxr", "stlxr", "ldxr", "stxr", "ldar", "stlr", "ldapr", "stlur",
    "cas", "casa", "casl", "casal", "swp", "swpa", "ldadd", "ldadda",
    "stadd", "ldclr", "ldset", "ldeor",
}
SYSREG_MN = {"mrs", "msr", "sys", "sysl", "hvc", "smc"}


def disas(elf: str, start: int, end: int) -> list[tuple[int, str]]:
    """[(addr, mnemonic)] for [start, end) of one function."""
    if end <= start:
        return []
    try:
        out = subprocess.run(
            ["llvm-objdump", "-d", f"--start-address={start}",
             f"--stop-address={end}", elf],
            capture_output=True, text=True, timeout=120).stdout
    except Exception:
        return []
    # `   29f24: b9400c04      \tldr\tw4, [x0, #0xc]`
    return [(int(m.group(1), 16), m.group(2))
            for m in re.finditer(r"^\s*([0-9a-f]+):\s+[0-9a-f]+\s+(\S+)", out, re.M)]


def classify(elf: str, start: int, size: int) -> tuple[int, str, str]:
    """(instruction count, verdict, detail) for one function."""
    ins = disas(elf, start, start + size)
    if not ins:
        return 0, "?", "no disassembly"
    mns = [m for _, m in ins]
    calls = sum(1 for m in mns if m in CALL_MN)
    indir = sum(1 for m in mns if m in INDIRECT_MN)
    svc = sum(1 for m in mns if m.startswith("svc"))
    atom = sum(1 for m in mns if m in ATOMIC_MN)
    sysr = sum(1 for m in mns if m in SYSREG_MN)
    if svc:
        return len(ins), "SYSCALL", f"{svc} svc"
    if indir:
        return len(ins), "INDIRECT", f"br x{indir}"
    if calls:
        return len(ins), "CALLS", f"{calls} bl"
    if atom:
        return len(ins), "ATOMIC", f"{atom} excl"
    if sysr:
        return len(ins), "SYSREG", f"{sysr} mrs/msr"
    return len(ins), "LEAF", "self-contained"


def analyze(args) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    rootfs = args.rootfs or os.path.join(os.path.dirname(here), "rootfs")

    by_pc: Counter[tuple[str, int]] = Counter()
    bases: dict[str, int] = {}
    windows = 0
    busy_total = 0
    idle_total = 0
    lost_total = 0
    for line in open(args.log, errors="replace"):
        m = BASE_MAP_RE.search(line)
        if m:
            bases[m.group(1)] = int(m.group(2), 16)
        m = BASE_EXE_RE.search(line)
        if m:
            bases.setdefault("app", int(m.group(1), 16))
        m = BASE_INTERP_RE.search(line)
        if m:
            bases.setdefault("ld", int(m.group(1), 16))
        h = HEADER_RE.search(line)
        if h:
            windows += 1
            busy_total += int(h.group(1))
            idle_total += int(h.group(2))
            lost_total += int(h.group(3))
            if args.dumps and windows > args.dumps:
                break
            continue
        r = ROW_RE.search(line)
        if r:
            by_pc[(r.group(4), int(r.group(3), 16))] += int(r.group(1))

    if not by_pc:
        print("no [prof] rows found; run with A64PORT_PROF=1", file=sys.stderr)
        return 1

    attributed = sum(by_pc.values())
    by_fn: Counter[tuple[str, int]] = Counter()
    sizes: dict[tuple[str, int], int] = {}
    for (mod, pc), hits in by_pc.items():
        base = bases.get(mod, 0)
        rel = pc - base if pc >= base else pc
        elf = find_elf(rootfs, mod)
        if elf:
            start = snap(elf, rel)
            rng = fde_ranges(elf)
            i = bisect.bisect_right(rng, (start, 1 << 62)) - 1
            size = (rng[i][1] - rng[i][0]) if (i >= 0 and rng[i][0] == start) else 0
        else:
            start, size = rel, 0
        key = (mod, start)
        by_fn[key] += hits
        sizes[key] = max(sizes.get(key, 0), size)

    print(f"windows={windows}  busy={busy_total}  idle/parked={idle_total}  lost={lost_total}")
    print(f"attributed samples={attributed}  ({100.0 * attributed / max(busy_total, 1):.1f}% of busy)")
    print(f"rootfs={rootfs}")
    print()
    print(f"{'self%':>6}  {'hits':>7}  {'size':>6}  {'insns':>6}  {'verdict':<9}  {'detail':<10}  function")
    print(f"{'-'*6}  {'-'*7}  {'-'*6}  {'-'*6}  {'-'*9}  {'-'*10}  {'-'*34}")
    for (mod, start), hits in by_fn.most_common(args.top):
        pct = 100.0 * hits / max(attributed, 1)
        size = sizes.get((mod, start), 0)
        n, verdict, detail = 0, "-", ""
        if not args.no_classify:
            elf = find_elf(rootfs, mod)
            if elf and size:
                n, verdict, detail = classify(elf, start, size)
        print(f"{pct:6.2f}  {hits:7d}  {size:6d}  {n:6d}  {verdict:<9}  {detail:<10}  "
              f"{mod}+0x{start:x}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--rootfs", default=None)
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--dumps", type=int, default=0,
                    help="use only the first N windows (0 = all)")
    ap.add_argument("--no-classify", action="store_true",
                    help="skip the leaf classification (no objdump runs)")
    ap.add_argument("--watch", type=float, default=0.0,
                    help="re-analyze the log every N seconds (live view); 0 = once")
    args = ap.parse_args()

    if args.watch and args.watch > 0:
        # Live view: the profiler appends to the log continuously, so re-run the
        # analysis in place.  The FDE/objdump caches above persist across
        # iterations, so a refresh only re-reads the log (fast).
        import time
        try:
            while True:
                os.system("clear")
                print(time.strftime("live hot functions  %H:%M:%S") + f"   {args.log}")
                try:
                    analyze(args)
                except FileNotFoundError:
                    print("(waiting for the log...)")
                time.sleep(args.watch)
        except KeyboardInterrupt:
            return 0
    return analyze(args)


if __name__ == "__main__":
    raise SystemExit(main())
