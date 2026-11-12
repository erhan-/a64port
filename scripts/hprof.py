#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""hprof.py - symbolize a A64PORT_HPROF host-PC profile (host_loader.c).

Each sample is {host pc, guest pc, tid}.  The host pc says what the HOST pays
(dispatcher, load/store helpers, block bodies, shim, host libc / kernel); the
guest pc (the block being run, c->pc) says for which guest code.

Usage:
  scripts/hprof.py <hprof.bin> <host binary> [--threads] [--top N] [--guest N]
                   [--thread NAME] [--rootfs DIR]

Categories (by the object that defines the host symbol, then by name):
  block      emitted block bodies (blk_*), per module
  leaf       hand leaves (a64port_hand_*)
  mem        load/store/ldp/stp/fm/host_ptr helpers, exclusives, hm_*
  dispatch   guest_run / dispatch / recomp_lookup* (the per-block host loop)
  fp         FP helpers in the runtime (recomp_fp*, fpx)
  runtime    other runtime functions
  shim       linux_syscalls.c (syscall translation)
  host       other multi-host code
  hostlib:X  a host shared object (libc.so, vdso, ...) - mostly syscalls
"""
from __future__ import annotations

import argparse
import bisect
import importlib.util
import os
import re
import struct
import subprocess
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))


def app_dir():
    """A64PORT_APP_DIR, else the only directory under <checkout>/apps (empty string if there is none or several)."""
    d = os.environ.get("A64PORT_APP_DIR")
    if d:
        return d
    apps = os.path.join(HERE, "..", "apps")
    subs = [os.path.join(apps, n) for n in sorted(os.listdir(apps))] if os.path.isdir(apps) else []
    subs = [x for x in subs if os.path.isdir(x)]
    return subs[0] if len(subs) == 1 else ""


def exe_module():
    """The main executable's module name: A64PORT_EXE_MOD, else the application profile's 'module' (default exe)."""
    m = os.environ.get("A64PORT_EXE_MOD")
    if m:
        return m
    try:
        import json
        return json.load(open(os.environ.get("A64PORT_PROFILE") or os.path.join(app_dir(), "profile.json"))).get("module", "exe")
    except Exception:
        return "exe"


def load_hot():
    # guest-hot.py: module -> ELF from the application profile, pc -> function start from .eh_frame
    spec = importlib.util.spec_from_file_location("guesthot", os.path.join(HERE, "guest-hot.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def read_prof(path):
    data = open(path, "rb").read()
    magic, n, us = struct.unpack_from("<QQQ", data, 0)
    assert magic == 0x31464F5250484252, "not an RBHPROF1 file"
    recs = []
    off = 24
    for i in range(n):
        hpc, gpc, tid, _ = struct.unpack_from("<QQII", data, off + 24 * i)
        recs.append((hpc, gpc, tid))
    tail = data[off + 24 * n:].decode("utf-8", "replace")
    maps, mods, threads = [], {}, {}
    sec = None
    for line in tail.splitlines():
        if line.startswith("#"):
            sec = line[1:]
            continue
        if not line.strip():
            continue
        if sec == "maps":
            p = line.split()
            a, b = (int(x, 16) for x in p[0].split("-"))
            maps.append((a, b, int(p[2], 16), p[5] if len(p) > 5 else "[anon]"))
        elif sec == "mods":
            name, base = line.split()
            mods[name] = int(base, 16)
        elif sec == "threads":
            p = line.split(None, 1)
            threads[int(p[0])] = p[1] if len(p) > 1 else "?"
    return recs, us, maps, mods, threads


class Syms:
    """nm of the host binary + its load bias (PIE) from the maps."""

    def __init__(self, binary, maps):
        out = subprocess.run([os.environ.get("NM", "nm"), "-n", "--defined-only", binary], capture_output=True,
                             text=True).stdout
        self.addr, self.name = [], []
        for line in out.splitlines():
            p = line.split()
            if len(p) < 3 or p[1] not in "tTwW" or p[2].startswith("$"):
                continue                           # ($t/$a/$d: ARM mapping symbols)
            self.addr.append(int(p[0], 16))
            self.name.append(p[2])
        # load bias: the first mapping of the binary at file offset 0
        real = os.path.realpath(binary)
        # a profile taken on another machine (the target) names the binary by
        # its path THERE: match the mappings by file name
        names = {os.path.realpath(p) for a, b, o, p in maps}
        if real not in names:
            base = os.path.basename(binary)
            for a, b, o, p in maps:
                if os.path.basename(p) == base:
                    real = os.path.realpath(p)
                    break
            else:
                # the target may run a deployed copy under another name
                # (app-armv7-v7) of a numbered local build (app-armv7-v7-b22)
                for a, b, o, p in maps:
                    rb = os.path.basename(p)
                    if rb and base.startswith(rb) and "x" in o.__class__.__name__ + "x":
                        real = os.path.realpath(p)
                        break
        self.real = real
        self.bias = 0
        ph = subprocess.run(["readelf", "-hW", binary], capture_output=True, text=True).stdout
        if "DYN" in ph:
            for a, b, off, path in maps:
                if os.path.realpath(path) == real and off == 0:
                    self.bias = a
                    break
        self.lo = min((a for a, b, o, p in maps if os.path.realpath(p) == real), default=0)
        self.hi = max((b for a, b, o, p in maps if os.path.realpath(p) == real), default=0)
        self.maps = maps

    def lookup(self, pc):
        if self.lo <= pc < self.hi:
            i = bisect.bisect_right(self.addr, pc - self.bias) - 1
            return self.name[i] if i >= 0 else "?"
        for a, b, off, path in self.maps:
            if a <= pc < b:
                return "@" + os.path.basename(path)
        return "@?"


MEM_RE = re.compile(r"^(recomp_(load|store|ldp|stp|ldst|fm_|host_ptr|excl|mem|ld|st|cas|swp|atomic)|hm_|excl_|a64port_ld|a64port_st|asan_)")
DISP_RE = re.compile(r"^(guest_run|dispatch|recomp_lookup|_build_idx|recomp_dispatch)")
FP_RE = re.compile(r"^(recomp_fp|recomp_fpx|recomp_f[a-z]*\d|recomp_vec)")


def category(sym):
    if sym.startswith("@"):
        return "hostlib:" + sym[1:]
    if sym.startswith("blk_") or sym.startswith("fn_"):
        return "block"
    if sym.startswith("a64port_hand_"):
        return "leaf"
    if MEM_RE.match(sym):
        return "mem"
    if DISP_RE.match(sym):
        return "dispatch"
    if FP_RE.match(sym):
        return "fp"
    if sym.startswith("recomp_svc") or sym.startswith("shim_") or sym.startswith("Guest") \
            or sym.startswith("futex") or sym.startswith("host_futex"):
        return "shim"
    if sym.startswith("recomp_"):
        return "runtime"
    return "host"


def block_module(sym):
    m = re.match(r"(?:blk|fn)_([a-zA-Z0-9]+)_", sym)
    return m.group(1) if m else "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("prof")
    ap.add_argument("binary")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--guest", type=int, default=30)
    ap.add_argument("--threads", action="store_true")
    ap.add_argument("--thread", help="only samples of threads whose name contains this")
    ap.add_argument("--rootfs", default=os.path.join(HERE, "..", "rootfs"))
    a = ap.parse_args()

    recs, us, maps, mods, threads = read_prof(a.prof)
    if a.thread:
        recs = [r for r in recs if a.thread in threads.get(r[2], "?")]
    syms = Syms(a.binary, maps)
    total = len(recs)
    print(f"{total} samples x {us} us = {total * us / 1e6:.1f} s of thread CPU")
    if not total:
        return 0
    cat, sym_c, blkmod = Counter(), Counter(), Counter()
    per_thread = defaultdict(Counter)
    guest_by_cat = defaultdict(Counter)
    cache = {}
    for hpc, gpc, tid in recs:
        s = cache.get(hpc)
        if s is None:
            s = cache[hpc] = syms.lookup(hpc)
        c = category(s)
        cat[c] += 1
        sym_c[s] += 1
        if c == "block":
            blkmod[block_module(s)] += 1
        per_thread[threads.get(tid, str(tid))][c] += 1
        guest_by_cat[c][gpc] += 1

    def pct(n):
        return f"{100.0 * n / total:5.1f}%"

    print("\n== by category ==")
    for c, n in cat.most_common():
        print(f"  {pct(n)}  {n * us / 1e6:7.2f} s  {c}")
    print("\n== block bodies by module ==")
    for m, n in blkmod.most_common(12):
        print(f"  {pct(n)}  {m}")
    print(f"\n== top {a.top} host symbols ==")
    for s, n in sym_c.most_common(a.top):
        print(f"  {pct(n)}  {category(s):10s} {s}")
    if a.threads:
        print("\n== threads (CPU s, then category split) ==")
        for t, cc in sorted(per_thread.items(), key=lambda kv: -sum(kv[1].values()))[:25]:
            n = sum(cc.values())
            split = "  ".join(f"{k}={100.0 * v / n:.0f}%" for k, v in cc.most_common(5))
            print(f"  {n * us / 1e6:7.2f} s  {t:18s} {split}")

    # guest functions: snap every guest pc to its module function (.eh_frame)
    hot = load_hot()
    bases = sorted((b, m) for m, b in mods.items() if b or m == exe_module())
    fn_all = Counter()
    fn_cat = defaultdict(Counter)
    for c, g in guest_by_cat.items():
        for gpc, n in g.items():
            i = bisect.bisect_right([b for b, m in bases], gpc) - 1
            if i < 0:
                key = ("?", gpc)
            else:
                b, m = bases[i]
                elf = hot.find_elf(a.rootfs, m)
                off = gpc - b
                start = hot.snap(elf, off) if elf else off
                key = (m, start)
            fn_all[key] += n
            fn_cat[key][c] += n
    names = {}
    tsv = os.environ.get("A64PORT_NAMES_TSV")
    for cand in (os.path.join(app_dir(), "names.tsv"), os.path.join(app_dir(), "functions.tsv")):
        if not tsv and os.path.exists(cand):
            tsv = cand
    tsv = tsv or os.devnull   # optional: address<TAB>name
    if os.path.exists(tsv):
        for line in open(tsv):
            p = line.rstrip("\n").split("\t")
            if len(p) >= 2:
                try:
                    names[int(p[0], 16)] = p[1]
                except ValueError:
                    pass
    print(f"\n== top {a.guest} guest functions (all host cost attributed to them) ==")
    for (m, start), n in fn_all.most_common(a.guest):
        cc = fn_cat[(m, start)]
        split = " ".join(f"{k}={100.0 * v / n:.0f}%" for k, v in cc.most_common(4))
        nm = names.get(start, "") if m == exe_module() else ""
        print(f"  {pct(n)}  {m}+0x{start:x} {nm[:40]:40s} {split}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
