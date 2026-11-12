#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""hprof-order.py - an lld --symbol-ordering-file from A64PORT_HPROF profiles.

The emitted C is the same for every host, so the host symbols an x86-64 run
samples (blk_*, fn_*, a64port_hand_*, runtime helpers) are the symbols of the
ARMv7 build too: sort them by samples, hottest first, and build-armv7.sh's
ORDER= packs the running app's code into a few MB (a Cortex-A17 core has 32 KB L1i, the
test board a 1 MB L2).

  scripts/hprof-order.py <binary> <hprof.bin>... -o order.txt [--min 1]
"""
import argparse
import importlib.util
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("hprof", os.path.join(HERE, "hprof.py"))
hp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hp)

ap = argparse.ArgumentParser()
ap.add_argument("binary")
ap.add_argument("profiles", nargs="+")
ap.add_argument("-o", "--out", required=True)
ap.add_argument("--min", type=int, default=1, help="drop symbols with fewer samples")
a = ap.parse_args()

counts = Counter()
for prof in a.profiles:
    recs, us, maps, mods, threads = hp.read_prof(prof)
    syms = hp.Syms(a.binary, maps)
    cache = {}
    for hpc, gpc, tid in recs:
        s = cache.get(hpc)
        if s is None:
            s = cache[hpc] = syms.lookup(hpc)
        if not s.startswith("@") and s != "?":
            counts[s] += 1
order = [s for s, n in counts.most_common() if n >= a.min]
with open(a.out, "w") as f:
    for s in order:
        f.write(s + "\n")
tot = sum(counts.values())
cum, k90, k99 = 0, None, None
for i, (s, n) in enumerate(counts.most_common()):
    cum += n
    if k90 is None and cum >= 0.9 * tot: k90 = i + 1
    if k99 is None and cum >= 0.99 * tot: k99 = i + 1
print(f"{len(order)} symbols -> {a.out}; 90% of samples in {k90}, 99% in {k99} symbols", file=sys.stderr)
