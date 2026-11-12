#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""hot-order.py — a link order that puts the application's hot code together.

The ARMv7 image is ~680 MB of text and the test board has 2 GB of RAM and eMMC: in
address order the blocks a running app actually uses are scattered over the
whole image, so every one costs its own page (and TLB entry).  Linked hottest-
first they share a few MB.

Input: one or more sampler tables from A64PORT_PROF=1 A64PORT_PROF_OUT=<file>
(host_loader.c), lines `module 0xoffset hits`, where offset is what the
block symbols carry: blk_<module>_[name_]<hex>.  The guest code is the same on
every host, so a table from a real-time x86-64 run orders the ARMv7 link.

Each sample is the guest pc a thread was at - a block start, or an interior
entry the block's own switch dispatches - so it is credited to the block with
the greatest start <= pc in its module, taken from the target binary's symbols.

Output: an lld --symbol-ordering-file, hottest first, preceded by the runtime's
memory/dispatch helpers (on every path).  Prints how much text the ordered set
covers.

  scripts/hot-order.py <binary> <table>... -o order.txt
"""
import argparse
import bisect
import collections
import re
import subprocess
import sys

SYM = re.compile(r"^([0-9a-f]+) ([0-9a-f]+) [tT] (blk_([A-Za-z0-9]+)_(?:.*_)?([0-9a-f]+))$")
# runtime helpers every guest path goes through, put first
RUNTIME_FIRST = re.compile(r"^(recomp_(load|store|ldp|stp|ldxr|stxr|acquire|release|host_ptr|cas|lse|"
                           r"umulh|fp_|fixed_to_fp|fp_to_int|excl)|a64port_(host_dispatch|hand_)|"
                           r"recomp_excl_store_touch|recomp_svc|hm_)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("tables", nargs="+")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--nm", default="llvm-nm")
    a = ap.parse_args()

    nm = subprocess.run([a.nm, "-S", "--defined-only", a.binary], capture_output=True, text=True, check=True)
    starts = collections.defaultdict(list)   # module -> [(guest offset, symbol, size)]
    runtime = []
    total_text = 0
    for line in nm.stdout.splitlines():
        m = SYM.match(line)
        if m:
            size = int(m.group(2), 16)
            total_text += size
            starts[m.group(4)].append((int(m.group(5), 16), m.group(3), size))
            continue
        parts = line.split()
        if len(parts) == 4 and parts[2] in "tT" and RUNTIME_FIRST.match(parts[3]):
            runtime.append(parts[3])
    for v in starts.values():
        v.sort()
    keys = {mod: [s for s, _, _ in v] for mod, v in starts.items()}

    hits = collections.Counter()
    size_of = {}
    unmatched = collections.Counter()
    for t in a.tables:
        for line in open(t):
            p = line.split()
            if len(p) != 3:
                continue
            mod, off, n = p[0], int(p[1], 16), int(p[2])
            if mod not in keys:
                unmatched[mod] += n
                continue
            i = bisect.bisect_right(keys[mod], off) - 1
            if i < 0:
                unmatched[mod] += n
                continue
            _, sym, size = starts[mod][i]
            hits[sym] += n
            size_of[sym] = size

    order = sorted(hits, key=lambda s: (-hits[s], s))
    with open(a.out, "w") as f:
        for s in sorted(set(runtime)):
            f.write(s + "\n")
        for s in order:
            f.write(s + "\n")

    tot = sum(hits.values())
    hot_bytes = sum(size_of[s] for s in order)
    acc, cut = 0, {}
    for k, s in enumerate(order):
        acc += hits[s]
        for q in (0.90, 0.99):
            if q not in cut and acc >= q * tot:
                cut[q] = (k + 1, sum(size_of[x] for x in order[:k + 1]))
    print(f"{len(order)} sampled blocks ({tot} samples), {hot_bytes / 1e6:.2f} MB of "
          f"{total_text / 1e6:.1f} MB block text; + {len(set(runtime))} runtime helpers first")
    for q, (n, b) in sorted(cut.items()):
        print(f"  {int(q * 100)}% of samples: {n} blocks, {b / 1e6:.2f} MB")
    if unmatched:
        print("  unmatched samples by module:", dict(unmatched.most_common(8)), file=sys.stderr)
    print(f"order -> {a.out}")


if __name__ == "__main__":
    main()
