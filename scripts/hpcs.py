#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""hpcs.py <hprof.bin> <thread-substring> [lo hi] [bin]: histogram of the GUEST pcs of one thread's samples
(the pc is the last block entered, so inside a --fn-single function it locates the hot region).
  hpcs.py run.hprof.bin "worker" 0x400000 0x410000 32"""
import collections, importlib.util, os, sys
spec = importlib.util.spec_from_file_location("hp", os.path.join(os.path.dirname(os.path.abspath(__file__)), "hprof.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
recs, us, maps, mods, threads = m.read_prof(sys.argv[1])
sel = [r for r in recs if sys.argv[2] in threads.get(r[2], "?")]
lo = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0; hi = int(sys.argv[4], 0) if len(sys.argv) > 4 else 1 << 40
b = int(sys.argv[5], 0) if len(sys.argv) > 5 else 64
h = collections.Counter(r[1] // b * b for r in sel if lo <= r[1] < hi)
print(f"{len(sel)} samples of '{sys.argv[2]}', {sum(h.values())} in range")
for g, n in sorted(h.items(), key=lambda x: -x[1])[:25]: print(f"  {g:#x}  {100 * n / len(sel):5.1f}%")
