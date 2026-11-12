#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""arena-resident.py — where is a running multi host's guest memory resident?

Reads /proc/<pid>/pagemap (present bit only; no root needed for your own
process) over the guest arena of a running app-multi* (x86-64 host).

    scripts/arena-resident.py <pid>                    # MB resident per 64 MB of guest VA
    scripts/arena-resident.py <pid> --stacks RUN.log   # per-thread guest stack depth

--stacks takes the run log (the `[a64port] clone thread ... tls=0x...` lines) and
measures, for each thread, the contiguous resident run of pages directly below
its TLS block — i.e. how deep its stack has ever been touched.

The arena is found as the one mapping larger than 8 GB (the 64-bit layout's
16 GB calloc); guest VA = host VA - g_mem + A64PORT_MEM_BASE, g_mem being the
calloc pointer rounded up to a page.  Does not apply to the ARMv7 build under
qemu-user (guest memory is inside qemu's address space there).
"""
import argparse, collections, re, struct, sys

MEM_BASE = 0x400000

def arena(pid):
    for line in open(f"/proc/{pid}/maps"):
        a, b = (int(x, 16) for x in line.split()[0].split("-"))
        if b - a > (8 << 30):
            return a, b, (a + 16 + 4095) & ~4095
    sys.exit("no >8 GB mapping: not a 64-bit multi host?")

def present(f, hva):
    f.seek((hva >> 12) * 8)
    return struct.unpack("<Q", f.read(8))[0] >> 63

def by_region(pid, bucket_mb):
    lo, hi, gbase = arena(pid)
    ch = bucket_mb << 20
    res = collections.Counter()
    with open(f"/proc/{pid}/pagemap", "rb") as f:
        step = 1 << 18
        for p0 in range(lo >> 12, hi >> 12, step):
            n = min(step, (hi >> 12) - p0)
            f.seek(p0 * 8)
            for i, (e,) in enumerate(struct.iter_unpack("<Q", f.read(n * 8))):
                if e >> 63:
                    res[(((p0 + i) << 12) - gbase + MEM_BASE) // ch] += 1
    print(f"resident guest memory: {sum(res.values()) * 4 / 1024:.0f} MB")
    for k in sorted(res):
        mb = res[k] * 4 / 1024
        if mb >= 8:
            print(f"  guest 0x{k * ch:09x}-0x{(k + 1) * ch:09x}: {mb:6.0f} MB")

def stacks(pid, log):
    _, _, gbase = arena(pid)
    tls = sorted({int(m, 16) for m in re.findall(
        r"clone thread tid=\d+ parent_tid=\d+ tls=(0x[0-9a-f]+)", open(log, errors="replace").read())})
    depth = []
    with open(f"/proc/{pid}/pagemap", "rb") as f:
        for t in tls:
            top, deepest = t & ~0xFFF, 0
            for k in range(1, 2048):                       # up to 8 MB below the TCB
                if present(f, gbase + (top - k * 4096 - MEM_BASE)):
                    deepest = k
                elif k > 4:
                    break                                  # first hole below the used run
            depth.append((deepest * 4, t))
    depth.sort()
    edges = [4, 64, 256, 1024, 2048, 4096, 8192]
    hist = collections.Counter(next(e for e in edges if d <= e) for d, _ in depth)
    print(f"{len(depth)} threads; stack touched below TLS, threads per bucket (<= KB):",
          sorted(hist.items()))
    for d, t in depth:
        if d > 1024:
            print(f"  deep: tls=0x{t:x} {d} KB")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pid", type=int)
    ap.add_argument("--stacks", metavar="RUN_LOG")
    ap.add_argument("--bucket-mb", type=int, default=64)
    a = ap.parse_args()
    if a.stacks:
        stacks(a.pid, a.stacks)
    else:
        by_region(a.pid, a.bucket_mb)

if __name__ == "__main__":
    main()
