#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""a64-lookup-tables.py - find AArch64 switch/lookup tables and report the case
targets our block discovery misses.

Why this exists
---------------
`repo/third_party/mk8-recomp/arm64_to_c.h` discovers blocks from the entry,
`.dynsym` FUNC symbols, `.eh_frame_hdr` FDE starts, and ADRP+ADD targets - all
of which are *addresses that appear in the instruction stream or the unwind
info*. LLVM's SwitchToLookupTable emits a switch as

    adrp xT, .rodata_page
    add  xT, xT, #imm
    ldrb wI, [xT, wIdx, uxtw]     ; signed byte offset / 4
    adr  xB, .Lbase               ; usually the instruction after the br
    add  xD, xB, wI, sxtb #2      ; target = base + (int8)entry * 4
    br   xD

The case bodies are reached only through that `.rodata` byte table. They are not
direct-branch targets, not terminator+1, not ADRP+ADD targets, and not functions
with their own FDE, so `recomp_lookup` returns null for them at run time. On the
hosted build that means the interpreter handles the case body; standalone it is a
halt. GCC uses the same shape with a word table and `sxtw #2`.

This script sizes each table from the guard (`cmp wIdx, #N` -> N+1 entries),
recovers every target, models the block starts our discovery would produce, and
prints the ones it misses. It also writes the missed targets as a bare-hex
`--roots` list for `tools/recomp/a64recomp`, which is the stop-gap until the
emitter learns the pattern itself.

Caveat: the model below is terminator+1, direct-branch targets, and eh_frame
roots. The emitter also seeds ADRP+ADD targets, which this does not model, so the
missed count here is an *upper bound* (real misses <= reported). A target counts
as "present" only if discovery would make it a **block start** - an indirect
`br` to a mid-block address misses even though the instructions are emitted.

Usage
-----
  scripts/a64-lookup-tables.py ELF [--roots FILE] [--dis FILE] [--objdump CMD]
                                    [--out-dir DIR] [--top N]

  ELF        the guest executable (e.g. rootfs/usr/bin/myapp)
  --roots    eh_frame function starts, one hex per line
             (default: <app dir>/evidence/<elf-stem>-eh_frame-roots.txt if present)
  --dis      a pre-made `llvm-objdump -d` dump to reuse
  --objdump  disassembler to run (default: llvm-objdump)
  --out-dir  where to write <stem>.lookup-roots (default: next to ELF)
"""

from __future__ import annotations

import argparse
import collections
import os
import re
import struct
import subprocess
import sys
import tempfile

LINE = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$")
TERM = {"b", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz", "svc", "brk"}


def clean(ops: str) -> str:
    # drop the symbol annotation llvm-objdump appends: "... <foo+0x10>"
    return re.sub(r"\s*<[^>]*>.*$", "", ops).strip()


class Elf:
    def __init__(self, path: str):
        self.bytes = open(path, "rb").read()
        b = self.bytes
        assert b[:4] == b"\x7fELF", "not an ELF"
        phoff = struct.unpack_from("<Q", b, 32)[0]
        phentsize = struct.unpack_from("<H", b, 54)[0]
        phnum = struct.unpack_from("<H", b, 56)[0]
        self.segments: list[tuple[int, int, int]] = []   # vaddr, vaddr_end, file off
        self.exec_ranges: list[tuple[int, int]] = []
        for i in range(phnum):
            o = phoff + i * phentsize
            p_type, p_flags = struct.unpack_from("<II", b, o)
            if p_type != 1:  # PT_LOAD
                continue
            off, vaddr, _paddr, filesz, _memsz = struct.unpack_from("<QQQQQ", b, o + 8)
            self.segments.append((vaddr, vaddr + filesz, off))
            if p_flags & 1:  # PF_X
                self.exec_ranges.append((vaddr, vaddr + filesz))

    def read(self, vaddr: int, n: int) -> bytes:
        for lo, hi, off in self.segments:
            if lo <= vaddr < hi:
                k = min(n, hi - vaddr)
                return self.bytes[off + (vaddr - lo): off + (vaddr - lo) + k]
        return b""

    def is_exec(self, vaddr: int) -> bool:
        return any(lo <= vaddr < hi for lo, hi in self.exec_ranges)


def read_roots(path: str | None) -> set[int]:
    if not path or not os.path.exists(path):
        return set()
    out = set()
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#"):
            try:
                out.add(int(line, 16))
            except ValueError:
                pass
    return out


def collect(dis_path: str):
    """One pass over the disassembly: terminators, branch targets, candidates.

    A candidate is (br_addr, table_addr, base_addr, index_reg, scale, kind).
    """
    term_addrs: set[int] = set()
    branch_targets: set[int] = set()
    candidates: list[tuple[int, int, int, int, int, str]] = []
    win: collections.deque = collections.deque(maxlen=120)
    for line in open(dis_path, errors="ignore"):
        m = LINE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        mn = m.group(2)
        ops = clean(m.group(3))
        if mn in TERM or mn.startswith("b.") or mn == "isb":
            term_addrs.add(addr)
        if mn.startswith("b"):
            bm = re.match(r"^0x([0-9a-f]+)", ops)
            if bm:
                branch_targets.add(int(bm.group(1), 16))
        win.append((addr, mn, ops))
        if mn == "br" and re.match(r"^x\d+$", ops):
            candidates.extend(_dispatch_at(list(win)))
    return term_addrs, branch_targets, candidates


def _resolve_reg(win, upto: int, reg: str) -> int | None:
    """Value of `reg` from the nearest preceding ADRP (+ADD) or MOV, backwards."""
    addend = 0
    for k in range(upto - 1, -1, -1):
        _a, mn, ops = win[k]
        m = re.match(rf"^{reg},\s*0x([0-9a-f]+)", ops)
        if mn == "adrp" and m:
            return int(m.group(1), 16) + addend
        m = re.match(rf"^{reg},\s*{reg},\s*#0x([0-9a-f]+)$", ops)
        if mn == "add" and m:
            addend = int(m.group(1), 16)
            continue
        m = re.match(rf"^{reg},\s*#0x([0-9a-f]+)$", ops)
        if mn in ("mov", "movz") and m:
            return int(m.group(1), 16) + addend
    return None


def _dispatch_at(win) -> list[tuple[int, int, int, int, int, str]]:
    """Recover the dispatch immediately before the `br` at the end of win."""
    out = []
    if not win or win[-1][1] != "br":
        return out
    br_addr = win[-1][0]
    for j in range(len(win) - 2, max(len(win) - 9, -1), -1):
        _a, mn, ops = win[j]
        # add xD, xB, wI, sxtb|sxtw #s   (xD may differ from xB)
        m = re.match(r"^(x\d+),\s*(x\d+),\s*w(\d+),\s*(sxtb|sxtw|uxtb|uxtw)\s*(?:#(\d+))?$", ops)
        if not (mn == "add" and m):
            continue
        base_reg = m.group(2)
        idx = m.group(3)
        scale = 1 << int(m.group(5) or 0)
        # adr xB, .Lbase
        base = None
        for k in range(j - 1, -1, -1):
            if win[k][1] == "adr":
                am = re.match(rf"^{base_reg},\s*0x([0-9a-f]+)", win[k][2])
                if am:
                    base = int(am.group(1), 16)
                    break
        if base is None:
            continue
        # ldrb/ldrh/ldr wI, [xT, wIdx, uxtw|lsl #s]
        for k in range(j - 1, -1, -1):
            lm = re.match(r"^w\d+,\s*\[(x\d+),\s*w(\d+),\s*(uxtw|lsl)\s*(?:#(\d+))?\]", win[k][2])
            if win[k][1] in ("ldrb", "ldrh", "ldr", "ldrsw") and lm and lm.group(2) == idx:
                table = _resolve_reg(win, k, lm.group(1))
                if table is not None:
                    kind = win[k][1]
                    out.append((br_addr, table, base, int(idx), scale, kind))
                break
        break
    return out


def guard_bound(opsmap: dict[int, tuple[str, str]], br_addr: int, idx: int) -> int | None:
    """N from the `cmp wIdx, #N` that guards the dispatch, if there is one."""
    for k in range(1, 90):
        e = opsmap.get(br_addr - 4 * k)
        if not e:
            continue
        m = re.match(rf"^w{idx},\s*#0x([0-9a-f]+)$", e[1])
        if e[0] == "cmp" and m:
            for j in range(1, k):
                e2 = opsmap.get(br_addr - 4 * j)
                if e2 and (e2[0].startswith("b.") or e2[0] in ("cbz", "cbnz", "tbz", "tbnz")):
                    return int(m.group(1), 16)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("elf")
    ap.add_argument("--roots")
    ap.add_argument("--dis")
    ap.add_argument("--objdump", default="llvm-objdump")
    ap.add_argument("--out-dir")
    ap.add_argument("--top", type=int, default=15)
    args = ap.parse_args()

    stem = os.path.splitext(os.path.basename(args.elf))[0]
    roots_path = args.roots
    if roots_path is None:
        guess = os.path.join(os.environ.get("A64PORT_APP_DIR", "."), "evidence", f"{stem}-eh_frame-roots.txt")
        if os.path.exists(guess):
            roots_path = guess
    out_dir = args.out_dir or "."

    dis = args.dis
    tmp = None
    if dis is None:
        tmp = tempfile.NamedTemporaryFile(suffix=".dis", delete=False)
        tmp.close()
        dis = tmp.name
        with open(dis, "w") as f:
            subprocess.run([args.objdump, "-d", "--no-show-raw-insn", args.elf], stdout=f, check=True)

    elf = Elf(args.elf)
    term_addrs, branch_targets, candidates = collect(dis)
    roots = read_roots(roots_path)

    starts = set(branch_targets)
    starts |= roots
    for t in term_addrs:
        starts.add(t + 4)

    # cache the ~90 instructions before each br for the guard search
    need = {c[0] - 4 * k for c in candidates for k in range(1, 90)}
    opsmap: dict[int, tuple[str, str]] = {}
    for line in open(dis, errors="ignore"):
        m = LINE.match(line)
        if not m:
            continue
        a = int(m.group(1), 16)
        if a in need:
            opsmap[a] = (m.group(2), clean(m.group(3)))

    total = missed = analyzed = no_bound = 0
    rows = []
    missed_targets: set[int] = set()
    for br, table, base, idx, scale, kind in candidates:
        n = guard_bound(opsmap, br, idx)
        if n is None:
            no_bound += 1
            continue
        raw = elf.read(table, n + 1)
        if len(raw) != n + 1:
            continue
        analyzed += 1
        targets = set()
        for by in raw:
            s = by - 256 if by >= 128 else by
            targets.add(base + s * scale)
        in_exec = [t for t in targets if elf.is_exec(t) and (t & 3) == 0]
        miss = [t for t in in_exec if t not in starts]
        total += len(in_exec)
        missed += len(miss)
        missed_targets.update(miss)
        if miss:
            rows.append((br, len(miss), len(in_exec), sorted(miss), kind))

    print(f"lookup-table dispatch candidates: {len(candidates)}")
    print(f"  with a recoverable cmp bound:    {analyzed}  (no bound: {no_bound})")
    print(f"case targets in executable ranges: {total}")
    pct = 100.0 * missed / max(total, 1)
    print(f"  not a block start (upper bound): {missed} ({pct:.1f}%)")
    print(f"  dispatches with >=1 miss:        {len(rows)}")
    bad = max(0, len(candidates) - analyzed)
    if bad:
        print(f"  {bad} candidates were not sized (guard not a plain cmp, or table unreadable)")
    print()
    for br, nmiss, ntot, miss, kind in sorted(rows, key=lambda r: -r[1])[: args.top]:
        ex = " ".join(f"0x{t:x}" for t in miss[:4])
        print(f"  br=0x{br:x}  {kind:5s}  missed {nmiss}/{ntot}  e.g. {ex}")

    if missed_targets:
        base_name = os.path.join(out_dir, f"{stem}.lookup-roots")
        with open(base_name, "w") as f:
            f.write("# case targets of AArch64 lookup tables that block discovery misses.\n")
            f.write("# feed to: tools/recomp/a64recomp <elf> <out> --mod <mod> --roots <this file>\n")
            for t in sorted(missed_targets):
                f.write(f"0x{t:x}\n")
        print(f"\n{len(missed_targets)} missed targets -> {base_name}")

    if tmp:
        os.unlink(tmp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
