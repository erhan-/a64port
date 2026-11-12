#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# emitter-fuzz.py — differential fuzzer for the a64recomp emitter.
#
# Generates a freestanding AArch64 guest made of many independent "cases": each
# case runs K random data-processing instructions and then dumps all 31 GPRs and
# NZCV to a buffer.  The guest is run under qemu-aarch64 (the reference) and
# under the recompiled native build; any byte that differs is an emitter bug in
# one of the instructions, and the case index names the block.
#
#   emitter-fuzz.py --cases N --per K [--seed S] [--keep]
import argparse, os, random, struct, subprocess, sys, tempfile, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRV = f"{ROOT}/repo/tools/recomp/a64recomp"
VECFAST = [False]   # set from --vec-fast-all: exercises the fork's SIMD fast paths
FPX = [False]       # set from --fpx: native FP fast paths (FPX1) instead of exact bodies only
BG  = f"{ROOT}/repo/tools/recomp/build-guest.sh"

# ---- instruction encoders (subset: register/flags/shift/mul/bitfield) -------
def rr(rd, rn, rm, base, shift=0, imm6=0, sf64=0):
    return (base | (sf64 << 31) | (shift << 22) | (rm << 16) | (imm6 << 10) | (rn << 5) | rd) & 0xFFFFFFFF

def rrr(rd, rn, rm, ra, base):
    return (base | (rm << 16) | (ra << 10) | (rn << 5) | rd) & 0xFFFFFFFF

def gen(rng):
    kind = rng.randrange(14)
    d = rng.randrange(31); n = rng.randrange(31); m = rng.randrange(31)
    # avoid rd==31 (SP) where the form would write SP; use 0..30
    if kind == 0:      # ADD/SUB/ADDS/SUBS shifted register (32/64)
        sf = rng.randrange(2)
        op = rng.randrange(2); s = rng.randrange(2)
        base = 0x0B000000 | (sf << 31) | (op << 30) | (s << 29)
        return rr(d, n, m, base & ~(1<<31), shift=rng.randrange(3),
                  imm6=rng.randrange(32 if not sf else 64), sf64=sf)
    if kind == 1:      # logical shifted register
        sf = rng.randrange(2)
        opc = rng.randrange(4)                     # AND ORR EOR ANDS
        base = 0x0A000000 | (sf << 31) | (opc << 29)
        return rr(d, n, m, base & ~(1<<31), shift=rng.randrange(4),
                  imm6=rng.randrange(32 if not sf else 64), sf64=sf)
    if kind == 2:      # MOVZ/MOVN/MOVK
        base = rng.choice([0x52800000, 0x12800000, 0x72800000,
                           0xD2800000, 0x92800000, 0xF2800000])
        hw = rng.randrange(2 if base < (1<<31) else 4)
        return (base | (hw << 21) | (rng.randrange(65536) << 5) | d) & 0xFFFFFFFF
    if kind == 3:      # bitfield UBFM/SBFM/BFM (N=1 for 64-bit)
        sf = rng.randrange(2)
        opc = rng.randrange(3)                     # 0 SBFM, 1 BFM, 2 UBFM
        base = 0x13000000 | (sf << 31) | (opc << 29) | (sf << 22)
        w = 64 if sf else 32
        return (base | (rng.randrange(w) << 16) | (rng.randrange(w) << 10) | (n << 5) | d) & 0xFFFFFFFF
    if kind == 4:      # EXTR
        base = rng.choice([0x13800000, 0x93C00000])
        w = 32 if base < (1<<31) else 64
        return (base | (m << 16) | (rng.randrange(w) << 10) | (n << 5) | d) & 0xFFFFFFFF
    if kind == 5:      # MADD/MSUB, SMADDL/UMADDL/SMSUBL/UMSUBL
        sf = rng.randrange(2)
        op31 = rng.choice([0]) if not sf else rng.choice([0,1,5])
        o0 = rng.randrange(2)
        ra = rng.randrange(31)
        return ((0x1B000000 | (sf << 31)) | (op31 << 21) | (o0 << 15) | (m << 16) | (ra << 10) | (n << 5) | d) & 0xFFFFFFFF
    if kind == 6:      # UMULH/SMULH
        op31 = rng.choice([2,6])
        return (0x9B000000 | (op31 << 21) | (m << 16) | (31 << 10) | (n << 5) | d) & 0xFFFFFFFF
    if kind == 7:      # CSEL/CSINC/CSINV/CSNEG
        sf = rng.randrange(2)
        base = rng.choice([0x1A800000, 0x1A800400, 0x5A800000, 0x5A800400])
        cond = rng.randrange(16)
        return ((sf << 31) | base | (m << 16) | (cond << 12) | (n << 5) | d) & 0xFFFFFFFF
    if kind == 8:      # CCMP/CCMN (register)
        sf = rng.randrange(2)
        base = rng.choice([0x3A400000, 0x7A400000])   # CCMN / CCMP
        cond = rng.randrange(16)
        nzcv = rng.randrange(16)
        return ((sf << 31) | base | (m << 16) | (cond << 12) | (n << 5) | nzcv) & 0xFFFFFFFF
    if kind == 9:      # UDIV/SDIV
        base = rng.choice([0x1AC00800, 0x1AC00C00, 0x9AC00800, 0x9AC00C00])
        return (base | (m << 16) | (n << 5) | d) & 0xFFFFFFFF
    if kind == 10:     # RBIT/REV16/REV32/REV/CLZ/CLS
        sf = rng.randrange(2)
        w = [0x5AC00000, 0x5AC00400, None, 0x5AC00800, 0x5AC01000, 0x5AC01400]
        x = [0xDAC00000, 0xDAC00400, 0xDAC00800, 0xDAC00C00, 0xDAC01000, 0xDAC01400]
        enc = rng.randrange(6)
        base = (x if sf else w)[enc]
        if base is None: base = x[2]
        return (base | (n << 5) | d) & 0xFFFFFFFF
    if kind == 11:     # LSLV/LSRV/ASRV/RORV
        base = rng.choice([0x1AC02000, 0x1AC02400, 0x1AC02800, 0x1AC02C00,
                           0x9AC02000, 0x9AC02400, 0x9AC02800, 0x9AC02C00])
        return (base | (m << 16) | (n << 5) | d) & 0xFFFFFFFF
    if kind == 12:     # ADD/SUB immediate
        sf = rng.randrange(2)
        op = rng.randrange(2); s = rng.randrange(2)
        base = 0x11000000 | (sf << 31) | (op << 30) | (s << 29)
        sh = rng.randrange(2) if sf else 0          # shift=1 is unallocated for 32-bit
        return (base | (sh << 22) | (rng.randrange(1 << 12) << 10) | (n << 5) | d) & 0xFFFFFFFF
    # kind 13: ADCS/SBCS/ADC/SBC
    base = rng.choice([0x1A000000, 0x3A000000, 0x5A000000, 0x7A000000,
                       0x9A000000, 0xBA000000, 0xDA000000, 0xFA000000])
    return (base | (m << 16) | (n << 5) | d) & 0xFFFFFFFF

def gen_mem(rng):
    """Loads/stores with the addressing modes a heap write would use.  Rn is one
    of the pinned scratch pointers x1/x2; Rt is x4..x30; the register-offset
    index is pinned in x3."""
    rt = rng.randrange(4, 31)
    # SP (31) included: prologue/epilogue pairs are SP-relative, and pinning
    # only x1/x2 left the whole prologue/epilogue pattern untested.
    rn = rng.choice([1, 2, 31])
    kind = rng.choice([0, 1, 2, 3, 5])   # no writeback, no exclusive (qemu LL/SC differs from HW)
    if kind in (0, 5):                                     # LDR/STR unsigned, signed loads
        size = rng.randrange(4)
        if kind == 0:
            opc = rng.randrange(2)
        else:
            size = rng.randrange(3); opc = 2 if size == 2 else rng.choice([2, 3])
        base = (size << 30) | (0x39 << 24) | (opc << 22)
        return (base | (rng.randrange(64) << 10) | (rn << 5) | rt) & 0xFFFFFFFF
    if kind == 1:                                          # LDUR/STUR unscaled
        size = rng.randrange(4); opc = rng.randrange(2)
        base = (size << 30) | (0x38 << 24) | (opc << 22) | (0 << 10)
        return (base | ((((rng.randrange(16) - 8) * 8) & 0x1FF) << 12) | (rn << 5) | rt) & 0xFFFFFFFF
    if kind == 2:                                          # LDR/STR register offset
        size = rng.randrange(4); opc = rng.randrange(2)
        option = rng.choice([2, 3, 6, 7]); S = rng.randrange(2)
        base = (size << 30) | (0x38 << 24) | (opc << 22) | (1 << 21) | (2 << 10)
        return (base | (3 << 16) | (option << 13) | (S << 12) | (rn << 5) | rt) & 0xFFFFFFFF
    if kind == 3:                                          # LDP/STP signed offset
        sf = rng.randrange(2); load = rng.randrange(2)
        base = 0x28000000 | (sf << 31) | (load << 22) | (2 << 23)
        rt2 = rng.randrange(4, 31)
        return (base | (((rng.randrange(16) - 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt) & 0xFFFFFFFF
    if kind == 4:                                          # LDP/STP pre/post-index
        sf = rng.randrange(2); load = rng.randrange(2); post = rng.randrange(2)
        base = 0x28000000 | (sf << 31) | (load << 22) | ((1 if post else 3) << 23)
        rt2 = rng.randrange(4, 31)
        return (base | (((rng.randrange(8) - 4) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt) & 0xFFFFFFFF
    if kind == 6:                                          # LDR/STR pre-index single
        size = rng.randrange(4); opc = rng.randrange(2)
        base = (size << 30) | (0x38 << 24) | (opc << 22) | (3 << 10)
        return (base | ((((rng.randrange(8) - 4) * 8) & 0x1FF) << 12) | (rn << 5) | rt) & 0xFFFFFFFF
    if kind == 7:                                          # LDR/STR post-index single
        size = rng.randrange(4); opc = rng.randrange(2)
        base = (size << 30) | (0x38 << 24) | (opc << 22) | (1 << 10)
        return (base | ((((rng.randrange(8) - 4) * 8) & 0x1FF) << 12) | (rn << 5) | rt) & 0xFFFFFFFF
    # kind 8: LDXR/STXR 64-bit (literal encodings)
    if rng.randrange(2):
        return (0xC85F7C00 | (rn << 5) | rt) & 0xFFFFFFFF
    rs = rng.randrange(4, 31)
    return (0xC8007C00 | (rs << 16) | (rn << 5) | rt) & 0xFFFFFFFF

def gen_simd(rng):
    """LD1-LD4 / ST1-ST4 whole-register structure access - the custom
    recomp_ldst_struct path.  Rn is the pinned scratch pointer x1; Rt is a
    random first vector register; no post-index (keeps Rn fixed)."""
    Q = rng.randrange(2)
    size = rng.randrange(4)
    load = rng.randrange(2)
    rt = rng.randrange(0, 29)
    opcode = rng.choice([0x7, 0xA]) if size == 3 else rng.choice([0x0, 0x2, 0x4, 0x6, 0x7, 0x8, 0xA])
    rn = 1
    i = (0x0C000000 | (Q << 30) | (load << 22) | (opcode << 12)
         | (size << 10) | (rn << 5) | rt)
    return i & 0xFFFFFFFF

def gen_simd_fp(rng):
    """A few scalar/vector FP forms (ADD/MUL/SUB/DIV/FMA/SQRT/NEG/ABS)."""
    vd = rng.randrange(32); vn = rng.randrange(32); vm = rng.randrange(32)
    kind = rng.randrange(4)
    dbl = rng.randrange(2)
    if kind == 0:      # FMUL/FADD/FSUB/FDIV (scalar, 2-source)
        op = rng.randrange(4)                     # 0 mul 1 div 2 add 3 sub
        base = 0x1E200800 | (dbl << 22) | (op << 12)
        return (base | (vm << 16) | (vn << 5) | vd) & 0xFFFFFFFF
    if kind == 1:      # FMADD/FMSUB (3-source)
        va = rng.randrange(32)
        base = 0x1F000000 | (dbl << 22) | (rng.randrange(2) << 15)
        return (base | (vm << 16) | (va << 10) | (vn << 5) | vd) & 0xFFFFFFFF
    if kind == 2:      # FSQRT / FNEG / FABS (1-source)
        opc = rng.choice([3, 1, 0])               # sqrt, abs, neg
        base = 0x1E204000 | (dbl << 22) | (opc << 15)
        return (base | (vn << 5) | vd) & 0xFFFFFFFF
    # vector 2-source (4S/2D)
    op = rng.choice([0, 2, 3])
    base = 0x0E20D400 | (dbl << 22) | (op << 12)
    return (base | (vm << 16) | (vn << 5) | vd) & 0xFFFFFFFF

def gen_atom(rng):
    """Exclusives, LSE atomics and fences, returned as assembly text (the
    encodings are too fiddly to hand-roll, and clang validates them).  The
    single-threaded harness makes every exclusive deterministic, so any
    difference against qemu is in the emulated monitor itself.

    kind 4 and 6 cover a past reservation bug: an intervening store to
    the same granule must clear the monitor, so the following STXR/STXP must
    report failure (status 1)."""
    rn = rng.choice([1, 2])
    rt = rng.randrange(4, 31); rs = rng.randrange(4, 31)
    sf = rng.randrange(2); X = "x" if sf else "w"
    kind = rng.randrange(12)
    if kind == 0:  return [f"ldxr {X}{rt}, [x{rn}]"]
    if kind == 1:  return [f"ldaxr {X}{rt}, [x{rn}]"]
    if kind == 2:  return [f"stxr w{rs}, {X}{rt}, [x{rn}]"] if rs != rt else [f"stxr w{rt}, {X}{rs}, [x{rn}]"]
    if kind == 3:  return [f"ldxr {X}{rt}, [x{rn}]", f"stxr w{rs}, {X}{rt}, [x{rn}]"] if rs != rt else [f"ldxr {X}{rt}, [x{rn}]"]
    if kind == 4:  return [f"ldxr {X}{rt}, [x{rn}]", f"str {X}{rt}, [x{rn}]",
                           f"stxr w{rs}, {X}{rt}, [x{rn}]"] if rs != rt else \
                          [f"ldxr {X}{rt}, [x{rn}]", f"str {X}{rt}, [x{rn}]"]
    if kind == 5:
        rt2 = rng.randrange(4, 31)
        while rt2 == rt: rt2 = rng.randrange(4, 31)
        while rs in (rt, rt2): rs = rng.randrange(4, 31)
        return [f"ldxp {X}{rt}, {X}{rt2}, [x{rn}]",
                f"stxp w{rs}, {X}{rt}, {X}{rt2}, [x{rn}]"]
    if kind == 6:
        rt2 = rng.randrange(4, 31)
        while rt2 == rt: rt2 = rng.randrange(4, 31)
        while rs in (rt, rt2): rs = rng.randrange(4, 31)
        return [f"ldxp {X}{rt}, {X}{rt2}, [x{rn}]", f"str {X}{rt}, [x{rn}]",
                f"stxp w{rs}, {X}{rt}, {X}{rt2}, [x{rn}]"]
    if kind == 7:
        op = rng.choice(["ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin",
                         "ldumax", "ldumin", "swp"])
        return [f"{op} {X}{rs}, {X}{rt}, [x{rn}]"]
    if kind == 8:
        return [f"{rng.choice(['cas', 'casa', 'casl', 'casal'])} {X}{rs}, {X}{rt}, [x{rn}]"]
    if kind == 9:  return [rng.choice(["dmb ish", "dsb ish", "dmb ishld", "dmb ishst"])]
    if kind == 10: return ["isb"]
    return [f"ldar {X}{rt}, [x{rn}]", f"stlr {X}{rt}, [x{rn}]"]

SETUP = """\
    adrp x9, outbuf
    add  x9, x9, :lo12:outbuf
    mov  sp, x9
"""

def shaped_vinit(rng):
    """512 bytes of vector init: 64 shaped binary32 words then 32 shaped binary64
    words - subnormals, tiny normals, values near 1, large, zeros, inf, NaN."""
    def f32():
        k = rng.randrange(8); sgn = rng.getrandbits(1) << 31
        if k == 0: return sgn | rng.randrange(1, 1 << 23)                      # subnormal
        if k == 1: return sgn | (rng.randrange(1, 4) << 23) | rng.getrandbits(23)  # tiny normal
        if k in (2, 3, 4): return sgn | (rng.randrange(120, 135) << 23) | rng.getrandbits(23)
        if k == 5: return sgn | (rng.randrange(1, 255) << 23) | rng.getrandbits(23)
        if k == 6: return sgn                                                   # zero
        return sgn | (255 << 23) | (rng.getrandbits(23) if rng.getrandbits(1) else 0)
    def f64():
        k = rng.randrange(8); sgn = rng.getrandbits(1) << 63
        if k == 0: return sgn | rng.randrange(1, 1 << 52)
        if k == 1: return sgn | (rng.randrange(1, 4) << 52) | rng.getrandbits(52)
        if k in (2, 3, 4): return sgn | (rng.randrange(1015, 1030) << 52) | rng.getrandbits(52)
        if k == 5: return sgn | (rng.randrange(1, 2047) << 52) | rng.getrandbits(52)
        if k == 6: return sgn
        return sgn | (2047 << 52) | (rng.getrandbits(52) if rng.getrandbits(1) else 0)
    b = b"".join(f32().to_bytes(4, "little") for _ in range(64))
    b += b"".join(f64().to_bytes(8, "little") for _ in range(32))
    # FUZZ_EXTRA=N appends N shaped binary64 words and N binary32 words after the 512 bytes the registers load
    # (offsets 512 + 8*i and 512 + 8*N + 4*i), for word corpora that `ldr` a fresh operand before each instruction.
    # Exponents are biased towards the binary32 range and its edges so conversions see normal, near-overflow and
    # near-underflow values, not only the extremes.
    n = int(os.environ.get("FUZZ_EXTRA", "0"))
    def f64n():
        k = rng.randrange(6); sgn = rng.getrandbits(1) << 63
        if k < 3: return sgn | (rng.randrange(1023 - 126, 1023 + 128) << 52) | rng.getrandbits(52)   # float normal range
        if k == 3: return sgn | (rng.choice([1023 - 127, 1023 - 126, 1023 - 150, 1023 + 127, 1023 + 128, 1023 + 129]) << 52) | rng.getrandbits(52)
        return f64()
    def f32n():
        k = rng.randrange(4); sgn = rng.getrandbits(1) << 31
        if k < 2: return sgn | (rng.randrange(1, 255) << 23) | rng.getrandbits(23)
        return f32()
    b += b"".join(f64n().to_bytes(8, "little") for _ in range(n))
    b += b"".join(f32n().to_bytes(4, "little") for _ in range(n))
    return list(b)

def build_asm(rng, cases, per, mode="dp", words_file=None, pin=False, fpcr=None, shaped=False):
    wordlist = []
    if mode == "words":
        wordlist = [int(l.split()[0], 16) for l in open(words_file) if l.strip()]
        cases = (len(wordlist) + per - 1) // per
    wi = 0
    lines = [".arch armv8.4-a", ".text", ".global _start", "_start:"]
    lines.append(SETUP.rstrip("\n"))
    if fpcr is not None:                  # an FP mode for the whole run (e.g. FZ)
        lines.append(f"    movz x0, #0x{fpcr & 0xffff:x}")
        lines.append(f"    movk x0, #0x{(fpcr >> 16) & 0xffff:x}, lsl #16")
        lines.append("    msr fpcr, x0")
    # initial register state
    for r in range(31):
        v = rng.getrandbits(64)
        lines.append(f"    movz x{r}, #0x{v & 0xffff:x}")
        for hw in (1, 2, 3):
            part = (v >> (16*hw)) & 0xffff
            if part:
                lines.append(f"    movk x{r}, #0x{part:x}, lsl #{16*hw}")
    if mode == "words":
        # The default corpus is register-only (corpus.regonly.txt), so the
        # random init above is enough.  --pin instead anchors every register a
        # little past outbuf, which is what a corpus containing loads, stores or
        # the LSE atomics needs: qemu maps only the ELF segments, so a random
        # 64-bit value used as an address would fault rather than test the emit.
        if pin:
            # Re-emitted before every case below: an LSE atomic (or any load)
            # writes its result into a register that a later word may use as an
            # address, so pinning once at start-up walks off into unmapped
            # memory a few cases in.
            # Anchor into `scratch`, not `outbuf`: a store or an LSE atomic
            # landing in the dump buffer would be compared through the very
            # bytes it just wrote.
            anchor = ["    adrp x9, scratch", "    add  x9, x9, :lo12:scratch"]
            for r in range(31):
                anchor.append(f"    add  x{r}, x9, #{rng.getrandbits(64) & 0xff8}")
            anchor.append("    add  x3, x9, #8")
            lines.extend(anchor)
    elif mode not in ("dp", "words"):
        lines.append("    adrp x1, scratch")
        lines.append("    add  x1, x1, :lo12:scratch")
        lines.append("    add  x2, x1, #0x8000")
        lines.append("    add  sp, x1, #0x4000")     # SP-relative ops need a real SP
        lines.append("    mov  x3, #8")
    if mode in ("simd", "words"):
        lines.append("    adrp x9, vinit")
        lines.append("    add  x9, x9, :lo12:vinit")
        for i in range(16):                         # ldp q2i,q2i+1,[x9,#32i]
            w = 0xAD400000 | ((2*i) << 15) | ((2*i+1) << 10) | (9 << 5) | (2*i)
            lines.append(f"    .long 0x{w:08x}")
    lines.append(f"    msr nzcv, xzr")   # start at 0; flags will vary
    for c in range(cases):
        if mode == "words" and pin:
            lines.extend(anchor)
        if mode == "mem":
            lines.append("    add  sp, x1, #0x4000")   # writeback ops move SP
        for _ in range(per):
            if mode == "words":
                w = wordlist[wi % len(wordlist)]; wi += 1
            elif mode == "dp":     w = gen(rng)
            elif mode == "mem":    w = gen_mem(rng)
            elif mode == "simd":   w = gen_simd(rng)
            else:                  w = gen_atom(rng)
            if isinstance(w, list): lines.extend("    " + x for x in w)
            else:                   lines.append(f"    .long 0x{w:08x}")
        for r in range(0, 30, 2):
            lines.append(f"    stp x{r}, x{r+1}, [sp, #{r*8}]")
        lines.append(f"    str x30, [sp, #240]")
        lines.append(f"    mrs x30, nzcv")
        if fpcr is not None:              # FPSR's flags share the slot (bits 0-7, 27)
            lines.append(f"    mrs x29, fpsr")
            lines.append(f"    orr x30, x30, x29")
        lines.append(f"    str x30, [sp, #248]")
        if mode in ("simd", "words"):
            for i in range(16):                      # stp q2i,q2i+1,[sp,#256+32i]
                w = 0xAD000000 | (((256 + 32*i)//16) << 15) | ((2*i+1) << 10) | (31 << 5) | (2*i)
                lines.append(f"    .long 0x{w:08x}")
        csz = 784 if mode in ("simd", "words") else 256
        if mode == "words":
            # Write each case's dump as it is produced.  The corpus is not
            # guaranteed to be free of words that fault on their own (a load
            # through a value it just computed, say); an incremental stream
            # still leaves a comparable prefix whose length names the case.
            lines += [
                "    mov  x0, #1",
                "    mov  x1, sp",
                f"    mov  x2, #{csz}",
                "    mov  x8, #64",
                "    svc  #0",
            ]
        lines.append(f"    add sp, sp, #{csz}")
    total = cases * (784 if mode in ("simd", "words") else 256)
    lines += [] if mode == "words" else [
        "    adrp x1, outbuf",
        "    add  x1, x1, :lo12:outbuf",
        f"    movz x2, #0x{total & 0xffff:x}",
        f"    movk x2, #0x{(total >> 16) & 0xffff:x}, lsl #16",
        f"    movk x2, #0x{(total >> 32) & 0xffff:x}, lsl #32",
        "    mov  x0, #1",
        "    mov  x8, #64",
        "    svc  #0",
    ]
    if mode != "dp":                      # dump the scratch after the registers
        lines += [
            "    adrp x1, scratch",
            "    add  x1, x1, :lo12:scratch",
            f"    mov  x2, #0x10000",
            "    mov  x0, #1",
            "    mov  x8, #64",
            "    svc  #0",
        ]
    lines += [
        "    mov  x0, #0",
        "    mov  x8, #93",
        "    svc  #0",
        ".bss", ".align 12", "outbuf:", f"    .skip {total}",
        ".align 12", "scratch:", "    .skip 0x10000",
        ".data", ".align 4", "vinit:", "    .byte " + ",".join(str(x) for x in (shaped_vinit(rng) if shaped else [rng.randrange(256) for _ in range(512)])),
    ]
    return "\n".join(lines) + "\n"

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, **kw)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=64)
    ap.add_argument("--per", type=int, default=24)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--mode", choices=["dp", "mem", "simd", "atomic", "words"], default="dp")
    ap.add_argument("--words", default=os.path.join(os.environ.get("A64PORT_BASE", os.path.expanduser("~/a64port-work")), "insn-corpus/corpus.regonly.txt"))
    ap.add_argument("--vec-fast-all", action="store_true", help="emit with the fork vector fast paths")
    ap.add_argument("--fpx", action="store_true", help="emit with --fpx (FPX1 native FP fast paths)")
    ap.add_argument("--emit-flags", default="", help="extra a64recomp flags, e.g. '--fp-outline --callret'")
    ap.add_argument("--fpcr", type=lambda x: int(x, 0), default=None,
                    help="set FPCR first (e.g. 0x1000000 = FZ) and compare FPSR too")
    ap.add_argument("--shaped-v", action="store_true", help="shaped FP values in the vector registers")
    ap.add_argument("--pin", action="store_true", help="anchor registers into mapped memory (for corpora with loads/stores)")
    ap.add_argument("--cc", default=None, help="compiler for the native build (e.g. scripts/armv7-cc)")
    ap.add_argument("--runner", default="", help="prefix to run the native build (e.g. 'qemu-arm -L <sysroot>')")
    a = ap.parse_args()
    VECFAST[0] = bool(getattr(a, "vec_fast_all", False))
    FPX[0] = bool(getattr(a, "fpx", False))
    work = tempfile.mkdtemp(prefix="emfuzz-")
    rng = random.Random(a.seed)
    asm = build_asm(rng, a.cases, a.per, a.mode, words_file=a.words, pin=a.pin, fpcr=a.fpcr, shaped=a.shaped_v)
    ncase = a.cases                   # words mode sizes the run from the corpus
    if a.mode == "words":
        nw = sum(1 for l in open(a.words) if l.strip())
        ncase = (nw + a.per - 1) // a.per
    src = os.path.join(work, "fuzz.S")
    open(src, "w").write(asm)
    elf = os.path.join(work, "fuzz.a64")
    r = run(["clang", "--target=aarch64-linux-gnu", "-nostdlib", "-static",
             "-fuse-ld=lld", "-Wl,-e,_start", src, "-o", elf])
    if r.returncode: sys.exit("clang failed:\n" + r.stderr.decode()[:2000])
    q = run(["qemu-aarch64", elf])
    if q.returncode not in (0,): sys.exit(f"qemu exit {q.returncode}\n{q.stderr.decode()[:1000]}")
    ref = q.stdout
    out = os.path.join(work, "rc")
    drv_args = [DRV, elf, out, "--mod", "fz", "--no-names", "--trusted"]
    if VECFAST[0]:
        drv_args.append("--vec-fast-all")     # the fork's hand-written SIMD paths
    if FPX[0]:
        drv_args.append("--fpx")
    drv_args += a.emit_flags.split()
    e = run(drv_args)
    if e.returncode: sys.exit("a64recomp failed:\n" + e.stderr.decode()[:2000])
    binp = os.path.join(work, "native")
    b = run([BG, out, "--out", binp, "--jobs", "4", "--clean"] + (["--cc", a.cc] if a.cc else []))
    if b.returncode: sys.exit("build-guest failed:\n" + b.stderr.decode()[-2000:])
    n = run(a.runner.split() + [binp])
    got = n.stdout
    if got == ref:
        print(f"ok: {ncase} cases x {a.per} instrs identical "
              f"({len(ref)} bytes, qemu exit {q.returncode}, native exit {n.returncode})")
        if not a.keep: shutil.rmtree(work, ignore_errors=True)
        return
    # report the first differing case.  simd/words cases dump 784 bytes (GPRs +
    # NZCV, then the V registers), the others 256; words mode also sets the case
    # count from the corpus, not --cases (ncase above).
    csz = 784 if a.mode in ("simd", "words") else 256
    bad = None
    for c in range(ncase + 1):        # +1: the trailing scratch dump
        o = c * csz
        if ref[o:o+csz] != got[o:o+csz]:
            bad = c; break
    print(f"MISMATCH at case {bad} (seed {a.seed}; qemu {len(ref)} bytes, native {len(got)})")
    if bad is not None:
        o = bad * csz
        if csz > 256 and ref[o:o+256] == got[o:o+256]:
            print("  GPRs/NZCV identical: the difference is in the V registers")
        for r in range(31):
            rq = struct.unpack_from("<Q", ref, o + r*8)[0]
            rn = struct.unpack_from("<Q", got, o + r*8)[0]
            if rq != rn: print(f"  x{r}: qemu={rq:#x} native={rn:#x}")
        fq = struct.unpack_from("<Q", ref, o + 248)[0]
        fn = struct.unpack_from("<Q", got, o + 248)[0]
        if fq != fn: print(f"  nzcv: qemu={fq:#x} native={fn:#x}")
        # show the case's instructions (words + disassembly)
        lines = asm.split("\n")
        words = [l.split("0x")[1] for l in lines if l.strip().startswith(".long")]
        lo = bad * a.per; hi = lo + a.per
        case_words = words[lo:hi]
        print("  case words:", " ".join(case_words))
        raw = b"".join(bytes.fromhex(w)[::-1] for w in case_words)
        open(os.path.join(work, "case.bin"), "wb").write(raw)
        d = subprocess.run(["aarch64-linux-gnu-objdump", "-D", "-b", "binary", "-m", "aarch64",
                            os.path.join(work, "case.bin")], capture_output=True, text=True)
        for ln in d.stdout.split("\n"):
            if ":" in ln and "\t" in ln: print("   ", ln.split("\t",1)[-1].strip())
    print("workdir:", work)
    sys.exit(1)

if __name__ == "__main__":
    main()
