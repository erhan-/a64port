#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# verify-leaf.sh - differential verification of one hand leaf.
#
# Emits the module twice -- once with the leaf disabled (--no-native-leaf) and
# once with it enabled -- then runs the block at <addr> from the SAME random
# GuestContext in both builds and compares the resulting registers, flags, VFP,
# FPCR/FPSR and memory. This is the oracle a leaf needs before it is trusted;
# reading the disassembly or the source is understanding, not verification.
#
# Scope: it compares ONE block from a random context, so it catches a leaf that
# is not state-equivalent (including a forgotten intermediate register write). It
# does not exercise how the leaf interacts with its callers -- that is the
# whole-program byte-exact / pixel-diff gate. Both variants are emitted with
# --trusted so the code guard does not need the real image in memory, and
# --no-names so the block symbol is the deterministic blk_<mod>_<hex>.
#
# usage: verify-leaf.sh <elf> <mod> <addr> [--hand DIR] [--iters N] [--cc CC]
#                       [--a-flags "FLAGS"] [--b-flags "FLAGS"] [--function]
#                       [--symbol NAME] [--abi] [--jobs N]
#                       [--seed mixed|small|varied] [--main FILE] [--clean]
#
# --main FILE replaces the generated harness with a function-specific one (it
# is compiled into both variants, so the A/B diff still applies). Include
# verify_symbol.h and call VERIFY_SYMBOL, and do your own setup/FOLLOW/printing.
# Use it when the behaviour needs specific pointers and counts -- the random
# seed cannot align argument roles, which is the case for every data-carrying
# leaf.
#
# --seed chooses how the random GuestContext's registers are filled. `mixed`
# (the default) alternates pointers, small ints and full words per register;
# `small` makes every argument small so a count-like argument keeps a loop
# short; `varied` cycles the roles across iterations. Use `small`/`varied` to
# verify a function whose trip count comes from an argument -- with `mixed` the
# translated side hits the 100000-step follow cap mid-loop while the leaf runs
# to completion, which is inconclusive rather than a mismatch.
#
# --function follows the translated code from the entry block to its return, so
# a whole-function leaf is compared against the whole function. --abi relaxes
# the comparison to the guest ABI at a function boundary: x1..x18 and NZCV are
# caller-saved (dead across a call) and the callee's stack frame is dead after it
# returns, so both emissions' copies are zeroed before the diff. Without it a
# whole-function leaf that leaves only ABI-dead scratch state different (as the
# committed _XGetPixel leaf does) is reported non-equivalent. Use --abi only for
# a leaf registered at a function entry; a block leaf must match every register.
#
# By default A is emitted with --no-native-leaf (the translated body) and B with
# the leaf enabled -- the leaf case. --a-flags/--b-flags compare any two emitter
# flag sets instead, which is how --fpx is checked against the exact body.
#
# --function follows the translated code from the entry block to its return (via
# the emitted recomp_lookup) before comparing. A hand leaf that implements a
# WHOLE function (the usual form for a hot function) returns immediately, so its
# entry block is not block-equivalent to the translated entry block; --function
# compares the end state of the whole function instead, which is what such a leaf
# must match.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
DRV="$ROOT/repo/tools/recomp/a64recomp"
RT="$ROOT/repo/tools/recomp/runtime"

ELF=""; MOD=""; ADDR=""; HAND=""; ITERS=200; CC="${CC:-$(command -v clang || echo cc)}"; SYMBOL_OVERRIDE=""
A_FLAGS="--no-native-leaf"; B_FLAGS=""; FOLLOW=0; ABI=0
SEED=mixed; MAIN=""; CLEAN=0
# Unit compilation is parallel but memory-bound (the biggest generated units need
# several GB each at -O1). 16 keeps peak RSS under the machine while paying the
# critical path; override with A64PORT_VERIFY_JOBS or --jobs.
JOBS="${A64PORT_VERIFY_JOBS:-$(nproc 2>/dev/null || echo 4)}"
[ "$JOBS" -gt 16 ] && JOBS=16
while [ $# -gt 0 ]; do
  case "$1" in
    --hand)  HAND=$2; shift 2 ;;
    --iters) ITERS=$2; shift 2 ;;
    --cc)    CC=$2; shift 2 ;;
    --a-flags) A_FLAGS=$2; shift 2 ;;
    --b-flags) B_FLAGS=$2; shift 2 ;;
    --function) FOLLOW=1; shift ;;
    --symbol)   SYMBOL_OVERRIDE=$2; shift 2 ;;
    --abi)      ABI=1; shift ;;
    --seed)     SEED=$2; shift 2 ;;
    --jobs)     JOBS=$2; shift 2 ;;
    --main)     MAIN=$2; shift 2 ;;
    --clean)    CLEAN=1; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) if [ -z "$ELF" ]; then ELF=$1; elif [ -z "$MOD" ]; then MOD=$1; elif [ -z "$ADDR" ]; then ADDR=$1; else echo "unexpected: $1" >&2; exit 2; fi; shift ;;
  esac
done
[ -n "$ELF" ] && [ -n "$MOD" ] && [ -n "$ADDR" ] || { sed -n '2,25p' "$0"; exit 2; }
[ -x "$DRV" ] || { echo "SKIP: $DRV not built"; exit 0; }

ADDR="${ADDR#0x}"; ADDR="${ADDR#0X}"
ADDR_HEX="$(printf '%x' "0x$ADDR")"
SYMBOL="${SYMBOL_OVERRIDE:-blk_${MOD}_${ADDR_HEX}}"
case "$SEED" in small) SEEDN=1 ;; varied) SEEDN=2 ;; *) SEEDN=0 ;; esac

# A stable per-(module,address) work dir, not a mktemp. The emitted units are
# deterministic, so a rerun after editing the leaf must reuse the objects of
# every unit that did not change -- otherwise each verification is a full
# ~15-minute rebuild for a one-line leaf edit. --clean forces a from-scratch
# build. The cache is ~1-2 GB per variant, bounded per address.
WORK="${A64PORT_VERIFY_DIR:-${TMPDIR:-/tmp}/a64port-verify}/${MOD}-${ADDR_HEX}"
if [ "${CLEAN:-0}" = 1 ]; then rm -rf "$WORK"; fi
mkdir -p "$WORK"
# Publish the work dir so another shell can count how many units of each
# variant are compiled; only the pointer is removed on exit, not the cache.
VW="${A64PORT_VERIFY_WORK:-/tmp/a64port-verify-work}"
printf '%s\n' "$WORK" > "$VW" 2>/dev/null || true
trap 'rm -f "$VW"' EXIT

emit() { # $1 = out dir, $2 = extra flags. Emit to a temp dir, then copy back
         # only the files that changed: that keeps the mtime of every identical
         # unit, which is what lets build()'s object cache skip it.
  local out="$1" tmp f rel
  tmp="$(mktemp -d)"
  if ! "$DRV" "$ELF" "$tmp" --mod "$MOD" --trusted --no-names ${HAND:+--hand "$HAND"} $2 >/dev/null 2>&1; then
    rm -rf "$tmp"; return 1
  fi
  mkdir -p "$out"
  while IFS= read -r -d '' f; do
    rel="${f#"$tmp"/}"
    if [ -e "$out/$rel" ] && cmp -s "$f" "$out/$rel"; then :; else
      mkdir -p "$(dirname "$out/$rel")"; cp "$f" "$out/$rel"
    fi
  done < <(find "$tmp" -type f -print0)
  rm -rf "$tmp"
}
emit "$WORK/a" "$A_FLAGS" || { echo "FAIL: emit (translated variant) failed" >&2; exit 1; }
emit "$WORK/b" "$B_FLAGS" || { echo "FAIL: emit (leaf variant) failed" >&2; exit 1; }

if ! grep -rq "void ${SYMBOL}(" "$WORK/b/src"; then
  echo "FAIL: ${SYMBOL} is not in the emitted module (wrong module/address?)" >&2
  exit 1
fi

if [ -n "$MAIN" ]; then
  # A function-specific harness replaces the generated one. It is compiled into
  # BOTH variants, so the A/B diff still works; it must define main and include
  # verify_symbol.h (written here) to call the function under test, and do its
  # own setup, FOLLOW and printing. Use it for a function whose behaviour needs
  # specific pointers and counts, which the random seed cannot align.
  printf '#define VERIFY_SYMBOL %s\nvoid VERIFY_SYMBOL(GuestContext*);\n' "${SYMBOL}" > "$WORK/verify_symbol.h"
  cp "$MAIN" "$WORK/verify_main.c"
else
cat > "$WORK/verify_main.c" <<EOF
#include "recomp_runtime.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

void ${SYMBOL}(GuestContext*);
void recomp_svc(GuestContext* c, unsigned imm){ (void)c; (void)imm; }

#define MEMSZ (1u << 20)
#define ITERS ${ITERS}
#define ENTRY 0x${ADDR_HEX}u
#define FOLLOW ${FOLLOW}
#define ABI ${ABI}
#define SEED ${SEEDN}

static uint8_t g_mem[MEMSZ];
static uint64_t g_rs;
static uint64_t rnd(void){ g_rs ^= g_rs << 13; g_rs ^= g_rs >> 7; g_rs ^= g_rs << 17; return g_rs; }
static uint64_t h64(uint64_t q){ uint64_t h = 1469598103934665603ull; for (int b = 0; b < 8; ++b){ h ^= (q >> (8*b)) & 0xffu; h *= 1099511628211ull; } return h; }
/* Two NaNs count as equal whatever their payload (3dsrecomp verify.rs): the
   hardware and the host compiler are each free to pick one. */
static uint32_t canon32(uint32_t w){ float f; memcpy(&f, &w, 4); return isnan(f) ? 0x7fc00000u : w; }
static uint64_t canon64(uint64_t d){ double f; memcpy(&f, &d, 8); return isnan(f) ? 0x7ff8000000000000ull : d; }

int main(void){
    const uint64_t base = 0x100000;
    for (int it = 0; it < ITERS; ++it) {
        g_rs = 0x9E3779B97F4A7C15ull ^ ((uint64_t)it * 0x100000001B3ull);
        for (size_t i = 0; i + 8 <= MEMSZ; i += 8){ uint64_t v = rnd(); memcpy(g_mem + i, &v, 8); }
        GuestContext c; memset(&c, 0, sizeof c);
        c.mem = g_mem; c.mem_size = MEMSZ; c.mem_base_vaddr = base;
        for (int r = 0; r < 31; ++r){
            uint64_t v;
#if SEED == 1
            /* every argument small: a count-like argument stays small, so a
               loop terminates and the translated --function run reaches its
               return instead of hitting the step cap mid-loop. Memory operands
               are below the arena then, and memload/memstore answer 0 for both
               emissions, so the comparison is still exact. */
            v = rnd() % 256;
#elif SEED == 2
            /* roles cycle across iterations: a count argument gets a pointer,
               a small int and a full word in turn, so some iterations both
               have real buffers and terminate. */
            switch ((r + it) % 3) {
                case 0:  v = base + (rnd() % (MEMSZ - 16)); break;
                case 1:  v = rnd() % 256; break;
                default: v = rnd(); break;
            }
#else
            switch (r % 3) {
                case 0:  v = base + (rnd() % (MEMSZ - 16)); break;   /* a guest pointer */
                case 1:  v = rnd() % 256; break;                       /* a small int */
                default: v = rnd(); break;                             /* full width */
            }
#endif
            c.x[r] = v;
        }
        c.x[31] = base + MEMSZ - 16;
        c.pc = ENTRY;
        c.x[30] = ENTRY + 0x1000;
        c.n = rnd() & 1; c.z = rnd() & 1; c.c = rnd() & 1; c.v = rnd() & 1;
        c.fpsr = 16;   /* FPSR.IXC already set, so FPX1's fast path may open */
        for (int v = 0; v < 32; ++v){
            uint32_t lo;
            switch (v % 4) {
                case 0: { float f = (float)((int)(rnd() % 20000) - 10000) / 100.0f; memcpy(&lo, &f, 4); break; }
                case 1: { float f = (float)rnd() * 1e30f; memcpy(&lo, &f, 4); break; }   /* large: FPX keeps */
                case 2: { lo = 0; break; }                                              /* zero: FPX keeps */
                default: { float f = 1.0f + (float)(rnd() % 1000) / 1000.0f; memcpy(&lo, &f, 4); break; }
            }
            c.vreg[v][0] = lo; c.vreg[v][1] = rnd();
        }
        ${SYMBOL}(&c);
#if FOLLOW
        /* Follow the translated code to its return, so a leaf that implements
           the whole function can be compared against all of it. */
        for (int _s = 0; _s < 100000 && c.pc != c.x[30] && !c.halted; ++_s) {
            BlockFn _f = recomp_lookup(c.pc - g_module_base);
            if (!_f) break;
            _f(&c);
        }
#endif
#if ABI
        /* Whole-function ABI comparison. The guest ABI makes x1..x18, NZCV and
           the FP/SIMD registers v0..v7 and v16..v31 caller-saved (dead across a
           call), and the callee's stack frame dead once it returns, but the
           recompiled body still leaves values in them (the exact-FP bodies load
           v0/v1). Zero both emissions' copies so the diff compares what the ABI
           actually makes observable: x0, callee-saved x19..x29 and v8..v15,
           LR/SP, pc and memory outside the stack. Use it only for a leaf
           registered at a function's entry, where the ABI applies; a block leaf
           must still match every register. */
        for (int r = 1; r <= 18; ++r) c.x[r] = 0;
        c.n = c.z = c.c = c.v = 0;
        for (int v = 0; v < 32; ++v)
            if (v < 8 || v >= 16) { c.vreg[v][0] = 0; c.vreg[v][1] = 0; }
        for (size_t i = (MEMSZ > 4096 ? MEMSZ - 4096 : 0); i < MEMSZ; ++i) g_mem[i] = 0;
#endif
        for (int r = 0; r < 32; ++r) printf("%d r%d %016llx\n", it, r, (unsigned long long)h64(c.x[r]));
        printf("%d pc %016llx\n", it, (unsigned long long)h64(c.pc));
        printf("%d flags %016llx\n", it, (unsigned long long)h64((uint64_t)c.n | ((uint64_t)c.z << 8) | ((uint64_t)c.c << 16) | ((uint64_t)c.v << 24)));
        for (int v = 0; v < 32; ++v){
            uint64_t d = ((uint64_t)c.vreg[v][1] << 32) | (uint32_t)c.vreg[v][0];
            d = canon64(d);
            printf("%d v%d %016llx %016llx\n", it, v,
                   (unsigned long long)h64(canon32((uint32_t)d)),
                   (unsigned long long)h64(canon32((uint32_t)(d >> 32))));
        }
        uint64_t mh = 1469598103934665603ull;
        for (size_t i = 0; i < MEMSZ; i += 16){ mh ^= g_mem[i]; mh *= 1099511628211ull; }
        printf("%d mem %016llx\n", it, (unsigned long long)mh);
        printf("%d misc %016llx\n", it, (unsigned long long)(h64(c.fpcr) ^ h64(c.fpsr) ^ h64(c.halted) ^ h64(c.pending_svc)));
    }
    return 0;
}
EOF
fi

build() { # $1 = emitted dir, $2 = output binary, $3 = optional reference dir
  # A and B are the same module emitted once without and once with the leaf, so
  # they differ in only the unit(s) holding an overridden block. When $3 is
  # given, reuse its object for every unit whose source is byte-identical
  # instead of recompiling it -- that is what makes a whole-module verify of a large executable
  # cost one full build, not two.
  local out="$1" bin="$2" ref="${3:-}"
  local fl=(-std=c11 -O1 -g -ffp-contract=off -fno-fast-math -fno-math-errno
            -foptimize-sibling-calls -D_GNU_SOURCE -I"$out" -I"$out/hand" -I"$out/a64port"
            -I"$WORK" -I"$RT" -include "$RT/neon_structs.h")
  # Compile the harness, the runtime and the shim only when their source is newer
  # than the object (the harness is rewritten each run; the other two usually are
  # not). The unit loop below uses the same rule.
  [ -e "$out/vmain.o" ] && [ "$out/vmain.o" -nt "$WORK/verify_main.c" ] || \
      "$CC" "${fl[@]}" -c "$WORK/verify_main.c" -o "$out/vmain.o"
  [ -e "$out/vrt.o" ] && [ "$out/vrt.o" -nt "$out/recomp_runtime.c" ] || \
      "$CC" "${fl[@]}" -DA64PORT_NO_INLINE_LOADS -Drecomp_svc=a64port_horizon_svc_unused -c "$out/recomp_runtime.c" -o "$out/vrt.o"
  # The emitted units call recomp_ldst_struct() for every LD1-LD4/ST1-ST4, and
  # its (weak) body lives in the Linux shim, which the product build links. Do
  # the same here: compile the shim, renaming its strong recomp_svc so it does
  # not collide with the harness's stub (the emitted code must keep calling the
  # stub, not make real syscalls).
  [ -e "$out/vlg.o" ] && [ -z "$(find "$RT" -newer "$out/vlg.o" \( -name '*.c' -o -name '*.inc' -o -name '*.h' \) | head -1)" ] || \
      "$CC" "${fl[@]}" -ffunction-sections -fdata-sections \
          -Dmain=a64port_guest_main_unused -Drecomp_svc=a64port_horizon_svc_verify_unused \
          ${A64PORT_APP_INC:-} -c "$RT/linux_syscalls.c" -o "$out/vlg.o"
  # Compile the units in parallel: a module can be ~100 units and serial cc1 of
  # the whole module is the entire cost (a large executable takes hours, not minutes). JOBS
  # bounds peak memory rather than cores -- the largest units are what matter.
  # Sort by size descending (as build-parallel.py does) so the biggest units
  # start in the first wave and set the wall, instead of finishing last.
  local running=0 f o rf ro
  for f in $(ls -S "$out"/src/*.c "$out"/hand/*.c 2>/dev/null); do
    [ -e "$f" ] || continue
    case "$f" in
      */hand/*) o="$out/hand_$(basename "${f%.c}").vo" ;;
      *)        o="$out/$(basename "${f%.c}").vo" ;;
    esac
    # cached across runs: an unchanged unit keeps its object
    if [ -e "$o" ] && [ "$o" -nt "$f" ]; then continue; fi
    if [ -n "$ref" ]; then
      rf="${f/#$out/$ref}"
      case "$rf" in
        */hand/*) ro="$ref/hand_$(basename "${rf%.c}").vo" ;;
        *)        ro="$ref/$(basename "${rf%.c}").vo" ;;
      esac
      if [ -e "$rf" ] && [ -e "$ro" ] && cmp -s "$f" "$rf"; then cp "$ro" "$o"; continue; fi
    fi
    "$CC" "${fl[@]}" -I"$out/hand" -c "$f" -o "$o" &
    running=$((running + 1))
    if [ "$running" -ge "$JOBS" ]; then wait -n; running=$((running - 1)); fi
  done
  wait
  # The final `wait` cannot report an individual job's status, so a unit that
  # failed to compile would otherwise be silently missing and only show up as an
  # undefined _seg_* at link. Count the objects instead. (neon_structs.h above is
  # force-included because every LD1-LD4/ST1-ST4 unit calls recomp_ldst_struct;
  # without it those units fail with an implicit-declaration error on GCC 14+.)
  local nsrc nvo
  nsrc=$({ ls "$out"/src/*.c "$out"/hand/*.c 2>/dev/null || true; } | wc -l)
  nvo=$(ls "$out"/*.vo 2>/dev/null | wc -l)
  if [ "$nvo" -ne "$nsrc" ]; then
    echo "FAIL: $((nsrc - nvo)) of $nsrc units did not compile in $out" >&2
    return 1
  fi
  local objs=("$out/vmain.o" "$out/vrt.o" "$out/vlg.o")
  for f in "$out"/*.vo; do objs+=("$f"); done
  "$CC" "${objs[@]}" -ffunction-sections -Wl,--gc-sections -o "$bin" -lm -lpthread -ldl -lrt
}

if ! build "$WORK/a" "$WORK/a/verify" 2>"$WORK/a.build.err"; then
  echo "FAIL: could not build the translated variant" >&2; tail -5 "$WORK/a.build.err" >&2; exit 1
fi
if ! build "$WORK/b" "$WORK/b/verify" "$WORK/a" 2>"$WORK/b.build.err"; then
  echo "FAIL: could not build the leaf variant" >&2; tail -5 "$WORK/b.build.err" >&2; exit 1
fi

"$WORK/a/verify" > "$WORK/a.out"
"$WORK/b/verify" > "$WORK/b.out"

if diff -q "$WORK/a.out" "$WORK/b.out" >/dev/null; then
  echo "PASS: ${MOD}+0x${ADDR_HEX} (${SYMBOL}) is state-equivalent over ${ITERS} random contexts"
else
  echo "FAIL: ${MOD}+0x${ADDR_HEX} (${SYMBOL}) differs from the translated body:"
  diff "$WORK/a.out" "$WORK/b.out" | head -10
  exit 1
fi
