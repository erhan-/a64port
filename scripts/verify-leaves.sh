#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# verify-leaves.sh - batch differential verification of hand leaves.
#
# verify-leaf.sh verifies ONE leaf per invocation and keys its work dir by
# address, so N leaves cost N cold caches and N x (emit A + emit B + build A).
# For many candidate leaves in one hand dir this batch
# variant restructures the cost:
#
#   * ONE work dir keyed by the HAND DIR CONTENTS - growing the candidate file
#     reuses every unchanged unit's object (mtime cache);
#   * emit A (--no-native-leaf) is address-independent: emitted once, then
#     stamp-skipped while (ELF, driver, flags) are unchanged;
#   * emit B stamp-skipped while the hand dir is unchanged too;
#   * ONE harness verifies ALL requested symbols in one binary: the marginal
#     cost of another leaf in a batch is a table row plus linear run time.
#
# First run for a hand dir: ~2 emits + 1 cold build (same as one verify-leaf).
# Later runs with edited candidates: 1 emit B + the changed units + 2 links.
# Later runs with unchanged candidates: 2 links + run (seconds).
#
# usage: verify-leaves.sh <elf> <mod> <addr>... [--hand DIR] [--iters N]
#                          [--function] [--abi] [--abi-void] [--seed mixed|small|varied]
#                          [--jobs N] [--cc CC] [--runner CMD] [--clean] [--shaped FILE]
#
# --dead-below-sp: after the function returns, do not compare guest memory
#   below the ENTRY stack pointer. The AArch64 Linux ABI has no red zone - the
#   kernel may write a signal frame there at any moment - so a caller can never
#   observe it, and a translated body (which spills callee-saved registers
#   there) and a leaf (which may not) legitimately differ in it. Off by default:
#   the strict comparison is what catches a leaf that gets its OWN frame wrong
#   while the function runs; this is for the gates that judge
#   a whole function by what its caller can see (the shaped contexts).
#
# --cc CC --runner CMD: build and run both variants for another host, e.g.
#   --cc scripts/armv7-cc --runner "qemu-arm -L <armhf sysroot>"
# so a leaf is verified on the host it ships on (a 32-bit host has its own
# width hazards).  The work dir is keyed by the compiler, so caches never mix.
#
# Semantics identical to verify-leaf.sh (--function follows the translated
# code to its return; --abi zeroes caller-saved state before the diff; the
# seed rules are documented there). Read its header before changing the
# context machinery - both scripts must stay in sync.
#
# --shaped FILE: a C file included into the generated harness that defines
#   int shaped_setup(uint64_t entry, int it, GuestContext *c);
# called per symbol per iteration AFTER the default random seeding (memory
# fill, registers, flags, vregs) and BEFORE the symbol runs; return 0 to skip
# the iteration. Override c->x[..] / flags / vregs and write structures into
# g_mem (guest base g_base, size MEMSZ, rng rnd()) to give data-carrying
# functions real pointers and counts - the random seed cannot align argument
# roles (as verify-leaf.sh --main does). The comparison,
# FOLLOW, ABI zeroing and tagged output are unchanged, so the A/B diff keeps
# its meaning: both variants receive byte-identical shaped contexts.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
DRV="$ROOT/repo/tools/recomp/a64recomp"
RT="$ROOT/repo/tools/recomp/runtime"

ELF=""; MOD=""; HAND=""; ITERS=200; CC="${CC:-$(command -v clang || echo cc)}"; RUNNER=""
A_FLAGS="--no-native-leaf"; B_FLAGS=""; FOLLOW=0; ABI=0; ABI_VOID=0; DEADSP=0
SEED=mixed; CLEAN=0; ADDRS=(); SHAPED=""
JOBS="${A64PORT_VERIFY_JOBS:-$(nproc 2>/dev/null || echo 4)}"
[ "$JOBS" -gt 16 ] && JOBS=16
while [ $# -gt 0 ]; do
  case "$1" in
    --hand)  HAND=$2; shift 2 ;;
    --iters) ITERS=$2; shift 2 ;;
    --cc)    CC=$2; shift 2 ;;
    --runner) RUNNER=$2; shift 2 ;;
    --a-flags) A_FLAGS=$2; shift 2 ;;
    --b-flags) B_FLAGS=$2; shift 2 ;;
    --function) FOLLOW=1; shift ;;
    --abi)   ABI=1; shift ;;
    --abi-void) ABI=1; ABI_VOID=1; shift ;;
    --dead-below-sp) DEADSP=1; shift ;;
    --seed)  SEED=$2; shift 2 ;;
    --jobs)  JOBS=$2; shift 2 ;;
    --clean) CLEAN=1; shift ;;
    --shaped) SHAPED=$2; shift 2 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) if [ -z "$ELF" ]; then ELF=$1; elif [ -z "$MOD" ]; then MOD=$1; else ADDRS+=("$1"); fi; shift ;;
  esac
done
[ -n "$ELF" ] && [ -n "$MOD" ] && [ "${#ADDRS[@]}" -ge 1 ] || { sed -n '2,22p' "$0"; exit 2; }
[ -x "$DRV" ] || { echo "SKIP: $DRV not built"; exit 0; }
case "$SEED" in small) SEEDN=1 ;; varied) SEEDN=2 ;; *) SEEDN=0 ;; esac
SHAPEDN=0
if [ -n "$SHAPED" ]; then
  [ -f "$SHAPED" ] || { echo "--shaped: no such file: $SHAPED" >&2; exit 2; }
fi

hash_file() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
hash_dir() { # deterministic content hash of a hand dir: every file the emitter
  # COPIES for that dir, which is *.c AND a64port_hand.h. Hashing only the .c
  # files meant a header-only edit left the stamp unchanged, B was not re-emitted
  # and the emitted hand/a64port_hand.h stayed stale - so the harness verified
  # code that did not include the change (found by a mutation test that passed
  # when it should have failed).
  ( cd "$1" && find . -maxdepth 1 \( -name '*.c' -o -name '*.h' \) | sort | xargs -r sha256sum ) 2>/dev/null | sha256sum | cut -d' ' -f1
}
ELF_H=$(hash_file "$ELF"); DRV_H=$(hash_file "$DRV")
HAND_H=nohand; [ -n "$HAND" ] && HAND_H=$(hash_dir "$HAND")
STAMP_A="$ELF_H $DRV_H $MOD $A_FLAGS"
STAMP_B="$ELF_H $DRV_H $MOD $B_FLAGS $HAND_H"

# The work dir is keyed by (module, ELF, driver) and NOT by the hand dir:
# variant A (--no-native-leaf) never reads the hand dir, so its emit and
# objects are identical across candidate edits, and variant B's emit is
# incrementally copy-backed (only changed units get new mtimes). Editing a
# leaf therefore costs one B emit plus the changed units - not a cold rebuild.
# The B stamp still carries the hand hash, so a candidate change re-emits B.
WORK="${A64PORT_VERIFY_DIR:-$HOME/a64port-work/verify}/${MOD}-${ELF_H:0:8}-${DRV_H:0:8}"
# objects from another compiler must never be reused: one work dir per CC
# (the default `cc` keeps the historical path, so the warm x86 cache stays valid)
[ "$CC" = cc ] || WORK="$WORK-$(basename "$CC")"
if [ "$CLEAN" = 1 ]; then rm -rf "$WORK"; fi
mkdir -p "$WORK"

# Crash/quota hygiene: a run that died on /tmp quota or
# a kill can leave silently truncated .vo files (the header check misses tail
# truncation). While the .dirty marker is present, restore every B object
# whose source is byte-identical to A's from A (authoritative), force-recompile
# the B-only ones, and drop any object without ELF magic in either variant.
sweep_objects() {
  local f N bad=0
  for f in "$WORK"/a/*.vo "$WORK"/b/*.vo; do
    [ -e "$f" ] || continue
    if ! head -c4 "$f" | od -An -tx1 | grep -q '7f 45 4c 46'; then rm -f "$f"; bad=1; fi
  done
  for f in "$WORK"/b/src/*.c; do
    [ -e "$f" ] || continue; N=$(basename "${f%.c}")
    if [ -f "$WORK/a/src/$N.c" ] && cmp -s "$f" "$WORK/a/src/$N.c"; then
      [ -f "$WORK/a/$N.vo" ] && cp -f "$WORK/a/$N.vo" "$WORK/b/$N.vo"
    else
      rm -f "$WORK/b/$N.vo"
    fi
  done
  for f in "$WORK"/b/hand/*.c; do
    [ -e "$f" ] || continue; N=$(basename "${f%.c}")
    if [ -f "$WORK/a/hand/$N.c" ] && cmp -s "$f" "$WORK/a/hand/$N.c"; then
      [ -f "$WORK/a/hand_$N.vo" ] && cp -f "$WORK/a/hand_$N.vo" "$WORK/b/hand_$N.vo"
    else
      rm -f "$WORK/b/hand_$N.vo"
    fi
  done
  [ "$bad" = 1 ] && echo "  swept: corrupted objects removed" >&2
  return 0
}
if [ -e "$WORK/.dirty" ]; then
  echo "  previous run did not finish cleanly - sweeping object cache" >&2
  sweep_objects
fi
: > "$WORK/.dirty"
if [ -n "$SHAPED" ]; then cp "$SHAPED" "$WORK/verify_shaped.c"; SHAPEDN=1; fi
# Publish the work dir so another shell can show a/b unit counts while this runs
# (same pointer verify-leaf.sh publishes; only the pointer is removed on exit).
VW="${A64PORT_VERIFY_WORK:-/tmp/a64port-verify-work}"
printf '%s\n' "$WORK" > "$VW" 2>/dev/null || true
trap 'rm -f "$VW"' EXIT

emit() { # $1 = out dir, $2 = extra flags, $3 = stamp file, $4 = stamp value
  local out="$1" flags="$2" stampf="$3" stampv="$4" tmp f rel
  if [ -e "$out/src" ] && [ -e "$stampf" ] && [ "$(cat "$stampf")" = "$stampv" ]; then
    echo "  emit $out: unchanged (stamp)"
    return 0
  fi
  tmp="$(mktemp -d)"
  if ! "$DRV" "$ELF" "$tmp" --mod "$MOD" --trusted --no-names ${HAND:+--hand "$HAND"} $flags >/dev/null 2>&1; then
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
  printf '%s' "$stampv" > "$stampf"
}

# ---- symbol table ---------------------------------------------------------
SYMS=(); ENTRIES=()
for a in "${ADDRS[@]}"; do
  a="${a#0x}"; a="${a#0X}"
  ENTRIES+=("$(printf '%x' "0x$a")")
  SYMS+=("blk_${MOD}_$(printf '%x' "0x$a")")
done
for s in "${SYMS[@]}"; do
  grep -rq "void ${s}(" "$WORK/b/src" 2>/dev/null || true
done

TBL=""
DECLS=""
for i in "${!SYMS[@]}"; do
  DECLS+="void ${SYMS[$i]}(GuestContext*);"$'\n'
  TBL+="    { \"${SYMS[$i]}\", ${SYMS[$i]}, 0x${ENTRIES[$i]}u },"$'\n'
done

cat > "$WORK/verify_main.c" <<EOF
#include "recomp_runtime.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <stdlib.h>

#define MEMSZ (1u << 20)
#define ITERS ${ITERS}
#define FOLLOW ${FOLLOW}
#define ABI ${ABI}
#define ABI_VOID ${ABI_VOID}
#define SEED ${SEEDN}
#define NSYM ${#SYMS[@]}
#define SHAPED ${SHAPEDN}
#define DEADSP ${DEADSP}

static uint8_t g_mem[MEMSZ];
static const uint64_t g_base = 0x100000;
static uint64_t g_rs;
static uint64_t rnd(void){ g_rs ^= g_rs << 13; g_rs ^= g_rs >> 7; g_rs ^= g_rs << 17; return g_rs; }
static uint64_t h64(uint64_t q){ uint64_t h = 1469598103934665603ull; for (int b = 0; b < 8; ++b){ h ^= (q >> (8*b)) & 0xffu; h *= 1099511628211ull; } return h; }
static uint32_t canon32(uint32_t w){ float f; memcpy(&f, &w, 4); return isnan(f) ? 0x7fc00000u : w; }
static uint64_t canon64(uint64_t d){ double f; memcpy(&f, &d, 8); return isnan(f) ? 0x7ff8000000000000ull : d; }

/* Debug aid: hex-dump a guest address range for one (symbol, iteration), so an
   A/B diff names the exact bytes that differ. RB_SHAPED_DUMP="lo-hi" (guest
   VAs, hex); RB_SHAPED_DUMP_S / _IT filter. Both variants dump the same
   addresses, so the a.out/b.out diff is the comparison. */
static void shaped_dump_if_wanted(int s, int it){
    const char* r = getenv("RB_SHAPED_DUMP");
    if(!r) return;
    const char* fs = getenv("RB_SHAPED_DUMP_S"); if(fs && atoi(fs) != s) return;
    const char* fi = getenv("RB_SHAPED_DUMP_IT"); if(fi && atoi(fi) != it) return;
    unsigned long long lo=0, hi=0;
    if(sscanf(r, "%llx-%llx", &lo, &hi) != 2) return;
    for(unsigned long long a = lo; a + 16 <= hi; a += 16){
        printf("s%d %d @%08llx", s, it, a);
        for(int k = 0; k < 16; ++k) printf(" %02x", g_mem[(size_t)(a - g_base) + k]);
        printf("\n");
    }
}

#if SHAPED
#include "verify_shaped.c"
#endif

typedef struct { const char *name; void (*fn)(GuestContext*); uint64_t entry; } Sym;
${DECLS}static const Sym SYMS[NSYM] = {
${TBL}};

void recomp_svc(GuestContext* c, unsigned imm){ (void)c; (void)imm; }

/* Cross-module callees. The harness links ONE module, so a call that leaves it
   (through a PLT/GOT slot, e.g. clock_gettime or operator delete) has no
   translated body here. Both variants must treat that identically or the
   comparison is meaningless: the translated side would set pc to the target and
   the follow loop would stop mid-function, while a leaf's rb_guest_call would
   either stop or continue - and stopping mid-function means the callee-saved
   registers and the frame are still live, which no leaf can reproduce. So the
   host dispatcher is given a stub that models "the callee returned": run the
   caller's return address. Both sides then finish their own function, and what
   the differential compares is the caller's own code, which is the point. */
static void rb_stub_return(GuestContext* c){
    if (getenv("RB_STUB_TRACE")) fprintf(stderr, "[stub] pc=%llx x30=%llx\n",
        (unsigned long long)c->pc, (unsigned long long)c->x[30]);
    c->pc = c->x[30];
}
BlockFn a64port_host_dispatch(uint64_t pc){ (void)pc; return rb_stub_return; }

int main(void){
    setvbuf(stdout, NULL, _IOLBF, 0);   /* a hung leaf names its symbol/iteration */
    const uint64_t base = g_base;
    for (int s = 0; s < NSYM; ++s) {
        for (int it = 0; it < ITERS; ++it) {
            g_rs = 0x9E3779B97F4A7C15ull ^ ((uint64_t)it * 0x100000001B3ull) ^ ((uint64_t)s * 0x2545F4914F6CDD1Dull);
            for (size_t i = 0; i + 8 <= MEMSZ; i += 8){ uint64_t v = rnd(); memcpy(g_mem + i, &v, 8); }
            /* A fresh guest stack is ZEROED memory (the kernel hands a new
               process zero pages). The translated side pushes a frame and
               restores x29/x30 from it, so a random stack makes its saved LR
               garbage - which showed up as pc=0 vs the leaf's correct
               entry+0x1000 on both frame-using leaves, with memory identical.
               Zero the top of the arena before the run, like a real stack; the
               post-run zeroing further down still keeps the frame itself (which
               sits well below the top) in the comparison. */
            for (size_t i = (MEMSZ > 65536 ? MEMSZ - 65536 : 0); i < MEMSZ; ++i) g_mem[i] = 0;
            GuestContext c; memset(&c, 0, sizeof c);
            c.mem = g_mem; c.mem_size = MEMSZ; c.mem_base_vaddr = base;
            for (int r = 0; r < 31; ++r){
                uint64_t v;
#if SEED == 1
                v = rnd() % 256;
#elif SEED == 2
                switch ((r + it) % 3) {
                    case 0:  v = base + (rnd() % (MEMSZ - 16)); break;
                    case 1:  v = rnd() % 256; break;
                    default: v = rnd(); break;
                }
#else
                switch (r % 3) {
                    case 0:  v = base + (rnd() % (MEMSZ - 16)); break;
                    case 1:  v = rnd() % 256; break;
                    default: v = rnd(); break;
                }
#endif
                c.x[r] = v;
            }
            c.x[31] = base + MEMSZ - 16;
            c.pc = SYMS[s].entry;
            c.x[30] = SYMS[s].entry + 0x1000;
            const uint64_t lr_sentinel = c.x[30];
            uint64_t entry_sp = c.x[31];      /* final value after the shaper, below */
            c.n = rnd() & 1; c.z = rnd() & 1; c.c = rnd() & 1; c.v = rnd() & 1;
            c.fpsr = 16;
            for (int v = 0; v < 32; ++v){
                uint32_t lo;
                switch (v % 4) {
                    case 0: { float f = (float)((int)(rnd() % 20000) - 10000) / 100.0f; memcpy(&lo, &f, 4); break; }
                    case 1: { float f = (float)rnd() * 1e30f; memcpy(&lo, &f, 4); break; }
                    case 2: { lo = 0; break; }
                    default: { float f = 1.0f + (float)(rnd() % 1000) / 1000.0f; memcpy(&lo, &f, 4); break; }
                }
                c.vreg[v][0] = lo; c.vreg[v][1] = rnd();
            }
#if SHAPED
            /* the shaper sees the fully-defaulted context and may override
               registers/flags/vregs and rewrite g_mem; 0 skips the iteration */
            if (!shaped_setup(SYMS[s].entry, it, &c)) continue;
#endif
            entry_sp = c.x[31];
            SYMS[s].fn(&c);
#if FOLLOW
            /* Stop when the FUNCTION returns, i.e. when control reaches the
               return address the harness installed before the call. Comparing
               against the LIVE c->x[30] instead stopped as soon as the first
               callee returned (a 'bl' sets x30 to its resume point, and the
               callee's ret lands exactly there) - so a leaf that ran its calls
               to completion looked different from the translated side, which
               merely stopped. That is what made leaves
               fail with identical memory. */
            for (int _s = 0; _s < 100000 && c.pc != lr_sentinel && !c.halted; ++_s) {
                BlockFn _f = recomp_lookup(c.pc - g_module_base);
                if (!_f) _f = a64port_host_dispatch(c.pc);   /* cross-module: the stub */
                if (!_f) break;
                _f(&c);
            }
#endif
#if ABI
            /* The stack window used to be zeroed here so that a leaf which did
               not reproduce the machine's frame would not be failed for the
               frame bytes it never wrote. Leaves now DO reproduce the frame
               (push x29/x30, adjust SP, restore on the way out), so nothing is
               masked - which is what makes a wrong frame-local offset visible
               (a mutation test proved the mask hid exactly that). */
            /* LR is caller-saved (every internal bl may clobber it) and x0 is
               the return slot (dead for a void function): both are ABI-dead,
               and a whole-function leaf vs translated body legitimately
               differ on them. --abi-void covers the void-return case. */
            c.x[30] = 0;
#if ABI_VOID
            c.x[0] = 0;
#endif
            for (int r = 1; r <= 18; ++r) c.x[r] = 0;
            c.n = c.z = c.c = c.v = 0;
            for (int v = 0; v < 32; ++v)
                if (v < 8 || v >= 16) { c.vreg[v][0] = 0; c.vreg[v][1] = 0; }
            /* (the stack is NOT masked: see the comment above) */
#endif
            printf("s%d %d rawpc %016llx rawx30 %016llx halted %u\n", s, it, (unsigned long long)c.pc, (unsigned long long)c.x[30], (unsigned)c.halted);
            for (int r = 0; r < 32; ++r) printf("s%d %d r%d %016llx\n", s, it, r, (unsigned long long)h64(c.x[r]));
            printf("s%d %d pc %016llx\n", s, it, (unsigned long long)h64(c.pc));
            printf("s%d %d flags %016llx\n", s, it, (unsigned long long)h64((uint64_t)c.n | ((uint64_t)c.z << 8) | ((uint64_t)c.c << 16) | ((uint64_t)c.v << 24)));
            for (int v = 0; v < 32; ++v){
                uint64_t d = ((uint64_t)c.vreg[v][1] << 32) | (uint32_t)c.vreg[v][0];
                d = canon64(d);
                printf("s%d %d v%d %016llx %016llx\n", s, it, v,
                       (unsigned long long)h64(canon32((uint32_t)d)),
                       (unsigned long long)h64(canon32((uint32_t)(d >> 32))));
            }
#if DEADSP
            /* --dead-below-sp: the STACK bytes below the entry SP are not the
               caller's to see (no red zone), so both variants read as zero
               there. Only the stack window (the top 64 KiB, zeroed before the
               run like a fresh stack) - data the shaper placed lower in the
               arena stays in the comparison. */
            {
                const uint64_t stk_lo = base + (MEMSZ > 65536 ? MEMSZ - 65536 : 0);
                if (entry_sp > stk_lo && entry_sp <= base + MEMSZ)
                    memset(g_mem + (size_t)(stk_lo - base), 0, (size_t)(entry_sp - stk_lo));
            }
#endif
            /* NaN-payload-insensitive by construction (same rule as the vreg
               compare / 3dsrecomp verify.rs): host-FP and exact-integer FP may
               pick different NaN payloads where the guest ABI does not care
               (e.g. inf*0 defaults differ in sign between ARM and x86). */
            uint64_t mh = 1469598103934665603ull;
            for (size_t i = 0; i + 4 <= MEMSZ; i += 4){
                uint32_t w; memcpy(&w, g_mem + i, 4);
                mh ^= canon32(w); mh *= 1099511628211ull;
            }
            printf("s%d %d mem %016llx\n", s, it, (unsigned long long)mh);
#if SHAPED
            shaped_dump_if_wanted(s, it);
#endif
            printf("s%d %d misc %016llx\n", s, it, (unsigned long long)(h64(c.fpcr) ^ h64(c.fpsr) ^ h64(c.halted) ^ h64(c.pending_svc)));
        }
    }
    return 0;
}
EOF

build() { # $1 = emitted dir, $2 = output binary, $3 = optional reference dir
  local out="$1" bin="$2" ref="${3:-}"
  local fl=(-std=c11 -O1 -g -ffp-contract=off -fno-fast-math -fno-math-errno
            -foptimize-sibling-calls -D_GNU_SOURCE -I"$out" -I"$out/hand" -I"$out/a64port"
            -I"$WORK" -I"$RT" -include "$RT/neon_structs.h")
  if [ -e "$out/vmain.o" ] && [ "$out/vmain.o" -nt "$WORK/verify_main.c" ]; then :; else
      "$CC" "${fl[@]}" -c "$WORK/verify_main.c" -o "$out/vmain.o" || return 1
  fi
  [ -e "$out/vrt.o" ] && [ "$out/vrt.o" -nt "$out/recomp_runtime.c" ] || \
      "$CC" "${fl[@]}" -DA64PORT_NO_INLINE_LOADS -Drecomp_svc=a64port_horizon_svc_unused -c "$out/recomp_runtime.c" -o "$out/vrt.o"
  [ -e "$out/vlg.o" ] && [ -z "$(find "$RT" -newer "$out/vlg.o" \( -name '*.c' -o -name '*.inc' -o -name '*.h' \) | head -1)" ] || \
      "$CC" "${fl[@]}" -ffunction-sections -fdata-sections \
          -Dmain=a64port_guest_main_unused -Drecomp_svc=a64port_horizon_svc_verify_unused \
          ${A64PORT_APP_INC:-} -c "$RT/linux_syscalls.c" -o "$out/vlg.o"
  local running=0 f o rf ro
  for f in $(ls -S "$out"/src/*.c "$out"/hand/*.c 2>/dev/null); do
    [ -e "$f" ] || continue
    case "$f" in
      */hand/*) o="$out/hand_$(basename "${f%.c}").vo" ;;
      *)        o="$out/$(basename "${f%.c}").vo" ;;
    esac
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

emit "$WORK/a" "$A_FLAGS" "$WORK/.stamp.a" "$STAMP_A" || { echo "FAIL: emit (translated variant)" >&2; exit 1; }
emit "$WORK/b" "$B_FLAGS" "$WORK/.stamp.b" "$STAMP_B" || { echo "FAIL: emit (leaf variant)" >&2; exit 1; }

for i in "${!SYMS[@]}"; do
  grep -rq "void ${SYMS[$i]}(" "$WORK/b/src" || { echo "FAIL: ${SYMS[$i]} not in the emitted module"; exit 1; }
done

if ! build "$WORK/a" "$WORK/a/verify" 2>"$WORK/a.build.err"; then
  echo "FAIL: could not build the translated variant" >&2; tail -5 "$WORK/a.build.err" >&2; exit 1
fi
if ! build "$WORK/b" "$WORK/b/verify" "$WORK/a" 2>"$WORK/b.build.err"; then
  echo "FAIL: could not build the leaf variant" >&2; tail -5 "$WORK/b.build.err" >&2; exit 1
fi

$RUNNER "$WORK/a/verify" > "$WORK/a.out"
$RUNNER "$WORK/b/verify" > "$WORK/b.out"
rm -f "$WORK/.dirty"   # both binaries ran: objects are sound, diff freely

if diff -q "$WORK/a.out" "$WORK/b.out" >/dev/null; then
  for i in "${!SYMS[@]}"; do
    echo "PASS: ${MOD}+0x${ENTRIES[$i]} (${SYMS[$i]}) state-equivalent over ${ITERS} random contexts"
  done
  exit 0
fi
# per-symbol verdicts from the tagged diff
# per-symbol verdicts from the tagged diff (plain diff|head would abort the
# script under set -e pipefail: diff exits 1 on any difference)
echo "DIFFERENCES FOUND (first lines):"
{ diff "$WORK/a.out" "$WORK/b.out" | head -10 || true; }
echo
# Symbol tags in the diff are `< s0 0 v8 ...`: take the index after the tag.
# (This used to be `sed 's/^.. s//'`, which never matched `< s0` - the pattern
# expects a space after the two characters - so BAD was always EMPTY and every
# symbol was reported PASS even when the outputs differed. A mutation test that
# changed a shift in one filter leaf is what caught it.)
mapfile -t BAD < <(diff "$WORK/a.out" "$WORK/b.out" \
                   | grep -oE '^[<>] s[0-9]+' | sed 's/^[<>] s//' | sort -u)
if [ "${#BAD[@]}" -eq 0 ]; then
  echo "FAIL: the A/B outputs differ but no symbol tag was parsed from the diff;" >&2
  echo "      refusing to report a verdict (a non-empty diff must never read as PASS)" >&2
  exit 1
fi
for i in "${!SYMS[@]}"; do
  if printf '%s\n' "${BAD[@]}" 2>/dev/null | grep -qx "$i"; then
    echo "FAIL: ${MOD}+0x${ENTRIES[$i]} (${SYMS[$i]}) differs from the translated body"
  else
    echo "PASS: ${MOD}+0x${ENTRIES[$i]} (${SYMS[$i]}) state-equivalent over ${ITERS} random contexts"
  fi
done
exit 1
