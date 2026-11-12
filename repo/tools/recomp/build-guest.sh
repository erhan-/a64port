#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# build-guest.sh — compile an emitted C project (tools/recomp/a64recomp output)
# into a native binary for a chosen target.
#
# The same emitted C is used for every target; only the compiler changes. That is
# the whole point of the design: the AArch64 -> C step happens once, the C ->
# machine step is whatever host we want.
#
#   tools/recomp/build-guest.sh <emitted-dir> [--cc CC] [--out BIN]
#                               [--opt "-O1"] [--jobs N] [--clean]
#
# Notes on cost, because a real title is ~2 GB of generated C:
#   * Generated translation units are large (20-30 MB each for a large executable). Compile
#     time is dominated by GCC's front/middle end, so it is nearly the same for
#     a cross target as for the native one. The levers that matter are
#     --jobs (one unit per core) and --opt (-O1 is ~2-3x faster than -O2).
#   * Parallelism is per unit. A single unit is one process and will show as one
#     busy core; that is expected, not a stall.
#   * Peak RSS is ~1-1.5 GB per unit at -O2, so --jobs defaults to a memory
#     bound rather than nproc.
#
# Examples:
#   tools/recomp/build-guest.sh /tmp/recomp-tiny --out /tmp/recomp-tiny/guest
#   tools/recomp/build-guest.sh /tmp/recomp-app --opt -O1 --jobs 14 \
#       --out /tmp/recomp-app/guest-x86_64
#   tools/recomp/build-guest.sh /tmp/recomp-app --cc arm-linux-gnueabihf-gcc \
#       --opt -O1 --jobs 14 --out /tmp/recomp-app/guest-armv7
#
# Note the asymmetry: recomp_runtime.c is compiled with its Horizon SVC handler
# renamed away, so our Linux handler in runtime/linux_syscalls.c is the one the
# generated code calls. Everything else compiles from the emitted tree as-is.

set -euo pipefail

OUT=${1:?usage: build-guest.sh <emitted-dir> [--cc CC] [--out BIN] [--opt FLAGS] [--jobs N]}
shift || true
CC=${CC:-cc}
BIN=""
OPT="-O1"
JOBS=""
KEEP_OBJ=1   # cache objects by default; --clean forces a rebuild

while [ $# -gt 0 ]; do
  case "$1" in
    --cc)   CC=$2; shift 2 ;;
    --out)  BIN=$2; shift 2 ;;
    --opt)  OPT=$2; shift 2 ;;
    --jobs) JOBS=$2; shift 2 ;;
    --keep-obj) KEEP_OBJ=1; shift ;;
    --clean)    KEEP_OBJ=0; shift ;;
    -j*)    JOBS=${1#-j}; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

OUT=$(cd "$OUT" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
RT="$HERE/runtime"
[ -f "$OUT/a64port/layout.h" ] || { echo "no a64port/layout.h in $OUT - not an emitted project?" >&2; exit 1; }
BIN=${BIN:-$OUT/guest}

if [ -z "$JOBS" ]; then
  CORES=$(nproc 2>/dev/null || echo 4)
  AVAIL_MB=$(awk '/MemAvailable/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 4096)
  # ~1.5 GB per unit at -O2; be conservative for -O2, looser for -O0/-O1.
  PER_JOB_MB=1536; case "$OPT" in *-O0*|*-O1*) PER_JOB_MB=1024 ;; esac
  MEM_JOBS=$(( AVAIL_MB / PER_JOB_MB )); [ "$MEM_JOBS" -lt 1 ] && MEM_JOBS=1
  JOBS=$(( CORES < MEM_JOBS ? CORES : MEM_JOBS ))
fi

OBJ="$OUT/.obj-$(basename "$CC")-$OPT"
[ "$KEEP_OBJ" -eq 0 ] && rm -rf "$OBJ"
mkdir -p "$OBJ"

# -ffp-contract=off and -fno-fast-math are required by the engine's FPX1 feature
# (RECOMP_FPX_HOST compiles itself out under __FAST_MATH__, and contraction would
# change the exact FP result); both are harmless when FPX1 is off.
# -foptimize-sibling-calls is not implied by -O1 and is what turns a chained
# block's tail call into a jump rather than a nested host frame.
CFLAGS_STR="-std=c11 -D_GNU_SOURCE $OPT -g -ffp-contract=off -fno-fast-math -fno-math-errno -foptimize-sibling-calls -I$OUT -I$OUT/hand -I$OUT/a64port -I$RT -include $RT/neon_structs.h"
UNITS=("$OUT"/src/*.c)

echo "build-guest: $OUT"
echo "  cc=$CC opt='$OPT' jobs=$JOBS units=${#UNITS[@]} bin=$BIN"

# ── Generated translation units, one process each, JOBS at a time ────────────
export A64PORT_CC="$CC" A64PORT_CFLAGS_STR="$CFLAGS_STR" A64PORT_OBJ="$OBJ"
t0=$SECONDS
printf '%s\n' "${UNITS[@]}" | xargs -P "$JOBS" -n1 -d '\n' bash -c '
  set -e
  f="$1"
  o="$A64PORT_OBJ/$(basename "${f%.c}").o"
  # Skip units whose object is newer than the source: iterating on the shim or
  # the runtime must not recompile gigabytes of generated code every time.
  if [ -f "$o" ] && [ "$o" -nt "$f" ]; then echo "  cached $(basename "$f")"; exit 0; fi
  read -r -a _cflags <<< "$A64PORT_CFLAGS_STR"
  "$A64PORT_CC" "${_cflags[@]}" -c "$f" -o "$o"
  echo "  compiled $(basename "$f")"
' _
echo "  units done in $((SECONDS - t0))s"

# ── Hand-written leaves ─────────────────────────────────────────────────────
# Copied into $OUT/hand/ by the driver from tools/recomp/hand/. Compiled with the
# same flags as the generated units; their objects are picked up by the link's
# find below. This is the whole point of the framework: a leaf is ordinary C.
HAND=("$OUT"/hand/*.c)
if [ -e "${HAND[0]}" ]; then
  echo "  compiling ${#HAND[@]} hand leaf source(s)"
  printf '%s\n' "${HAND[@]}" | xargs -P "$JOBS" -n1 -d '\n' bash -c '
    set -e
    f="$1"
    o="$A64PORT_OBJ/hand_$(basename "${f%.c}").o"
    if [ -f "$o" ] && [ "$o" -nt "$f" ]; then echo "  cached hand/$(basename "$f")"; exit 0; fi
    read -r -a _cflags <<< "$A64PORT_CFLAGS_STR"
    "$A64PORT_CC" "${_cflags[@]}" -c "$f" -o "$o"
    echo "  compiled hand/$(basename "$f")"
  ' _
fi

# ── Shim + runtime ──────────────────────────────────────────────────────────
# -D_GNU_SOURCE on both: -std=c11 sets __STRICT_ANSI__, which hides POSIX
# declarations such as nanosleep (used by the generated recomp_runtime.c) and
# openat/fstatat/st_atim (used by linux_syscalls.c). GCC <= 13 only warned about the
# implicit declaration; GCC >= 14 makes it an error, so the define is required.
echo "  compiling linux_syscalls.c"
# A64PORT_APP_INC (e.g. -I<app>/runtime) supplies an application's runtime layer (app_layer/*.inc); without it the
# generic guest (app_none.inc) is built.
"$CC" -std=c11 "$OPT" -g -D_GNU_SOURCE -I"$OUT" -I"$OUT/a64port" -I"$RT" ${A64PORT_APP_INC:-} \
  -c "$RT/linux_syscalls.c" -o "$OBJ/linux_syscalls.o"
echo "  compiling recomp_runtime.c (Horizon recomp_svc renamed away)"
"$CC" -std=c11 "$OPT" -g -D_GNU_SOURCE -ffp-contract=off -fno-fast-math -fno-math-errno -foptimize-sibling-calls \
  -I"$OUT" -I"$OUT/a64port" -I"$RT" \
  -Drecomp_svc=a64port_horizon_svc_unused \
  -c "$OUT/recomp_runtime.c" -o "$OBJ/recomp_runtime.o"

# ── Link ────────────────────────────────────────────────────────────────────
echo "  linking ${#UNITS[@]} objects + runtime"
t1=$SECONDS
mapfile -t OBJS < <(find "$OBJ" -name '*.o' | sort)
"$CC" "${OBJS[@]}" -o "$BIN" -lm
echo "  link done in $((SECONDS - t1))s, total $((SECONDS - t0))s"

# The binary looks for <binary>.a64port/ next to itself (or $A64PORT_ROOT/a64port), so several programs can be
# built into one directory.
ln -sfn "$OUT/a64port" "$BIN.a64port"
ls -la "$BIN"
echo "built $BIN"
