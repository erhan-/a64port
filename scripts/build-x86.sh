#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# build-x86.sh — the multi-module host binary for x86-64, built the same way as
# build-armv7.sh (clang, -O2 units, the REPO host sources, the tree's own hand/
# leaves), so an x86-64 A/B predicts the ARMv7 one and runs in real time.
#
#   APP_EXE_DIR  emit tree (default $WORK/<exe module><emit suffix>)
#   UNIT_OPT   optimisation for the emitted units (default -O2)
#   TAG        object-directory suffix (default x86-O2); change it with the flags
#   HOST_CF    extra flags for the three host units only (fast rebuilds)
#   BIN        output (default multi/app-x86)
#   ORDER      lld --symbol-ordering-file
set -uo pipefail

. "$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")/a64port-env.sh"
ROOT=$A64PORT_HOME
REPO=$ROOT/repo
WORK=$A64PORT_BASE/a64port
RT=$REPO/tools/recomp/runtime
SCHED=$ROOT/scripts/pipeline/build-parallel.py
MULTI=${MULTI_DIR:-$WORK/multi}
ESUF=${A64PORT_EMIT_SUFFIX:--v2}
EP=${EXE_DIR:-${APP_EXE_DIR:-$WORK/$A64PORT_EXE_MOD$ESUF}}
UNIT_OPT=${UNIT_OPT:--O2}
TAG=${TAG:-x86-O2}
EPOBJ=$EP/.obj-$TAG
OBJ=$MULTI/obj-$TAG
BIN=${BIN:-$MULTI/$A64PORT_EXE_MOD-x86}
MEM=${MEM:-$(awk '/^MemTotal/ { m = int($2 / 1048576 * 0.8); print (m > 1 ? m : 1) }' /proc/meminfo)}   # GB the compile may use: 80 % of RAM
JOBS=${JOBS:-$(nproc)}

[ -f "$MULTI/mods.h" ] || { echo "no $MULTI/mods.h - run scripts/pipeline/gen_mods.py first (docs/TUTORIAL.md, 3.4)"; exit 1; }
TGT=""
CF="-g0 -ffunction-sections -ffp-contract=off -fno-plt ${EXTRA_CF:-}"

MODS="${MODS:-$(tail -n +2 "$MULTI/modules.txt" | cut -f1 | tr '\n' ' ')}"   # every module of gen_mods.py's table but the executable

mkdir -p "$OBJ" "$EPOBJ"
MAN=$MULTI/manifest-$TAG.tsv
echo "=== manifest ==="
: > "$MAN"
for f in "$EP"/src/*.c; do
  o="$EPOBJ/$(basename "${f%.c}").o"
  printf '%s\t%s\t%s\n' "$f" "$o" "$CF -I$EP -I$EP/a64port -I$RT -include $RT/neon_structs.h" >> "$MAN"
done
for m in $MODS; do
  d=$WORK/libs$ESUF/$m
  [ -d "$d/src" ] || { echo "  WARNING: $m not emitted"; continue; }
  for f in "$d"/src/*.c; do
    o="$OBJ/$m-$(basename "${f%.c}").o"
    extra="$CF -I$d -I$d/a64port -I$RT -include $RT/neon_structs.h -Dg_module_base=g_mb_$m"
    extra="$extra -Dg_recomp_guard_host_v2=g_guard_$m"
    extra="$extra -Drecomp_lookup=recomp_lookup_$m"
    extra="$extra -Drecomp_build_index=recomp_build_index_$m"
    extra="$extra -D_recomp_index_view=_recomp_index_view_$m"
    printf '%s\t%s\t%s\n' "$f" "$o" "$extra" >> "$MAN"
  done
done
# The hand leaves the tree was emitted with (the emitter copies them to $EP/hand):
# a leaf variant's tree carries its own set, and its objects stay with the tree.
rm -f "$OBJ"/hand-*.o                 # hand objects live with the tree, never in $OBJ
for f in "$EP"/hand/*.c; do
  [ -e "$f" ] || continue
  o="$EPOBJ/hand-$(basename "${f%.c}").o"
  printf '%s\t%s\t%s\n' "$f" "$o" "$CF -I$EP/hand -I$EP -I$EP/a64port -I$RT -include $RT/neon_structs.h" >> "$MAN"
done
echo "  $(wc -l < "$MAN") units in manifest"

echo "=== compile (cached units are skipped) ==="
python3 "$SCHED" --manifest "$MAN" --obj "$OBJ" --cc clang --opt $UNIT_OPT \
  --mem-gb "$MEM" --jobs-max "$JOBS" --log "$MULTI/build-$TAG.log" \
  --status "$MULTI/build-$TAG.status"
[ $? -eq 0 ] || { echo "compile FAILED (see $MULTI/build-$TAG.log and *.o.stderr)"; exit 1; }

echo "=== shim + runtime + loader ==="
HF="-std=c11 -O2 $CF ${HOST_CF:-} -D_GNU_SOURCE -I$EP -I$EP/a64port -I$RT"
clang $HF -ffp-contract=off -fno-fast-math -foptimize-sibling-calls \
    -Drecomp_svc=a64port_horizon_svc_unused \
    -c "$EP/recomp_runtime.c" -o "$OBJ/zz_recomp_runtime.o" || exit 1
clang $HF -Dmain=a64port_guest_main_unused \
    $A64PORT_APP_INC -c "$RT/linux_syscalls.c" -o "$OBJ/zz_linux_syscalls.o" || exit 1
# The REPO's loader (it carries the 32-bit layout); mods.h still comes from $MULTI.
clang $HF -I"$MULTI" -DA64PORT_ROOTFS="\"$ROOT/rootfs\"" \
    $A64PORT_APP_INC -c "$REPO/tools/recomp/multi/host_loader.c" -o "$OBJ/zz_multi.o" || exit 1

echo "=== link ==="
mapfile -t EPOBJS < <(find "$EPOBJ" -name '*.o' ! -name 'linux_syscalls.o' ! -name 'recomp_runtime.o' | sort)
mapfile -t LIBOBJS < <(find "$OBJ" -name '*.o' | sort)
echo "  ${#EPOBJS[@]} executable + ${#LIBOBJS[@]} module/runtime objects"
LDORDER=()
[ -n "${ORDER:-}" ] && LDORDER=(-Wl,--symbol-ordering-file="$ORDER" -Wl,--no-warn-symbol-ordering)
time clang -fuse-ld=lld "${LDORDER[@]}" "${EPOBJS[@]}" "${LIBOBJS[@]}" \
    -lpthread -ldl -lm -o "$BIN" || exit 1
ls -la "$BIN" | awk '{printf "  %s: %.2f GB\n", $9, $5/1073741824}'
llvm-size "$BIN" 2>/dev/null || size "$BIN" 2>/dev/null || true
echo "done: $BIN"
