#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# build-armv7.sh — the multi-module host binary for a 32-bit ARM host (ARMv7).
#
# The emitted C is host-neutral, so this is rebuild-multi.sh with a different
# compiler: the same emit tree, the same mods.h, cross-compiled by clang for
# armv7-a/NEON/hard-float against an armhf sysroot.  Objects and the binary go
# to their own paths, so the x86-64 build and its cache are untouched.
#
# The host side picks its 32-bit layout itself (host_loader.c: A64PORT_ILP32_HOST,
# a 1.5 GB arena).  Leaves that assume a 64-bit `long` are NOT linked:
# `long` is 4 bytes here.
#
#   ARMHF_SYSROOT   armhf sysroot (glibc headers + libs; no gcc runtime needed)
#   A64PORT_EMIT_SUFFIX  emit tree suffix, as for reemit.sh / rebuild-multi.sh
#   ARENA_TOP       override A64PORT_ARENA_TOP (guest VA top; default 0x68000000)
#   ARM_CPU         code generation target (default "-mcpu=cortex-a17 -mthumb":
#                   a Cortex-A17 test board's core - hardware sdiv/udiv, its scheduling - and
#                   Thumb-2, ~28 % less text than ARM mode for the same code)
#   UNIT_OPT        optimisation for the emitted units (default -O2: smaller
#                   than -O1 here, and the x86 measurements favour it)
#   TAG             object-directory suffix, so builds with other flags keep
#                   their caches (default a17t2-O2-fs)
#   APP_EXE_DIR       the executable's emit tree (default $WORK/app$A64PORT_EMIT_SUFFIX); its
#                   hand/ dir - the leaves it was emitted with - is compiled
#                   into the tree's own object dir, so two trees never share one
#   BIN             output binary (default multi/app-multi-armv7)
#   ORDER           lld --symbol-ordering-file (scripts/hot-order.py): links the
#                   sampled hot blocks first, so the running app's code shares
#                   a few MB instead of being spread over the whole image
#
# Run under qemu:  qemu-arm -L "$ARMHF_SYSROOT" <bin> <rootfs>
set -uo pipefail

. "$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")/a64port-env.sh"
ROOT=$A64PORT_HOME
REPO=$ROOT/repo
WORK=$A64PORT_BASE/a64port
RT=$REPO/tools/recomp/runtime
SCHED=$ROOT/scripts/pipeline/build-parallel.py
MULTI=${MULTI_DIR:-$WORK/multi}
SR=$ARMHF_SYSROOT
SRL=$SR/usr/lib/arm-linux-gnueabihf
ESUF=${A64PORT_EMIT_SUFFIX:--v2}
EP=${EXE_DIR:-${APP_EXE_DIR:-$WORK/$A64PORT_EXE_MOD$ESUF}}
ARM_CPU=${ARM_CPU:--mcpu=cortex-a17 -mthumb}
UNIT_OPT=${UNIT_OPT:--O2}
TAG=${TAG:-a17t2-O2-fs}
EPOBJ=$EP/.obj-armv7-$TAG
OBJ=$MULTI/obj-armv7-$TAG
BIN=${BIN:-$MULTI/$A64PORT_EXE_MOD-multi-armv7}
MEM=${MEM:-$(awk '/^MemTotal/ { m = int($2 / 1048576 * 0.8); print (m > 1 ? m : 1) }' /proc/meminfo)}   # GB the compile may use: 80 % of RAM
JOBS=${JOBS:-$(nproc)}

[ -d "$SRL" ] || { echo "no armhf sysroot at $SR (set ARMHF_SYSROOT)"; exit 1; }
[ -f "$MULTI/mods.h" ] || { echo "no $MULTI/mods.h - run scripts/pipeline/gen_mods.py first (docs/TUTORIAL.md, 3.4)"; exit 1; }

# -g0: the scheduler adds -g, and DWARF for 650 MB of text is not wanted on a
# 32-bit board.  -fno-pic: a non-PIE image keeps r9-class registers free and
# skips GOT indirection on every global the emitted code touches.
# -ffp-contract=off: no fused multiply-add the guest did not ask for (what gcc's
# ISO mode gives the x86-64 build; clang's C default would fuse within a statement).
TGT="--target=arm-linux-gnueabihf $ARM_CPU -mfpu=neon-vfpv4 -mfloat-abi=hard --sysroot=$SR"
# -ffunction-sections: one section per block function, so ORDER can place it.
# (The object cache is keyed on mtime, not flags: a flag change needs a new TAG.)
CF="$TGT -g0 -fno-pic -ffunction-sections -ffp-contract=off -D_FILE_OFFSET_BITS=64 -D_TIME_BITS=64 ${EXTRA_CF:-}"
[ -n "${ARENA_TOP:-}" ] && CF="$CF -DA64PORT_ARENA_TOP=${ARENA_TOP}ull"

MODS="${MODS:-$(tail -n +2 "$MULTI/modules.txt" | cut -f1 | tr '\n' ' ')}"   # every module of gen_mods.py's table but the executable

mkdir -p "$OBJ" "$EPOBJ"
MAN=$MULTI/manifest-armv7.tsv
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
  --mem-gb "$MEM" --jobs-max "$JOBS" --log "$MULTI/build-armv7.log" \
  --status "$MULTI/build-armv7.status"
[ $? -eq 0 ] || { echo "compile FAILED (see $MULTI/build-armv7.log and *.o.stderr)"; exit 1; }

echo "=== shim + runtime + loader ==="
HF="-std=c11 -O2 $CF -D_GNU_SOURCE -I$EP -I$EP/a64port -I$RT"
clang $HF -ffp-contract=off -fno-fast-math -foptimize-sibling-calls \
    -Drecomp_svc=a64port_horizon_svc_unused \
    -c "$EP/recomp_runtime.c" -o "$OBJ/zz_recomp_runtime.o" || exit 1
clang $HF -Dmain=a64port_guest_main_unused \
    $A64PORT_APP_INC -c "$RT/linux_syscalls.c" -o "$OBJ/zz_linux_syscalls.o" || exit 1
# The REPO's loader (it carries the 32-bit layout); mods.h still comes from $MULTI.
clang $HF -I"$MULTI" -DA64PORT_ROOTFS="\"$ROOT/rootfs\"" \
    $A64PORT_APP_INC -c "$REPO/tools/recomp/multi/host_loader.c" -o "$OBJ/zz_multi.o" || exit 1

echo "=== link ==="
# The sysroot carries glibc's crt files but no gcc runtime (crtbegin/libgcc.a),
# so link those by hand; libgcc_s supplies the __aeabi_* helpers.
mapfile -t EPOBJS < <(find "$EPOBJ" -name '*.o' ! -name 'linux_syscalls.o' ! -name 'recomp_runtime.o' | sort)
mapfile -t LIBOBJS < <(find "$OBJ" -name '*.o' | sort)
echo "  ${#EPOBJS[@]} executable + ${#LIBOBJS[@]} module/runtime objects"
LDORDER=()
[ -n "${ORDER:-}" ] && LDORDER=(-Wl,--symbol-ordering-file="$ORDER" -Wl,--no-warn-symbol-ordering)
# A -DA64PORT_FASTMEM build needs the identity arena (guest VA == host address,
# 0x400000..ARENA_TOP), so the host image goes above it: IMAGE_BASE.
LDBASE=()
case "${EXTRA_CF:-}" in *A64PORT_FASTMEM*) LDBASE=(-Wl,--image-base=${IMAGE_BASE:-0x68800000}) ;; esac
# STATIC=1: glibc's static archives + repo/tools/recomp/runtime/armv7-builtins.c (the
# sysroot has no libgcc.a).  Nothing is mapped below the image before main(),
# which qemu-user needs for the identity arena (it puts a dynamic binary's
# ld.so and libraries at 0x40000000+), and the target's glibc stops mattering.
if [ "${STATIC:-0}" = 1 ]; then
  clang $TGT -O2 -c "$RT/armv7-builtins.c" -o "$OBJ/zz_armv7_rt.o" || exit 1
  mapfile -t LIBOBJS < <(find "$OBJ" -name '*.o' | sort)
  time clang $TGT -fuse-ld=lld -static -nostartfiles -nodefaultlibs "${LDORDER[@]}" "${LDBASE[@]}" \
      "$SRL/crt1.o" "$SRL/crti.o" "${EPOBJS[@]}" "${LIBOBJS[@]}" \
      -L"$SRL" -Wl,--start-group -lpthread -ldl -lm -lc -Wl,--end-group "$SRL/crtn.o" \
      -o "$BIN" || exit 1
else
  rm -f "$OBJ/zz_armv7_rt.o"
  time clang $TGT -fuse-ld=lld -no-pie -nostartfiles -nodefaultlibs "${LDORDER[@]}" "${LDBASE[@]}" \
      "$SRL/crt1.o" "$SRL/crti.o" "${EPOBJS[@]}" "${LIBOBJS[@]}" \
      -L"$SRL" -lpthread -ldl -lm -lc -l:libgcc_s.so.1 "$SRL/crtn.o" \
      -o "$BIN" || exit 1
fi
ls -la "$BIN" | awk '{printf "  %s: %.2f GB\n", $9, $5/1073741824}'
llvm-size "$BIN" 2>/dev/null || size "$BIN" 2>/dev/null || true
echo "done: qemu-arm -L $SR $BIN $ROOT/rootfs"
