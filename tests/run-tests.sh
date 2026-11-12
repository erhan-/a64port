#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# tests/run-tests.sh — recompile AArch64 test programs with THIS tree's own tools and compare each with qemu-aarch64
# (exit status + stdout md5), for the build host and, when qemu-arm and an armhf sysroot are present, as ARMv7 builds.
#
#   tests/run-tests.sh                run everything
#   A64PORT_TEST_DIR=/tmp/t tests/run-tests.sh   keep the work files there (emitted C, binaries, logs)
#
# Needs: g++ (C++20), clang, ld.lld, qemu-aarch64; for the C-library programs an AArch64 cross GCC with a static glibc
# (aarch64-linux-gnu-gcc); for the ARMv7 part qemu-arm and ARMHF_SYSROOT (see scripts/a64port-env.sh).  A missing tool
# prints SKIP for that part; it is not a failure.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for t in g++ clang ld.lld qemu-aarch64; do command -v $t >/dev/null || { echo "SKIP: $t not found"; exit 0; }; done
if [ -n "${A64PORT_TEST_DIR:-}" ]; then W=$A64PORT_TEST_DIR; mkdir -p "$W"; else W=$(mktemp -d); trap 'rm -rf "$W"' EXIT; fi
fail() { echo "FAIL: $*" >&2; exit 1; }; ok() { echo "ok: $*"; }
DRV=$ROOT/repo/tools/recomp/a64recomp; BG=$ROOT/repo/tools/recomp/build-guest.sh; SRC=$ROOT/tests/guests

# the driver, from this tree's sources
if [ ! -x "$DRV" ]; then
  g++ -std=c++20 -O1 -I"$ROOT/repo/third_party/mk8-recomp" "$ROOT/repo/tools/recomp/a64recomp.cpp" -o "$DRV" 2>"$W/gpp.log" \
      || { tail -5 "$W/gpp.log"; fail "the driver does not build"; }
fi
ok "driver ready ($DRV)"

# the programs: freestanding ones with clang, C-library ones with the cross GCC (static glibc)
export RB_TEST_VAR=hello
ARGS_args="alpha beta 3"
run_ref() { local r=0 out; out=$(cd "$W" && echo "input" | timeout 60 "$@" 2>/dev/null) || r=$?; printf '%s %s' "$r" "$(printf '%s' "$out" | md5sum | cut -c1-12)"; }
mk() { clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld -Wl,-e,_start -Wl,--eh-frame-hdr -O1 "$SRC/$2" -o "$W/$1"; }
mk leaf hand-leaf-test.c; mk chain chain-bench.c; mk grouping grouping-test.c; mk fp fp-bench.c; mk cat cat-a64.c
cp "$SRC/data.txt" "$W/data.txt"            # cat-a64 opens data.txt in the working directory
GUESTS="leaf chain grouping fp cat"
XCC=${XCC:-aarch64-linux-gnu-gcc}
if command -v "$XCC" >/dev/null; then
  add() { local name=$1 src=$2; shift 2; "$XCC" -static -O1 "$@" "$SRC/$src" -o "$W/$name" && GUESTS="$GUESTS $name"; }
  add hello hello.c                     # stdio over a static glibc
  add sockets libc-sockets.c -lm        # files, mmap, TCP over loopback, poll/epoll, timerfd
  add threads libc-threads.c -pthread   # pthread_create/join, mutex + condvar
  add threads-stress libc-threads-stress.c -pthread   # contention, atomics, barrier, TSD, nested/detached, exit() from a thread
  add signals libc-signals.c -pthread   # handlers: SA_SIGINFO, sigqueue, masks, nesting, pthread_kill, EINTR
  add args libc-args.c                  # the real command line and environment; ENOSYS for an unknown syscall
else
  echo "SKIP: C-library programs (no $XCC)"
fi

args_of() { eval echo \${ARGS_${1//-/_}:-}; }
for g in $GUESTS; do
  ref=$(run_ref qemu-aarch64 "$W/$g" $(args_of "$g"))
  "$DRV" "$W/$g" "$W/$g-e" --mod t --trusted --callret >"$W/$g-emit.log" 2>&1 || { tail -5 "$W/$g-emit.log"; fail "$g: emit"; }
  CC=clang "$BG" "$W/$g-e" --out "$W/$g-bin" --opt -O2 --jobs "$(nproc)" >"$W/$g-build.log" 2>&1 || { tail -15 "$W/$g-build.log"; fail "$g: build"; }
  got=$(run_ref "$W/$g-bin" $(args_of "$g"))
  [ "$got" = "$ref" ] || fail "$g: recompiled '$got' != qemu '$ref'"
  ok "$g: native build == qemu ('$ref')"
done

# leaf verification (docs/TUTORIAL.md, part 5): a correct hand leaf passes, a wrong one is rejected and the report names the register
if [ -x "$ROOT/scripts/verify-leaf.sh" ] && command -v readelf >/dev/null; then
  clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld -Wl,-e,_start -O1 "$SRC/leaf-fixture.c" -o "$W/fixture"
  ADD3=$(readelf -sW "$W/fixture" | awk '$8=="add3"{print $2; exit}' | sed 's/^0*//')
  [ -n "$ADD3" ] || fail "leaf walkthrough: add3 not found in the fixture"
  mkdir -p "$W/leaves"; cp "$ROOT/repo/tools/recomp/hand/a64port_hand.h" "$W/leaves/"
  cat > "$W/leaves/add3.c" <<LEAF
#include "a64port_hand.h"
A64PORT_LEAF(leaffix, 0x$ADD3) {
    c->x[8] = c->x[1] + c->x[0];
    c->x[0] = c->x[8] + c->x[2];
    c->pc = c->x[30];
}
LEAF
  "$ROOT/scripts/verify-leaf.sh" "$W/fixture" leaffix "0x$ADD3" --hand "$W/leaves" --iters 20 >"$W/leaf-good.log" 2>&1 \
      || { tail -8 "$W/leaf-good.log"; fail "leaf walkthrough: the correct leaf was rejected"; }
  sed -i '/c->x\[8\] = /d; s/c->x\[0\] = c->x\[8\] + c->x\[2\];/c->x[0] = c->x[1] + c->x[0] + c->x[2];/' "$W/leaves/add3.c"
  if "$ROOT/scripts/verify-leaf.sh" "$W/fixture" leaffix "0x$ADD3" --hand "$W/leaves" --iters 20 >"$W/leaf-bad.log" 2>&1; then
    fail "leaf walkthrough: a leaf that drops x8 was accepted"
  fi
  grep -q ' r8 ' "$W/leaf-bad.log" || fail "leaf walkthrough: the rejection did not name r8"
  ok "leaf walkthrough: a correct leaf passes, one that drops x8 is rejected (r8)"
else
  echo "SKIP: leaf walkthrough (scripts/verify-leaf.sh or readelf missing)"
fi

# the same programs for a 32-bit ARM host (ARMv7-A + NEON, hard-float)
. "$ROOT/scripts/a64port-env.sh"; export ARMHF_SYSROOT
if command -v qemu-arm >/dev/null && [ -d "$ARMHF_SYSROOT/usr/lib" ]; then
  for g in $GUESTS; do
    ref=$(run_ref qemu-aarch64 "$W/$g" $(args_of "$g"))
    CC="$ROOT/scripts/armv7-cc" "$BG" "$W/$g-e" --out "$W/$g-arm" --opt -O2 --jobs "$(nproc)" >"$W/$g-armbuild.log" 2>&1 \
        || { tail -15 "$W/$g-armbuild.log"; fail "$g: ARMv7 build"; }
    got=$(run_ref qemu-arm -L "$ARMHF_SYSROOT" "$W/$g-arm" $(args_of "$g"))
    [ "$got" = "$ref" ] || fail "$g: ARMv7 '$got' != qemu-aarch64 '$ref'"
    ok "$g: ARMv7 build == qemu-aarch64 ('$ref')"
  done
else
  echo "SKIP: ARMv7 part (needs qemu-arm and an armhf sysroot: set ARMHF_SYSROOT)"
fi
echo "PASS: tests"
