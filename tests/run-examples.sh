#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# tests/run-examples.sh - recompile three real open-source AArch64 programs (Lua 5.4, the SQLite shell, zlib's
# minigzip) with THIS tree's tools and compare each with qemu-aarch64 (exit status + full stdout), for the build host
# and, when qemu-arm and an armhf sysroot are present, as ARMv7 builds.
#
#   tests/run-examples.sh                      download (once), build and compare everything
#   A64PORT_TEST_DIR=/tmp/ex tests/run-examples.sh   keep sources and work files there
#
# Needs: curl, sha256sum, unzip, g++ (C++20), clang, ld.lld, qemu-aarch64, an AArch64 cross GCC with a static glibc
# (aarch64-linux-gnu-gcc); for the ARMv7 part qemu-arm and ARMHF_SYSROOT (see scripts/a64port-env.sh).  The sources
# are downloaded from their official sites and checked against the SHA-256 sums below; nothing is redistributed.
# A full run takes several minutes per program and target.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
EX=$ROOT/tests/examples
for t in curl sha256sum unzip g++ clang ld.lld qemu-aarch64; do command -v $t >/dev/null || { echo "SKIP: $t not found"; exit 0; }; done
XCC=${XCC:-aarch64-linux-gnu-gcc}
command -v "$XCC" >/dev/null || { echo "SKIP: no AArch64 cross compiler ($XCC)"; exit 0; }
W=${A64PORT_TEST_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/a64port-examples}; mkdir -p "$W/src"
fail() { echo "FAIL: $*" >&2; exit 1; }; ok() { echo "ok: $*"; }
DRV=$ROOT/repo/tools/recomp/a64recomp; BG=$ROOT/repo/tools/recomp/build-guest.sh

# Pinned sources (URL, SHA-256).
# fetch SHA256 URL [MIRROR...]: tries each URL (with retries) until the file is there; the checksum decides.
fetch() {
  local sum=$1; shift; local f="$W/src/${1##*/}" u
  for u in "$@"; do
    [ -s "$f" ] && break
    curl -sfL --retry 3 --retry-delay 5 --max-time 300 -o "$f" "$u" || rm -f "$f"
  done
  [ -s "$f" ] || fail "download ${f##*/} (tried: $*)"
  echo "$sum  $f" | sha256sum -c --quiet - || { rm -f "$f"; fail "checksum of ${f##*/}"; }
}
fetch 7d5ea1b9cb6aa0b59ca3dde1c6adcb57ef83a1ba8e5432c0ecd06bf439b3ad88 https://www.lua.org/ftp/lua-5.4.6.tar.gz \
      https://www.tecgraf.puc-rio.br/lua/mirror/ftp/lua-5.4.6.tar.gz
fetch 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 https://zlib.net/fossils/zlib-1.3.1.tar.gz \
      https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
fetch 77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784 https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip
ok "sources present and verified"

# The driver, from this tree's sources.
if [ ! -x "$DRV" ]; then
  g++ -std=c++20 -O1 -I"$ROOT/repo/third_party/mk8-recomp" "$ROOT/repo/tools/recomp/a64recomp.cpp" -o "$DRV" 2>"$W/gpp.log" \
      || { tail -5 "$W/gpp.log"; fail "the driver does not build"; }
fi

# The AArch64 programs (static glibc).
B=$W/build; rm -rf "$B"; mkdir -p "$B"; cd "$B"
tar xzf "$W/src/lua-5.4.6.tar.gz"; tar xzf "$W/src/zlib-1.3.1.tar.gz"; unzip -q "$W/src/sqlite-amalgamation-3460100.zip"
L=lua-5.4.6/src
"$XCC" -static -O2 -std=gnu99 -DLUA_USE_POSIX -I$L $(ls $L/*.c | grep -vE '/(lua|luac)\.c$') $L/lua.c -o lua -lm
S=sqlite-amalgamation-3460100
"$XCC" -static -O2 -DSQLITE_OMIT_LOAD_EXTENSION -I$S $S/sqlite3.c $S/shell.c -o sqlite3 -lpthread -lm
Z=zlib-1.3.1
"$XCC" -static -O2 -DHAVE_UNISTD_H -I$Z \
    $Z/{adler32,crc32,deflate,infback,inffast,inflate,inftrees,trees,zutil,compress,uncompr,gzclose,gzlib,gzread,gzwrite}.c \
    $Z/test/minigzip.c -o minigzip
ok "AArch64 programs built"

# One workload per program; "$@" is the command prefix that runs the program (e.g. qemu-aarch64 ./lua).
# stderr is dropped: the runtime prints its own diagnostics there.
run_lua()    { local r=0; "$@" "$EX/test.lua" 2>/dev/null || r=$?; echo "exit=$r"; }
run_sqlite() { local r=0; rm -f t.db; "$@" t.db < "$EX/test.sql" 2>/dev/null || r=$?; echo "exit=$r"; rm -f t.db; }
run_zlib()   { local r=0; sh "$EX/zlib-roundtrip.sh" "$@" 2>/dev/null || r=$?; echo "exit=$r"; }
workload() { case $1 in lua) echo run_lua;; sqlite3) echo run_sqlite;; minigzip) echo run_zlib;; esac; }

PROGS="lua sqlite3 minigzip"
for p in $PROGS; do
  $(workload $p) qemu-aarch64 "$B/$p" > "$B/$p.ref"
  "$DRV" "$B/$p" "$B/$p-e" --mod t --trusted --callret > "$B/$p-emit.log" 2>&1 || { tail -5 "$B/$p-emit.log"; fail "$p: emit"; }
  # Each binary in its own directory: a translated program loads its segments from a64port/ beside it.
  mkdir -p "$B/host-$p"
  CC=clang "$BG" "$B/$p-e" --out "$B/host-$p/$p" --opt -O2 --jobs "$(nproc)" > "$B/$p-build.log" 2>&1 \
      || { tail -15 "$B/$p-build.log"; fail "$p: build"; }
  $(workload $p) "$B/host-$p/$p" > "$B/$p.host"
  cmp -s "$B/$p.ref" "$B/$p.host" || { diff "$B/$p.ref" "$B/$p.host" | head -20; fail "$p: native build differs from qemu-aarch64"; }
  ok "$p: native build == qemu-aarch64 ($(wc -l < "$B/$p.ref") lines, $(tail -1 "$B/$p.ref"))"
done

. "$ROOT/scripts/a64port-env.sh"; export ARMHF_SYSROOT
if command -v qemu-arm >/dev/null && [ -d "${ARMHF_SYSROOT:-/nonexistent}/usr/lib" ]; then
  for p in $PROGS; do
    mkdir -p "$B/arm-$p"
    CC="$ROOT/scripts/armv7-cc" "$BG" "$B/$p-e" --out "$B/arm-$p/$p" --opt -O2 --jobs "$(nproc)" > "$B/$p-armbuild.log" 2>&1 \
        || { tail -15 "$B/$p-armbuild.log"; fail "$p: ARMv7 build"; }
    $(workload $p) qemu-arm -L "$ARMHF_SYSROOT" "$B/arm-$p/$p" > "$B/$p.arm"
    cmp -s "$B/$p.ref" "$B/$p.arm" || { diff "$B/$p.ref" "$B/$p.arm" | head -20; fail "$p: ARMv7 build differs from qemu-aarch64"; }
    ok "$p: ARMv7 build == qemu-aarch64"
  done
else
  echo "SKIP: ARMv7 part (needs qemu-arm and an armhf sysroot: set ARMHF_SYSROOT)"
fi
echo "PASS: examples"
