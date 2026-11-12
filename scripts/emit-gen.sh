#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# emit-gen.sh <gen> [a64recomp flags...] — emit EVERY module into a new generation:
#   $WORK/<exe module>-<gen>  and  $WORK/libs-<gen>/<mod>
# with one flag set and one hand dir, so the whole binary is one consistent
# emission (a --callret GuestContext differs from the old one: never mix).
# Incremental: a unit whose bytes did not change keeps its mtime (object cache).
#
#   HAND=<dir>   hand leaves for every module (default: $WORK/hand-armv7-merged if it exists, else the leaf
#                directories the emitter finds: A64PORT_HAND_DIRS = <app dir>/hand)
#   JOBS=<n>     modules emitted at once (default 8)
#
#   scripts/emit-gen.sh v3 --trusted --callret --vec-fast --fpx
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")/a64port-env.sh"
WORK=${A64PORT_WORK:-$A64PORT_BASE/a64port}
DRV=$ROOT/repo/tools/recomp/a64recomp
GEN=${1:?usage: emit-gen.sh <gen> [flags...]}; shift
FLAGS=("$@")
# Leaves: HAND=<dir> forces one directory for every module; else the merged set ($WORK/hand-armv7-merged) when this
# work tree has one; else the emitter's own search (A64PORT_HAND_DIRS, which scripts/a64port-env.sh points at <app dir>/hand).
HAND=${HAND:-}
[ -z "$HAND" ] && [ -d "$WORK/hand-armv7-merged" ] && HAND=$WORK/hand-armv7-merged
HANDOPT=${HAND:+--hand $HAND}
JOBS=${JOBS:-8}
# an optional symbol-names file for the executable (--names): A64PORT_NAMES, else <app dir>/evidence/<module>-names.tsv
NAMES_FILE="${A64PORT_NAMES:-${A64PORT_NAMES_APP:-${A64PORT_APP_DIR:+$A64PORT_APP_DIR/evidence/$A64PORT_EXE_MOD-names.tsv}}}"
[ -z "$HAND" ] || [ -d "$HAND" ] || { echo "no hand dir $HAND" >&2; exit 1; }

emit_one() {   # mod rel
  local mod=$1 rel=$2 out tmp
  if [ "$mod" = "$A64PORT_EXE_MOD" ]; then out=$WORK/$A64PORT_EXE_MOD-$GEN; else out=$WORK/libs-$GEN/$mod; fi
  tmp=$(mktemp -d "$WORK/.emit-$mod-XXXX")
  local names=()
  [ "$mod" = "$A64PORT_EXE_MOD" ] && [ -f "$NAMES_FILE" ] && names=(--names "$NAMES_FILE")
  if ! "$DRV" "$ROOT/$rel" "$tmp" --mod "$mod" "${FLAGS[@]}" $HANDOPT "${names[@]}" \
        >"$tmp.log" 2>&1; then
    echo "  $mod: EMIT FAILED"; tail -5 "$tmp.log"; rm -rf "$tmp"; return 1
  fi
  mkdir -p "$out"
  local chg=0 same=0 rel2
  while IFS= read -r -d '' f; do
    rel2=${f#"$tmp"/}
    if [ -e "$out/$rel2" ] && cmp -s "$f" "$out/$rel2"; then same=$((same + 1))
    else mkdir -p "$(dirname "$out/$rel2")"; cp "$f" "$out/$rel2"; chg=$((chg + 1)); fi
  done < <(find "$tmp" -type f -print0)
  cp "$tmp.log" "$out/emit.err"
  rm -rf "$tmp" "$tmp.log"
  printf '  %-12s %4d changed %5d unchanged\n' "$mod" "$chg" "$same"
}
export -f emit_one
export WORK GEN DRV ROOT HAND HANDOPT
export FLAGS_STR="${FLAGS[*]}"
t0=$SECONDS
echo "=== emit generation $GEN: ${FLAGS[*]} (hand: $HAND) ==="
# the executable first (the long one), then the libraries, JOBS at a time
rc=0
cut -f1,2 "$WORK/multi/modules.txt" | grep -v '^$' | \
  xargs -P "$JOBS" -L1 bash -c 'read -r -a FLAGS <<< "$FLAGS_STR"; emit_one "$0" "$1"' || rc=1
echo "=== done in $((SECONDS - t0)) s (rc=$rc) ==="
exit $rc
