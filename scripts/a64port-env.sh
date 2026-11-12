# SPDX-License-Identifier: GPL-2.0-or-later
# a64port-env.sh - locations shared by the build scripts.  Sourced, never run.
#   A64PORT_HOME     this checkout (derived from the script's own location)
#   A64PORT_BASE     where the work trees, toolchain and caches live (default ~/a64port-work)
#   ARMHF_SYSROOT   armhf sysroot: glibc headers + libs (default $A64PORT_BASE/armhf-sysroot)
# Machine-specific values go in ${A64PORT_ENV:-~/.config/a64port/env} (plain shell assignments), which is read first;
# anything already in the environment wins.
_rb_env=${A64PORT_ENV:-$HOME/.config/a64port/env}
[ -f "$_rb_env" ] && . "$_rb_env"
unset _rb_env
A64PORT_HOME=${A64PORT_HOME:-$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)}
A64PORT_BASE=${A64PORT_BASE:-$HOME/a64port-work}
ARMHF_SYSROOT=${ARMHF_SYSROOT:-$A64PORT_BASE/armhf-sysroot}
# The application being recompiled: apps/<app>/ holds its profile.json (module list) and hand/ (leaf plug-ins,
# see repo/tools/recomp/hand/a64port_hand.h for the SDK).  The emitter reads A64PORT_HAND_DIRS (colon list) when no
# --hand is given.
if [ -z "${A64PORT_APP_DIR:-}" ]; then          # default: the only directory under apps/, if there is exactly one
    _rb_apps=()                                 # (never `set --`: this file is sourced and must not touch "$@")
    for _rb_d in "$A64PORT_HOME"/apps/*/; do [ -d "$_rb_d" ] && _rb_apps+=("${_rb_d%/}"); done
    if [ ${#_rb_apps[@]} -eq 1 ]; then A64PORT_APP_DIR=${_rb_apps[0]}; else A64PORT_APP_DIR=; fi
    unset _rb_apps _rb_d
fi
[ -d "$A64PORT_APP_DIR/hand" ] && export A64PORT_HAND_DIRS=${A64PORT_HAND_DIRS-$A64PORT_APP_DIR/hand}
export A64PORT_APP_DIR
# The main executable's module name (profile.json "module", default exe): emit/work directories, --mod and mods.h use it.
if [ -z "${A64PORT_EXE_MOD:-}" ]; then
    A64PORT_EXE_MOD=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("module", "exe"))' \
                     "${A64PORT_PROFILE:-$A64PORT_APP_DIR/profile.json}" 2>/dev/null) || A64PORT_EXE_MOD=exe
fi
export A64PORT_EXE_MOD
# The application's runtime layer: apps/<app>/runtime/app_layer/*.inc is included by the runtime and the host when this
# directory is on the include path (without it runtime/app_none.inc makes a generic guest).
A64PORT_APP_INC=
[ -d "$A64PORT_APP_DIR/runtime/app_layer" ] && [ "${A64PORT_APP_NONE:-0}" = 0 ] && A64PORT_APP_INC="-I$A64PORT_APP_DIR/runtime"
export A64PORT_APP_INC
