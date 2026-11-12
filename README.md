# a64port

A static recompiler for 64-bit ARM (AArch64) Linux programs. It turns an AArch64 ELF into portable C, and that C is
built with an ordinary compiler for the machine you want to run on:

| Host | Result |
|---|---|
| **x86-64 Linux** (a normal PC) | an x86-64 program: run AArch64 Linux software on a PC without an emulator |
| **32-bit ARM Linux** (ARMv7-A + NEON, hard-float) | an ARMv7 program: run 64-bit ARM software on older 32-bit boards |
| AArch64 Linux | a native rebuild of the same program |

The AArch64-to-C step happens once; the same C builds for every host. There is no interpreter and no JIT at run
time: the result is native code.

It grew out of one large, multi-threaded GUI application, which is why the focus is on real programs: threads,
signals, sockets, dynamic linking, and hand-written replacements ("leaves") for hot code.

**Bring your own binary.** This repository contains no program, firmware or library of anyone else's. You supply the
AArch64 program you are entitled to recompile, and for a dynamically linked one the libraries it loads. The only
downloads are the open-source test programs fetched by `tests/run-examples.sh`.

## How it works

```
AArch64 ELF ──a64recomp──▶ C project ──build-guest.sh / build-*.sh──▶ native program
 (+ libraries)   lift per     one directory     compiler + runtime
                 function     per module        (Linux syscalls, threads, signals)
```

* `repo/tools/recomp/a64recomp` lifts an ELF to C, one function (or block) at a time.
* `repo/tools/recomp/runtime/` is the Linux runtime the translated code runs on: syscalls, futexes, threads, signals,
  memory. `repo/tools/recomp/multi/host_loader.c` is the loader for dynamically linked programs: it maps the
  executable and the dynamic linker, and the guest's own `ld.so` does the rest, as on a real system.
* **Hand leaves** replace translated code for one function with C you wrote and verified
  (`repo/tools/recomp/hand/`, the SDK header; leaves live with the application).
* **Hooks** (`repo/tools/recomp/runtime/app_none.inc`) let you fabricate device nodes, files or shell probes a
  program expects from its original system (see [docs/TUTORIAL.md](docs/TUTORIAL.md), part 4).

## Status

Verified against `qemu-aarch64` as the reference (exit status and complete output must match), both as x86-64 builds
and as ARMv7 builds under `qemu-arm`, by `tests/run-tests.sh` and `tests/run-examples.sh`:

| Area | Covered |
|---|---|
| Programs | freestanding programs and static-glibc programs |
| Real software | Lua 5.4.6 (interpreter running a test script), the SQLite 3.46.1 shell (file database, transactions, window functions, JSON), zlib 1.3.1 (`minigzip` round trips at three levels) |
| OS surface | files, `mmap`/`mprotect`, TCP over loopback, `poll`/`epoll`, timers, pipes, `setjmp`, `qsort`, float `printf` |
| Threads | `pthread_create`/`join`, mutex, condvar, barrier, thread-local storage, atomics, nested and detached threads, `exit()` from a thread |
| Signals | handlers with `SA_SIGINFO`, `sigqueue`, masks, nesting, `pthread_kill`, `EINTR`, `alarm` |
| Command line | real `argv` and environment; unknown syscalls return `ENOSYS` |

Known limits: build with clang (the runtime does not compile with GCC yet: it uses `__atomic_*_n` on a `double` in a
diagnostic path); a signal is delivered at a syscall boundary, so a program in a pure compute loop sees it late;
synchronous faults (`SIGSEGV`), `sigaltstack` and handlers that edit the saved context are not supported. Only Linux
user-space programs are handled, and the guest's own C library is translated, never replaced by the host's.

## Quick start

Needs: `g++` (C++20), `clang`, `ld.lld`, and `qemu-aarch64` for the tests. For ARMv7 builds also `qemu-arm` and an
armhf sysroot (`ARMHF_SYSROOT`, see `scripts/a64port-env.sh`). The real-program tests also need `curl` and an AArch64
cross GCC with a static glibc (`aarch64-linux-gnu-gcc`).

```sh
g++ -std=c++20 -O2 -Irepo/third_party/mk8-recomp repo/tools/recomp/a64recomp.cpp -o repo/tools/recomp/a64recomp
tests/run-tests.sh                                  # builds and checks the test programs against qemu
tests/run-examples.sh                               # the same for Lua, SQLite and zlib (downloads their sources)
```

Recompile a program of your own for your x86-64 PC (a static AArch64 program here; a dynamically linked application
is in the tutorial):

```sh
repo/tools/recomp/a64recomp my-program-a64 /tmp/emit --mod t --trusted --callret     # AArch64 -> C
mkdir -p /tmp/my-program
CC=clang repo/tools/recomp/build-guest.sh /tmp/emit --out /tmp/my-program/prog --opt -O2   # C -> x86-64
/tmp/my-program/prog args...   # same exit status and output as: qemu-aarch64 my-program-a64 args...
```

For a 32-bit ARM board, build the same `/tmp/emit` with `CC=scripts/armv7-cc`. Each program loads its sections from
`<program>.a64port/`, a link next to it that `build-guest.sh` creates.

## Repository layout

| Path | What |
|---|---|
| `repo/tools/recomp/` | the driver (`a64recomp.cpp`), `build-guest.sh`, the runtime, the loader, the leaf SDK |
| `repo/third_party/mk8-recomp/` | the AArch64-to-C engine we build on (GPL, patched; see its `PROVENANCE.md`) |
| `scripts/` | build and emit scripts, leaf verification (`verify-leaf.sh`), profiling (`hprof.py`), `armv7-cc` |
| `scripts/pipeline/` | the module-table generator (`gen_mods.py`) and incremental re-emit helpers |
| `apps/<app>/` | everything specific to one program: `profile.json` and `hand/` leaves (you create it) |
| `tests/` | `run-tests.sh` with the test programs in `tests/guests/`, and `run-examples.sh` with the real-program workloads in `tests/examples/` |
| `docs/` | the tutorial |

## Applications

A program that needs more than the generic runtime lives in `apps/<app>/`:

* `profile.json` names the executable, the dynamic linker and every library inside your root file system, and the module
  name used in generated code.
* `hand/` holds leaves (C files marked with `A64PORT_LEAF…`) and an optional `vec_fast_blocks.txt`.
* Device nodes, files or shell probes the program expects from its original system are fabricated with the hooks in
  `repo/tools/recomp/runtime/app_none.inc` (tutorial, part 4).

The application this project was developed with is not included here.

## Configuration

Locations come from `scripts/a64port-env.sh`; machine-specific values go in `~/.config/a64port/env`.

| Variable | Meaning |
|---|---|
| `A64PORT_BASE` | work directory for emitted trees and build caches (default `~/a64port-work`) |
| `ARMHF_SYSROOT` | armhf glibc sysroot for ARMv7 builds |
| `A64PORT_APP_DIR` | the application directory (default: the only directory under `apps/`) |
| `A64PORT_PROFILE` | profile file, if not `<app dir>/profile.json` |
| `A64PORT_HAND_DIRS` | colon-separated leaf directories for the emitter (else `<app dir>/hand`) |
| `A64PORT_HALT_UNIMPLEMENTED=1` | halt on an unknown syscall instead of returning `ENOSYS` |

## Licence

GPL-2.0-or-later (`COPYING`, `NOTICE`). `repo/third_party/mk8-recomp/arm64_to_c.h` comes from the suyu project
(GPL-2.0-or-later). Not affiliated with any hardware or software vendor.
