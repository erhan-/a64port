# Tutorial: recompiling a program with a64port

This walks from "I have an AArch64 Linux binary" to "it runs natively on my x86-64 PC" (or on a 32-bit ARM board),
in seven parts. The same emitted C builds for either host; only the compiler changes. Parts 1, 2 and 5 are exercised
by `tests/run-tests.sh`, and `tests/run-examples.sh` does the same for three real open-source programs, so they stay
true. Parts 3 and 6 describe the flow used for a large dynamically linked GUI program; they have not been re-run on a
different program yet, and the places where that matters are marked **[unverified for a second program]**.

Contents: [0 Before you start](#0-before-you-start) · [1 A static program](#1-a-static-program) ·
[2 Threads, signals, sockets](#2-threads-signals-sockets) · [3 A dynamically linked application](#3-a-dynamically-linked-application) ·
[4 Hooks for program-specific devices and files](#4-hooks-for-program-specific-devices-and-files) · [5 Hand leaves and profiling](#5-hand-leaves-and-profiling) ·
[6 A new version of the same program](#6-a-new-version-of-the-same-program) · [7 When something goes wrong](#7-when-something-goes-wrong)

## 0. Before you start

**Words used here**

* **guest**: the AArch64 program you are recompiling. **host**: the machine the result runs on.
* **module**: one ELF file (the executable, or one shared library). Each module is lifted separately into its own
  directory of C. Generated symbols are named after the module (`blk_<module>_<address>`).
* **emit**: lifting a module to C (`a64recomp`). **build**: compiling that C and linking it with the runtime.
* **leaf**: a function you replaced by hand-written C. **hooks**: the places where the runtime lets you fabricate
  devices or files a program expects (part 4).

**Tools.** `g++` (C++20), `clang`, `ld.lld`; `qemu-aarch64` to compare against; for ARM32 hosts `qemu-arm` and an
armhf glibc sysroot (`ARMHF_SYSROOT`); an AArch64 cross GCC with a static glibc (`aarch64-linux-gnu-gcc`) if you want
to compile C-library test programs. Build the driver once:

```sh
g++ -std=c++20 -O2 -Irepo/third_party/mk8-recomp repo/tools/recomp/a64recomp.cpp -o repo/tools/recomp/a64recomp
```

**Where things live.** `scripts/a64port-env.sh` derives every location (you rarely call it yourself; the scripts
source it). Put machine-specific values in `~/.config/a64port/env`, for example:

```sh
ARMHF_SYSROOT=/opt/armhf-sysroot
A64PORT_BASE=$HOME/a64port-work        # emitted trees, object caches, built binaries
```

Run the self-test first. If it passes, your toolchain is fine and anything that fails later is about your program:

```sh
tests/run-tests.sh
```

## 1. A static program

A static program has no dynamic linker and no libraries: one module, the simplest case. Here is a freestanding one
from `tests/guests/`:

```sh
clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld -Wl,-e,_start -Wl,--eh-frame-hdr -O1 \
      tests/guests/hand-leaf-test.c -o /tmp/prog-a64
qemu-aarch64 /tmp/prog-a64; echo "reference exit status: $?"
```

**Emit** (AArch64 to C). `--mod` is the module name, `--trusted` skips the self-modifying-code guard, `--callret` turns
guest calls into host calls:

```sh
repo/tools/recomp/a64recomp /tmp/prog-a64 /tmp/prog-emit --mod t --trusted --callret
ls /tmp/prog-emit            # recomp_runtime.{c,h}  src/*.c  a64port/layout.h  a64port/segments/*.bin
```

`src/` is the translated program, one C function per block. `a64port/segments/` are the program's own sections
(code and data) at their link addresses; the runtime maps them at start.

**Build** with the host compiler, then run. On an x86-64 PC the result is an ordinary x86-64 Linux program:

```sh
CC=clang repo/tools/recomp/build-guest.sh /tmp/prog-emit --out /tmp/prog-native --opt -O2
/tmp/prog-native; echo "recompiled exit status: $?"
```

The two exit statuses (and any output) must match. For a 32-bit ARM host the only change is the compiler (the
emitted C stays the same):

```sh
CC=scripts/armv7-cc repo/tools/recomp/build-guest.sh /tmp/prog-emit --out /tmp/prog-arm --opt -O2
qemu-arm -L "$ARMHF_SYSROOT" /tmp/prog-arm       # or copy it to the board
```

`scripts/armv7-cc` is clang pointed at the armhf sysroot (ARMv7-A, NEON, hard-float, Thumb-2).

Each built program loads its sections from `<program>.a64port/`, a link next to it that `build-guest.sh` creates
(or from `$A64PORT_ROOT/a64port`).

**Real programs.** `tests/run-examples.sh` downloads Lua, the SQLite shell and zlib at fixed versions (checked by
SHA-256), builds them for AArch64 with a static glibc, recompiles them for the host and for ARMv7, and compares every
line of output with `qemu-aarch64`. It is the quickest way to see the tool on code you did not write.

If it fails to emit: `a64recomp` with no arguments lists the main options. Unhandled instructions are reported at emit
time; `scripts/classify-unhandled.py` groups them.

## 2. Threads, signals, sockets

A program that uses the C library needs a static glibc to start with. Build one with the cross GCC and recompile it
exactly as in part 1:

```sh
aarch64-linux-gnu-gcc -static -O1 -pthread tests/guests/libc-threads-stress.c -o /tmp/threads-a64
repo/tools/recomp/a64recomp /tmp/threads-a64 /tmp/threads-emit --mod t --trusted --callret
CC=clang repo/tools/recomp/build-guest.sh /tmp/threads-emit --out /tmp/threads --opt -O2
/tmp/threads; echo $?                 # 7, as under: qemu-aarch64 /tmp/threads-a64
```

Everything the runtime provides for such programs is in `repo/tools/recomp/runtime/linux_syscalls.c`:

* **threads**: a `clone` becomes a host `pthread` running the child context; the thread id is the host thread id;
  `CLONE_CHILD_CLEARTID` and futexes make `pthread_join` and mutexes work.
* **signals**: a handler runs at the next syscall return of the thread that received the signal, on the guest stack,
  with a `siginfo`; a compute loop with no syscalls sees the signal late.
* **memory**: `mmap`/`munmap` reuse freed ranges, so threads (8 MB stacks) and buffers do not exhaust the arena.
* **the rest**: files, sockets, `epoll`, timers, pipes, `argv` and the environment. A syscall the runtime does not
  know returns `ENOSYS` (logged once); `A64PORT_HALT_UNIMPLEMENTED=1` halts instead, which is handy when you want the
  first missing syscall to stop the run.

Adding a syscall is a `case` in `a64port_svc_body()`: translate the arguments (a guest pointer is an offset into one
host allocation, so go through `GuestPtr`), call the host, return the result or `-errno`.

## 3. A dynamically linked application

Most real programs are dynamically linked. The guest's own `ld.so` and libraries are translated too and run
unchanged; the loader (`multi/host_loader.c`) only does what a kernel does: map the executable and the interpreter,
build the initial stack, jump to the interpreter. **[unverified for a second program]**

**3.1 Get the root file system.** Copy what the program needs at run time (the executable, `ld.so`, every library it
loads, and its data files) into `rootfs/` at the top of the checkout, keeping the original paths:

```
rootfs/usr/bin/myapp        rootfs/lib/ld-linux-aarch64.so.1        rootfs/usr/lib/libc.so.6 ...
```

`readelf -d` shows what an ELF needs (`NEEDED`); follow the chain until nothing new appears. Do not commit `rootfs/`.

**3.2 Write the profile.** Create `apps/myapp/profile.json`. Paths are relative to `rootfs/`:

```json
{
  "module": "myapp",
  "exe": "usr/bin/myapp",
  "interp": "lib/ld-linux-aarch64.so.1",
  "dso_dir": "usr/lib",
  "dsos": [["libc", "libc.so.6"], ["libm", "libm.so.6"], ["libstdcxx", "libstdc++.so.6"]]
}
```

`module` names the executable's module. Each `dsos` entry is a name you choose (it appears in symbols, keep it a plain
identifier) and the file name inside `dso_dir`. The list must be the complete closure of `NEEDED`.

**3.3 Make the module list**, then **emit every module**. The first step needs only the profile:

```sh
python3 scripts/pipeline/gen_mods.py --modules-only . "$A64PORT_BASE/a64port"      # writes multi/modules.txt
scripts/emit-gen.sh g1 --trusted --callret                                          # one directory per module
```

`emit-gen.sh <generation> <flags>` writes `$A64PORT_BASE/a64port/<module>-g1/` for the executable and
`libs-g1/<lib>/` for each library, all with the same flags (never mix flag sets inside one build). Re-running it only
rewrites units whose bytes changed, so object caches survive. The flag set that worked best for a large GUI program,
found by measuring, is: `--trusted --fn-single --vec-fast --fpx --fp-outline --flags-dce --fpx-batch --restrict --narrow-pc`.
Start with the short set and add flags one at a time; the emitter test scripts show what each one must preserve.

**3.4 Generate the module table.** This reads the ELFs and the emitted layouts and writes `multi/mods.h`:

```sh
A64PORT_EMIT_SUFFIX=-g1 python3 scripts/pipeline/gen_mods.py . "$A64PORT_BASE/a64port"
```

`A64PORT_EMIT_SUFFIX` must match the generation name (`g1` gives `-g1`). The table holds each module's segments, its
dynamic symbols and every relocation by name.

**3.5 Build.** For an x86-64 host:

```sh
A64PORT_EMIT_SUFFIX=-g1 BIN=/tmp/myapp-x86 scripts/build-x86.sh      # EXE_DIR defaults to <work>/<module>-g1
```

For a 32-bit ARM board, the flags below are the ones used for that program (`FASTMEM` maps guest memory
1:1 into the host, `MULTI_HOST` selects the loader; `STATIC=1` links the host image statically so the board's own libc
is not needed; `ORDER` is an optional symbol-order file from `scripts/hot-order.py` that packs the hot code together):

```sh
TAG=a17t2-O2-g1 A64PORT_EMIT_SUFFIX=-g1 EXTRA_CF="-DA64PORT_FASTMEM -DA64PORT_MULTI_HOST" \
STATIC=1 BIN=/tmp/myapp-armv7 scripts/build-armv7.sh
```

Needs `ld.lld` and `clang` on `PATH`, `ARMHF_SYSROOT`, and the emit tree of the executable (`EXE_DIR`, default
`$A64PORT_BASE/a64port/<module><suffix>`). A first full build of a large program takes tens of minutes; after that only
changed units are recompiled.

**3.6 Run.** The binary takes the root file system as its argument:

```sh
qemu-arm -L "$ARMHF_SYSROOT" /tmp/myapp-armv7 "$PWD/rootfs"        # or: scp to the board and run it there
```

**3.7 First-run triage.** A program of this size rarely starts on the first try. Work through these in order:

| Symptom | Likely cause | What to do |
|---|---|---|
| `unimplemented aarch64 syscall N` in the log | the runtime lacks that syscall | add it (part 2), or ignore if the program copes with `ENOSYS` |
| `no block at 0x...` | the guest jumped somewhere nothing was emitted for | check the module list is complete; re-emit with the flags you intended; a bad pointer is also possible |
| exits at once, nothing printed | the dynamic linker could not find a library | the profile's `dsos` is incomplete; `A64PORT_EXIT_TRACE=1` prints where it exits |
| hangs | a thread waits on a futex nobody wakes | see the thread notes in part 2; `A64PORT_SYSCALL_TIMELINE`/`A64PORT_WAIT_PROF` show what each thread waits on |
| aborts in `malloc`/`free` | memory corruption in the guest, or a runtime bug | run the original under `qemu-aarch64` with the same input: if it is fine there, the runtime is at fault |
| the program needs a device or file that does not exist | it expects its original hardware | part 4: fabricate it with a hook |

## 4. Hooks for program-specific devices and files

Some programs expect hardware or files the host does not have: a device node, a sysfs file, a helper program they
run with `execve`. The runtime calls a small set of hooks at those points, all defined in
`repo/tools/recomp/runtime/app_none.inc`. Each default returns "not mine, use the plain host operation":

* `device_open` / `device_is_fabricated`: return a file descriptor of your own for a path the host does not have;
  `device_read` / `device_readv` / `device_ioctl` / `device_ppoll` then serve it (`a64port_device_fdtype` tells the
  runtime which descriptors are yours);
* `guest_netif_ioctl` / `host_link_iface` / `guest_ifname_is_alias`: present a host network interface under another
  name;
* `sandbox_shell_command`: answer a shell probe the program runs with `execve` (enabled with `A64PORT_SHELL_STUB=1`).

To adapt the runtime to a program, edit `app_none.inc` (or keep your own copy of it in a fork) and give the hooks
bodies as the program demands them: run it, and each missing device or file shows up as an `ENOENT` or a hang
(`A64PORT_SYSCALL_ERR=1` lists each failing syscall once). Keep every fabrication behind a check that fails closed,
and return "not mine" for anything else; `tests/run-tests.sh` must still pass.

Per-program data: `apps/<app>/hand/vec_fast_blocks.txt` (blocks given the NEON fast path by `--vec-fast`, one hex
address per line), and an optional names file (`--names`, passed through `A64PORT_NAMES`) that gives readable names to
function addresses in the generated C.

## 5. Hand leaves and profiling

A leaf replaces the translated code of one block (or a whole function) with C you write. Use it on the few functions
that dominate the profile; everything else stays translated. A leaf must be checked against the code it replaces:
`scripts/verify-leaf.sh` emits the module twice, with and without the leaf, runs the block from the same random
register and memory states in both builds, and compares every register, the flags and memory. Random states do not
reach code behind narrow conditions (a length that must equal 64, a pointer that must hold a certain object); for
such functions write input generators that produce realistic states.

A worked example. A function that adds three numbers:

```sh
clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld -Wl,-e,_start -O1 tests/guests/leaf-fixture.c -o /tmp/fixture
ADD3=$(readelf -sW /tmp/fixture | awk '$8=="add3"{print $2; exit}' | sed 's/^0*//')      # its address
mkdir -p /tmp/leaves && cp repo/tools/recomp/hand/a64port_hand.h /tmp/leaves/
cat > /tmp/leaves/add3.c <<EOF
#include "a64port_hand.h"
A64PORT_LEAF(leaffix, 0x$ADD3) {          /* module name, guest address of the block */
    c->x[8] = c->x[1] + c->x[0];            /* the original code leaves a temporary in x8: keep it equal */
    c->x[0] = c->x[8] + c->x[2];
    c->pc = c->x[30];                         /* return to the caller */
}
EOF
scripts/verify-leaf.sh /tmp/fixture leaffix 0x$ADD3 --hand /tmp/leaves --iters 20      # prints PASS
```

Leave out the `x8` line and the verifier fails and names the register that differs. That is the point: a leaf has to
reproduce every register the original block writes that the rest of the program can observe, and the flags.

**Plugging leaves into the build.** Leaf files live in `apps/<app>/hand/`. The emitter takes them from `--hand DIR`
(repeatable), else the colon-separated `A64PORT_HAND_DIRS`, which `scripts/a64port-env.sh` points at
`<app dir>/hand`. Then re-emit and rebuild. The leaf macros, in `hand/a64port_hand.h`:

| Macro | Meaning |
|---|---|
| `A64PORT_LEAF(mod, 0xADDR)` | replaces the block body entirely |
| `A64PORT_LEAF_FILTER(mod, 0xADDR)` | runs first; return 1 when handled, 0 to run the translated body (slow paths) |
| `A64PORT_LEAF_FILTER_TO(mod, 0xADDR, 0xTARGET)` | as above, and continue at a fixed target inside the same function |

The emitter finds leaves by scanning for those macro names in the source text, so a leaf cannot hide in `#if 0`, and
**a leaf that matches no block fails the emit**: you cannot silently lose one. `scripts/verify-leaves.sh` verifies a
whole file of leaves.

**Finding what to replace.** Switch on the sampling profilers in the run you want to optimise:

```sh
A64PORT_PROF=1 myapp-armv7 rootfs 2> run.log        # guest-pc samples; rank them: scripts/guest-hot.py run.log
A64PORT_HPROF=1 A64PORT_HPROF_OUT=prof.bin myapp-armv7 rootfs
python3 scripts/hprof.py prof.bin myapp-armv7 --thread "worker"   # host cost per guest function and thread
```

`guest-hot.py` snaps sample addresses to function starts using the ELFs from your profile. Write a leaf only where one
function carries several percent of a thread, and measure again afterwards: a leaf that copies state in and out for
every call can be slower than the code it replaced.

## 6. A new version of the same program

A new build of an application moves every address. Some of what you have is version-independent, some is bound to one
build. Treat the bound parts as suspect until each has been checked.

| Artifact | Bound to a build? | What happens on a new version |
|---|---|---|
| core (`a64recomp`, runtime, loader, scripts) | no | unchanged |
| `profile.json` | the file names | update the library file names and paths if they changed |
| emitted trees, object caches, `mods.h` | yes | use a **new generation** (`emit-gen.sh g2`); never reuse a tree |
| leaves in `apps/<app>/hand/` | yes (addresses, struct offsets, instruction sequences) | the emit fails for any leaf that no longer matches a block; the rest may match the **wrong** code, so every leaf must be re-verified |
| `vec_fast_blocks.txt` | yes (block addresses) | re-derive from the profile |
| hook bodies (part 4) | partly | checks guarded by "bytes match" skip themselves; fabricated devices usually carry over |
| names file | yes | regenerate |

**Checklist** (the order matters: get a correct baseline first, optimise second):

1. **Record what you are porting.** Hash the new executable and libraries (`sha256sum`) into `apps/<app>/versions/<id>.sha256`
   so later you can tell which build a leaf or a patch was written for.
2. **Profile.** Update `profile.json` (library versions in file names are the usual change). Check the closure:
   `python3 scripts/pipeline/gen_mods.py --modules-only . "$A64PORT_BASE/a64port"` and compare `modules.txt` with `readelf -d`.
3. **Baseline without leaves.** Move `hand/` aside (or point `A64PORT_HAND_DIRS` at an empty directory), then emit a new generation,
   generate `mods.h`, build, run. The program must start and behave correctly, only slowly. Fix anything the application
   layer needs here (devices, files) before going further. If it does not run without leaves, no leaf will fix that.
4. **Re-establish a reference.** For each behaviour you will use as the gate, record it with the baseline build: a screenshot, an
   output file, a timing, a test script's result. Leaves are accepted only if the gate result is unchanged.
5. **Port the leaves one at a time**, hottest first (profile the new build, part 5). For each old leaf: find the function in
   the new binary (same strings, same call pattern, same neighbours, or the symbol if there is one); take the old leaf
   as the specification; adjust addresses and offsets; run `scripts/verify-leaf.sh`; only then add it to the build.
   Reject a leaf you cannot verify rather than shipping it on trust.
6. **Port the hook bodies** (part 4) the same way; delete the ones you do not need.
7. **Gate the whole build** with your acceptance tests, on the target hardware if it matters (timing, audio, frame rate).
8. **Keep both builds.** Name binaries after the build number and keep the previous working one deployed until the new one passes.

A useful signal of how big the job is: emit the new version **with the old leaves** and count how many the emitter
rejects. Those are the functions that moved or changed; the others still need re-verification, because "an address
exists" does not mean "it is the same function".

## 7. When something goes wrong

| Where | Problem | Check |
|---|---|---|
| emit | `unhandled` instructions | `scripts/classify-unhandled.py`; the emitter fuzzer `scripts/emitter-fuzz.py` compares single instructions against qemu |
| emit | "leaf matches no block" | address or module name wrong; `readelf -sW`, and the module name must be the one in `--mod` |
| build | `recomp_runtime.h` not found | a unit is compiled without the emit directory on the include path: run through the scripts |
| build | `ld.lld`/`invalid linker name` | put `ld.lld` on `PATH` |
| build | stale objects after a header edit | the cache keys on file times and ignores header edits: delete the affected object directory |
| run | wrong output, no crash | switch to the simplest flag set, then add flags back one at a time; compare against `qemu-aarch64` |
| run | a thread never wakes | `A64PORT_SYSCALL_TIMELINE='*:0:2'` lists every thread's syscalls for two seconds; a `futex` with no waker is the usual cause |
| ARMv7 | works on x86-64, not on the board | 32-bit hosts have a smaller address space (the loader builds with a 32-bit layout: `A64PORT_ILP32_HOST`); check the arena size (`A64PORT_ARENA_TOP`, a compile-time setting of the loader) and the thread stack size (`A64PORT_HOST_STACK_KB`) |

Every `A64PORT_*` switch above is read in `host_loader.c`, `linux_syscalls.c` or the scripts; `grep -rn A64PORT_ repo scripts`
shows the full list with its context.
