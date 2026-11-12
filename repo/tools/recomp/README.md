# repo/tools/recomp: the recompiler

```
AArch64 ELF ──a64recomp──▶ C project ──build-guest.sh (clang / armv7-cc)──▶ x86-64 or ARMv7 program
```

| File | What |
|---|---|
| `a64recomp.cpp` | the driver: finds the code (all executable sections, `.eh_frame` function starts, dynamic symbols, switch tables, relocations and code pointers in data), translates it with the engine in `repo/third_party/mk8-recomp/`, and writes one C project per module |
| `build-guest.sh` | compiles an emitted project for the host the compiler targets: `CC=clang` for the machine you are on (x86-64), `CC=scripts/armv7-cc` for 32-bit ARM |
| `runtime/linux_syscalls.c` | the Linux runtime for a single-module (static) program: AArch64 system calls mapped field by field onto the host's, threads, futexes, signals, memory |
| `runtime/app_none.inc` | hooks for devices or files a program expects from its original system (docs/TUTORIAL.md, part 4) |
| `runtime/neon_structs.h`, `runtime/armv7-builtins.c` | NEON structure loads/stores; compiler-runtime helpers for a static ARMv7 link |
| `multi/host_loader.c` | the loader for dynamically linked programs: maps the executable and the guest's own `ld.so` into one arena and lets the translated `ld.so` link everything else |
| `hand/a64port_hand.h` | the SDK for hand-written replacement code ("leaves") |

## Emitting

```sh
g++ -std=c++20 -O2 -Irepo/third_party/mk8-recomp repo/tools/recomp/a64recomp.cpp -o repo/tools/recomp/a64recomp
repo/tools/recomp/a64recomp prog-a64 out/ --mod t --trusted --callret        # emit
repo/tools/recomp/a64recomp prog-a64 --stats-only --coverage                 # coverage only, writes nothing
```

Every unhandled instruction is reported at emit time and stops the program if it is reached: there is no JIT to fall
back on. With `A64PORT_GAP_DUMP=<base>` the runtime writes the addresses that execution reached but discovery missed
to `<base>.roots`; pass that file back with `--roots` on the next emit.

## Options

All default off; the default output is the engine's per-block shape, which is the easiest to verify.

| Option | Effect |
|---|---|
| `--trusted` | no per-block check against self-modifying code (for programs that never rewrite their code) |
| `--chain` | direct branches become C tail calls instead of returns to the dispatcher |
| `--callret` | guest calls become host calls; implies `--chain` |
| `--functions`, `--fn-single` | one C function per guest function; `--fn-single` gives each a single entry so the compiler can keep guest registers in host registers |
| `--locals`, `--locals-changed` | guest registers in C locals inside a function |
| `--flags-dce` | drop condition-flag computations no instruction reads |
| `--fpx`, `--fpx-batch`, `--fp-outline` | native floating point kept only when provably equal to the exact result; shared exact bodies |
| `--restrict`, `--narrow-pc` | aliasing and 32-bit address hints for the host compiler |
| `--vec-fast` | 128-bit vector types for the blocks listed in `vec_fast_blocks.txt` |
| `--fastmem`, `--guard-gen` | page-table memory helpers; verify code guards once per code generation |
| `--hand DIR` | hand-written leaves (`A64PORT_LEAF…` markers) from `DIR`; a leaf that matches no block stops the emit |
| `--names FILE` | readable names for function addresses (`addr<TAB>name`, from any source) |
| `--roots FILE` | extra discovery roots (hex addresses) |

The flag set that worked best for a large dynamically linked program was
`--trusted --fn-single --vec-fast --fpx --fp-outline --flags-dce --fpx-batch --restrict --narrow-pc`; start with
`--trusted --callret` and add flags one at a time, checking the output against `qemu-aarch64` each time.
