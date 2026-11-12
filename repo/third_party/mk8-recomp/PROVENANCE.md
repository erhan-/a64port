# third_party/mk8-recomp: vendored recompiler engine

## What is here

`arm64_to_c.h` is the header-only "AArch64 to portable C" static recompiler engine from suyu's mk8-recomp branch.
a64port uses it as an instruction decoder and C emitter: it turns AArch64 machine code into portable C plus a small
runtime, and an ordinary C compiler turns that C into a native program for x86-64, 32-bit ARM (ARMv7) or AArch64.
Nothing about Switch emulation is involved when the engine is used this way.

## Pin and licence

| | |
|---|---|
| Upstream repository | `https://github.com/dougchansan/mk8-recomp` (submodule `third_party/suyu`: `https://github.com/dougchansan/suyu-v0.0.4.git`, branch `mk8-recomp`) |
| Path upstream | `src/core/recompiler/arm64_to_c.h` |
| Upstream commit | `058fa89ac1dcbfde92759ccb475678315378d342` (2026-09-27), the branch head when fetched on 2026-10-01 |
| Upstream size | 7,897 lines, SHA-256 `4de5bc7646a7afb90d548110aebac365681937a8c42e28cfe04ca98b1f90fd64` |
| Licence | GPL-2.0-or-later, Copyright 2026 suyu Emulator Project |

All local changes are in one patch series, `repo/patches/a64port-recomp.patch`. Regenerate it with:

```sh
curl -sfL https://raw.githubusercontent.com/dougchansan/suyu-v0.0.4/058fa89ac1dcbfde92759ccb475678315378d342/src/core/recompiler/arm64_to_c.h \
  -o /tmp/pristine-arm64_to_c.h
diff -u /tmp/pristine-arm64_to_c.h repo/third_party/mk8-recomp/arm64_to_c.h > repo/patches/a64port-recomp.patch
```

## What the patch changes

**Correctness without a JIT.** Upstream relies on a JIT (Dynarmic) for anything it does not translate; a64port has
no fallback, so:

- every unhandled instruction stops the program instead of being stepped over, and "translate all" is always on;
- `MRS DCZID_EL0` reports a block size that matches the engine's `DC ZVA`;
- `RET Xn` returns through the named register, not always `x30`;
- literal loads add the module base, so position-independent libraries work;
- exclusive loads/stores clear their reservation on any store to the granule, LSE atomics and compare-and-swap are
  host atomic operations, and barriers are real fences, so multi-threaded programs are correct on weakly ordered
  hosts;
- the `GuestContext` offset checks apply to 64-bit hosts only, so the same emitted C builds for 32-bit hosts.

**Emit options** (all off by default; the default output is the upstream shape): `--trusted` (no self-modification
guard), `--chain` (direct branches as tail calls), `--callret` (guest calls as host calls), `--functions` /
`--fn-single` (one C function per guest function, single entry), `--locals` / `--locals-changed` (guest registers in
C locals), `--flags-dce` (dead condition-flag elimination), `--fp-outline` / `--fpx` / `--fpx-batch` (shared exact FP
bodies, native fast paths kept only when provably equal), `--restrict`, `--narrow-pc`, `--vec-fast` (vector types for
listed blocks), `--fastmem` / `--guard-gen`.

**Hooks for the driver**: names for emitted functions, and hand-written replacement code for single blocks
(a full replacement, or a filter that may decline).

**Size and build time**: one verification image per unit, short aliases for the most frequent helpers, and
write-if-changed output, which roughly halve the emitted C and keep object caches valid across re-emits.
