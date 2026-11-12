/* SPDX-License-Identifier: GPL-2.0-or-later */
/* neon_structs.h — force-included into every emitted translation unit.
 *
 * Declares recomp_ldst_struct(), the one-call form of AArch64 LD1-LD4 / ST1-ST4
 * whole-register structure access.  The emitter used to expand those into
 * lanes*regs scalar recomp_load/store calls plus a memcpy each - a single
 * `ld4 {v8.16b,v9.16b,v10.16b,v11.16b},[x2],#64` became 64 load8() calls and 64
 * memcpys - which is a ~300-1000x penalty on an instruction that is one NEON
 * structure access on real hardware.  Those instructions are concentrated in
 * image code (thousands in a large C++ program, 1,094 in libjpeg), which is often the
 * code at the top of the profile.
 *
 * The body lives in host_loader.c (the host), NOT in the emitted tree, because
 * a64recomp regenerates recomp_runtime.[ch] on every emit and would clobber it.
 * It is force-included with -include from the build manifest. */
#ifndef A64PORT_LDST_H
#define A64PORT_LDST_H
#include "recomp_runtime.h"

/* addr = base address; rt = first vector register; regs = 1..4;
   lanes = elements per register (bytes/esz); esz = element size in bytes;
   step = 1 for the non-interleaved LD1/ST1 forms, else regs;
   load = 1 for LD*, 0 for ST*; bytes = 16 for the Q form, 8 otherwise. */
void recomp_ldst_struct(GuestContext* c, uint64_t addr, uint32_t rt,
                        uint32_t regs, uint32_t lanes, uint32_t esz,
                        uint32_t step, uint32_t load, uint32_t bytes);

/* Double-free detector hook, called at the head of the guest libc's free().
   Implemented in recomp_runtime.c; A64PORT_FREEWATCH=1 turns it on. */
void a64port_free_hook(GuestContext* c, uint64_t p);
/* Called at the return of the guest libc's malloc()/calloc()/realloc() with the
   returned pointer, so the double-free detector can clear it as live. */
void a64port_alloc_hook(GuestContext* c, uint64_t p);
/* Records the requested size at malloc/calloc/realloc entry (thread-local) so
   the guest address sanitizer can place the redzone at the right offset. */
void a64port_alloc_enter(GuestContext* c, uint64_t size);

/* 32-bit hosts: guest loads inline the runtime's flat fast path.
 *
 * Every guest load is otherwise a call into recomp_runtime.c, and on ARMv7 that
 * call saves eight registers to answer what is a range check and an add.  The
 * inline form is the runtime's own flat branch (recomp_host_ptr_n with
 * g_flat_state == 1) word for word: g_flat_len is 0 until the probe has found
 * the page table flat, so before that - and for any address outside the arena,
 * a non-flat table, or a host with a memory bridge - the check fails and the
 * out-of-line helper answers exactly as before.  Stores stay out of line: they
 * also retire exclusive reservations.  A64PORT_NO_INLINE_LOADS turns this off,
 * and MUST be defined when this header is force-included into recomp_runtime.c
 * itself (the verifiers do that): the macros would rename the runtime's own
 * definitions of these helpers.  x86-64 never sees any of it. */
/* --callret code resolves a computed target (BR, BLR, the resume after an SVC,
 * a return to a non-block address) through RECOMP_RESOLVE.  In the multi host
 * that is one global table over every module (host_loader.c, "global block
 * resolver"): two dependent loads, then the host's dispatcher on a miss - so a
 * call into another module (every PLT call) stays a host call. */
#if defined(A64PORT_MULTI_HOST) && defined(RECOMP_HAS_CALL_DEPTH)
#if UINTPTR_MAX == 0xffffffffu
#define A64PORT_RX_L1_N 1024
#else
#define A64PORT_RX_L1_N 16384
#endif
extern BlockFn** g_rx_l1[A64PORT_RX_L1_N];
BlockFn a64port_resolve_slow(uint64_t pc);
static inline __attribute__((always_inline)) BlockFn a64port_resolve(uint64_t pc) {
    if (__builtin_expect((pc >> 22) < A64PORT_RX_L1_N && !(pc & 3), 1)) {
        BlockFn** l2 = g_rx_l1[pc >> 22];
        if (__builtin_expect(l2 != 0, 1)) {
            BlockFn* pg = l2[(pc >> 12) & 1023];
            if (__builtin_expect(pg != 0, 1)) {
                BlockFn f = pg[(pc & 0xFFF) >> 2];
                if (__builtin_expect(f != 0, 1)) return f;
            }
        }
    }
    return a64port_resolve_slow(pc);
}
#undef RECOMP_RESOLVE
#define RECOMP_RESOLVE(pc) a64port_resolve(pc)
#endif

#if defined(A64PORT_FASTMEM) && !defined(A64PORT_NO_INLINE_LOADS)
/* -DA64PORT_FASTMEM (any host): the multi host maps the arena at its own guest
 * addresses (host_loader.c, "identity arena", and refuses to start otherwise),
 * so a guest VA IS the host address and every plain load and store is one host
 * access through it - no range check, no helper call.  On a 32-bit host the
 * cast drops the high half, and with it the compiler drops the 64-bit address
 * arithmetic that only fed it.
 *
 * What this gives up, deliberately:
 *  - out-of-arena accesses are no longer caught by a check: they fault (SIGSEGV
 *    -> the crash reporter) or, for a stray host pointer, hit host memory.  The
 *    checked build (no -DA64PORT_FASTMEM) is the debugging build;
 *  - plain stores no longer retire peers' exclusive reservations.  STXR still
 *    succeeds only if memory still holds the value its LDXR read (a host CAS,
 *    host_loader.c hm_excl_store), which is qemu-user's model; what is lost is
 *    only an intervening store of the SAME value (ABA);
 *  - the guest ASan / store watch detectors (they hang off the store helpers).
 * Exclusives, LSE atomics, LD1-4/ST1-4 and acquire/release forms keep their
 * helpers. */
#define A64PORT_HP(a) ((unsigned char*)(uintptr_t)(a))
static inline __attribute__((always_inline)) uint64_t a64port_ld8(GuestContext* c, uint64_t a) {
    (void)c; return *A64PORT_HP(a); }
static inline __attribute__((always_inline)) uint64_t a64port_ld16(GuestContext* c, uint64_t a) {
    (void)c; uint16_t v; __builtin_memcpy(&v, A64PORT_HP(a), 2); return v; }
static inline __attribute__((always_inline)) uint64_t a64port_ld32(GuestContext* c, uint64_t a) {
    (void)c; uint32_t v; __builtin_memcpy(&v, A64PORT_HP(a), 4); return v; }
static inline __attribute__((always_inline)) uint64_t a64port_ld64(GuestContext* c, uint64_t a) {
    (void)c; uint64_t v; __builtin_memcpy(&v, A64PORT_HP(a), 8); return v; }
static inline __attribute__((always_inline)) void a64port_ldp64(GuestContext* c, uint64_t a, uint64_t* lo, uint64_t* hi) {
    (void)c; __builtin_memcpy(lo, A64PORT_HP(a), 8); __builtin_memcpy(hi, A64PORT_HP(a) + 8, 8); }
static inline __attribute__((always_inline)) void a64port_ldp32(GuestContext* c, uint64_t a, uint64_t* lo, uint64_t* hi) {
    (void)c; uint32_t x, y; __builtin_memcpy(&x, A64PORT_HP(a), 4); __builtin_memcpy(&y, A64PORT_HP(a) + 4, 4);
    *lo = x; *hi = y; }
static inline __attribute__((always_inline)) void a64port_st8(GuestContext* c, uint64_t a, uint64_t v) {
    (void)c; *A64PORT_HP(a) = (unsigned char)v; }
static inline __attribute__((always_inline)) void a64port_st16(GuestContext* c, uint64_t a, uint64_t v) {
    (void)c; uint16_t t = (uint16_t)v; __builtin_memcpy(A64PORT_HP(a), &t, 2); }
static inline __attribute__((always_inline)) void a64port_st32(GuestContext* c, uint64_t a, uint64_t v) {
    (void)c; uint32_t t = (uint32_t)v; __builtin_memcpy(A64PORT_HP(a), &t, 4); }
static inline __attribute__((always_inline)) void a64port_st64(GuestContext* c, uint64_t a, uint64_t v) {
    (void)c; __builtin_memcpy(A64PORT_HP(a), &v, 8); }
static inline __attribute__((always_inline)) void a64port_stp64(GuestContext* c, uint64_t a, uint64_t v0, uint64_t v1) {
    (void)c; __builtin_memcpy(A64PORT_HP(a), &v0, 8); __builtin_memcpy(A64PORT_HP(a) + 8, &v1, 8); }
static inline __attribute__((always_inline)) void a64port_stp32(GuestContext* c, uint64_t a, uint64_t v0, uint64_t v1) {
    (void)c; uint32_t x = (uint32_t)v0, y = (uint32_t)v1;
    __builtin_memcpy(A64PORT_HP(a), &x, 4); __builtin_memcpy(A64PORT_HP(a) + 4, &y, 4); }
#define recomp_load8(c, a)  a64port_ld8((c), (a))
#define recomp_load16(c, a) a64port_ld16((c), (a))
#define recomp_load32(c, a) a64port_ld32((c), (a))
#define recomp_load64(c, a) a64port_ld64((c), (a))
#define recomp_ldp64(c, a, lo, hi) a64port_ldp64((c), (a), (lo), (hi))
#define recomp_ldp32(c, a, lo, hi) a64port_ldp32((c), (a), (lo), (hi))
#define recomp_store8(c, a, v)  a64port_st8((c), (a), (v))
#define recomp_store16(c, a, v) a64port_st16((c), (a), (v))
#define recomp_store32(c, a, v) a64port_st32((c), (a), (v))
#define recomp_store64(c, a, v) a64port_st64((c), (a), (v))
#define recomp_stp64(c, a, v0, v1) a64port_stp64((c), (a), (v0), (v1))
#define recomp_stp32(c, a, v0, v1) a64port_stp32((c), (a), (v0), (v1))
#elif UINTPTR_MAX == 0xffffffffu && !defined(A64PORT_NO_INLINE_LOADS)
extern uint64_t  g_flat_lo, g_flat_len;
extern uintptr_t g_flat_bias;
/* The runtime's flat test; on a hit the host address is g_flat_bias + va.  The
   tag mask only clears bits above 31, which uintptr_t drops anyway.  (The
   runtime also rejects a NULL result; bias + va is never 0 inside the arena,
   so testing it again would only cost an instruction per load.) */
static inline __attribute__((always_inline)) int a64port_flat(uint64_t a, uint64_t n) {
    const uint64_t off = (a & 0xffffffffffffULL) - g_flat_lo;
    return off < g_flat_len && n <= g_flat_len - off;
}
#define A64PORT_FLAT_P(a) ((const unsigned char*)(g_flat_bias + (uintptr_t)(a)))
static inline __attribute__((always_inline)) uint64_t a64port_ld8(GuestContext* c, uint64_t a) {
    return __builtin_expect(a64port_flat(a, 1), 1) ? (uint64_t)*A64PORT_FLAT_P(a) : (recomp_load8)(c, a);
}
static inline __attribute__((always_inline)) uint64_t a64port_ld16(GuestContext* c, uint64_t a) {
    if (__builtin_expect(a64port_flat(a, 2), 1)) {
        const unsigned char* p = A64PORT_FLAT_P(a); uint16_t v; __builtin_memcpy(&v, p, 2); return v; }
    return (recomp_load16)(c, a);
}
static inline __attribute__((always_inline)) uint64_t a64port_ld32(GuestContext* c, uint64_t a) {
    if (__builtin_expect(a64port_flat(a, 4), 1)) {
        const unsigned char* p = A64PORT_FLAT_P(a); uint32_t v; __builtin_memcpy(&v, p, 4); return v; }
    return (recomp_load32)(c, a);
}
static inline __attribute__((always_inline)) uint64_t a64port_ld64(GuestContext* c, uint64_t a) {
    if (__builtin_expect(a64port_flat(a, 8), 1)) {
        const unsigned char* p = A64PORT_FLAT_P(a); uint64_t v; __builtin_memcpy(&v, p, 8); return v; }
    return (recomp_load64)(c, a);
}
static inline __attribute__((always_inline)) void a64port_ldp64(GuestContext* c, uint64_t a, uint64_t* lo, uint64_t* hi) {
    if (__builtin_expect(a64port_flat(a, 16), 1)) {
        const unsigned char* p = A64PORT_FLAT_P(a); __builtin_memcpy(lo, p, 8); __builtin_memcpy(hi, p + 8, 8); return; }
    (recomp_ldp64)(c, a, lo, hi);
}
static inline __attribute__((always_inline)) void a64port_ldp32(GuestContext* c, uint64_t a, uint64_t* lo, uint64_t* hi) {
    if (__builtin_expect(a64port_flat(a, 8), 1)) {
        const unsigned char* p = A64PORT_FLAT_P(a);
        uint32_t x, y; __builtin_memcpy(&x, p, 4); __builtin_memcpy(&y, p + 4, 4);
        *lo = x; *hi = y; return;
    }
    (recomp_ldp32)(c, a, lo, hi);
}
/* Function-like, so a declaration written `recomp_load64(GuestContext*,...)`
   would also be renamed: emitted units carry none (they rely on the runtime
   header, included above), and the parenthesised calls above bypass these. */
#define recomp_load8(c, a)  a64port_ld8((c), (a))
#define recomp_load16(c, a) a64port_ld16((c), (a))
#define recomp_load32(c, a) a64port_ld32((c), (a))
#define recomp_load64(c, a) a64port_ld64((c), (a))
#define recomp_ldp64(c, a, lo, hi) a64port_ldp64((c), (a), (lo), (hi))
#define recomp_ldp32(c, a, lo, hi) a64port_ldp32((c), (a), (lo), (hi))
#endif
#endif
