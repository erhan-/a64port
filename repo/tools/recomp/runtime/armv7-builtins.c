/* SPDX-License-Identifier: GPL-2.0-or-later */
/* armv7-builtins.c - the few compiler-runtime helpers a STATIC ARMv7 link of the
 * multi host needs (build-armv7.sh STATIC=1).  The armhf sysroot has glibc's
 * static archives but no libgcc.a, and this machine's clang has no ARM
 * compiler-rt builtins, so they are written out here.
 *
 * Why static at all: a dynamic ARMv7 binary gets its ld.so and libraries mapped
 * by the loader before main() - under qemu-user they land at 0x40000000+,
 * inside the identity arena (0x400000..ARENA_TOP) a -DA64PORT_FASTMEM build
 * needs.  A static image has nothing mapped low.  On a target it also removes
 * the dependency on the target's own glibc.
 *
 * Built for -mcpu=cortex-a17 (hardware sdiv/udiv).  The 64-bit division is a
 * plain shift-subtract (it is called by libc's printf/strtoull paths, not by
 * guest code: emitted code divides with C operators that the compiler turns
 * into these calls only for 64-bit operands). */
#include <stdint.h>
#include <stdlib.h>

#if !defined(__arm__)
#error "armv7-builtins.c is for 32-bit ARM only"
#endif
/* The RTABI helpers use the BASE procedure call standard even in a hard-float
   program: floating-point arguments and results travel in core registers. */
#define RTABI __attribute__((pcs("aapcs")))

int __aeabi_idiv(int a, int b) { return a / b; }
unsigned __aeabi_uidiv(unsigned a, unsigned b) { return a / b; }
/* {quotient, remainder} in r0, r1: a 64-bit return value occupies r0:r1. */
uint64_t __aeabi_idivmod(int a, int b) {
    const int q = a / b, r = a - q * b;
    return (uint64_t)(uint32_t)q | ((uint64_t)(uint32_t)r << 32);
}
uint64_t __aeabi_uidivmod(unsigned a, unsigned b) {
    const unsigned q = a / b, r = a - q * b;
    return (uint64_t)q | ((uint64_t)r << 32);
}

uint64_t a64port_udivmoddi4(uint64_t n, uint64_t d, uint64_t* rem) {
    if (d == 0) { if (rem) *rem = n; return ~UINT64_C(0); }   /* undefined; no trap */
    if (n < d) { if (rem) *rem = n; return 0; }
    if ((d >> 32) == 0 && (n >> 32) == 0) {
        const uint32_t q = (uint32_t)n / (uint32_t)d;
        if (rem) *rem = (uint32_t)n - q * (uint32_t)d;
        return q;
    }
    const int shift = __builtin_clzll(d) - __builtin_clzll(n);
    uint64_t q = 0, r = n, dd = d << shift;
    for (int i = shift; i >= 0; --i, dd >>= 1) {
        q <<= 1;
        if (r >= dd) { r -= dd; q |= 1; }
    }
    if (rem) *rem = r;
    return q;
}

/* __aeabi_uldivmod / __aeabi_ldivmod: quotient in r0:r1, remainder in r2:r3. */
__attribute__((naked)) void __aeabi_uldivmod(void) {
    __asm__ volatile(
        "push {r4, lr}\n"
        "sub sp, sp, #16\n"
        "add r4, sp, #8\n"
        "str r4, [sp]\n"            /* 5th argument (rem*) on the stack */
        "bl a64port_udivmoddi4\n"
        "ldrd r2, r3, [sp, #8]\n"
        "add sp, sp, #16\n"
        "pop {r4, pc}\n");
}

int64_t a64port_divmoddi4(int64_t n, int64_t d, int64_t* rem) {
    const int nn = n < 0, nd = d < 0;
    uint64_t r;
    const uint64_t q = a64port_udivmoddi4(nn ? -(uint64_t)n : (uint64_t)n,
                                         nd ? -(uint64_t)d : (uint64_t)d, &r);
    if (rem) *rem = nn ? -(int64_t)r : (int64_t)r;
    return (nn != nd) ? -(int64_t)q : (int64_t)q;
}
__attribute__((naked)) void __aeabi_ldivmod(void) {
    __asm__ volatile(
        "push {r4, lr}\n"
        "sub sp, sp, #16\n"
        "add r4, sp, #8\n"
        "str r4, [sp]\n"
        "bl a64port_divmoddi4\n"
        "ldrd r2, r3, [sp, #8]\n"
        "add sp, sp, #16\n"
        "pop {r4, pc}\n");
}

/* Conversions: both halves convert exactly, hi*2^32 is exact, so the one
   addition is the only rounding - the correctly rounded result. */
RTABI double __aeabi_ul2d(uint64_t x) {
    return (double)(uint32_t)(x >> 32) * 4294967296.0 + (double)(uint32_t)x;
}
RTABI double __aeabi_l2d(int64_t x) {
    return (double)(int32_t)(x >> 32) * 4294967296.0 + (double)(uint32_t)x;
}

/* double/float -> 64-bit integer, truncating toward zero; out of range
   saturates (what the ARM VFP conversions do for 32 bits; C leaves it UB). */
RTABI uint64_t __aeabi_d2ulz(double d) {
    if (!(d >= 1.0)) return 0;                                   /* also NaN */
    if (d >= 18446744073709551616.0) return ~UINT64_C(0);
    if (d < 4294967296.0) return (uint32_t)d;
    const uint32_t hi = (uint32_t)(d / 4294967296.0);            /* exact: power-of-two scale */
    const double rest = d - (double)hi * 4294967296.0;           /* exact: same binade */
    return ((uint64_t)hi << 32) | (uint32_t)rest;
}
RTABI int64_t __aeabi_d2lz(double d) {
    if (d != d) return 0;
    if (d >= 9223372036854775808.0) return INT64_MAX;
    if (d <= -9223372036854775808.0) return INT64_MIN;
    return d < 0 ? -(int64_t)__aeabi_d2ulz(-d) : (int64_t)__aeabi_d2ulz(d);
}
RTABI uint64_t __aeabi_f2ulz(float f) { return __aeabi_d2ulz((double)f); }
RTABI int64_t __aeabi_f2lz(float f) { return __aeabi_d2lz((double)f); }
/* 64-bit integer -> float: via double would round twice; round once here.
   Shift the value into 25 significant bits plus a sticky bit, then let one
   conversion of that exact 32-bit integer do the rounding. */
RTABI float __aeabi_ul2f(uint64_t x) {
    if (x < (UINT64_C(1) << 32)) return (float)(uint32_t)x;
    int sh = 0;
    while ((x >> sh) >= (UINT64_C(1) << 31)) ++sh;               /* keep <= 31 bits */
    const uint32_t sticky = (x & ((UINT64_C(1) << sh) - 1)) != 0;
    const uint32_t m = (uint32_t)(x >> sh) | sticky;             /* exact, odd if inexact */
    float r = (float)m;                                          /* the one rounding */
    while (sh--) r *= 2.0f;                                      /* exact scaling */
    return r;
}
RTABI float __aeabi_l2f(int64_t x) {
    return x < 0 ? -__aeabi_ul2f(-(uint64_t)x) : __aeabi_ul2f((uint64_t)x);
}

int __ctzdi2(uint64_t x) {
    return (uint32_t)x ? __builtin_ctz((uint32_t)x) : 32 + __builtin_ctz((uint32_t)(x >> 32));
}

/* Unwinder entry points static glibc references for thread cancellation,
   pthread_exit's forced unwind and backtrace().  The host never cancels a
   thread or calls pthread_exit (host threads return), so these only fail. */
int _Unwind_Backtrace(void* fn, void* arg) { (void)fn; (void)arg; return 5; /* _URC_END_OF_STACK */ }
void _Unwind_Resume(void* e) { (void)e; abort(); }
int _Unwind_ForcedUnwind(void* e, void* stop, void* arg) { (void)e; (void)stop; (void)arg; abort(); }
uintptr_t _Unwind_GetCFA(void* ctx) { (void)ctx; return 0; }
int _Unwind_VRS_Get(void* ctx, int cls, uint32_t reg, int rep, void* val) {
    (void)ctx; (void)cls; (void)reg; (void)rep; (void)val; return 2; /* _UVRSR_FAILED */
}
int __gcc_personality_v0(int v, int a, uint64_t c, void* e, void* ctx) {
    (void)v; (void)a; (void)c; (void)e; (void)ctx; return 9; /* _URC_FAILURE */
}
