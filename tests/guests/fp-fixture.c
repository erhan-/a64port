/* SPDX-License-Identifier: GPL-2.0-or-later */
/* A freestanding AArch64 fixture for verifying --fpx (FPX1).

 * Every function is a single basic block with no branches, so
 * scripts/verify-leaf.sh can call it directly and diff the whole state,
 * including the VFP registers. FPX1 keeps a native result only when it provably
 * equals the architectural one and adds no new FPSR bit, so each must be
 * state-equivalent to the exact-body emission.
 *
 * Build: clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld \
 *               -Wl,-e,_start -O1 tests/guests/fp-fixture.c -o fp-fixture-a64
 */

__attribute__((noinline)) float fpmul(float a, float b) { return a * b; }
__attribute__((noinline)) float fpadd(float a, float b) { return a + b; }
__attribute__((noinline)) float fpsub(float a, float b) { return a - b; }
__attribute__((noinline)) float fpdiv(float a, float b) { return a / b; }
__attribute__((noinline)) float fpfma(float a, float b, float c) { return a * b + c; }
__attribute__((noinline)) double fpmuld(double a, double b) { return a * b; }
__attribute__((noinline)) double fpdivd(double a, double b) { return a / b; }
__attribute__((noinline)) float fpsqrt(float a) {
    float r;
    __asm__ volatile("fsqrt %s0, %s1" : "=w"(r) : "w"(a));
    return r;
}

void _start(void) {
    volatile float m = fpmul(1.5f, 2.25f);
    volatile float a = fpadd(3.5f, 4.25f);
    volatile float s = fpsub(3.5f, 4.25f);
    volatile float d = fpdiv(7.0f, 3.0f);
    volatile float f = fpfma(1.1f, 2.2f, 3.3f);
    volatile double md = fpmuld(1.5, 2.25);
    volatile double dd = fpdivd(7.0, 3.0);
    volatile float q = fpsqrt(2.0f);
    register long x0 __asm__("x0") = (long)(m + a + s + d + f + (float)md + (float)dd + q);
    register long x8 __asm__("x8") = 93;
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8) : "memory");
    for (;;) {
    }
}
