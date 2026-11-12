/* SPDX-License-Identifier: GPL-2.0-or-later */
/* A freestanding AArch64 guest for measuring --fpx (FPX1).
 *
 * An FP-heavy loop: without FPX1 every op expands to the exact integer body,
 * with it the host's own correctly-rounded FP runs. A clear speedup is proof
 * that the fast path is actually taken (not merely emitted).
 *
 * Build: clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld \
 *               -Wl,-e,_start -O1 tests/guests/fp-bench.c -o fp-bench-a64
 */

#define N 20000000UL

__attribute__((noinline)) float work(void) {
    float s = 1.0f;
    for (unsigned long i = 0; i < N; ++i)
        s = s * 1.0009765625f + 0.5f;
    return s;
}

void _start(void) {
    float r = work();
    register long x0 __asm__("x0") = (long)(r * 1000.0f);
    register long x8 __asm__("x8") = 93;
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8) : "memory");
    for (;;) {
    }
}
