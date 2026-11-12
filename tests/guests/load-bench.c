/* SPDX-License-Identifier: GPL-2.0-or-later */
/* A freestanding AArch64 guest for the load-aliasing experiment.
 *
 * The loop reads two static tables per iteration, so the translated body emits
 * real loads between the register recurrence. Whether the compiler can keep the
 * recurrence in a host register across a `recomp_load*` call decides the
 * runtime: if the load helper is opaque and may write `c->x[]`, every load forces
 * a reload of the whole register file.
 *
 * Build: clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld \
 *               -Wl,-e,_start -O1 tests/guests/load-bench.c -o load-bench-a64
 */

#define N 20000000UL

static unsigned long arr[64];
static unsigned long brr[64];

__attribute__((noinline)) unsigned long work(void) {
    unsigned long s = 1;
    for (unsigned long i = 0; i < N; ++i)
        s = s * 6364136223846793005UL + arr[i & 63] + brr[(i + 7) & 63];
    return s;
}

void _start(void) {
    for (int i = 0; i < 64; ++i) {
        arr[i] = (unsigned long)i * 2654435761UL;
        brr[i] = arr[i] ^ 0x9E3779B97F4A7C15UL;
    }
    unsigned long r = work();
    register long x0 __asm__("x0") = (long)(r & 0x7f);
    register long x8 __asm__("x8") = 93;
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8) : "memory");
    for (;;) {
    }
}
