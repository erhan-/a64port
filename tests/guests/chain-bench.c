/* SPDX-License-Identifier: GPL-2.0-or-later */
/* A freestanding AArch64 guest for scripts/bench-chaining.sh.
 *
 * A loop with a loop-carried dependency (an LCG step) that clang at -O1 cannot
 * close-form or vectorise, so the translated code is a real multi-block loop and
 * the only difference between the two builds under test is how a block edge
 * reaches the next block: the host dispatch loop (`RCJ`) or a chained tail call
 * (`--chain`).
 *
 * _start exits with a few bits of the result, so a wrong run is visible as a
 * changed exit code as well as in the timing.
 *
 * Build: clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld \
 *               -Wl,-e,_start -O1 tests/guests/chain-bench.c -o chain-bench-a64
 */

#define N 50000000UL   /* below the standalone recomp_run watchdog (100M dispatches);
                          with --chain one dispatch runs many blocks, so N must be
                          chosen so the *unchained* build also completes */

__attribute__((noinline)) unsigned long spin(unsigned long n) {
    unsigned long s = 1;
    for (unsigned long i = 0; i < n; ++i)
        s = s * 6364136223846793005UL + 1442695040888963407UL + i;
    return s;
}

void _start(void) {
    unsigned long r = spin(N);
    register long x0 __asm__("x0") = (long)(r & 0x7f);
    register long x8 __asm__("x8") = 93; /* exit */
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8) : "memory");
    for (;;) {
    }
}
