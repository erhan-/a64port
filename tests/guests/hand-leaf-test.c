/* SPDX-License-Identifier: GPL-2.0-or-later */
/* A freestanding AArch64 guest for scripts/test-hand-leaves.sh.
 *
 * `classify` has a fast path (x == 0) and a slow path (everything else). The
 * test's filter leaf handles only x == 0 and returns 0 for the rest, so a
 * correct run proves the filter ran *and* that the translated body still runs
 * when the filter declines -- the two halves of the framework.
 *
 * _start exits with classify(0) + classify(5), so the exit code distinguishes:
 *   baseline (translated only)  7 + 16 = 23
 *   with the test filter leaf   100 + 16 = 116
 *
 * Build: clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld \
 *               -Wl,-e,_start -O1 tests/guests/hand-leaf-test.c -o hand-leaf-test-a64
 */

__attribute__((noinline)) int classify(int x) {
    if (x == 0)
        return 7;
    return x * 3 + 1;
}

void _start(void) {
    int a = classify(0);
    int b = classify(5);
    register long x0 __asm__("x0") = (long)(a + b);
    register long x8 __asm__("x8") = 93;  /* exit */
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8) : "memory");
    for (;;) {
    }
}
