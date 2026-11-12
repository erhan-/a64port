/* SPDX-License-Identifier: GPL-2.0-or-later */
/* A freestanding fixture for scripts/verify-leaf.sh and scripts/test-verify-leaf.sh.
 *
 * `add3` is a single-block leaf: add x8,x1,x0 ; add x0,x8,x2 ; ret. The
 * intermediate write to x8 is exactly the kind of guest-visible detail a hand
 * leaf can forget, and the differential verifier must catch it.
 *
 * Build: clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld \
 *               -Wl,-e,_start -O1 tests/guests/leaf-fixture.c -o leaf-fixture-a64
 */

__attribute__((noinline)) long add3(long a, long b, long c) {
    return a + b + c;
}

/* multi-block: the entry block branches, so a whole-function leaf must cover it
   and the second block, and the test needs --function to compare both. */
__attribute__((noinline)) long classify(long x) {
    if (x == 0)
        return 7;
    return x * 3 + 1;
}

/* a loop: several blocks, so --function must follow them to the return */
__attribute__((noinline)) long sumto(long n) {
    long s = 0;
    for (long i = 0; i < n; ++i)
        s += i;
    return s;
}

void _start(void) {
    long r = add3(1, 2, 3) + classify(5) + sumto(7);
    register long x0 __asm__("x0") = r;
    register long x8 __asm__("x8") = 93; /* exit */
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8) : "memory");
    for (;;) {
    }
}
