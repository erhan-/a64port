/* SPDX-License-Identifier: GPL-2.0-or-later */
/* A freestanding multi-function AArch64 guest for scripts/test-locals.sh.
 *
 * --functions/--locals group a guest function's basic blocks into one C
 * function. That needs *function entries*: build with -Wl,--eh-frame-hdr so the
 * emitter finds .eh_frame FDEs and actually groups. Without them every block is
 * an orphan and the grouping path falls back to per-block emission - which
 * still exercises --locals, but not grouping.
 *
 * _start exits with (compute(1000) ^ (add(3,4) * mul(5,6))) & 0x7f; the test
 * compares that against qemu-aarch64 for every emission variant.
 *
 * Build:
 *   clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld \
 *         -Wl,-e,_start -Wl,--eh-frame-hdr -O1 tests/guests/grouping-test.c -o ...
 */

__attribute__((noinline)) int add(int a, int b) { return a + b; }

__attribute__((noinline)) int mul(int a, int b) { return a * b; }

__attribute__((noinline)) int compute(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if (i & 1)
            s += mul(i, 3);
        else
            s += add(i, 5);
    }
    return s;
}

void _start(void) {
    int v = compute(1000) ^ (add(3, 4) * mul(5, 6));
    register long x0 __asm__("x0") = (long)(v & 0x7f);
    register long x8 __asm__("x8") = 93; /* exit */
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8) : "memory");
    for (;;) {
    }
}
