/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Freestanding cat: read a line from stdin, echo it, exit 7. */
static long sys3(long n, long a, long b, long c) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
void _start(void) {
    static char buf[64];
    long n = sys3(63 /* read */, 0, (long)buf, sizeof buf);
    if (n > 0) sys3(64 /* write */, 1, (long)buf, n);
    sys3(93 /* exit */, 7, 0, 0);
    __builtin_unreachable();
}
