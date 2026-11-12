/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Freestanding `cat data.txt`, exercising openat/read/write/close/exit. */
static long sys4(long n, long a, long b, long c, long d) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return x0;
}
void _start(void) {
    static char buf[4096];
    long fd = sys4(56 /* openat */, -100 /* AT_FDCWD */, (long)"data.txt", 0, 0);
    if (fd < 0) { sys4(64, 1, (long)"open failed\n", 12, 0); sys4(93, 1, 0, 0, 0); }
    long n;
    while ((n = sys4(63 /* read */, fd, (long)buf, sizeof buf, 0)) > 0)
        sys4(64 /* write */, 1, (long)buf, n, 0);
    sys4(57 /* close */, fd, 0, 0, 0);
    sys4(93 /* exit */, 3, 0, 0, 0);
    __builtin_unreachable();
}
