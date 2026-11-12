/* SPDX-License-Identifier: GPL-2.0-or-later */
/* epoll-check.c - freestanding AArch64 guest for the shim's epoll translation.
 *
 * The AArch64 struct epoll_event is 16 bytes {u32 events; u32 pad; u64 data};
 * x86-64's is 12 bytes and packed.  The shim used to pass guest memory straight
 * to the host, so event 0 lined up by accident and every later event came back
 * at the wrong offsets.  This guest registers two pipes with
 * distinct 64-bit data values, makes both readable, and checks that ONE
 * epoll_pwait returns both, each with its own events and full 64-bit data.
 *
 * Exit status: 42 = pass; anything else names the first failing check.
 * Build: clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld \
 *        -Wl,-e,_start -O1 tests/guests/epoll-check.c -o epoll-check
 */
typedef unsigned long u64;
typedef unsigned int u32;

static long sys6(long n, long a, long b, long c, long d, long e, long f) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory");
    return x0;
}

struct ev { u32 events; u32 pad; u64 data; };   /* the AArch64 layout */

#define SYS_epoll_create1 20
#define SYS_epoll_ctl     21
#define SYS_epoll_pwait   22
#define SYS_pipe2         59
#define SYS_write         64
#define SYS_exit          93
#define EPOLLIN 1u
#define EPOLL_CTL_ADD 1

static const u64 kData[2] = { 0x1122334455667788ul, 0x99aabbccddeeff01ul };

static __attribute__((noreturn)) void quit(long code) {
    sys6(SYS_exit, code, 0, 0, 0, 0, 0);
    for (;;) {}
}

void _start(void) {
    int p[2][2];
    const long ep = sys6(SYS_epoll_create1, 0, 0, 0, 0, 0, 0);
    if (ep < 0) quit(1);
    for (int i = 0; i < 2; ++i) {
        if (sys6(SYS_pipe2, (long)p[i], 0, 0, 0, 0, 0) != 0) quit(2);
        struct ev e;
        e.events = EPOLLIN;
        e.pad = 0xdeadbeefu;               /* garbage in the padding, as on a real stack */
        e.data = kData[i];
        if (sys6(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, p[i][0], (long)&e, 0, 0) != 0) quit(3);
        char b = 'x';
        if (sys6(SYS_write, p[i][1], (long)&b, 1, 0, 0, 0) != 1) quit(4);
    }
    struct ev out[4];
    for (int i = 0; i < 4; ++i) { out[i].events = 0; out[i].pad = 0; out[i].data = 0; }
    const long n = sys6(SYS_epoll_pwait, ep, (long)out, 4, 1000, 0, 8);
    if (n != 2) quit(10 + (n < 0 ? 9 : n));
    int seen = 0;
    for (int i = 0; i < 2; ++i) {
        if (out[i].events != EPOLLIN) quit(20 + i);
        if (out[i].data == kData[0]) seen |= 1;
        else if (out[i].data == kData[1]) seen |= 2;
        else quit(30 + i);                 /* wrong 64-bit data: the layout bug */
    }
    if (seen != 3) quit(40);
    if (out[2].data != 0 || out[2].events != 0) quit(41);   /* nothing past n */
    quit(42);
}
