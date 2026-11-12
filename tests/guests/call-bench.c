/* SPDX-License-Identifier: GPL-2.0-or-later */
/* A freestanding AArch64 guest for call/return-bound translation costs
 * (scripts/bench-arm.sh, --callret): recursion (BL/RET), calls through a table
 * of function pointers (BLR, like C++ virtual calls) and a small object walk,
 * the shape of large C++ GUI code.  Exits with a few bits of the result.
 *
 * Build: clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld \
 *               -Wl,-e,_start -Wl,--eh-frame-hdr -O2 tests/guests/call-bench.c -o call-bench
 */
typedef struct Obj { unsigned long (*op)(struct Obj*, unsigned long); unsigned long k; struct Obj* next; } Obj;

__attribute__((noinline)) unsigned long fib(unsigned long n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
__attribute__((noinline)) static unsigned long op_add(Obj* o, unsigned long x) { return x + o->k; }
__attribute__((noinline)) static unsigned long op_mul(Obj* o, unsigned long x) { return x * (o->k | 1); }
__attribute__((noinline)) static unsigned long op_xor(Obj* o, unsigned long x) { return (x ^ o->k) + 3; }
__attribute__((noinline)) static unsigned long op_rot(Obj* o, unsigned long x) { return (x << 7 | x >> 57) + o->k; }

static Obj objs[16];

__attribute__((noinline)) unsigned long walk(unsigned long n) {
    unsigned long (*ops[4])(Obj*, unsigned long) = { op_add, op_mul, op_xor, op_rot };
    for (int i = 0; i < 16; ++i) { objs[i].op = ops[i & 3]; objs[i].k = i * 2654435761UL; objs[i].next = &objs[(i * 5 + 1) & 15]; }
    unsigned long x = 1; Obj* o = &objs[0];
    for (unsigned long i = 0; i < n; ++i) { x = o->op(o, x); o = o->next; }
    return x;
}

void _start(void) {
    unsigned long r = fib(27) + walk(3000000);
    register long x0 __asm__("x0") = (long)(r & 0x7f);
    register long x8 __asm__("x8") = 93; /* exit */
    __asm__ volatile("svc #0" :: "r"(x0), "r"(x8));
    for (;;) {}
}
