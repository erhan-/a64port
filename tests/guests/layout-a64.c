/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Does a guest-computed struct layout survive the trip to a 32-bit host?
 *
 * The guest builds a `struct iovec` array using ITS OWN (LP64) layout -- pointer
 * first, then size_t, 16 bytes per entry -- and hands it to `writev`, which is a
 * *library* function: on the translated side that call resolves to the armhf
 * libc, whose iovec is ILP32 (4-byte pointer, then 4-byte length, 8 bytes per
 * entry). Same mechanism as std::string: the layout the guest inlined versus the
 * layout the host library expects.
 */
struct iovec { void *base; unsigned long len; };

extern long writev(int fd, const struct iovec *iov, int iovcnt);

void _start(void) {
    struct iovec iov[2];
    iov[0].base = "AA\n"; iov[0].len = 3;
    iov[1].base = "BB\n"; iov[1].len = 3;
    writev(1, iov, 2);
    register long x8 __asm__("x8") = 93;   /* exit */
    register long x0 __asm__("x0") = 9;
    __asm__ volatile("svc #0" : : "r"(x8), "r"(x0));
    __builtin_unreachable();
}
