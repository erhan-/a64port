/* SPDX-License-Identifier: GPL-2.0-or-later */
/* libc-args.c - the guest sees the program's real command line and environment, and an unknown syscall fails with
 * ENOSYS (as on Linux) instead of ending the program.  Run with: alpha beta 3, and RB_TEST_VAR=hello in the environment.
 * Build: aarch64-linux-gnu-gcc -static -O1 tests/guests/libc-args.c -o libc-args-a64 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
int main(int argc, char** argv) {
    printf("argc=%d\n", argc);
    for (int i = 1; i < argc; ++i) printf("arg[%d]=%s\n", i, argv[i]);
    const char* h = getenv("RB_TEST_VAR"); printf("env=%s\n", h ? h : "(null)");
    long r = syscall(9999); printf("bogus syscall: %ld errno=%d\n", r, errno);
    return argc;
}
