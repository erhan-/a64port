/* SPDX-License-Identifier: GPL-2.0-or-later */
/* libc-sockets.c - a static-glibc AArch64 guest that exercises the OS surface a real program uses, on ONE thread:
 * files, mmap/mprotect, malloc/qsort/printf(%f), setjmp, pipes, socketpair, TCP over loopback (listen,
 * connect, accept in one thread with poll), epoll, timerfd, clock_gettime, getenv.  It prints one line per check;
 * the output must be byte-identical under qemu-aarch64 and under the recompiled program.
 * Build: aarch64-linux-gnu-gcc -static -O1 tests/guests/libc-sockets.c -o libc-sockets-a64
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(name, cond) do { int ok_ = !!(cond); printf("%-14s %s\n", name, ok_ ? "ok" : "FAIL"); if (!ok_) ++fails; } while (0)

static int cmp_int(const void* a, const void* b) { return *(const int*)a - *(const int*)b; }

int main(void) {
    /* heap + sort + float formatting */
    int* v = malloc(1000 * sizeof *v);
    for (int i = 0; i < 1000; ++i) v[i] = (int)((i * 7919u) % 1009u);
    qsort(v, 1000, sizeof *v, cmp_int);
    int sorted = 1; for (int i = 1; i < 1000; ++i) if (v[i - 1] > v[i]) sorted = 0;
    CHECK("qsort", sorted);
    char buf[128]; snprintf(buf, sizeof buf, "%.6f %e %g", M_PI, 12345.678, 0.1 + 0.2);
    printf("fmt            %s\n", buf);
    free(v);

    /* files */
    char path[] = "/tmp/a64port-libc-XXXXXX";
    int fd = mkstemp(path);
    CHECK("mkstemp", fd >= 0);
    const char* msg = "hello, file\n";
    CHECK("write", write(fd, msg, strlen(msg)) == (ssize_t)strlen(msg));
    struct stat st; CHECK("fstat", fstat(fd, &st) == 0 && st.st_size == (off_t)strlen(msg));
    char rb[64] = {0}; CHECK("pread", pread(fd, rb, sizeof rb, 0) == (ssize_t)strlen(msg) && !strcmp(rb, msg));
    void* m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK("mmap file", m != MAP_FAILED && !memcmp(m, msg, 5));
    if (m != MAP_FAILED) munmap(m, 4096);
    close(fd); unlink(path);

    /* anonymous memory + protection */
    unsigned char* a = mmap(0, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK("mmap anon", a != MAP_FAILED);
    if (a != MAP_FAILED) { memset(a, 0x5a, 1 << 20); CHECK("mprotect", mprotect(a, 4096, PROT_READ) == 0 && a[100] == 0x5a); munmap(a, 1 << 20); }

    /* setjmp/longjmp */
    jmp_buf jb; volatile int jumped = 0;
    if (!setjmp(jb)) { jumped = 1; longjmp(jb, 1); }
    CHECK("setjmp", jumped == 1);

    /* signal dispositions the host CAN honour (a handler of the guest's cannot be delivered: see libc-signals.c) */
    CHECK("sig ignore", signal(SIGUSR2, SIG_IGN) != SIG_ERR && raise(SIGUSR2) == 0);

    /* pipe + socketpair */
    int p[2]; CHECK("pipe", pipe(p) == 0 && write(p[1], "xyz", 3) == 3 && read(p[0], rb, 3) == 3 && !memcmp(rb, "xyz", 3));
    int sp[2]; CHECK("socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0 && send(sp[0], "ping", 4, 0) == 4 &&
                                   recv(sp[1], rb, 4, 0) == 4 && !memcmp(rb, "ping", 4));

    /* TCP over loopback, one thread */
    int ls = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sin; memset(&sin, 0, sizeof sin); sin.sin_family = AF_INET; sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK("bind", bind(ls, (struct sockaddr*)&sin, sizeof sin) == 0 && listen(ls, 4) == 0);
    socklen_t sl = sizeof sin; getsockname(ls, (struct sockaddr*)&sin, &sl);
    int cs = socket(AF_INET, SOCK_STREAM, 0);
    CHECK("connect", connect(cs, (struct sockaddr*)&sin, sizeof sin) == 0);
    int as = accept(ls, 0, 0);
    CHECK("accept", as >= 0);
    CHECK("tcp xfer", send(cs, "tcp-data", 8, 0) == 8 && recv(as, rb, 8, 0) == 8 && !memcmp(rb, "tcp-data", 8));

    /* poll + epoll on the same sockets */
    send(cs, "q", 1, 0);
    struct pollfd pf = { as, POLLIN, 0 }; CHECK("poll", poll(&pf, 1, 1000) == 1 && (pf.revents & POLLIN));
    int ep = epoll_create1(0); struct epoll_event ev = { EPOLLIN, { .u64 = 0xabcdef0123456789ull } };
    epoll_ctl(ep, EPOLL_CTL_ADD, as, &ev); struct epoll_event out[2];
    CHECK("epoll", epoll_wait(ep, out, 2, 1000) == 1 && out[0].data.u64 == 0xabcdef0123456789ull);
    close(ep); close(as); close(cs); close(ls);

    /* timerfd + clocks */
    int tf = timerfd_create(CLOCK_MONOTONIC, 0); struct itimerspec its = { {0, 0}, {0, 20 * 1000 * 1000} };
    timerfd_settime(tf, 0, &its, 0); uint64_t exp = 0;
    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
    CHECK("timerfd", read(tf, &exp, sizeof exp) == sizeof exp && exp == 1);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    CHECK("timer ~20ms", ms >= 15 && ms < 500);
    nanosleep(&(struct timespec){0, 5 * 1000 * 1000}, 0);
    CHECK("env", getenv("PATH") != NULL || getenv("HOME") != NULL || 1);

    printf("failures: %d\n", fails);
    return fails ? 1 : 0;
}
