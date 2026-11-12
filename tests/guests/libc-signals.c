/* SPDX-License-Identifier: GPL-2.0-or-later */
/* libc-signals.c - guest signal handlers on a static-glibc AArch64 program: raise/kill to self with SA_SIGINFO,
 * sigqueue values, a blocked signal delivered on unblock, alarm()+pause(), nested handlers with sa_mask, SA_NODEFER,
 * pthread_kill to another thread, EINTR on a blocking read.  Delivery points of the recompiled runtime are syscall
 * returns, so every test arranges for a syscall after the signal is sent (raise/kill/pause/read all are).
 * Build: aarch64-linux-gnu-gcc -static -O1 -pthread tests/guests/libc-signals.c -o libc-signals-a64 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

static int fails;
#define CHECK(name, cond) do { int ok_ = !!(cond); printf("%-16s %s\n", name, ok_ ? "ok" : "FAIL"); if (!ok_) ++fails; } while (0)

static volatile sig_atomic_t hit_usr1, hit_usr2, order[8], norder, in_usr1;
static volatile int info_signo, info_code, info_pid, info_val;
static volatile long handler_tid;

static void h_simple(int s) { (void)s; hit_usr1++; order[norder++] = 1; }
static void h_info(int s, siginfo_t* si, void* uc) {
    (void)uc; info_signo = s; info_code = si->si_code; info_pid = si->si_pid; info_val = si->si_value.sival_int; hit_usr1++;
}
static void h_usr2(int s) { (void)s; hit_usr2++; order[norder++] = 2; }
static void h_nest(int s) {                      /* USR1 handler that raises USR2 (blocked by its sa_mask) */
    (void)s; in_usr1 = 1; order[norder++] = 10;
    raise(SIGUSR2);                              /* USR2 must NOT run until this handler returns */
    order[norder++] = 11; in_usr1 = 0;
}
static void h_usr2_check(int s) { (void)s; order[norder++] = in_usr1 ? 99 : 20; hit_usr2++; }
static void h_tid(int s) { (void)s; handler_tid = syscall(SYS_gettid); hit_usr1++; }
static void h_alarm(int s) { (void)s; hit_usr1++; }

static void install(int sig, void (*h)(int), int flags, int blockmask_sig) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = h; sa.sa_flags = flags; sigemptyset(&sa.sa_mask);
    if (blockmask_sig) sigaddset(&sa.sa_mask, blockmask_sig);
    sigaction(sig, &sa, 0);
}

static pthread_t main_thread;
static volatile int target_ready;
static void* waiter(void* a) {
    (void)a;
    install(SIGUSR1, h_tid, 0, 0);
    target_ready = 1;
    for (int i = 0; i < 400 && !hit_usr1; ++i) usleep(10000);      /* syscalls: delivery points */
    return 0;
}

int main(void) {
    setvbuf(stdout, 0, _IOLBF, 0);
    main_thread = pthread_self();

    install(SIGUSR1, h_simple, 0, 0);
    raise(SIGUSR1);
    CHECK("raise", hit_usr1 == 1);

    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = h_info; sa.sa_flags = SA_SIGINFO; sigemptyset(&sa.sa_mask); sigaction(SIGUSR1, &sa, 0);
    hit_usr1 = 0; kill(getpid(), SIGUSR1);
    CHECK("siginfo kill", hit_usr1 == 1 && info_signo == SIGUSR1 && info_code == SI_USER && info_pid == getpid());
    hit_usr1 = 0; union sigval v; v.sival_int = 4242; sigqueue(getpid(), SIGUSR1, v);
    CHECK("sigqueue", hit_usr1 == 1 && info_code == SI_QUEUE && info_val == 4242);

    install(SIGUSR2, h_usr2, 0, 0); hit_usr2 = 0;
    sigset_t blk, old; sigemptyset(&blk); sigaddset(&blk, SIGUSR2); sigprocmask(SIG_BLOCK, &blk, &old);
    raise(SIGUSR2);
    CHECK("blocked", hit_usr2 == 0);
    sigprocmask(SIG_SETMASK, &old, 0);                             /* the unblock delivers the pending signal */
    CHECK("unblock", hit_usr2 == 1);

    install(SIGALRM, h_alarm, 0, 0); hit_usr1 = 0; alarm(1);
    int r = pause();
    CHECK("alarm+pause", r == -1 && errno == EINTR && hit_usr1 == 1);

    install(SIGUSR1, h_nest, 0, SIGUSR2); install(SIGUSR2, h_usr2_check, 0, 0);
    norder = 0; hit_usr2 = 0; raise(SIGUSR1);
    CHECK("sa_mask nest", norder == 3 && order[0] == 10 && order[1] == 11 && order[2] == 20 && hit_usr2 == 1);

    install(SIGUSR1, h_simple, SA_NODEFER, 0); hit_usr1 = 0; raise(SIGUSR1); raise(SIGUSR1);
    CHECK("nodefer", hit_usr1 == 2);

    hit_usr1 = 0; handler_tid = 0; target_ready = 0;
    pthread_t t; pthread_create(&t, 0, waiter, 0);
    while (!target_ready) usleep(1000);
    usleep(20000);
    pthread_kill(t, SIGUSR1);
    pthread_join(t, 0);
    CHECK("pthread_kill", hit_usr1 == 1 && handler_tid != 0 && handler_tid != syscall(SYS_gettid));

    int p[2]; pipe(p);
    install(SIGALRM, h_alarm, 0, 0);                               /* no SA_RESTART: read() must fail with EINTR */
    hit_usr1 = 0;
    struct itimerval it = { {0, 0}, {0, 50000} }; setitimer(ITIMER_REAL, &it, 0);
    char c; ssize_t n = read(p[0], &c, 1);
    CHECK("read EINTR", n == -1 && errno == EINTR && hit_usr1 == 1);

    printf("failures: %d\n", fails);
    return fails ? 1 : 0;
}
