/* SPDX-License-Identifier: GPL-2.0-or-later */
/* libc-threads.c - threads in the standalone runtime: pthread_create/join, mutex and condvar.
 * Exit 0 = every worker ran and the mutex/condvar handshake completed.
 * Build: aarch64-linux-gnu-gcc -static -O1 -pthread tests/guests/libc-threads.c -o libc-threads-a64 */
#include <pthread.h>
#include <stdio.h>
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static long sum; static int done;
static void* worker(void* a) {
    long v = 0; for (int i = 1; i <= 1000; ++i) v += i * (long)(size_t)a;
    pthread_mutex_lock(&mu); sum += v; ++done; pthread_cond_signal(&cv); pthread_mutex_unlock(&mu);
    return 0;
}
int main(void) {
    pthread_t t[4];
    for (long i = 0; i < 4; ++i) if (pthread_create(&t[i], 0, worker, (void*)(i + 1))) { puts("create failed"); return 2; }
    pthread_mutex_lock(&mu); while (done < 4) pthread_cond_wait(&cv, &mu); pthread_mutex_unlock(&mu);
    for (int i = 0; i < 4; ++i) pthread_join(t[i], 0);
    printf("sum=%ld\n", sum);
    return sum == 5005000L ? 0 : 1;
}
