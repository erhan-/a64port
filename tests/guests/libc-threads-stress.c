/* SPDX-License-Identifier: GPL-2.0-or-later */
/* libc-threads-stress.c - static-glibc AArch64 guest that stresses the thread support of the recompiled runtime:
 * mutex contention, atomic counters (exclusive/LSE paths), condvar ping-pong, thread-specific data, a barrier,
 * return values through join, nested thread creation, a detached thread, and exit() called by a non-main thread.
 * Every line printed is deterministic.  Build: aarch64-linux-gnu-gcc -static -O1 -pthread tests/guests/libc-threads-stress.c */
#define _GNU_SOURCE
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NT 8
#define ITER 20000
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static long counter;
static atomic_long acounter;

static void* bump(void* a) {
    (void)a;
    for (int i = 0; i < ITER; ++i) {
        pthread_mutex_lock(&mu); ++counter; pthread_mutex_unlock(&mu);
        atomic_fetch_add_explicit(&acounter, 1, memory_order_relaxed);
    }
    return (void*)(size_t)ITER;
}

static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int turn, rounds;
static void* pingpong(void* a) {
    const int me = (int)(size_t)a;
    for (int i = 0; i < 2000; ++i) {
        pthread_mutex_lock(&mu);
        while (turn != me) pthread_cond_wait(&cv, &mu);
        ++rounds; turn = 1 - me;
        pthread_cond_broadcast(&cv);
        pthread_mutex_unlock(&mu);
    }
    return 0;
}

static pthread_key_t key;
static void* tsd(void* a) {
    pthread_setspecific(key, a);
    for (int i = 0; i < 1000; ++i) sched_yield();
    return pthread_getspecific(key) == a ? (void*)1 : (void*)0;
}

static pthread_barrier_t bar;
static atomic_int after_barrier;
static void* barrier_worker(void* a) {
    (void)a;
    pthread_barrier_wait(&bar);
    atomic_fetch_add(&after_barrier, 1);
    return 0;
}

static void* leaf(void* a) { return a; }
static void* nester(void* a) {
    pthread_t t; void* r = 0;
    if (pthread_create(&t, 0, leaf, a)) return 0;
    pthread_join(t, &r);
    return r;
}

static sem_t detached_done;
static void* detached(void* a) { (void)a; sem_post(&detached_done); return 0; }

static void* exiter(void* a) { (void)a; usleep(20000); printf("exiter calling exit(7)\n"); fflush(stdout); exit(7); return 0; }

int main(void) {
    setvbuf(stdout, 0, _IOLBF, 0);          /* progress is visible even if a run is killed */
    pthread_t t[NT];
    long total = 0;
    for (int i = 0; i < NT; ++i) pthread_create(&t[i], 0, bump, 0);
    for (int i = 0; i < NT; ++i) { void* r; pthread_join(t[i], &r); total += (long)(size_t)r; }
    printf("mutex counter  %ld (expect %d)\n", counter, NT * ITER);
    printf("atomic counter %ld (expect %d)\n", (long)atomic_load(&acounter), NT * ITER);
    printf("join values    %ld\n", total);

    pthread_t a, b;
    pthread_create(&a, 0, pingpong, (void*)0); pthread_create(&b, 0, pingpong, (void*)1);
    pthread_join(a, 0); pthread_join(b, 0);
    printf("pingpong       %d rounds\n", rounds);

    pthread_key_create(&key, 0);
    int good = 0;
    for (int i = 0; i < NT; ++i) pthread_create(&t[i], 0, tsd, (void*)(size_t)(i + 1));
    for (int i = 0; i < NT; ++i) { void* r; pthread_join(t[i], &r); good += (int)(size_t)r; }
    printf("tsd            %d/%d\n", good, NT);

    pthread_barrier_init(&bar, 0, NT + 1);
    for (int i = 0; i < NT; ++i) pthread_create(&t[i], 0, barrier_worker, 0);
    pthread_barrier_wait(&bar);
    for (int i = 0; i < NT; ++i) pthread_join(t[i], 0);
    printf("barrier        %d\n", (int)atomic_load(&after_barrier));

    pthread_create(&a, 0, nester, (void*)0x1234); void* r = 0; pthread_join(a, &r);
    printf("nested         %p\n", r);

    sem_init(&detached_done, 0, 0);
    pthread_create(&a, 0, detached, 0); pthread_detach(a);
    sem_wait(&detached_done);
    printf("detached       ok\n");

    pthread_create(&a, 0, exiter, 0);
    sleep(5);                      /* the exiter ends the whole process with status 7 */
    printf("not reached\n");
    return 1;
}
