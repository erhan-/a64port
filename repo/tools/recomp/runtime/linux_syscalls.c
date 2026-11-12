/* SPDX-License-Identifier: GPL-2.0-or-later */
/* linux_syscalls.c — a64port platform shim for mk8-recomp-emitted C.
 *
 * We are translating a *Linux* AArch64 userland, so this replaces the generated
 * project's Switch/Horizon pieces:
 *
 *   - main(): allocates the guest address space, places every loadable section
 *     at its link address, applies relocations, builds the initial process
 *     stack (argc/argv/envp/auxv, which static glibc reads for AT_HWCAP,
 *     AT_PHDR, AT_RANDOM ...), and runs the dispatcher.
 *
 *   - recomp_svc(): Linux AArch64 syscall ABI — svc #0, number in x8, args in
 *     x0..x5, result in x0, errors as -errno. The host side calls host libc, so
 *     this file is target-independent: it compiles unchanged for x86-64 and
 *     ARMv7. What differs between hosts is *struct layout*, which matters only
 *     for syscalls that pass structs (stat, rlimit, ...); each of those is
 *     translated explicitly at the boundary.
 *
 *   - guest memory services: the whole guest address space is one host
 *     allocation, so brk and mmap hand out ranges of it instead of calling the
 *     host kernel, and mprotect/madvise are no-ops. That is only sound because
 *     the image is loaded at its link addresses (module base 0), which makes
 *     every guest VA a fixed host offset.
 *
 * A system call the runtime does not implement returns ENOSYS and is logged once
 * (A64PORT_HALT_UNIMPLEMENTED=1 halts instead), as a kernel without it would.
 */

/* glibc hides openat/fstatat/readlinkat/st_atim under strict -std=c11 unless a
   feature-test macro is set. Defined before any include. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <math.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/msg.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/select.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* A program-specific layer (fabricated device nodes, network tweaks and shell probes: see
   runtime/app_none.inc for the hooks) is included when present, unless A64PORT_APP_NONE; otherwise app_none.inc makes a generic guest. */

#include "recomp_runtime.h"
#include "layout.h"

extern uint64_t g_module_base;

static int g_exit_code = 0;

/* ── guest memory ─────────────────────────────────────────────────────────── */

static void* GuestPtr(GuestContext* c, uint64_t va, uint64_t len) {
    if (va < c->mem_base_vaddr) return NULL;
    const uint64_t off = va - c->mem_base_vaddr;
    if (off > c->mem_size || c->mem_size - off < len) return NULL;
    /* A64PORT_SLOT_WATCH (see recomp_runtime.c): catch a syscall path that
       writes into the watched guest window (pc = the guest call site, x8 =
       the syscall number it is serving). */
    {
        static uint64_t sw; static int sw_init;
        if (!sw_init) {
            sw_init = 1;
            const char* e = getenv("A64PORT_SLOT_WATCH");
            if (e && *e) sw = strtoull(e, 0, 16);
        }
        if (sw && va < sw + 0x28 && va + len > sw - 0x20)
            fprintf(stderr, "[slot] syscall-touch va=0x%llx len=%llu pc=0x%llx x8=%llu\n",
                    (unsigned long long)va, (unsigned long long)len,
                    (unsigned long long)c->pc, (unsigned long long)c->x[8]);
    }
    return c->mem + off;
}

static uint64_t RetU(ssize_t r) { return r < 0 ? (uint64_t)(-errno) : (uint64_t)r; }

/* ── per-thread host tid, cached ───────────────────────────────────────────
   The shim asked for its own tid on every futex, set_tid_address and gettid
   — 5.1k real syscalls/s in a busy run — and a host thread's tid never
   changes, so cache it in TLS. */
static __thread uint32_t t_shim_tid;
static uint32_t shim_tid(void) {
    if (!t_shim_tid) t_shim_tid = (uint32_t)gettid();
    return t_shim_tid;
}

/* Arena anchor, captured on the first guest syscall so host-side code with
   no GuestContext (the thread-exit futex wake) can resolve guest VAs.  Every
   guest thread shares one arena, so any context is as good as another. */
static uint8_t* g_arena_mem;
static uint64_t g_arena_base, g_arena_size;
static void arena_capture(GuestContext* c) {
    if (!g_arena_mem) {
        g_arena_mem = c->mem;
        g_arena_base = c->mem_base_vaddr;
        g_arena_size = c->mem_size;
    }
}

/* ── LD1-LD4 / ST1-ST4 in one native call ─────────────────────────────────
   Declared in neon_structs.h, which build-guest.sh force-includes into every
   generated translation unit. The body lives here (the standalone host),
   because a64recomp regenerates recomp_runtime.[ch] on every emit and would
   clobber it. See runtime/neon_structs.h for why this exists: the emitter used
   to expand one NEON structure access into 64 scalar loads plus 64 memcpys.

   Weak on purpose: the multi-module host (host_loader.c) already defines this
   function, and the multi build links linux_syscalls.c and host_loader.c into the
   same binary. A strong definition here would be a duplicate symbol and break
   that link; weak lets the multi host's copy win while the standalone
   build-guest.sh link still has a definition. */
/* Defined in recomp_runtime.c.  A structure store is a store to the granule, so
   it must retire any local reservation there, exactly as a plain store does. */
extern void recomp_excl_store_touch(uint64_t a, uint32_t size);
__attribute__((weak))
void recomp_ldst_struct(GuestContext* c, uint64_t addr, uint32_t rt,
                        uint32_t regs, uint32_t lanes, uint32_t esz,
                        uint32_t step, uint32_t load, uint32_t bytes)
{
    uint8_t tmp[4][16];
    const uint32_t total = lanes * regs * esz;          /* <= 64 */
    uint8_t* fast = NULL;
    if (addr >= c->mem_base_vaddr &&
        addr - c->mem_base_vaddr + total <= c->mem_size)
        fast = c->mem + (addr - c->mem_base_vaddr);

    if (load) {
        if (fast) {
            if (step == 1) {                            /* contiguous per register */
                for (uint32_t r = 0; r < regs; ++r)
                    memcpy(tmp[r], fast + (size_t)r * lanes * esz, lanes * esz);
            } else {                                    /* byte de-interleave */
                /* Incremental (e,r) instead of k%regs / k/regs (regs and lanes
                   are runtime, so the division cannot be folded). esz is
                   1/2/4/8 for every structural access a guest executes, so
                   switch on it: a constant-size memcpy is inlined, where a
                   runtime-size one is a call per element (one per byte for
                   ld4 {v8-v11}.16b, a common hot ldst site). */
                uint32_t e = 0, r = 0;
                switch (esz) {
                case 1:
                    for (uint32_t k = 0; k < lanes * regs; ++k) {
                        tmp[r][e] = fast[k];
                        if (++r == regs) { r = 0; ++e; }
                    }
                    break;
                case 2:
                    for (uint32_t k = 0; k < lanes * regs; ++k) {
                        memcpy(&tmp[r][e * 2], fast + (size_t)k * 2, 2);
                        if (++r == regs) { r = 0; ++e; }
                    }
                    break;
                case 4:
                    for (uint32_t k = 0; k < lanes * regs; ++k) {
                        memcpy(&tmp[r][e * 4], fast + (size_t)k * 4, 4);
                        if (++r == regs) { r = 0; ++e; }
                    }
                    break;
                case 8:
                    for (uint32_t k = 0; k < lanes * regs; ++k) {
                        memcpy(&tmp[r][e * 8], fast + (size_t)k * 8, 8);
                        if (++r == regs) { r = 0; ++e; }
                    }
                    break;
                default:
                    for (uint32_t k = 0; k < lanes * regs; ++k) {
                        memcpy(&tmp[r][e * esz], fast + (size_t)k * esz, esz);
                        if (++r == regs) { r = 0; ++e; }
                    }
                    break;
                }
            }
        } else {
            memset(tmp, 0, sizeof tmp);
            for (uint32_t k = 0; k < lanes * regs; ++k) {
                const uint64_t v = recomp_load64(c, addr + (uint64_t)k * esz);
                if (step == 1) memcpy(&tmp[k / lanes][(k % lanes) * esz], &v, esz);
                else           memcpy(&tmp[k % regs][(k / regs) * esz], &v, esz);
            }
        }
        for (uint32_t r = 0; r < regs; ++r) {
            const uint32_t idx = (rt + r) & 31u;
            memcpy((uint8_t*)&c->vreg[idx][0], tmp[r], bytes);
            if (bytes <= 8) c->vreg[idx][1] = 0;        /* 64-bit forms clear the top */
        }
        return;
    }

    for (uint32_t r = 0; r < regs; ++r)
        memcpy(tmp[r], (const uint8_t*)&c->vreg[(rt + r) & 31u][0], bytes);
    /* A structure store is a store to the granule, so it retires the local
       reservation there.  Without this a guest doing ldxr / st1 / stxr has its
       store-exclusive succeed here and fail on hardware. */
    recomp_excl_store_touch(addr, total ? total : 1);
    if (fast) {
        if (step == 1) {
            for (uint32_t r = 0; r < regs; ++r)
                memcpy(fast + (size_t)r * lanes * esz, tmp[r], lanes * esz);
        } else {
            uint32_t e = 0, r = 0;
            switch (esz) {
            case 1:
                for (uint32_t k = 0; k < lanes * regs; ++k) {
                    fast[k] = tmp[r][e];
                    if (++r == regs) { r = 0; ++e; }
                }
                break;
            case 2:
                for (uint32_t k = 0; k < lanes * regs; ++k) {
                    memcpy(fast + (size_t)k * 2, &tmp[r][e * 2], 2);
                    if (++r == regs) { r = 0; ++e; }
                }
                break;
            case 4:
                for (uint32_t k = 0; k < lanes * regs; ++k) {
                    memcpy(fast + (size_t)k * 4, &tmp[r][e * 4], 4);
                    if (++r == regs) { r = 0; ++e; }
                }
                break;
            case 8:
                for (uint32_t k = 0; k < lanes * regs; ++k) {
                    memcpy(fast + (size_t)k * 8, &tmp[r][e * 8], 8);
                    if (++r == regs) { r = 0; ++e; }
                }
                break;
            default:
                for (uint32_t k = 0; k < lanes * regs; ++k) {
                    memcpy(fast + (size_t)k * esz, &tmp[r][e * esz], esz);
                    if (++r == regs) { r = 0; ++e; }
                }
                break;
            }
        }
        return;
    }
    for (uint32_t k = 0; k < lanes * regs; ++k) {
        const uint32_t e = step == 1 ? k % lanes : k / regs;
        const uint32_t r = step == 1 ? k / lanes : k % regs;
        uint64_t v = 0;
        memcpy(&v, &tmp[r][e * esz], esz);
        recomp_store64(c, addr + (uint64_t)k * esz, v);
    }
}

#include "app_none.inc"

static int guest_setsockopt(GuestContext* c, int fd, int level, int opt,
                            uint64_t val_va, uint64_t len) {
    void* val = len ? GuestPtr(c, val_va, len) : NULL;
    if (len && !val) { errno = EFAULT; return -1; }
    if (level == SOL_SOCKET && opt == SO_BINDTODEVICE && val && len) {
        char requested[IFNAMSIZ] = {0};
        size_t n = len < IFNAMSIZ ? (size_t)len : IFNAMSIZ;
        memcpy(requested, val, n);
        requested[IFNAMSIZ - 1] = 0;
        if (guest_ifname_is_alias(requested)) {
            char real[IFNAMSIZ] = {0};
            snprintf(real, sizeof real, "%s", host_link_iface());
            return setsockopt(fd, level, opt, real, (socklen_t)(strlen(real) + 1));
        }
    }
#if UINTPTR_MAX == 0xffffffffu
    /* SO_RCVTIMEO/SO_SNDTIMEO (20/21 on aarch64) carry the guest's 16-byte
       {int64 sec, int64 usec} timeval; the host's option 20/21 is the 8-byte
       32-bit one and fails with EINVAL.  Hand the host a struct timeval and its
       own option name: under _TIME_BITS=64 that is SO_*TIMEO_NEW, which glibc
       falls back from on kernels without it. */
    if (level == SOL_SOCKET && (opt == 20 || opt == 21) && val && len == 16) {
        const int64_t* g = (const int64_t*)val;
        struct timeval tv = { (time_t)g[0], (suseconds_t)g[1] };
        return setsockopt(fd, level, opt == 20 ? SO_RCVTIMEO : SO_SNDTIMEO, &tv, sizeof tv);
    }
#endif
    return setsockopt(fd, level, opt, val, (socklen_t)len);
}


/* ── hooks the kernel-faithful multi-module host overrides ──────────────────
   The single-image build keeps the defaults below, so its behaviour is
   unchanged. The multi-module host (host_loader.c) provides strong definitions
   that resolve guest paths inside the guest rootfs and manage the guest
   address space itself, because there ld.so - not this file - is the loader. */
__attribute__((weak)) const char* a64port_guest_path(const char* p) { return p; }
__attribute__((weak)) void a64port_guest_note_open(int fd, const char* guest_path) {
    (void)fd; (void)guest_path;
}
/* True if a .so path is one of the DSOs the emitter translated. Any other DSO
   must never be dlopen'd: the loader would map raw AArch64 bytes and the first
   constructor/PLT call would halt the thread inside _dl_open, leaving the loader
   lock held and deadlocking every later resolve. The multi-module host overrides
   this with the real module list. */
__attribute__((weak)) int a64port_known_dso(const char* guest_path) {
    (void)guest_path; return 1;
}
__attribute__((weak)) int a64port_guest_mmap(uint64_t* addr_io, uint64_t len, int prot,
                                            uint64_t flags, int fd, uint64_t off) {
    (void)addr_io; (void)len; (void)prot; (void)flags; (void)fd; (void)off;
    return 0;                       /* not handled: use the built-in policy */
}
void a64port_guest_munmap(uint64_t va, uint64_t len);     /* defined with the allocator below (weak: the multi host overrides it) */

/* Guest threads of the standalone (single-image) runtime.  A CLONE_THREAD clone starts a host pthread that runs
   the child context with recomp_run(), like the kernel does for clone(): the child's tid (= the host thread's tid,
   which the PI futexes and tgkill need) is published to PARENT_SETTID / CHILD_SETTID before either side runs guest
   code, and when the child's code ends CHILD_CLEARTID is zeroed and futex-woken (pthread_join waits on it).  Not
   handled: fork-style clones (-> ENOSYS).  The multi-module host provides its own, strong a64port_guest_clone. */
int a64port_futex_wake(uint64_t va, int n);
static void sa_run(GuestContext* c);       /* the standalone dispatch loop, below */
__thread int a64port_sa_thread;          /* set on threads started below: their exit does not set the process status */
typedef struct SaThread {
    GuestContext ctx;
    uint64_t flags, ptid, ctid;
    uint32_t tid;
    int ready, refs;                    /* refs: the creator and the thread; the last one frees */
    pthread_mutex_t mu;
    pthread_cond_t cv;
} SaThread;
static void sa_store32(GuestContext* c, uint64_t va, uint32_t v) {
    uint32_t* p = (uint32_t*)GuestPtr(c, va, 4);
    if (p) __atomic_store_n(p, v, __ATOMIC_SEQ_CST);
}
static void sa_release(SaThread* t) {
    if (__atomic_sub_fetch(&t->refs, 1, __ATOMIC_ACQ_REL) == 0) {
        pthread_cond_destroy(&t->cv);
        pthread_mutex_destroy(&t->mu);
        free(t);
    }
}
static void* sa_thread_entry(void* arg) {
    SaThread* t = (SaThread*)arg;
    a64port_sa_thread = 1;
    const uint32_t tid = shim_tid();
    if (t->flags & UINT64_C(0x00100000)) sa_store32(&t->ctx, t->ptid, tid);   /* CLONE_PARENT_SETTID */
    if (t->flags & UINT64_C(0x01000000)) sa_store32(&t->ctx, t->ctid, tid);   /* CLONE_CHILD_SETTID */
    pthread_mutex_lock(&t->mu);
    t->tid = tid;
    t->ready = 1;
    pthread_cond_signal(&t->cv);
    pthread_mutex_unlock(&t->mu);
    sa_run(&t->ctx);
    if ((t->flags & UINT64_C(0x00200000)) && t->ctid) {                       /* CLONE_CHILD_CLEARTID */
        sa_store32(&t->ctx, t->ctid, 0);
        recomp_excl_store_touch(t->ctid, 4);
        a64port_futex_wake(t->ctid, 0x7fffffff);
    }
    sa_release(t);
    return NULL;
}
__attribute__((weak)) int64_t a64port_guest_clone(GuestContext* parent, GuestContext* child,
                                                 uint64_t flags, uint64_t ptid,
                                                 uint64_t tls, uint64_t ctid) {
    (void)parent;
    if (!(flags & UINT64_C(0x10000)))        /* not CLONE_THREAD */
        return -1;                           /* not handled without the multi-module host */
    SaThread* t = (SaThread*)calloc(1, sizeof *t);
    if (!t) return -EAGAIN;
    t->ctx = *child;
#ifdef RECOMP_HAS_CALL_DEPTH
    t->ctx.call_depth = 0;                   /* a new thread has no host call frames */
#endif
    if (flags & UINT64_C(0x00080000)) t->ctx.tpidr_el0 = tls;                 /* CLONE_SETTLS */
    t->flags = flags; t->ptid = ptid; t->ctid = ctid;
    t->refs = 2;
    pthread_mutex_init(&t->mu, NULL);
    pthread_cond_init(&t->cv, NULL);
    pthread_t host;
    const int err = pthread_create(&host, NULL, sa_thread_entry, t);
    if (err != 0) {
        fprintf(stderr, "[a64port] clone: pthread_create failed: %s\n", strerror(err));
        t->refs = 1;
        sa_release(t);
        return -EAGAIN;
    }
    pthread_detach(host);
    pthread_mutex_lock(&t->mu);              /* clone() returns in the parent only after the tid is published */
    while (!t->ready) pthread_cond_wait(&t->cv, &t->mu);
    const uint32_t tid = t->tid;
    pthread_mutex_unlock(&t->mu);
    sa_release(t);
    return (int64_t)tid;
}

/* The multi-module host records a vfork child's exit here so wait4 can report
   it. Weak: the single-image build has no children, so the defaults are inert. */
static int g_child_pid, g_child_status;
__attribute__((weak)) void a64port_guest_child_exited(int pid, int status) {
    g_child_pid = pid; g_child_status = status;
}

/* Nonzero while the multi host runs a simulated vfork child on this host
   thread (it shares the parent's process, so its exit_group must only end
   the child).  Set by host_loader.c around the child's dispatch loop. */
__thread int a64port_vfork_child;

/* exit_group(2): end the whole process.  Returns 0 when not handled, which
   keeps the single-image build's behaviour (halt the only thread; main()
   then reports and returns the status).  The multi host overrides this and
   never returns. */
__attribute__((weak)) int a64port_guest_exit_group(GuestContext* c, int status) {
    (void)c;
    if (a64port_sa_thread) {                  /* a standalone-runtime thread: ending only it would leave main running */
        fflush(NULL);
        _exit(status);
    }
    return 0;
}

/* The launchers always export the diagnostic switches (as "0" when off), and a
   bare getenv() truthiness test treats "0" as ON - which left the syscall trace
   enabled in every run and turned bring-up into megabytes of stderr writes.
   Treat "" and "0" as off. */
static int EnvOn_(const char* name) {
    const char* v = getenv(name);
    return v && *v && strcmp(v, "0") != 0;
}
/* Cached per call site: the hot paths (futex wake, poll, device read/write, writev, timers) asked getenv() on every
   call - ~0.5 % of a core in all.  The launcher exports these before the start and nothing
   changes them later (the only host setenv is A64PORT_ALLOCWATCH, at startup, not read here). */
#define EnvOn(name) __extension__({ static int env_on_ = -1; if (env_on_ < 0) env_on_ = EnvOn_(name); env_on_; })

static int g_syscall_trace = -1;
static int g_drm_trace __attribute__((unused)) = -1;   /* used by app_layer/devices.inc */
static int g_mmap_diag;

/* Guest signal dispositions. The host cannot deliver a guest handler address,
   but it can honour SIG_DFL/SIG_IGN - which is what stops a stray SIGPIPE from
   killing the whole translated process. */
#define A64PORT_NSIG 65
static struct { uint64_t handler, flags, restorer, mask; } g_guest_sigact[A64PORT_NSIG];

/* SysV shared-memory attachments (X11 MIT-SHM). */
#define A64PORT_MAX_SHM 64
static struct { int shmid; uint64_t va, len, rva, rlen; } g_shm_attach[A64PORT_MAX_SHM];
static int g_shm_n;

/* ── guest futex: real blocking, needed once clone creates threads ─────────
   a large threaded program issues millions of futex operations, and every one of them used to walk a
   single global linked list - futex_wake() scanned *every* node in the process
   on every call - all under one mutex.  Hash the nodes by address so a lookup
   touches one bucket. */
typedef struct FutexNode {
    uint64_t va;
    pthread_cond_t cond;
    int waiters;
    struct FutexNode* next;
} FutexNode;
static pthread_mutex_t g_futex_mu = PTHREAD_MUTEX_INITIALIZER;
#define FUTEX_NBUCKET 1024u
static FutexNode* g_futex_buckets[FUTEX_NBUCKET];

static unsigned futex_hash(uint64_t va) {
    return (unsigned)((va >> 3) ^ (va >> 13) ^ (va >> 23)) & (FUTEX_NBUCKET - 1u);
}

static FutexNode* futex_find(uint64_t va) {
    for (FutexNode* n = g_futex_buckets[futex_hash(va)]; n; n = n->next)
        if (n->va == va) return n;
    return NULL;
}

/* Caller holds g_futex_mu. */
static FutexNode* futex_node(uint64_t va) {
    FutexNode* found = futex_find(va);
    if (found) return found;
    const unsigned h = futex_hash(va);
    FutexNode* n = (FutexNode*)calloc(1, sizeof *n);
    if (!n) return NULL;
    n->va = va;
    pthread_cond_init(&n->cond, NULL);
    n->next = g_futex_buckets[h];
    g_futex_buckets[h] = n;
    return n;
}

/* 0 = woken, -EAGAIN = value changed, -ETIMEDOUT = timeout. The value is
   re-checked under the mutex, the same discipline the kernel uses. */
static int futex_wait(GuestContext* c, uint64_t va, uint32_t val,
                      const struct timespec* to) {
    uint32_t* u = (uint32_t*)GuestPtr(c, va, 4);
    if (!u) return -EFAULT;
    pthread_mutex_lock(&g_futex_mu);
    if (__atomic_load_n(u, __ATOMIC_RELAXED) != val) {
        pthread_mutex_unlock(&g_futex_mu);
        return -EAGAIN;
    }
    FutexNode* n = futex_node(va);
    if (!n) { pthread_mutex_unlock(&g_futex_mu); return -ENOMEM; }
    if (EnvOn("A64PORT_FUTEX_DIAG")) {
        const int32_t* m = (const int32_t*)u;
        double wait_s = -1.0;
        if (to) {
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            wait_s = (double)(to->tv_sec - now.tv_sec) +
                     (double)(to->tv_nsec - now.tv_nsec) / 1e9;
        }
        fprintf(stderr, "[futex] wait va=0x%llx val=%u lock=%d count=%u owner=%d kind=%d tid=%u"
                        " wait_s=%.3f%s\n",
                (unsigned long long)va, val, m[0], (unsigned)m[1], m[2], m[4],
                (unsigned)gettid(), wait_s, wait_s < 0 ? " (blocking)" : "");
    }
    n->waiters++;
    int rc = to ? pthread_cond_timedwait(&n->cond, &g_futex_mu, to)
                : pthread_cond_wait(&n->cond, &g_futex_mu);
    n->waiters--;
    pthread_mutex_unlock(&g_futex_mu);
    return (rc == ETIMEDOUT) ? -ETIMEDOUT : 0;
}

static int futex_wake(GuestContext* c, uint64_t va, int n) {
    (void)c;
    if (n <= 0) return 0;
    int woken = 0;
    pthread_mutex_lock(&g_futex_mu);
    FutexNode* x = futex_find(va);
    if (x) {
        /* One node per address holds every waiter on that address, so a
           FUTEX_WAKE(INT_MAX) (glibc's broadcast) must wake ALL of them, not
           just one - signalling each node once left every other waiter asleep. */
        if (n >= x->waiters) {
            pthread_cond_broadcast(&x->cond);
            woken += x->waiters;
        } else {
            for (int i = 0; i < n; ++i) pthread_cond_signal(&x->cond);
            woken += n;
        }
    }
    pthread_mutex_unlock(&g_futex_mu);
    if (EnvOn("A64PORT_FUTEX_DIAG"))
        fprintf(stderr, "[futex] WAKE va=0x%llx n=%d woken=%d tid=%u\n",
                (unsigned long long)va, n, woken, (unsigned)gettid());
    return woken;
}

/* ── plain futexes: forward to the host kernel ─────────────────────────────
   The emulated table below (one global process-wide mutex + a condvar per
   address + two clock_gettime calls per timed wait) was, together with the
   translated wrappers around it, ~65 % of all guest CPU in a busy run:
   a multi-threaded GUI application waits and wakes through it thousands of times a second.
   The PI ops already go to the host kernel, relying on exactly the two
   facts the plain ops need too — guest words have stable host addresses
   (the flat arena) and hold host tids.  The guest Linux futex ABI (op
   numbers, PRIVATE/CLOCK_REALTIME flag bits, timespec layout, 32-bit words,
   -errno returns) is identical on aarch64 and x86-64, so op, value, timeout
   and bitset pass through unchanged and a blocked waiter costs no CPU at
   all.  A64PORT_FUTEX_EMUL=1 keeps the emulated table (A/B, escape hatch).
   Returns 1 when serviced (result in *out), 0 when the switch below must
   handle the op (PI ops, WAIT_REQUEUE_PI, or an untranslatable uaddr2). */
/* A host futex with a GUEST timeout: gts is the guest's {int64 sec, int64 nsec}
   (or NULL).  On an LP64 host that is the kernel's struct timespec, so it goes
   straight to SYS_futex as it always has.  On an ILP32 host (ARMv7) SYS_futex is
   the old call that reads {int32 sec, int32 nsec}: handing it the guest's
   16 bytes made every timeout lose its nanoseconds (a 10 ms wait became 0 and
   spun; an absolute deadline was cut to the whole second).  There the guest
   layout IS struct __kernel_timespec, so SYS_futex_time64 (Linux >= 5.1) takes
   it unchanged; older kernels get it converted to 32-bit fields. */
static long host_futex_timed(void* u, int op, int val, const int64_t* gts,
                             void* u2, int val3) {
#if UINTPTR_MAX == 0xffffffffu
#ifdef SYS_futex_time64
    static int no_time64;
    if (!__atomic_load_n(&no_time64, __ATOMIC_RELAXED)) {
        const long r = syscall(SYS_futex_time64, u, op, val, gts, u2, val3);
        if (!(r < 0 && errno == ENOSYS)) return r;
        __atomic_store_n(&no_time64, 1, __ATOMIC_RELAXED);
    }
#endif
    if (gts) {
        struct { int32_t sec, nsec; } t32 = { (int32_t)gts[0], (int32_t)gts[1] };
        return syscall(SYS_futex, u, op, val, &t32, u2, val3);
    }
    return syscall(SYS_futex, u, op, val, NULL, u2, val3);
#else
    return syscall(SYS_futex, u, op, val, gts, u2, val3);
#endif
}

static int futex_kernel_forward(GuestContext* c, uint32_t* u, uint32_t opall,
                                uint64_t* out) {
    switch (opall & 0x7fu) {
    case 0:  /* FUTEX_WAIT: relative timeout, CLOCK_MONOTONIC */
    case 9: { /* FUTEX_WAIT_BITSET: absolute; REALTIME iff flag 0x100 */
        const int64_t* tp = NULL;
        if (c->x[3]) {
            tp = (const int64_t*)GuestPtr(c, c->x[3], 16);
            if (!tp) { *out = (uint64_t)(-EFAULT); return 1; }
        }
        long r = host_futex_timed(u, (int)opall, (int)(uint32_t)c->x[2],
                                  tp, NULL, (int)c->x[5]);    /* bitset: 0 is EINVAL */
        *out = r < 0 ? (uint64_t)(-errno) : (uint64_t)r;
        return 1;
    }
    case 1:  /* FUTEX_WAKE */
    case 10: /* FUTEX_WAKE_BITSET (x5 = bitset) */
    {
        long r = syscall(SYS_futex, u, (int)opall, (int)(uint32_t)c->x[2],
                         NULL, NULL, (unsigned long)c->x[5]);
        *out = r < 0 ? (uint64_t)(-errno) : (uint64_t)r;
        return 1;
    }
    case 3:  /* FUTEX_REQUEUE */
    case 4: { /* FUTEX_CMP_REQUEUE: x3 is nr_requeue (an integer carried in
                 the timeout slot, passed by value — no translation), x5 the
                 expected word for the CMP form */
        uint32_t* u2 = (uint32_t*)GuestPtr(c, c->x[4], 4);
        if (!u2) return 0;          /* untranslatable uaddr2: emulate below */
        long r = syscall(SYS_futex, u, (int)opall, (int)(uint32_t)c->x[2],
                         (void*)(uintptr_t)c->x[3], u2, (unsigned long)c->x[5]);
        *out = r < 0 ? (uint64_t)(-errno) : (uint64_t)r;
        return 1;
    }
    default:
        return 0;
    }
}

/* For the multi host's CLONE_CHILD_CLEARTID: guest waiters (pthread_join, the
   glibc stack cache) now sleep in the HOST KERNEL, so the wake that follows
   the kernel-style "store 0 to *ctid" must be a real FUTEX_WAKE on the host
   address of the word. */
int a64port_futex_wake(uint64_t va, int n) {
    if (g_arena_mem && va >= g_arena_base && va - g_arena_base <= g_arena_size - 4) {
        const long r = syscall(SYS_futex, g_arena_mem + (va - g_arena_base),
                               1 /* FUTEX_WAKE */, n, NULL, NULL, 0);
        return r < 0 ? 0 : (int)r;
    }
    return futex_wake(NULL, va, n);   /* no arena seen yet: the old table */
}

/* AArch64/asm-generic open flags do NOT match x86-64's in three bits, and the
   guest's are passed straight to the host openat():

     flag        guest (aarch64)   host (x86-64)
     O_DIRECT    0x10000           0x4000
     O_DIRECTORY 0x4000            0x10000
     O_NOFOLLOW  0x8000            0x20000
     O_LARGEFILE 0x20000           0

   So open(dir, O_DIRECTORY) arrived as host O_DIRECT and failed with EINVAL.
   That is exactly fontconfig's directory scan of /usr/share/fonts, so it found
   no fonts, the app never loaded one, and no text was drawn. Translate the
   arch-specific bits explicitly. */
/* 32-bit hosts: the guest's {int64 sec, int64 nsec} timespec is the kernel's 64-bit one,
   so use the *_time64 calls (ARM numbers; glibc < 2.32 has no SYS_ names for them). */
#if UINTPTR_MAX == 0xffffffffu
#  define A64PORT_SYS_rt_sigtimedwait_time64 421
#  define A64PORT_SYS_timer_gettime 408
#  define A64PORT_SYS_timer_settime 409
#else
#  define A64PORT_SYS_timer_gettime SYS_timer_gettime
#  define A64PORT_SYS_timer_settime SYS_timer_settime
#endif
#define A64PORT_O_DIRECTORY 0x4000u
#define A64PORT_O_NOFOLLOW  0x8000u
#define A64PORT_O_DIRECT    0x10000u
#define A64PORT_O_LARGEFILE 0x20000u
static int HostOpenFlags(uint32_t g) {
    int h = (int)(g & ~(A64PORT_O_DIRECTORY | A64PORT_O_NOFOLLOW | A64PORT_O_DIRECT |
                        A64PORT_O_LARGEFILE));
#ifdef O_DIRECTORY
    if (g & A64PORT_O_DIRECTORY) h |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    if (g & A64PORT_O_NOFOLLOW) h |= O_NOFOLLOW;
#endif
#ifdef O_DIRECT
    if (g & A64PORT_O_DIRECT) h |= O_DIRECT;
#endif
    return h;
}

/* Guest-side struct layouts that differ from the host's. AArch64 is LP64 and so
   is x86-64, so these happen to match there - but the shim must stay correct on
   an ILP32 host (ARMv7), where iovec/timeval/timespec are 32-bit. Every one of
   these is therefore translated field by field rather than cast. */
struct GuestIovec { uint64_t base, len; };

/* AArch64 struct epoll_event: NOT packed, so 16 bytes with `data` at offset 8.
   x86-64 declares it __attribute__((packed)) - 12 bytes, `data` at 4 - which
   is why epoll is translated rather than passed through. */
struct GuestEpollEvent { uint32_t events; uint32_t pad; uint64_t data; };

/* Translate a guest iovec array (16 bytes per entry, each holding a guest VA)
   into host iovecs. Shared by readv/writev and the msg syscalls. */
static int XlateIov(GuestContext* c, uint64_t gva, uint64_t cnt, struct iovec* hi, int max) {
    if (cnt > (uint64_t)max) return -1;
    if (cnt == 0) return 0;
    const struct GuestIovec* gi = (const struct GuestIovec*)GuestPtr(c, gva, cnt * 16);
    if (!gi) return -1;
    for (uint64_t i = 0; i < cnt; ++i) {
        uint8_t* b = GuestPtr(c, gi[i].base, gi[i].len);
        if (!b && gi[i].len) return -1;
        hi[i].iov_base = b;
        hi[i].iov_len = (size_t)gi[i].len;
    }
    return 0;
}

/* aarch64 struct msghdr: 56 bytes of 8- and 4-byte fields, so it is NOT the
   host's layout on an ILP32 machine even though it is on this LP64 one. */
struct GuestMsghdr {
    uint64_t name; uint32_t namelen; uint32_t pad0;
    uint64_t iov; uint64_t iovlen;
    uint64_t control; uint64_t controllen;
    int32_t flags; uint32_t pad1;
};

/* aarch64 structs whose fields are kernel `long`s: identical to the host's on
   LP64, different on ILP32, so they are converted field by field rather than
   memcpy'd. */
struct GuestStatfs {
    int64_t f_type, f_bsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree;
    int32_t f_fsid[2];
    int64_t f_namelen, f_frsize, f_flags, f_spare[4];
};
static void FillGuestStatfs(struct GuestStatfs* g, const struct statfs* h) {
    memset(g, 0, sizeof *g);
    g->f_type = h->f_type;   g->f_bsize = h->f_bsize;
    g->f_blocks = (int64_t)h->f_blocks; g->f_bfree = (int64_t)h->f_bfree;
    g->f_bavail = (int64_t)h->f_bavail; g->f_files = (int64_t)h->f_files;
    g->f_ffree = (int64_t)h->f_ffree;
#ifdef __USE_MISC
    g->f_fsid[0] = h->f_fsid.__val[0]; g->f_fsid[1] = h->f_fsid.__val[1];
#endif
    g->f_namelen = (int64_t)h->f_namelen; g->f_frsize = (int64_t)h->f_frsize;
    g->f_flags = (int64_t)h->f_flags;
}
struct GuestSysinfo {
    int64_t uptime;
    uint64_t loads[3];
    uint64_t totalram, freeram, sharedram, bufferram, totalswap, freeswap;
    uint16_t procs, pad;
    uint64_t totalhigh, freehigh;
    uint32_t mem_unit;
    /* linux/sysinfo.h ends with char _f[20-2*sizeof(u64)-sizeof(u32)] == _f[0],
       i.e. no bytes at all; the struct is 108 rounded up to 8 = 112.  A tail
       here made this 120, so the memset below wrote 8 bytes past the caller's
       stack object (glibc's sysconf(_SC_PHYS_PAGES) passes a 112-byte local). */
};
static void FillGuestSysinfo(struct GuestSysinfo* g, const struct sysinfo* h) {
    memset(g, 0, sizeof *g);
    g->uptime = (int64_t)h->uptime;
    for (int i = 0; i < 3; ++i) g->loads[i] = (uint64_t)h->loads[i];
    g->totalram = (uint64_t)h->totalram; g->freeram = (uint64_t)h->freeram;
    g->sharedram = (uint64_t)h->sharedram; g->bufferram = (uint64_t)h->bufferram;
    g->totalswap = (uint64_t)h->totalswap; g->freeswap = (uint64_t)h->freeswap;
    g->procs = h->procs;
    g->totalhigh = (uint64_t)h->totalhigh; g->freehigh = (uint64_t)h->freehigh;
    g->mem_unit = h->mem_unit;
}
struct GuestRusage {
    int64_t utime_s, utime_us, stime_s, stime_us;
    int64_t ru[14];
};
static void FillGuestRusage(struct GuestRusage* g, const struct rusage* h) {
    memset(g, 0, sizeof *g);
    g->utime_s = h->ru_utime.tv_sec;  g->utime_us = h->ru_utime.tv_usec;
    g->stime_s = h->ru_stime.tv_sec;  g->stime_us = h->ru_stime.tv_usec;
    const long v[14] = { h->ru_maxrss, h->ru_ixrss, h->ru_idrss, h->ru_isrss,
        h->ru_minflt, h->ru_majflt, h->ru_nswap, h->ru_inblock, h->ru_oublock,
        h->ru_msgsnd, h->ru_msgrcv, h->ru_nsignals, h->ru_nvcsw, h->ru_nivcsw };
    for (int i = 0; i < 14; ++i) g->ru[i] = (int64_t)v[i];
}

/* Guest allocation. brk grows up from the end of the image, mmap grows down
   from below the stack reservation; they meet in the middle, so neither can
   walk into the image or into the stack. */
#define A64PORT_ALLOC_MID  (A64PORT_MEM_BASE + A64PORT_MEM_SIZE / 2)
#define A64PORT_STACK_TOP  (A64PORT_MEM_BASE + A64PORT_MEM_SIZE)
#define A64PORT_STACK_RESERVE (UINT64_C(4) << 20)
#define A64PORT_MMAP_FIRST (A64PORT_STACK_TOP - A64PORT_STACK_RESERVE)
static uint64_t g_brk_cur = A64PORT_IMAGE_END;
static uint64_t g_mmap_next = A64PORT_MMAP_FIRST;

/* The standalone policy for anonymous/file mappings: a high-water mark that grows down, plus a first-fit list of
   freed ranges, so a program that creates and ends threads (8 MB stack each) or maps and unmaps buffers does not
   exhaust the arena.  Guest threads call mmap/munmap concurrently, hence the lock.  The multi-module host owns
   its own pool and never reaches this (its hooks answer first). */
#define SA_FREE_MAX 64
static struct { uint64_t lo, hi; } g_sa_free[SA_FREE_MAX];     /* ascending, disjoint, not adjacent */
static int g_sa_nfree;
static pthread_mutex_t g_sa_mu = PTHREAD_MUTEX_INITIALIZER;
static void sa_free_insert(uint64_t lo, uint64_t hi) {           /* caller holds g_sa_mu; [lo, hi) is page aligned */
    if (lo < g_mmap_next) lo = g_mmap_next;                      /* below the mark: never mapped */
    if (hi > A64PORT_MMAP_FIRST) hi = A64PORT_MMAP_FIRST;
    if (lo >= hi) return;
    int i = 0;
    while (i < g_sa_nfree && g_sa_free[i].hi < lo) ++i;          /* first range that can touch or follow [lo, hi) */
    while (i < g_sa_nfree && g_sa_free[i].lo <= hi) {            /* merge everything that touches or overlaps */
        if (g_sa_free[i].lo < lo) lo = g_sa_free[i].lo;
        if (g_sa_free[i].hi > hi) hi = g_sa_free[i].hi;
        memmove(&g_sa_free[i], &g_sa_free[i + 1], (size_t)(g_sa_nfree - i - 1) * sizeof g_sa_free[0]);
        --g_sa_nfree;
    }
    if (lo == g_mmap_next) { g_mmap_next = hi; return; }         /* adjoins the mark: lower the high-water mark */
    if (g_sa_nfree == SA_FREE_MAX) return;                       /* list full: the range leaks */
    memmove(&g_sa_free[i + 1], &g_sa_free[i], (size_t)(g_sa_nfree - i) * sizeof g_sa_free[0]);
    g_sa_free[i].lo = lo; g_sa_free[i].hi = hi;
    ++g_sa_nfree;
}
static void sa_free_remove(uint64_t lo, uint64_t hi) {           /* a MAP_FIXED mapping takes [lo, hi) */
    for (int i = 0; i < g_sa_nfree; ) {
        const uint64_t a = g_sa_free[i].lo, b = g_sa_free[i].hi;
        if (b <= lo || a >= hi) { ++i; continue; }
        memmove(&g_sa_free[i], &g_sa_free[i + 1], (size_t)(g_sa_nfree - i - 1) * sizeof g_sa_free[0]);
        --g_sa_nfree;
        if (a < lo) sa_free_insert(a, lo);
        if (b > hi) sa_free_insert(hi, b);
        i = 0;                                                    /* the list changed: rescan */
    }
}
static uint64_t sa_alloc(uint64_t len) {                         /* page-rounded length; 0 = no room */
    pthread_mutex_lock(&g_sa_mu);
    uint64_t va = 0;
    for (int i = 0; i < g_sa_nfree && !va; ++i) {
        if (g_sa_free[i].hi - g_sa_free[i].lo < len) continue;
        va = g_sa_free[i].lo;
        if (g_sa_free[i].hi - va == len) {
            memmove(&g_sa_free[i], &g_sa_free[i + 1], (size_t)(g_sa_nfree - i - 1) * sizeof g_sa_free[0]);
            --g_sa_nfree;
        } else {
            g_sa_free[i].lo += len;
        }
    }
    if (!va && g_mmap_next >= A64PORT_ALLOC_MID + len) { g_mmap_next -= len; va = g_mmap_next; }
    pthread_mutex_unlock(&g_sa_mu);
    return va;
}
__attribute__((weak)) void a64port_guest_munmap(uint64_t va, uint64_t len) {
    const uint64_t lo = (va + 0xFFF) & ~UINT64_C(0xFFF), hi = (va + len) & ~UINT64_C(0xFFF);
    pthread_mutex_lock(&g_sa_mu);
    sa_free_insert(lo, hi);
    pthread_mutex_unlock(&g_sa_mu);
}

/* Upper bound for the guest's brk heap. The single-image build grows it to the
   middle of its own arena; the multi-module host overrides this with the
   address of ld.so (the first fixed mapping above the image), which is the real
   ceiling for a contiguous brk region. */
__attribute__((weak)) uint64_t a64port_guest_brk_limit(void) {
    return A64PORT_ALLOC_MID;
}

/* Reserve (not map) a range of guest address space for shmat and friends. The
   multi-module host overrides these with its mmap pool so the range is not
   handed out twice. */
__attribute__((weak)) uint64_t a64port_guest_reserve(uint64_t len) {
    const uint64_t rounded = ((len + 0xFFF) & ~UINT64_C(0xFFF)) ? : 0x1000;
    if (g_mmap_next < A64PORT_ALLOC_MID + rounded) return 0;
    g_mmap_next -= rounded;
    return g_mmap_next;
}
__attribute__((weak)) void a64port_guest_release(uint64_t va, uint64_t len) {
    (void)va; (void)len;    /* single-image bump allocator does not reclaim */
}

/* ── Linux AArch64 syscall ABI ────────────────────────────────────────────── */

/* AArch64 (asm-generic-ish) struct stat, 128 bytes. The host's is a different
   shape, so fstat/newfstatat translate field by field. */
struct GuestStat {
    uint64_t st_dev;
    uint64_t st_ino;
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint64_t st_rdev;
    uint64_t __pad1;
    int64_t st_size;
    uint32_t st_blksize;
    uint32_t __pad2;
    int64_t st_blocks;
    int64_t st_atime_s, st_atime_ns;
    int64_t st_mtime_s, st_mtime_ns;
    int64_t st_ctime_s, st_ctime_ns;
    uint32_t __unused[2];
};

static void FillGuestStat(struct GuestStat* g, const struct stat* h) {
    memset(g, 0, sizeof *g);
    g->st_dev = (uint64_t)h->st_dev;
    g->st_ino = (uint64_t)h->st_ino;
    g->st_mode = (uint32_t)h->st_mode;
    g->st_nlink = (uint32_t)h->st_nlink;
    g->st_uid = (uint32_t)h->st_uid;
    g->st_gid = (uint32_t)h->st_gid;
    g->st_rdev = (uint64_t)h->st_rdev;
    g->st_size = (int64_t)h->st_size;
    g->st_blksize = (uint32_t)h->st_blksize;
    g->st_blocks = (int64_t)h->st_blocks;
    g->st_atime_s = (int64_t)h->st_atim.tv_sec;
    g->st_atime_ns = (int64_t)h->st_atim.tv_nsec;
    g->st_mtime_s = (int64_t)h->st_mtim.tv_sec;
    g->st_mtime_ns = (int64_t)h->st_mtim.tv_nsec;
    g->st_ctime_s = (int64_t)h->st_ctim.tv_sec;
    g->st_ctime_ns = (int64_t)h->st_ctim.tv_nsec;
}

static void HaltUnimplemented(GuestContext* c, uint64_t n) {
    fprintf(stderr,
            "[a64port] unimplemented aarch64 syscall %llu (x0=0x%llx x1=0x%llx x2=0x%llx "
            "x3=0x%llx) at pc=0x%llx\n",
            (unsigned long long)n, (unsigned long long)c->x[0], (unsigned long long)c->x[1],
            (unsigned long long)c->x[2], (unsigned long long)c->x[3],
            (unsigned long long)c->pc);
    c->halted = 1;
}


/* Kernel sigsets are one 8-byte mask; glibc's sigset_t is wider. */
static void SigsetFromKernel(sigset_t* out, const uint64_t* k) {
    sigemptyset(out);
    const uint64_t m = k ? *k : 0;
    for (int s = 1; s < A64PORT_NSIG; ++s)
        if (m & (UINT64_C(1) << (s - 1))) sigaddset(out, s);
}
static void SigsetToKernel(uint64_t* k, const sigset_t* in) {
    uint64_t m = 0;
    for (int s = 1; s < A64PORT_NSIG; ++s)
        if (sigismember(in, s)) m |= (UINT64_C(1) << (s - 1));
    *k = m;
}


#if defined(__arm__)
/* A STATIC 32-bit ARM glibc does not route clock_gettime through the vDSO:
   every call was a real system call (__libc_do_syscall), ~10 % of a thread
   that times its own work, on a Cortex-A17 test board.  Find the
   kernel's __vdso_clock_gettime64 (struct __kernel_timespec = two int64, the
   guest's own layout) once, from AT_SYSINFO_EHDR. */
#include <elf.h>
#include <sys/auxv.h>
typedef int (*a64port_cgt64_fn)(int, int64_t*);
static a64port_cgt64_fn a64port_vdso_find(void) {
    const uintptr_t base = (uintptr_t)getauxval(AT_SYSINFO_EHDR);
    if (!base) return 0;
    const Elf32_Ehdr* eh = (const Elf32_Ehdr*)base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) || eh->e_ident[EI_CLASS] != ELFCLASS32) return 0;
    const Elf32_Phdr* ph = (const Elf32_Phdr*)(base + eh->e_phoff);
    uintptr_t bias = 0; const Elf32_Dyn* dyn = 0; int have_load = 0;
    for (int i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type == PT_LOAD && !have_load) { bias = base + ph[i].p_offset - ph[i].p_vaddr; have_load = 1; }
        if (ph[i].p_type == PT_DYNAMIC) dyn = (const Elf32_Dyn*)(base + ph[i].p_offset);
    }
    if (!dyn || !have_load) return 0;
    const Elf32_Sym* sym = 0; const char* str = 0; const Elf32_Word* hash = 0;
    for (const Elf32_Dyn* d = dyn; d->d_tag != DT_NULL; ++d) {
        if (d->d_tag == DT_SYMTAB) sym = (const Elf32_Sym*)(bias + d->d_un.d_ptr);
        else if (d->d_tag == DT_STRTAB) str = (const char*)(bias + d->d_un.d_ptr);
        else if (d->d_tag == DT_HASH) hash = (const Elf32_Word*)(bias + d->d_un.d_ptr);
    }
    if (!sym || !str || !hash) return 0;
    for (Elf32_Word k = 0; k < hash[1]; ++k)                 /* nchain = symbol count */
        if (sym[k].st_shndx != SHN_UNDEF && !strcmp(str + sym[k].st_name, "__vdso_clock_gettime64"))
            return (a64port_cgt64_fn)(bias + sym[k].st_value);
    /* Some kernels (seen: Linux 6.6 on a Cortex-A17 test board) ship a vDSO whose function symbols have
       st_name 0 (the names are in .dynstr, unreferenced).  Identify
       clock_gettime64 by behaviour, safely: (1) call each function with a
       VALID pointer as its first argument - the clock_gettime variants reject
       it as a clock id and write nothing, gettimeofday writes through it
       harmlessly - and drop whatever wrote; (2) call the rest with
       CLOCK_MONOTONIC: only clock_gettime64 writes 64-bit seconds equal to the
       real time64 syscall's, with nanoseconds in range (clock_gettime writes
       two 32-bit words, clock_getres a zero second). */
    for (Elf32_Word k = 0; k < hash[1]; ++k) {
        if (sym[k].st_shndx == SHN_UNDEF || sym[k].st_shndx >= SHN_LORESERVE || !sym[k].st_value) continue;
        if (ELF32_ST_TYPE(sym[k].st_info) != STT_FUNC) continue;
        const a64port_cgt64_fn f = (a64port_cgt64_fn)(bias + sym[k].st_value);
        int64_t probe[4] = {-7, -7, -7, -7}, guard[4] = {-7, -7, -7, -7};
        f((int)(uintptr_t)probe, guard);
        if (probe[0] != -7 || probe[1] != -7 || guard[0] != -7 || guard[1] != -7) continue;
        int64_t got[2] = {-7, -7}, ref[2] = {0, 0};
        if (f(CLOCK_MONOTONIC, got) != 0) continue;
        if (syscall(SYS_clock_gettime64, CLOCK_MONOTONIC, ref) != 0) continue;
        if (got[0] >= 0 && got[1] >= 0 && got[1] < 1000000000 && got[0] <= ref[0] && ref[0] - got[0] <= 1) {
            fprintf(stderr, "[a64port] vDSO clock_gettime64 found by probing (unnamed vDSO symbols)\n");
            return f;
        }
    }
    return 0;
}
/* A64PORT_FAST_CLOCK=1: CLOCK_MONOTONIC from the CPU's virtual counter, no system call.
 *
 * Some 32-bit ARM kernels run the arch timer on the PHYSICAL counter (the boot firmware never set CNTVOFF), so
 * their vDSO has no usable clock and every clock_gettime above is a real system call: ~0.6 us each, and a
 * program with a 1 ms periodic callback made ~31,700/s of them (plus ~15,000/s from its other threads).  User space can still read CNTVCT
 * (= CNTPCT - CNTVOFF, ~20 ns): the same 24 MHz system counter with a RANDOM per-CPU offset.  So:
 *   - calibrate each CPU's offset once (a helper thread pinned to each CPU in turn): the kernel's clock is
 *     bracketed by two system calls around a counter read, and intersecting 2000 such brackets pins the offset
 *     to ~1 count = 42 ns (measured stable; rate exactly 24 MHz; no NTP was running);
 *   - per call, which CPU we are on is unknown (sched_getcpu is a system call too), but the offsets of
 *     different CPUs are ~1e11 s apart, so exactly ONE candidate lands near the last time handed out;
 *   - never hand out a value below the last one (shared CAS max), so time stays monotonic across threads
 *     and migrations despite the +-1 count calibration error;
 *   - every 1024th call is checked against the system call; a mismatch > 1 ms (a CPU lost its CNTVOFF,
 *     hot-plug, NTP slewing) turns the fast path off for good and says so.
 * The kernel's mult rounding drifts ~1 count per ~80 s against exact 125/3 ns: ~40 us a day, irrelevant. */
#define FCLK_MAXCPU 8
#define FCLK_HZ 24000000ll
static int g_fclk_on;                      /* 1 = calibrated and enabled */
static int g_fclk_ncpu;
static int64_t g_fclk_base[FCLK_MAXCPU];   /* CNTVCT at the kernel's CLOCK_MONOTONIC zero, per CPU */
static int64_t g_fclk_last;                /* last handed-out time, in counts since the monotonic zero */
static unsigned g_fclk_n;
static inline uint64_t fclk_cntvct(void) {
    uint32_t lo, hi;
    __asm__ volatile("isb\n\tmrrc p15, 1, %0, %1, c14" : "=r"(lo), "=r"(hi));
    return ((uint64_t)hi << 32) | lo;
}
static int64_t fclk_sys_ns(void) { int64_t t[2] = {0, 0}; syscall(SYS_clock_gettime64, CLOCK_MONOTONIC, t); return t[0] * 1000000000 + t[1]; }
static void fclk_raise(int64_t c) {        /* g_fclk_last = max(g_fclk_last, c) */
    int64_t last = __atomic_load_n(&g_fclk_last, __ATOMIC_RELAXED);
    while (c > last && !__atomic_compare_exchange_n(&g_fclk_last, &last, c, 1, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {}
}
static void* fclk_calibrate(void* arg) {
    (void)arg;
    for (int cpu = 0; cpu < g_fclk_ncpu; ++cpu) {
        cpu_set_t s; CPU_ZERO(&s); CPU_SET(cpu, &s);
        if (sched_setaffinity(0, sizeof s, &s) != 0) { g_fclk_ncpu = 0; return 0; }
        int64_t best_lo = 0, best_hi = INT64_MAX;
        for (int tries = 0; tries < 8 && best_hi - best_lo > 2; ++tries) {
            int64_t lo = INT64_MIN, hi = INT64_MAX;
            for (int k = 0; k < 2000; ++k) {
                const int64_t a = fclk_sys_ns(); const uint64_t v = fclk_cntvct(); const int64_t b = fclk_sys_ns();
                const int64_t l = (int64_t)(v - (uint64_t)((b * 3 + 124) / 125)), h = (int64_t)(v - (uint64_t)(a * 3 / 125));
                if (l > lo) lo = l;
                if (h < hi) hi = h;
            }
            if (hi < lo) { g_fclk_ncpu = 0; return 0; }          /* inconsistent: the counter is not what we think */
            if (hi - lo < best_hi - best_lo) { best_lo = lo; best_hi = hi; }
        }
        if (best_hi - best_lo > 48) { g_fclk_ncpu = 0; return 0; }  /* worse than 2 us: don't */
        g_fclk_base[cpu] = best_lo + (best_hi - best_lo) / 2;
    }
    return 0;
}
static void fclk_init(void) {
    const char* e = getenv("A64PORT_FAST_CLOCK");
    if (!e || !*e || *e == '0') return;
    const long n = sysconf(_SC_NPROCESSORS_CONF);
    if (n < 1 || n > FCLK_MAXCPU) { fprintf(stderr, "[a64port] fast clock: %ld CPUs, off\n", n); return; }
    g_fclk_ncpu = (int)n;
    pthread_t th;
    if (pthread_create(&th, 0, fclk_calibrate, 0) != 0 || pthread_join(th, 0) != 0) g_fclk_ncpu = 0;
    if (g_fclk_ncpu == 0) { fprintf(stderr, "[a64port] fast clock: calibration failed, off\n"); return; }
    for (int i = 0; i < g_fclk_ncpu; ++i)               /* candidates must be far apart (they are ~1e11 s) */
        for (int j = i + 1; j < g_fclk_ncpu; ++j) {
            const int64_t d = g_fclk_base[i] - g_fclk_base[j];
            if (d > -3600 * FCLK_HZ && d < 3600 * FCLK_HZ) {
                fprintf(stderr, "[a64port] fast clock: CPU %d and %d offsets too close, off\n", i, j); return;
            }
        }
    g_fclk_last = fclk_sys_ns() * 3 / 125;
    __atomic_store_n(&g_fclk_on, 1, __ATOMIC_RELEASE);
    fprintf(stderr, "[a64port] fast clock: CLOCK_MONOTONIC from CNTVCT, %d CPUs calibrated (A64PORT_FAST_CLOCK)\n", g_fclk_ncpu);
}
static __thread int t_fclk_cpu;            /* this thread's last CPU index (a hint: tried first) */
static __thread int64_t t_fclk_sec_cnt = -1, t_fclk_sec;   /* count at the start of second t_fclk_sec */
static int fclk_mono(int64_t* out) {
    const int check = (++g_fclk_n & 1023) == 0;       /* racy counter: an occasional skipped check is harmless */
    const int64_t k1 = check ? fclk_sys_ns() : 0;      /* spot check: the kernel's clock BEFORE and AFTER our read */
    const uint64_t v = fclk_cntvct();
    const int64_t last = __atomic_load_n(&g_fclk_last, __ATOMIC_RELAXED);
    int i = t_fclk_cpu;
    int64_t c = (int64_t)(v - (uint64_t)g_fclk_base[i]);
    if (c < last - 2400 || c > last + 600 * FCLK_HZ) {  /* the one CPU whose offset puts v near the last time */
        for (i = 0; i < g_fclk_ncpu; ++i) {
            c = (int64_t)(v - (uint64_t)g_fclk_base[i]);
            if (c >= last - 2400 && c <= last + 600 * FCLK_HZ) break;     /* -100 us .. +10 min */
        }
        if (i == g_fclk_ncpu) {                        /* idle > 10 min (or a lost offset): re-anchor, system call */
            const int64_t k = fclk_sys_ns();
            fclk_raise(k * 3 / 125);
            out[0] = k / 1000000000; out[1] = k % 1000000000;
            return 0;
        }
        t_fclk_cpu = i;
    }
    if (c > last) fclk_raise(c);
    else c = last;                                     /* never below a time already handed out */
    /* counts -> (sec, nsec): a per-thread whole-second anchor; else sec from a double estimate (c < 2^53) */
    int64_t rem = c - t_fclk_sec_cnt;
    if (t_fclk_sec_cnt < 0 || rem < 0 || rem >= FCLK_HZ) {
        int64_t sec = (int64_t)(((double)(uint32_t)(c >> 32) * 4294967296.0 + (double)(uint32_t)c) * (1.0 / FCLK_HZ));
        rem = c - sec * FCLK_HZ;
        while (rem < 0) { rem += FCLK_HZ; --sec; }
        while (rem >= FCLK_HZ) { rem -= FCLK_HZ; ++sec; }
        t_fclk_sec = sec; t_fclk_sec_cnt = c - rem;
    }
    out[0] = t_fclk_sec; out[1] = (int64_t)((uint32_t)rem * 125u / 3u);
    if (check) {                                       /* k1 <= ours <= k2, within 100 us (preemption-proof) */
        const int64_t k2 = fclk_sys_ns(), f = out[0] * 1000000000 + out[1];
        if (f < k1 - 100000 || f > k2 + 100000) {
            __atomic_store_n(&g_fclk_on, 0, __ATOMIC_RELAXED);
            fprintf(stderr, "[a64port] fast clock: %lld ns, kernel %lld..%lld ns - turned off\n", (long long)f, (long long)k1, (long long)k2);
            out[0] = k2 / 1000000000; out[1] = k2 % 1000000000;
        }
    }
    return 0;
}

int a64port_vdso_cgt64(int clk, int64_t* out) {   /* not static: the libc clock_gettime leaf calls it */
    static a64port_cgt64_fn fn = (a64port_cgt64_fn)1;
    if (__atomic_load_n(&fn, __ATOMIC_ACQUIRE) == (a64port_cgt64_fn)1) {
        static pthread_once_t once = PTHREAD_ONCE_INIT;
        pthread_once(&once, fclk_init);
        a64port_cgt64_fn f = getenv("A64PORT_NO_VDSO") ? 0 : a64port_vdso_find();
        __atomic_store_n(&fn, f, __ATOMIC_RELEASE);
    }
    if (clk == CLOCK_MONOTONIC && __atomic_load_n(&g_fclk_on, __ATOMIC_ACQUIRE)) return fclk_mono(out);
    a64port_cgt64_fn f = __atomic_load_n(&fn, __ATOMIC_ACQUIRE);
    return f ? f(clk, out) : -1;
}
#endif

/* A64PORT_WAIT_PROF=1: wall time spent INSIDE guest syscalls, per (thread, syscall,
   guest caller x30), printed every 10 s (top 12, then reset).  A64PORT_WAIT_PROF=<s>
   (anything but "1") prints the top 20 of the threads whose name contains <s>.  CPU profiles
   (A64PORT_HPROF) cannot see a thread that is waiting; this names what it waits
   on - e.g. the GUI thread's ppoll/clock_nanosleep between frames. */
#define WAITPROF_N 512
static struct { unsigned tid; unsigned nr; uint64_t x30, up; double sec; unsigned long cnt; } g_wp[WAITPROF_N];
static pthread_mutex_t g_wp_mu = PTHREAD_MUTEX_INITIALIZER;
static double g_wp_last;
static void waitprof_add(unsigned nr, uint64_t x30, uint64_t up, double dt, double now) {
    const unsigned tid = (unsigned)gettid();
    pthread_mutex_lock(&g_wp_mu);
    unsigned h = (tid * 2654435761u ^ nr * 40503u ^ (unsigned)(x30 >> 2)) % WAITPROF_N;
    for (unsigned k = 0; k < WAITPROF_N; ++k, h = (h + 1) % WAITPROF_N) {
        if (g_wp[h].cnt && (g_wp[h].tid != tid || g_wp[h].nr != nr || g_wp[h].x30 != x30)) continue;
        g_wp[h].tid = tid; g_wp[h].nr = nr; g_wp[h].x30 = x30; g_wp[h].up = up; g_wp[h].sec += dt; g_wp[h].cnt++;
        break;
    }
    if (g_wp_last == 0) g_wp_last = now;
    if (now - g_wp_last >= 10.0) {
        const char* filt = getenv("A64PORT_WAIT_PROF");
        if (filt && !strcmp(filt, "1")) filt = 0;
        fprintf(stderr, "[wait] --- %.1f s window: blocked time per thread/syscall/caller ---\n", now - g_wp_last);
        for (int top = 0; top < (filt ? 20 : 12); ) {
            int best = -1;
            for (int i = 0; i < WAITPROF_N; ++i)
                if (g_wp[i].cnt && (best < 0 || g_wp[i].sec > g_wp[best].sec)) best = i;
            if (best < 0) break;
            char comm[32] = "?", path[64];
            snprintf(path, sizeof path, "/proc/self/task/%u/comm", g_wp[best].tid);
            FILE* f = fopen(path, "r");
            if (f) { if (fgets(comm, sizeof comm, f)) comm[strcspn(comm, "\n")] = 0; fclose(f); }
            if (filt && !strstr(comm, filt)) { g_wp[best].cnt = 0; continue; }
            ++top;
            fprintf(stderr, "[wait] %7.3f s %6lu x  tid %u %-16s nr %3u  x30=0x%llx  up=0x%llx\n",
                    g_wp[best].sec, g_wp[best].cnt, g_wp[best].tid, comm, g_wp[best].nr,
                    (unsigned long long)g_wp[best].x30, (unsigned long long)g_wp[best].up);
            g_wp[best].cnt = 0;
        }
        memset(g_wp, 0, sizeof g_wp);
        g_wp_last = now;
    }
    pthread_mutex_unlock(&g_wp_mu);
}

/* A64PORT_SYSCALL_TIMELINE=<thread-name prefix>:<start s>:<length s>: every syscall
   of the matching threads in that window, with start time (ms since the window
   opened), duration and guest caller - a per-frame picture of where a thread's
   wall time goes (compute = the gaps between lines).  Lines go to stderr at the
   end of each call; the window is measured from the first syscall seen.
   Name "*" = every thread.  A64PORT_TL_TRIGGER=<path>: the window opens (start 0) when <path> appears instead -
   e.g. loadtrace.py creates it at the load press.  A call is listed if it ENDS in the window (a wait that began
   before it shows a negative start), with the thread's name. */
static struct { int on, all; char name[16]; double t0, start, len; const char* trig; double trig_seen; } g_tl;
static int tl_match(void) {
    static __thread int m = -1;                  /* per thread: 1 match, 0 no, -1 unknown */
    if (g_tl.all) return 1;
    if (m >= 0) return m;
    char comm[32] = "", path[64];
    snprintf(path, sizeof path, "/proc/self/task/%d/comm", (int)syscall(SYS_gettid));
    FILE* f = fopen(path, "r");
    if (f) { if (fgets(comm, sizeof comm, f)) comm[strcspn(comm, "\n")] = 0; fclose(f); }
    if (!*comm) return 0;
    m = strncmp(comm, g_tl.name, strlen(g_tl.name)) == 0;
    return m;
}

/* ── guest signal handlers (standalone runtime) ─────────────────────────────────────────────────────────
 * The host cannot call a guest handler address, so a signal is delivered the way a syscall return can be: the host
 * handler only marks the signal pending on the thread it arrived on (async-signal-safe), and when that thread's
 * guest code next returns from a syscall (raise()/kill() to self return from one, so do pause(), sigsuspend(), a
 * blocked read() cut short by EINTR, ...) the saved guest context goes on a per-thread stack, a frame with a
 * siginfo and a (partly filled) ucontext is built on the guest stack, and execution continues in the handler with
 * x30 = the guest's sa_restorer.  The restorer's rt_sigreturn (139) pops the context.  The signal is blocked while
 * its handler runs (unless SA_NODEFER), exactly as the kernel does.  Not covered: delivery in the middle of
 * compute code that makes no syscall, synchronous faults (SIGSEGV...), SA_ONSTACK/sigaltstack, handlers without
 * SA_RESTORER.  Off in the multi-module host (g_sa_sig stays 0): its application never had guest handlers run. */
static int g_sa_sig;                                  /* set by the standalone main() */
/* where a handler without a guest-supplied restorer returns to (see sa_run): unmapped low memory */
#define A64PORT_SIGRET_PC UINT64_C(0x1000)
static __thread volatile uint64_t t_sig_pending;      /* bit (sig - 1) */
static __thread struct { int32_t code, pid, uid; uint64_t val; } t_sig_info[A64PORT_NSIG];
typedef struct { GuestContext ctx; sigset_t mask; } SigFrame;
#define SA_SIG_FRAMES 8
static __thread SigFrame* t_sigframes;
static __thread int t_sigdepth;
static void sa_host_handler(int sig, siginfo_t* si, void* uc) {
    (void)uc;
    if (sig <= 0 || sig >= A64PORT_NSIG) return;
    if (si) {
        t_sig_info[sig].code = si->si_code; t_sig_info[sig].pid = si->si_pid == getpid() ? 1 : (int32_t)si->si_pid;
        t_sig_info[sig].uid = (int32_t)si->si_uid; t_sig_info[sig].val = (uint64_t)(uintptr_t)si->si_value.sival_ptr;
    }
    __atomic_or_fetch(&t_sig_pending, UINT64_C(1) << (sig - 1), __ATOMIC_RELEASE);
}
static void sa_deliver(GuestContext* c) {
    const uint64_t pend = __atomic_load_n(&t_sig_pending, __ATOMIC_ACQUIRE);
    if (!pend) return;
    const int sig = __builtin_ctzll(pend) + 1;
    __atomic_and_fetch(&t_sig_pending, ~(UINT64_C(1) << (sig - 1)), __ATOMIC_ACQ_REL);
    const uint64_t h = g_guest_sigact[sig].handler, fl = g_guest_sigact[sig].flags, rs = g_guest_sigact[sig].restorer;
    if (h <= 1) return;                                           /* disposition changed meanwhile */
    if (t_sigdepth >= SA_SIG_FRAMES) { fprintf(stderr, "[a64port] signal %d dropped: handlers nested too deep\n", sig); return; }
    if (!t_sigframes) t_sigframes = (SigFrame*)calloc(SA_SIG_FRAMES, sizeof(SigFrame));
    if (!t_sigframes) return;
    enum { kSi = 128, kUc = 4560 };                                /* the AArch64 siginfo_t / ucontext_t sizes */
    uint64_t sp = (c->x[31] - kSi - kUc - 16) & ~UINT64_C(15);
    uint8_t* fr = (uint8_t*)GuestPtr(c, sp, kSi + kUc);
    if (!fr) return;
    SigFrame* f = &t_sigframes[t_sigdepth];
    f->ctx = *c;
    sigset_t add; sigemptyset(&add);
    if (!(fl & UINT64_C(0x40000000))) sigaddset(&add, sig);       /* not SA_NODEFER: block the signal itself */
    { sigset_t m; SigsetFromKernel(&m, &g_guest_sigact[sig].mask);
      for (int i = 1; i < A64PORT_NSIG; ++i) if (sigismember(&m, i) == 1) sigaddset(&add, i); }
    pthread_sigmask(SIG_BLOCK, &add, &f->mask);                    /* f->mask = the mask to restore */
    memset(fr, 0, kSi + kUc);
    const int32_t si_signo = sig, si_code = t_sig_info[sig].code;
    memcpy(fr + 0, &si_signo, 4); memcpy(fr + 8, &si_code, 4);
    memcpy(fr + 16, &t_sig_info[sig].pid, 4); memcpy(fr + 20, &t_sig_info[sig].uid, 4);
    memcpy(fr + 24, &t_sig_info[sig].val, 8);
    uint8_t* uc = fr + kSi;                                        /* uc_sigmask @40, uc_mcontext @176 */
    uint64_t old_kernel = 0; SigsetToKernel(&old_kernel, &f->mask); memcpy(uc + 40, &old_kernel, 8);
    memcpy(uc + 176 + 8, &f->ctx.x[0], 31 * 8);                   /* regs[31] after fault_address */
    memcpy(uc + 176 + 8 + 248, &f->ctx.x[31], 8);                 /* sp */
    memcpy(uc + 176 + 8 + 256, &f->ctx.pc, 8);                    /* pc */
    ++t_sigdepth;
    c->x[0] = (uint64_t)sig; c->x[1] = sp; c->x[2] = sp + kSi;
    c->x[30] = (fl & UINT64_C(0x04000000)) ? rs : A64PORT_SIGRET_PC; c->x[31] = sp; c->pc = h;
}
/* AArch64 glibc registers no sa_restorer (the kernel supplies one in the vDSO), and the recompiled program has no
   such code, so a handler returns to this address in unmapped low memory instead: the block code unwinds to the
   dispatch loop with c->pc here, and sa_run() below completes the sigreturn.  A guest that does supply a restorer
   (SA_RESTORER) uses it and ends with the real rt_sigreturn syscall. */
static int sa_sigreturn(GuestContext* c) {
    if (t_sigdepth <= 0 || !t_sigframes) return 0;
    SigFrame* f = &t_sigframes[--t_sigdepth];
    *c = f->ctx;                                  /* registers (incl. the interrupted syscall's result) and pc */
    pthread_sigmask(SIG_SETMASK, &f->mask, NULL);
    return 1;
}
/* The standalone dispatch loop (what recomp_run does, plus the sigreturn above; no 100M-block watchdog). */
static void sa_run(GuestContext* c) {
#ifdef RECOMP_FPX_HOST
    recomp_fpx_ensure_env();
#endif
    while (!c->halted) {
        if (c->pc == A64PORT_SIGRET_PC && g_sa_sig) {
            if (!sa_sigreturn(c)) { fprintf(stderr, "[a64port] return to the signal trampoline without a frame\n"); c->halted = 1; }
            else sa_deliver(c);                   /* a signal the handler's mask held back runs as soon as the handler returns */
            continue;
        }
        c->chain_budget = 256;
        BlockFn f = recomp_lookup(c->pc);
        if (!f) {
            recomp_gap_note(RECOMP_GAP_MISS, c->pc, 0);
            fprintf(stderr, "[recomp] no block at 0x%llx\n", (unsigned long long)c->pc);
            break;
        }
        f(c);
    }
}
static void a64port_svc_body(GuestContext* c, unsigned imm);
void recomp_svc(GuestContext* c, unsigned imm) {
    a64port_svc_body(c, imm);
    if (g_sa_sig && !c->halted) sa_deliver(c);                    /* a pending signal of THIS thread runs its handler now */
}
static void a64port_svc_body(GuestContext* c, unsigned imm) {
    c->pending_svc = ~UINT64_C(0); /* standalone: serviced here */
    if (imm != 0) {
        fprintf(stderr, "[a64port] svc #%u is not a Linux syscall (expected #0)\n", imm);
        c->halted = 1;
        return;
    }
    const uint64_t n = c->x[8];
    arena_capture(c);
    struct timespec _t0;
    /* Cache the env probe: recomp_svc runs ~1.7M times in the first 17 s of a
       large program's run (1.16M of them clock_gettime), and getenv() per call is pure
       overhead. The trace flag below is cached the same way. */
    static int g_slow_syscall = -1;
    if (g_slow_syscall < 0) {
        const char* tl = getenv("A64PORT_SYSCALL_TIMELINE");
        if (tl && *tl) {
            char nm[16] = "";
            double a = 60, b = 1;
            if (sscanf(tl, "%15[^:]:%lf:%lf", nm, &a, &b) >= 1) {
                snprintf(g_tl.name, sizeof g_tl.name, "%s", nm);
                g_tl.start = a; g_tl.len = b; g_tl.on = 1; g_tl.all = !strcmp(nm, "*");
                g_tl.trig = getenv("A64PORT_TL_TRIGGER");
                if (g_tl.trig && !*g_tl.trig) g_tl.trig = 0;
                struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
                g_tl.t0 = (double)t.tv_sec + (double)t.tv_nsec / 1e9;
            }
        }
        g_slow_syscall = (EnvOn("A64PORT_SLOW_SYSCALL") ? 1 : 0) | (EnvOn("A64PORT_WAIT_PROF") ? 2 : 0) |
                         (g_tl.on ? 4 : 0) | (EnvOn("A64PORT_SYSCALL_ERR") ? 8 : 0);
    }
    const int _slow = g_slow_syscall;
    {   /* A64PORT_SYSCALL_STATS=1: per-syscall counts (all threads), top 12 printed every 2^18 calls */
        static int on = -1; static unsigned long cnt[512]; static unsigned long total;
        if (on < 0) on = EnvOn("A64PORT_SYSCALL_STATS") ? 1 : 0;
        if (on) {
            __atomic_add_fetch(&cnt[n & 511], 1, __ATOMIC_RELAXED);
            if ((__atomic_add_fetch(&total, 1, __ATOMIC_RELAXED) & 0x3ffff) == 0) {
                unsigned long snap[512]; for (int i = 0; i < 512; ++i) snap[i] = cnt[i];
                fprintf(stderr, "[sysstat] total %lu:", total);
                for (int k = 0; k < 12; ++k) {
                    int b = 0; for (int i = 1; i < 512; ++i) if (snap[i] > snap[b]) b = i;
                    if (!snap[b]) break;
                    fprintf(stderr, " %d=%lu", b, snap[b]); snap[b] = 0;
                }
                fprintf(stderr, "\n");
            }
        }
    }
    const uint64_t _x30 = c->x[30];
    uint64_t _up = 0;                      /* A64PORT_WAIT_PROF: the caller's caller (x29 chain) */
    if (_slow & 14) { const uint64_t* _fr = (const uint64_t*)GuestPtr(c, c->x[29], 16); if (_fr) _up = _fr[1]; }
    if (_slow) clock_gettime(CLOCK_MONOTONIC, &_t0);
    if (g_syscall_trace < 0) g_syscall_trace = EnvOn("A64PORT_SYSCALL_TRACE") ? 1 : 0;
    if (g_syscall_trace)
        fprintf(stderr, "[svc] %4llu x0=0x%-12llx x1=0x%-12llx x2=0x%-10llx x3=0x%llx\n",
                (unsigned long long)n, (unsigned long long)c->x[0],
                (unsigned long long)c->x[1], (unsigned long long)c->x[2],
                (unsigned long long)c->x[3]);
    switch (n) {
    case 29: { /* ioctl — isatty() probing a non-tty must fail the way it does
                 on Linux, but X11/XCB asks sockets for FIONREAD to decide
                 whether a reply is already buffered, so that one is served. */
        const int dt = a64port_device_fdtype((int)c->x[0]);
        if (dt) {
            c->x[0] = (uint64_t)(int64_t)device_ioctl(c, dt, (int)c->x[0], c->x[1], c->x[2]);
            break;
        }
        if (c->x[1] == SIOCGIFCONF || is_guest_ifreq_ioctl(c->x[1])) {
            c->x[0] = (uint64_t)(int64_t)guest_netif_ioctl(
                c, (int)c->x[0], c->x[1], c->x[2]);
            break;
        }
        if (c->x[1] == 0x541B) {            /* FIONREAD */
            int* out = (int*)GuestPtr(c, c->x[2], 4);
            int avail = 0;
            if (!out) { c->x[0] = (uint64_t)(-EFAULT); break; }
            if (ioctl((int)c->x[0], 0x541B, &avail) < 0) { c->x[0] = (uint64_t)(-errno); break; }
            *out = avail;
            c->x[0] = 0;
            break;
        }
        /* ALSA PCM data transfer: the sample buffer pointer is INSIDE the
           snd_xferi struct { result; void* buf; frames; }, so the generic
           single-argument translation below does not reach it and the kernel
           copy_from_user faults (observed EFAULT on WRITEI_FRAMES, which made
           the guest tear its sound device down).
           Translate the nested pointer and pass a local struct. */
        if (c->x[1] == 0x40184150u /* WRITEI_FRAMES _IOW('A',0x50,snd_xferi) */ ||
            c->x[1] == 0x80184151u /* READI_FRAMES  _IOR('A',0x51,snd_xferi) */) {
            struct { int64_t result; uint64_t buf; uint64_t frames; } xf;
            void* gp = GuestPtr(c, c->x[2], sizeof xf);
            if (!gp) { c->x[0] = (uint64_t)(-EFAULT); break; }
            memcpy(&xf, gp, sizeof xf);
            const uint64_t guest_buf = xf.buf;
            if (xf.buf) {
                uint64_t n = xf.frames ? xf.frames * 8u : 8u;
                if (n > (1u << 30)) n = 1u << 30;
                void* hp = GuestPtr(c, xf.buf, n);
                if (!hp) hp = GuestPtr(c, xf.buf, 1);
                if (!hp) { c->x[0] = (uint64_t)(-EFAULT); break; }
                xf.buf = (uint64_t)(uintptr_t)hp;
            }
            c->x[0] = RetU(ioctl((int)c->x[0], c->x[1], &xf));
            xf.buf = guest_buf;          /* never leak the host VA back */
            memcpy(gp, &xf, sizeof xf);  /* result/frames updated by the kernel */
            break;
        }
        /* Real kernel objects the guest opened itself (ALSA controlC / pcmC,
           hidraw, evdev, ...): an ioctl on those was returning ENOTTY, which
           made libasound's hw plugin open /dev/snd/controlC* and then fail
           every SNDRV_CTL and SNDRV_PCM call - the guest ended up with
           no sound output at all.  Hand the request to the
           host.  For _IOR/_IOW/_IOWR the argument is a guest VA whose size is
           encoded in the request's _IOC_SIZE field; size 0 means a scalar. */
        {
            const unsigned iocsz = (unsigned)((c->x[1] >> 16) & 0x3fffu);
            void* arg = NULL;
            if (c->x[2]) {
                if (iocsz) {
                    arg = GuestPtr(c, c->x[2], iocsz);
                    if (!arg) { c->x[0] = (uint64_t)(-EFAULT); break; }
                } else {
                    arg = (void*)(uintptr_t)c->x[2];
                }
            }
            c->x[0] = RetU(ioctl((int)c->x[0], c->x[1], arg));
            break;
        }
    }

    /* ── the rest of the Linux AArch64 surface ─────────────────────────────
       Grouped here rather than at their numeric positions so additions stay in
       one readable place. Every pointer argument goes through GuestPtr: a guest
       VA is an offset into one host allocation, never a host pointer. */
    case 17: { /* getcwd(buf, size) */
        char* p = (char*)GuestPtr(c, c->x[0], c->x[1]);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = getcwd(p, (size_t)c->x[1]) ? c->x[0] : (uint64_t)(-errno);
        break;
    }
    case 85: /* timerfd_create(clockid, flags) */
        c->x[0] = RetU(timerfd_create((int)c->x[0], (int)c->x[1]));
        break;
    case 86: { /* timerfd_settime(fd, flags, new_value, old_value): struct itimerspec is two 64-bit timespecs on the
                  guest and (with 64-bit time_t) on every host this runtime builds for */
        const struct itimerspec* nv = (const struct itimerspec*)GuestPtr(c, c->x[2], sizeof(struct itimerspec));
        struct itimerspec* ov = c->x[3] ? (struct itimerspec*)GuestPtr(c, c->x[3], sizeof(struct itimerspec)) : NULL;
        if (!nv || (c->x[3] && !ov)) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(timerfd_settime((int)c->x[0], (int)c->x[1], nv, ov));
        break;
    }
    case 87: { /* timerfd_gettime(fd, curr_value) */
        struct itimerspec* cv = (struct itimerspec*)GuestPtr(c, c->x[1], sizeof(struct itimerspec));
        if (!cv) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(timerfd_gettime((int)c->x[0], cv));
        break;
    }
    case 19: /* eventfd2(initval, flags) */
        c->x[0] = RetU(eventfd((unsigned)c->x[0], (int)c->x[1]));
        break;
    case 20: /* epoll_create1(flags) */
        c->x[0] = RetU(epoll_create1((int)c->x[0]));
        break;
    case 21: { /* epoll_ctl(epfd, op, fd, event)
                  The AArch64 struct epoll_event is 16 bytes {u32 events; u32 pad;
                  u64 data}; x86-64's is 12 bytes and PACKED (data at offset 4).
                  Passing guest memory straight through made the host read `data`
                  from the guest's padding and write results at a 12-byte stride
                  the guest reads at 16.  Translate both ways. */
        struct epoll_event hev, *hp = NULL;
        if (c->x[3]) {
            const struct GuestEpollEvent* g =
                (const struct GuestEpollEvent*)GuestPtr(c, c->x[3], sizeof *g);
            if (!g) { c->x[0] = (uint64_t)(-EFAULT); break; }
            memset(&hev, 0, sizeof hev);
            hev.events = g->events;
            hev.data.u64 = g->data;
            hp = &hev;
        }
        c->x[0] = RetU(epoll_ctl((int)c->x[0], (int)c->x[1], (int)c->x[2], hp));
        break;
    }
    case 22: { /* epoll_pwait(epfd, events, max, timeout_ms, sigmask, sigsetsize)
                  The signal mask is dropped: installing a guest-sized sigset_t
                  would need its own translation.  Events are collected in host
                  layout and written back in the guest's 16-byte layout. */
        const int maxev = (int)c->x[2];
        if (maxev <= 0) { c->x[0] = (uint64_t)(-EINVAL); break; }
        struct GuestEpollEvent* gev = (struct GuestEpollEvent*)GuestPtr(
            c, c->x[1], (uint64_t)maxev * sizeof(struct GuestEpollEvent));
        if (!gev) { c->x[0] = (uint64_t)(-EFAULT); break; }
        struct epoll_event stackev[64];
        struct epoll_event* hev = stackev;
        if (maxev > 64) {
            hev = (struct epoll_event*)malloc((size_t)maxev * sizeof *hev);
            if (!hev) { c->x[0] = (uint64_t)(-ENOMEM); break; }
        }
        const int r = epoll_wait((int)c->x[0], hev, maxev, (int)c->x[3]);
        const int e = errno;
        for (int i = 0; i < r; ++i) {
            gev[i].events = hev[i].events;
            gev[i].pad = 0;
            gev[i].data = hev[i].data.u64;
        }
        if (hev != stackev) free(hev);
        c->x[0] = r < 0 ? (uint64_t)(-e) : (uint64_t)r;
        break;
    }
    case 23: { /* dup(fd) */
        const int t = a64port_device_fdtype((int)c->x[0]);
        const int r = dup((int)c->x[0]);
        if (r >= 0) device_reg(r, t);
        c->x[0] = RetU(r);
        break;
    }
    case 24: { /* dup3(oldfd, newfd, flags) */
        const int t = a64port_device_fdtype((int)c->x[0]);
        const int r = dup3((int)c->x[0], (int)c->x[1], (int)c->x[2]);
        if (r >= 0) device_reg(r, t);
        c->x[0] = RetU(r);
        break;
    }
    case 25: { /* fcntl(fd, cmd, arg) — only the lock commands take a pointer */
        const int cmd = (int)c->x[1];
        void* arg = (void*)(uintptr_t)c->x[2];
        const int t = a64port_device_fdtype((int)c->x[0]);
        if (cmd == 5 || cmd == 6 || cmd == 7 ||    /* F_GETLK / F_SETLK / F_SETLKW */
            cmd == 36 || cmd == 37 || cmd == 38) { /* F_OFD_GETLK / SETLK / SETLKW */
            arg = GuestPtr(c, c->x[2], 32);
            if (!arg) { c->x[0] = (uint64_t)(-EFAULT); break; }
        }
#if UINTPTR_MAX == 0xffffffffu
        /* The guest's struct flock has 64-bit l_start/l_len (aarch64 layout = ARM EABI struct flock64).
           A 32-bit host kernel reads cmd 5/6/7 as the old 32-bit struct flock: l_start came from the
           guest's uninitialised padding word -> random EINVAL (SQLite "disk I/O error") and wrong lock
           ranges. Use F_GETLK64/F_SETLK64/F_SETLKW64 (12/13/14); OFD commands already take flock64. */
        const int hcmd = (cmd >= 5 && cmd <= 7) ? cmd + 7 : cmd;
        const long r = syscall(SYS_fcntl64, (int)c->x[0], hcmd, arg);
#else
        const long r = fcntl((int)c->x[0], cmd, arg);
#endif
        if (r >= 0 && (cmd == 0 || cmd == 1030)) device_reg((int)r, t);  /* F_DUPFD* */
        c->x[0] = RetU(r);
        break;
    }
    case 34: { /* mkdirat(dirfd, path, mode) */
        const char* p = (const char*)GuestPtr(c, c->x[1], 1);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(mkdirat((int)(int32_t)c->x[0], a64port_guest_path(p), (mode_t)c->x[2]));
        break;
    }
    case 35: { /* unlinkat(dirfd, path, flags) */
        const char* p = (const char*)GuestPtr(c, c->x[1], 1);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(unlinkat((int)(int32_t)c->x[0], a64port_guest_path(p), (int)c->x[2]));
        break;
    }
    case 36: { /* symlinkat(target, newdirfd, linkpath) */
        const char* tgt = (const char*)GuestPtr(c, c->x[0], 1);
        const char* link = (const char*)GuestPtr(c, c->x[2], 1);
        if (!tgt || !link) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(symlinkat(tgt, (int)(int32_t)c->x[1], a64port_guest_path(link)));
        break;
    }
    case 37: { /* linkat(olddirfd, oldpath, newdirfd, newpath, flags) */
        const char* a = (const char*)GuestPtr(c, c->x[1], 1);
        const char* b = (const char*)GuestPtr(c, c->x[3], 1);
        if (!a || !b) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(linkat((int)(int32_t)c->x[0], a64port_guest_path(a),
                              (int)(int32_t)c->x[2], a64port_guest_path(b), (int)c->x[4]));
        break;
    }
    case 38: { /* renameat(olddirfd, oldpath, newdirfd, newpath) */
        const char* a = (const char*)GuestPtr(c, c->x[1], 1);
        const char* b = (const char*)GuestPtr(c, c->x[3], 1);
        if (!a || !b) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(renameat((int)(int32_t)c->x[0], a64port_guest_path(a),
                                (int)(int32_t)c->x[2], a64port_guest_path(b)));
        break;
    }
    case 39: { /* umount2(target, flags) */
        const char* p = (const char*)GuestPtr(c, c->x[0], 1);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(umount2(a64port_guest_path(p), (int)c->x[1]));
        break;
    }
    case 40: { /* mount(source, target, fstype, flags, data) */
        const char* src = (const char*)GuestPtr(c, c->x[0], 1);
        const char* tgt = (const char*)GuestPtr(c, c->x[1], 1);
        const char* fst = (const char*)GuestPtr(c, c->x[2], 1);
        const void* data = c->x[4] ? (const void*)GuestPtr(c, c->x[4], 1) : NULL;
        if (!src || !tgt || !fst) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(mount(a64port_guest_path(src), a64port_guest_path(tgt), fst,
                             (unsigned long)c->x[3], data));
        break;
    }
    case 43: { /* statfs(path, buf) */
        const char* p = (const char*)GuestPtr(c, c->x[0], 1);
        void* out = GuestPtr(c, c->x[1], sizeof(struct GuestStatfs));
        struct statfs h;
        if (!p || !out) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (statfs(a64port_guest_path(p), &h) < 0) { c->x[0] = (uint64_t)(-errno); break; }
        FillGuestStatfs((struct GuestStatfs*)out, &h);
        c->x[0] = 0;
        break;
    }
    case 44: { /* fstatfs(fd, buf) */
        void* out = GuestPtr(c, c->x[1], sizeof(struct GuestStatfs));
        struct statfs h;
        if (!out) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (fstatfs((int)c->x[0], &h) < 0) { c->x[0] = (uint64_t)(-errno); break; }
        FillGuestStatfs((struct GuestStatfs*)out, &h);
        c->x[0] = 0;
        break;
    }
    case 45: { /* truncate(path, length) */
        const char* p = (const char*)GuestPtr(c, c->x[0], 1);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(truncate(a64port_guest_path(p), (off_t)(int64_t)c->x[1]));
        break;
    }
    case 46: /* ftruncate(fd, length) */
        c->x[0] = RetU(ftruncate((int)c->x[0], (off_t)(int64_t)c->x[1]));
        break;
    case 47: /* fallocate(fd, mode, offset, len) */
        c->x[0] = RetU(fallocate((int)c->x[0], (int)c->x[1],
                                 (off_t)(int64_t)c->x[2], (off_t)(int64_t)c->x[3]));
        break;
    case 49: { /* chdir(path) */
        const char* p = (const char*)GuestPtr(c, c->x[0], 1);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(chdir(a64port_guest_path(p)));
        break;
    }
    case 52: /* fchmod(fd, mode) */
        c->x[0] = RetU(fchmod((int)c->x[0], (mode_t)c->x[1]));
        break;
    case 53: { /* fchmodat(dirfd, path, mode) - three arguments, like faccessat */
        const char* p = (const char*)GuestPtr(c, c->x[1], 1);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(fchmodat((int)(int32_t)c->x[0], a64port_guest_path(p),
                                (mode_t)c->x[2], 0));
        break;
    }
    case 59: { /* pipe2(fds, flags) */
        int32_t* out = (int32_t*)GuestPtr(c, c->x[0], 8);
        int fd[2];
        if (!out) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (pipe2(fd, (int)c->x[1]) < 0) { c->x[0] = (uint64_t)(-errno); break; }
        out[0] = fd[0]; out[1] = fd[1];
        c->x[0] = 0;
        break;
    }
    case 65: { /* readv(fd, iov, iovcnt) */
        struct iovec hi[256];
        if (c->x[2] > 256 || XlateIov(c, c->x[1], c->x[2], hi, 256) != 0) {
            c->x[0] = (uint64_t)(-EFAULT); break;
        }
        if (a64port_device_fdtype((int)c->x[0])) {
            const ssize_t r = device_readv(c, (int)c->x[0], hi, (int)c->x[2]);
            c->x[0] = r < 0 ? (uint64_t)(-errno) : (uint64_t)r;
            break;
        }
        c->x[0] = RetU(readv((int)c->x[0], hi, (int)c->x[2]));
        break;
    }
    case 72: { /* pselect6(nfds, r, w, e, timeout, sig) — the sigset is dropped */
        fd_set* r = (fd_set*)GuestPtr(c, c->x[1], 128);
        fd_set* w = (fd_set*)GuestPtr(c, c->x[2], 128);
        fd_set* e = (fd_set*)GuestPtr(c, c->x[3], 128);
        int64_t* t = (int64_t*)GuestPtr(c, c->x[4], 16);
        struct timespec ts;
        if (t) { ts.tv_sec = (time_t)t[0]; ts.tv_nsec = (long)t[1]; }
        c->x[0] = RetU(pselect((int)c->x[0], r, w, e, t ? &ts : NULL, NULL));
        break;
    }
    case 73: { /* ppoll(fds, nfds, timeout, sigmask, sigsetsize) */
        struct pollfd* f = (struct pollfd*)GuestPtr(c, c->x[0], c->x[1] * 8);
        int64_t* t = (int64_t*)GuestPtr(c, c->x[2], 16);
        if (!f && c->x[1]) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (EnvOn("A64PORT_POLL_TRACE")) {
            /* Who is polling?  Walking the guest's x29 chain here gives the
               *app* frames (the PC is inside libc's __ppoll). */
            fprintf(stderr, "[poll] ppoll nfds=%llu fd=%d timeout=%s caller_x30=0x%llx\n",
                    (unsigned long long)c->x[1], c->x[1] ? f[0].fd : -1,
                    t ? "" : "blocking", (unsigned long long)c->x[30]);
            if (t) fprintf(stderr, "[poll]   timeout=%lld.%09lld\n",
                           (long long)t[0], (long long)t[1]);
            uint64_t fp = c->x[29];
            for (int k = 0; k < 24; ++k) {
                uint64_t* fr = (uint64_t*)GuestPtr(c, fp, 16);
                if (!fr) break;
                fprintf(stderr, "[poll]   bt#%-2d ret=0x%llx\n", k,
                        (unsigned long long)fr[1]);
                if (fr[0] <= fp) break;
                fp = fr[0];
            }
        }
        const int timeout_ms = t ? (int)(t[0] * 1000 + t[1] / 1000000) : -1;
        const int dr = device_ppoll(c, f, c->x[1], timeout_ms);
        if (dr != -2) { c->x[0] = dr < 0 ? (uint64_t)(-errno) : (uint64_t)dr; break; }
        struct timespec ts;
        if (t) { ts.tv_sec = (time_t)t[0]; ts.tv_nsec = (long)t[1]; }
        c->x[0] = RetU(ppoll(f, (nfds_t)c->x[1], t ? &ts : NULL, NULL));
        break;
    }
    case 88: { /* utimensat(dirfd, path, times, flags) */
        const char* p = (const char*)GuestPtr(c, c->x[1], 1);
        int64_t* t = (int64_t*)GuestPtr(c, c->x[2], 32);
        struct timespec ts[2];
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (t) {
            ts[0].tv_sec = (time_t)t[0]; ts[0].tv_nsec = (long)t[1];
            ts[1].tv_sec = (time_t)t[2]; ts[1].tv_nsec = (long)t[3];
        }
        c->x[0] = RetU(utimensat((int)(int32_t)c->x[0], a64port_guest_path(p),
                                 t ? ts : NULL, (int)c->x[3]));
        break;
    }
    case 118:   /* sched_setparam(pid, param) */
    case 119: { /* sched_setscheduler(pid, policy, param) */
        /* Passed to the host: a guest tid IS a host tid, and the policy
           numbers and struct sched_param (one int) are the same on every Linux
           ABI.  A guest's real-time thread asks for SCHED_FIFO; ignoring that left
           it competing at normal priority with hundreds of threads on a 4-core
           board, and every lock its peers held turned into a missed deadline.  A refusal (no
           CAP_SYS_NICE: the x86 sandbox) still answers 0, as before.
           A64PORT_SCHED=0 ignores the requests again. */
        const int32_t* pp = (const int32_t*)GuestPtr(c, c->x[c->x[8] == 118 ? 1 : 2], 4);
        if (!pp) { c->x[0] = (uint64_t)(-EFAULT); break; }
        /* A64PORT_SCHED: "nice" (default) keeps the requested ORDER without real
           time - FIFO/RR priority 1..99 becomes nice -1..-19 under SCHED_OTHER.
           A toolkit may ask for RR 50 on nearly every thread; granted for real on a
           4-core board with hundreds of threads, a waiting thread spun at RT and
           starved the page fillers, X and the other real-time work.  "rt" passes
           the request through as is, "0" ignores it. */
        static int sched_mode = -1;                 /* 0 ignore, 1 nice, 2 rt */
        if (sched_mode < 0) {
            const char* e = getenv("A64PORT_SCHED");
            sched_mode = !e || !*e || !strcmp(e, "nice") ? 1 : !strcmp(e, "rt") ? 2 : *e == '0' ? 0 : 1;
        }
        if (sched_mode) {
            struct sched_param sp; memset(&sp, 0, sizeof sp);
            sp.sched_priority = *pp;
            const pid_t who = (pid_t)(int32_t)c->x[0];
            const int pol = c->x[8] == 118 ? -1 : (int)c->x[1];
            int r;
            if (sched_mode == 2) {
                r = c->x[8] == 118 ? sched_setparam(who, &sp) : sched_setscheduler(who, pol, &sp);
            } else if (pol == 1 || pol == 2 || (pol == -1 && *pp > 0)) {
                int nice = -(1 + (*pp > 0 ? (*pp - 1) * 18 / 98 : 0));
                const int tid = who ? (int)who : (int)syscall(SYS_gettid);
                /* a CPU pin rule with a nice value wins (host_loader.c, A64PORT_CPU_PIN "@nice") */
                extern int a64port_pin_nice(int tid, int* nice) __attribute__((weak));
                if (a64port_pin_nice) a64port_pin_nice(tid, &nice);
                r = setpriority(PRIO_PROCESS, (id_t)tid, nice);
            } else {
                r = 0;                              /* OTHER/BATCH/IDLE: keep the default nice */
            }
            static int logged;
            if (logged < 64) {
                ++logged;
                char nm[32] = "?";
                char path[64]; snprintf(path, sizeof path, "/proc/self/task/%d/comm", who ? (int)who : (int)syscall(SYS_gettid));
                FILE* f = fopen(path, "r");
                if (f) { if (fgets(nm, sizeof nm, f)) nm[strcspn(nm, "\n")] = 0; fclose(f); }
                fprintf(stderr, "[a64port] sched: %s tid %d policy %d prio %d -> %s\n", nm, (int)who,
                        c->x[8] == 118 ? -1 : (int)c->x[1], *pp, r == 0 ? "applied" : strerror(errno));
            }
        }
        c->x[0] = 0;
        break;
    }
    case 120: { /* sched_getscheduler(pid) */
        const int r = sched_getscheduler((pid_t)(int32_t)c->x[0]);
        c->x[0] = r < 0 ? 0 : (uint64_t)r;   /* SCHED_OTHER if the host will not say */
        break;
    }
    case 121: { /* sched_getparam(pid, param) — struct sched_param is one int */
        int32_t* p = (int32_t*)GuestPtr(c, c->x[1], 4);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        struct sched_param sp; memset(&sp, 0, sizeof sp);
        *p = sched_getparam((pid_t)(int32_t)c->x[0], &sp) == 0 ? sp.sched_priority : 0;
        c->x[0] = 0;
        break;
    }
    case 122:   /* sched_setaffinity(pid, cpusetsize, mask) — one CPU is fine */
        c->x[0] = 0;
        break;
    case 124:   /* sched_yield() */
        sched_yield();
        c->x[0] = 0;
        break;
    case 125:   /* sched_get_priority_max(policy) */
    case 126: { /* sched_get_priority_min(policy) */
        /* The host's answer (1..99 for FIFO/RR): the application's toolkit derives every thread
           priority from this range, and 0/0 turned its real-time requests into
           priority 0, which the kernel rejects (EINVAL) for FIFO/RR. */
        const int pol = (int)c->x[0];
        const int r = c->x[8] == 125 ? sched_get_priority_max(pol) : sched_get_priority_min(pol);
        c->x[0] = r < 0 ? (uint64_t)(-errno) : (uint64_t)r;
        break;
    }
    case 102:   /* getitimer(which, curr) and setitimer(which, new, old): struct itimerval is two 64-bit timevals */
    case 103: {
        const int setting = n == 103;
        struct itimerval* a = (struct itimerval*)GuestPtr(c, c->x[1], sizeof(struct itimerval));
        struct itimerval* b = setting && c->x[2] ? (struct itimerval*)GuestPtr(c, c->x[2], sizeof(struct itimerval)) : NULL;
        if (!a || (setting && c->x[2] && !b)) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = setting ? RetU(setitimer((int)c->x[0], a, b)) : RetU(getitimer((int)c->x[0], a));
        break;
    }
    case 138:   /* rt_sigqueueinfo(tgid, sig, uinfo) */
    case 240: { /* rt_tgsigqueueinfo(tgid, tid, sig, uinfo): the guest's siginfo is rebuilt for the host's layout */
        const int sig = (int)(n == 138 ? c->x[1] : c->x[2]);
        const uint8_t* gi = (const uint8_t*)GuestPtr(c, n == 138 ? c->x[2] : c->x[3], 32);
        if (!gi) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (sig < 0 || sig >= NSIG) { c->x[0] = (uint64_t)(-EINVAL); break; }
        if ((int32_t)c->x[0] != 1) { c->x[0] = (uint64_t)(-ESRCH); break; }      /* only this process exists */
        siginfo_t hi;
        memset(&hi, 0, sizeof hi);
        int32_t code, gpid, guid; uint64_t gval;
        memcpy(&code, gi + 8, 4); memcpy(&gpid, gi + 16, 4); memcpy(&guid, gi + 20, 4); memcpy(&gval, gi + 24, 8);
        hi.si_signo = sig; hi.si_code = code; hi.si_pid = getpid(); hi.si_uid = getuid();
        hi.si_value.sival_ptr = (void*)(uintptr_t)gval;
        (void)gpid; (void)guid;
        c->x[0] = n == 138 ? RetU(syscall(SYS_rt_sigqueueinfo, getpid(), sig, &hi))
                           : RetU(syscall(SYS_rt_tgsigqueueinfo, getpid(), (int)(int32_t)c->x[1], sig, &hi));
        break;
    }
    case 129: { /* kill(pid, sig) — guest PID 1 is this translated process.
                   Never forward arbitrary guest PIDs to the host: children are
                   synthetic, and forwarding SIGKILL used to kill the host
                   process running the translator. */
        const int pid = (int32_t)c->x[0], sig = (int)c->x[1];
        if (sig < 0 || sig >= NSIG) { c->x[0] = (uint64_t)(-EINVAL); break; }
        if (pid == 1) {
            if (sig) { if (g_sa_sig) kill(getpid(), sig); else raise(sig); }   /* standalone: process-directed, SI_USER */
            c->x[0] = 0;
        } else {
            c->x[0] = (uint64_t)(-ESRCH); /* no external guest processes */
        }
        break;
    }
    case 130: { /* tkill(tid, sig): constrain delivery to this process. */
        const int tid = (int32_t)c->x[0], sig = (int)c->x[1];
        if (sig < 0 || sig >= NSIG) { c->x[0] = (uint64_t)(-EINVAL); break; }
        c->x[0] = RetU((ssize_t)syscall(SYS_tgkill, getpid(), tid, sig));
        break;
    }
    case 131: { /* tgkill(tgid, tid, sig): map guest PID 1 to this host process,
                   and let the kernel verify the target TID belongs to it. */
        const int tgid = (int32_t)c->x[0], tid = (int32_t)c->x[1];
        const int sig = (int)c->x[2];
        if (sig < 0 || sig >= NSIG) { c->x[0] = (uint64_t)(-EINVAL); break; }
        if (tgid != 1) { c->x[0] = (uint64_t)(-ESRCH); break; }
        c->x[0] = RetU((ssize_t)syscall(SYS_tgkill, getpid(), tid, sig));
        break;
    }
    case 132: { /* sigaltstack(ss, oss)
                   Recorded per thread, NOT installed on the host: the guest
                   stack_t's ss_sp is a guest VA, and a host handler that ran on
                   it (SA_ONSTACK) would write its frame at a bogus host address.
                   Guest handlers are never invoked by the
                   host kernel, so the recorded value is all the guest can
                   observe.  Layout: {u64 ss_sp; i32 ss_flags; pad; u64 ss_size}. */
        static __thread uint64_t alt[3] = { 0, 2 /* SS_DISABLE */, 0 };
        if (c->x[1]) {
            uint64_t* o = (uint64_t*)GuestPtr(c, c->x[1], 24);
            if (!o) { c->x[0] = (uint64_t)(-EFAULT); break; }
            o[0] = alt[0]; o[1] = alt[1]; o[2] = alt[2];
        }
        if (c->x[0]) {
            const uint64_t* n2 = (const uint64_t*)GuestPtr(c, c->x[0], 24);
            if (!n2) { c->x[0] = (uint64_t)(-EFAULT); break; }
            const int32_t fl = (int32_t)(uint32_t)n2[1];
            if (fl & 2) { alt[0] = 0; alt[1] = 2; alt[2] = 0; }      /* SS_DISABLE */
            else {
                if (n2[2] < 2048) { c->x[0] = (uint64_t)(-ENOMEM); break; } /* MINSIGSTKSZ */
                alt[0] = n2[0]; alt[1] = (uint32_t)fl; alt[2] = n2[2];
            }
        }
        c->x[0] = 0;
        break;
    }
    case 165: { /* getrusage(who, usage) */
        void* out = GuestPtr(c, c->x[1], sizeof(struct GuestRusage));
        struct rusage h;
        if (!out) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (getrusage((int)c->x[0], &h) < 0) { c->x[0] = (uint64_t)(-errno); break; }
        FillGuestRusage((struct GuestRusage*)out, &h);
        c->x[0] = 0;
        break;
    }
    case 167: { /* prctl(option, ...) */
        if (c->x[0] == 15) {          /* PR_SET_NAME */
            const char* p = (const char*)GuestPtr(c, c->x[1], 16);
            if (p) { char nm[16]; memcpy(nm, p, 15); nm[15] = 0; prctl(PR_SET_NAME, nm, 0, 0, 0); }
        } else if (c->x[0] == 16) {   /* PR_GET_NAME */
            char* p = (char*)GuestPtr(c, c->x[1], 16);
            if (p) { memset(p, 0, 16); prctl(PR_GET_NAME, p, 0, 0, 0); }
        }
        c->x[0] = 0;
        break;
    }
    case 179: { /* sysinfo(info) — what sysconf(_SC_PHYS_PAGES) reads */
        void* out = GuestPtr(c, c->x[0], sizeof(struct GuestSysinfo));
        struct sysinfo h;
        if (!out) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (sysinfo(&h) < 0) { c->x[0] = (uint64_t)(-errno); break; }
        FillGuestSysinfo((struct GuestSysinfo*)out, &h);
        c->x[0] = 0;
        break;
    }
    case 283:   /* membarrier — nothing to do; the host orders these stores */
        c->x[0] = 0;
        break;

    /* ── sockets: what X11/XCB needs before it can reach a display ───────── */
    case 198:   /* socket(domain, type, protocol) */
        c->x[0] = RetU(socket((int)c->x[0], (int)c->x[1], (int)c->x[2]));
        break;
    case 199: { /* socketpair(domain, type, protocol, sv[2]) */
        int32_t* out = (int32_t*)GuestPtr(c, c->x[3], 8);
        int fd[2];
        if (!out) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (socketpair((int)c->x[0], (int)c->x[1], (int)c->x[2], fd) < 0) {
            c->x[0] = (uint64_t)(-errno); break;
        }
        out[0] = fd[0]; out[1] = fd[1];
        c->x[0] = 0;
        break;
    }
    case 200: { /* bind(fd, addr, len) */
        void* a = GuestPtr(c, c->x[1], c->x[2] ? c->x[2] : 1);
        if (!a) { c->x[0] = (uint64_t)(-EFAULT); break; }
        int r = bind((int)c->x[0], (struct sockaddr*)a, (socklen_t)c->x[2]);
        const char* relax_bind = getenv("A64PORT_RELAX_PRIVILEGED_BIND");
        if (r < 0 && relax_bind && !strcmp(relax_bind, "1") &&
            (errno == EACCES || errno == EPERM) &&
            c->x[2] >= sizeof(struct sockaddr_in) &&
            ((struct sockaddr*)a)->sa_family == AF_INET) {
            const struct sockaddr_in* requested = (const struct sockaddr_in*)a;
            FILE* f = fopen("/proc/sys/net/ipv4/ip_unprivileged_port_start", "r");
            unsigned low_port = 1024;
            if (f) { (void)fscanf(f, "%u", &low_port); fclose(f); }
            if (ntohs(requested->sin_port) < low_port) {
                struct sockaddr_in ephemeral = *requested;
                ephemeral.sin_port = 0;
                r = bind((int)c->x[0], (struct sockaddr*)&ephemeral,
                         (socklen_t)sizeof ephemeral);
                if (r == 0) {
                    fprintf(stderr, "[a64port] host lacks low-port privilege; guest bind %u -> ephemeral port\n",
                            ntohs(requested->sin_port));
                }
            }
        }
        if (r < 0) {
            const struct sockaddr* sa = (const struct sockaddr*)a;
            if (sa->sa_family == AF_INET && c->x[2] >= sizeof(struct sockaddr_in)) {
                const struct sockaddr_in* sin = (const struct sockaddr_in*)sa;
                fprintf(stderr, "[a64port] bind(fd=%d %s:%u len=%llu) failed: %s\n",
                        (int)c->x[0], inet_ntoa(sin->sin_addr), ntohs(sin->sin_port),
                        (unsigned long long)c->x[2], strerror(errno));
            } else {
                fprintf(stderr, "[a64port] bind(fd=%d family=%u len=%llu) failed: %s\n",
                        (int)c->x[0], (unsigned)sa->sa_family,
                        (unsigned long long)c->x[2], strerror(errno));
            }
        }
        c->x[0] = RetU(r);
        break;
    }
    case 201:   /* listen(fd, backlog) */
        c->x[0] = RetU(listen((int)c->x[0], (int)c->x[1]));
        break;
    case 202:   /* accept(fd, addr, len) */
    case 242: { /* accept4(fd, addr, len, flags) */
        void* a = GuestPtr(c, c->x[1], 128);
        uint32_t* al = (uint32_t*)GuestPtr(c, c->x[2], 4);
        if (al && *al > 128) *al = 128;
        c->x[0] = RetU(n == 242
            ? accept4((int)c->x[0], (struct sockaddr*)a, (socklen_t*)al, (int)c->x[3])
            : accept((int)c->x[0], (struct sockaddr*)a, (socklen_t*)al));
        break;
    }
    case 203: { /* connect(fd, addr, len) */
        void* a = GuestPtr(c, c->x[1], c->x[2] ? c->x[2] : 1);
        if (!a) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(connect((int)c->x[0], (struct sockaddr*)a, (socklen_t)c->x[2]));
        break;
    }
    case 204:   /* getsockname(fd, addr, len) */
    case 205: { /* getpeername(fd, addr, len) */
        void* a = GuestPtr(c, c->x[1], 128);
        uint32_t* al = (uint32_t*)GuestPtr(c, c->x[2], 4);
        c->x[0] = RetU(n == 204
            ? getsockname((int)c->x[0], (struct sockaddr*)a, (socklen_t*)al)
            : getpeername((int)c->x[0], (struct sockaddr*)a, (socklen_t*)al));
        break;
    }
    case 206: { /* sendto(fd, buf, len, flags, addr, addrlen) */
        void* b = GuestPtr(c, c->x[1], c->x[2] ? c->x[2] : 1);
        void* a = GuestPtr(c, c->x[4], c->x[5] ? c->x[5] : 1);
        c->x[0] = RetU(sendto((int)c->x[0], b, (size_t)c->x[2], (int)c->x[3],
                              (struct sockaddr*)a, (socklen_t)c->x[5]));
        break;
    }
    case 207: { /* recvfrom(fd, buf, len, flags, addr, addrlen) */
        void* b = GuestPtr(c, c->x[1], c->x[2] ? c->x[2] : 1);
        void* a = GuestPtr(c, c->x[4], 128);
        uint32_t* al = (uint32_t*)GuestPtr(c, c->x[5], 4);
        c->x[0] = RetU(recvfrom((int)c->x[0], b, (size_t)c->x[2], (int)c->x[3],
                                (struct sockaddr*)a, (socklen_t*)al));
        break;
    }
    case 208:   /* setsockopt(fd, level, optname, val, optlen) */
    case 209: { /* getsockopt(fd, level, optname, val, optlen) */
        if (n == 208) {
            int r = guest_setsockopt(c, (int)c->x[0], (int)c->x[1], (int)c->x[2],
                                     c->x[3], c->x[4]);
            if (r < 0)
                fprintf(stderr, "[a64port] setsockopt(fd=%d level=%d opt=%d len=%llu) failed: %s\n",
                        (int)c->x[0], (int)c->x[1], (int)c->x[2],
                        (unsigned long long)c->x[4], strerror(errno));
            c->x[0] = RetU(r);
        } else {
            /* x4 is a POINTER to the length (setsockopt's x4 is the length itself): the value
               buffer is as long as that length says.  Sizing it by x4 itself - an address -
               made GuestPtr fail for every call, so libpcap's SO_BPF_EXTENSIONS / PACKET_HDRLEN
               probes got EFAULT and the guest's pcap handles never came up. */
            uint32_t* ol = c->x[4] ? (uint32_t*)GuestPtr(c, c->x[4], 4) : NULL;
            void* v = (ol && c->x[3]) ? GuestPtr(c, c->x[3], *ol ? *ol : 1) : NULL;
            if ((c->x[4] && !ol) || (c->x[3] && !v)) { c->x[0] = (uint64_t)(-EFAULT); break; }
            c->x[0] = RetU(getsockopt((int)c->x[0], (int)c->x[1], (int)c->x[2],
                                       v, (socklen_t*)ol));
        }
        break;
    }
    case 210:   /* shutdown(fd, how) */
        c->x[0] = RetU(shutdown((int)c->x[0], (int)c->x[1]));
        break;
    case 211:   /* sendmsg(fd, msg, flags) */
    case 212: { /* recvmsg(fd, msg, flags) */
        struct GuestMsghdr* gm =
            (struct GuestMsghdr*)GuestPtr(c, c->x[1], sizeof *gm);
        struct iovec hi[256];
        struct msghdr hm;
        ssize_t r;
        if (!gm) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (XlateIov(c, gm->iov, gm->iovlen, hi, 256) != 0) {
            if (EnvOn("A64PORT_SYSCALL_ERR")) {
                const uint64_t* iv = (const uint64_t*)GuestPtr(c, gm->iov, 16);
                fprintf(stderr, "[msg] %s(fd %d): bad iov array 0x%llx x%llu (iov[0] base=0x%llx len=%llu)\n",
                        n == 211 ? "sendmsg" : "recvmsg", (int)c->x[0], (unsigned long long)gm->iov,
                        (unsigned long long)gm->iovlen, iv ? (unsigned long long)iv[0] : 0ull,
                        iv ? (unsigned long long)iv[1] : 0ull);
            }
            c->x[0] = (uint64_t)(-EFAULT); break;
        }
        memset(&hm, 0, sizeof hm);
        hm.msg_name = gm->name
            ? GuestPtr(c, gm->name, gm->namelen ? gm->namelen : 128) : NULL;
        hm.msg_namelen = gm->namelen;
        hm.msg_iov = hi;
        hm.msg_iovlen = (size_t)gm->iovlen;
        hm.msg_control = gm->control
            ? GuestPtr(c, gm->control, gm->controllen ? gm->controllen : 1) : NULL;
        hm.msg_controllen = (size_t)gm->controllen;
        hm.msg_flags = gm->flags;
        r = (n == 211) ? sendmsg((int)c->x[0], &hm, (int)c->x[2])
                       : recvmsg((int)c->x[0], &hm, (int)c->x[2]);
        /* recvmsg reports how much of the name and control buffers it used,
           and the message flags (MSG_TRUNC/MSG_CTRUNC), through the msghdr:
           the guest must see those, not its own input values. */
        if (n == 212 && r >= 0) {
            gm->namelen = (uint32_t)hm.msg_namelen;
            gm->controllen = (uint64_t)hm.msg_controllen;
            gm->flags = hm.msg_flags;
        }
        c->x[0] = RetU(r);
        break;
    }
    case 48: { /* faccessat(dirfd, path, mode)
                  The aarch64 faccessat syscall (#48) takes only THREE arguments -
                  dfd, filename, mode. There is no flags argument (that arrived
                  with faccessat2, #439). Passing the caller's stray x3 as flags
                  made the host reject every call with EINVAL, so access() always
                  reported "not accessible" - which silently disabled libXau's
                  cookie lookup (no X authorisation) and made the toolkit's
                  file-exists check return false for files that exist. */
        const char* gpath = (const char*)GuestPtr(c, c->x[1], 1);
        if (!gpath) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (device_is_fabricated(gpath)) { c->x[0] = 0; break; }   /* the shim serves it */
        c->x[0] = RetU(faccessat((int)(int32_t)c->x[0], a64port_guest_path(gpath),
                                 (int)c->x[2], 0));
        break;
    }
    case 62: { /* lseek(fd, off, whence) — ld.so seeks before reading headers */
        const int lt = a64port_device_fdtype((int)c->x[0]);
        if (lt == FT_GPIO ||
            lt == FT_SYSFS_ZERO || lt == FT_SYSFS_CPUS) {
            c->x[0] = c->x[1];   /* register-file semantics: report the offset back */
            break;
        }
        c->x[0] = RetU((ssize_t)lseek((int)c->x[0], (off_t)(int64_t)c->x[1], (int)c->x[2]));
        break;
    }
    case 67: { /* pread64(fd, buf, count, pos) */
        uint8_t* p = GuestPtr(c, c->x[1], c->x[2]);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (a64port_device_fdtype((int)c->x[0])) {
            const ssize_t r = device_read(c, (int)c->x[0], p, (size_t)c->x[2]);
            c->x[0] = r < 0 ? (uint64_t)(-errno) : (uint64_t)r;
            break;
        }
        c->x[0] = RetU(pread((int)c->x[0], p, (size_t)c->x[2], (off_t)(int64_t)c->x[3]));
        break;
    }
    case 68: { /* pwrite64(fd, buf, count, pos) */
        const uint8_t* p = GuestPtr(c, c->x[1], c->x[2]);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (a64port_device_fdtype((int)c->x[0])) { c->x[0] = c->x[2]; break; }
        c->x[0] = RetU(pwrite((int)c->x[0], p, (size_t)c->x[2], (off_t)(int64_t)c->x[3]));
        break;
    }
    case 56: { /* openat(dirfd, path, flags, mode) — what open() compiles to */
        const char* gpath = (const char*)GuestPtr(c, c->x[1], 1);
        if (!gpath) { c->x[0] = (uint64_t)(-EFAULT); break; }
        /* Never let the guest ld.so dlopen a DSO that was not translated. The
           NSS service modules (libnss_files.so.2), gconv modules, ALSA plugin
           modules and similar all land here. Report them absent so the caller's
           fallback runs instead of jumping into raw AArch64 code and halting
           inside _dl_open with the loader lock held. */
        if ((strstr(gpath, ".so") || strstr(gpath, "libnss_")) &&
            !a64port_known_dso(gpath)) {
            c->x[0] = (uint64_t)(-ENOENT);
            break;
        }
        const int dev = device_open(gpath);
        if (dev >= 0) { c->x[0] = (uint64_t)dev; break; }
        const int r = openat((int)(int32_t)c->x[0], a64port_guest_path(gpath),
                             HostOpenFlags((uint32_t)c->x[2]), (mode_t)c->x[3]);
        /* Font loading is the difference between "the UI has text" and "the UI
           is blank": fontconfig finds nothing and the app silently draws no
           glyphs. A64PORT_FONT_DIAG=1 records every attempt so a run that lost
           its text can be told apart from one that never asked for a font. */
        if ((strstr(gpath, "/fonts") || strstr(gpath, ".ttf") ||
             strstr(gpath, ".otf") || strstr(gpath, ".ttc")) &&
            EnvOn("A64PORT_FONT_DIAG"))
            fprintf(stderr, "[font] openat(\"%s\") = %d (%s)\n",
                    gpath, r, r < 0 ? strerror(errno) : "ok");
        if (r >= 0) a64port_guest_note_open(r, gpath);
        c->x[0] = RetU(r);
        break;
    }
    case 57: { /* close(fd) */
        device_reg((int)c->x[0], FT_NONE);
        c->x[0] = RetU(close((int)c->x[0]));
        break;
    }
    case 63: { /* read(fd, buf, count) */
        uint8_t* p = GuestPtr(c, c->x[1], c->x[2]);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (a64port_device_fdtype((int)c->x[0])) {
            const ssize_t r = device_read(c, (int)c->x[0], p, (size_t)c->x[2]);
            c->x[0] = r < 0 ? (uint64_t)(-errno) : (uint64_t)r;
            break;
        }
        c->x[0] = RetU(read((int)c->x[0], p, (size_t)c->x[2]));
        break;
    }
    case 64: { /* write(fd, buf, count) */
        const uint8_t* p = GuestPtr(c, c->x[1], c->x[2]);
        if (!p) {
            fprintf(stderr, "[a64port] write: guest buffer 0x%llx+%llu out of range\n",
                    (unsigned long long)c->x[1], (unsigned long long)c->x[2]);
            c->x[0] = (uint64_t)(-EFAULT);
            break;
        }
        if (a64port_device_fdtype((int)c->x[0])) {
#ifdef A64PORT_HAVE_DEVICE_WRITE
            c->x[0] = (uint64_t)device_write((int)c->x[0], p, (size_t)c->x[2]);
#else
            c->x[0] = c->x[2];   /* fabricated devices accept and drain */
#endif
            break;
        }
        c->x[0] = RetU(write((int)c->x[0], p, (size_t)c->x[2]));
        break;
    }
    case 66: { /* writev(fd, iov, iovcnt) */
        const int fd = (int)c->x[0];
        const uint64_t cnt = c->x[2];
        if (cnt > 1024) { c->x[0] = (uint64_t)(-EINVAL); break; }
        const struct GuestIovec* gi = (const struct GuestIovec*)GuestPtr(c, c->x[1], cnt * 16);
        if (!gi) { c->x[0] = (uint64_t)(-EFAULT); break; }
        struct iovec hi[1024];
        int ok = 1;
        for (uint64_t i = 0; i < cnt; ++i) {
            /* A zero-length iovec carries no bytes, so its base is never
               dereferenced. POSIX explicitly allows iov_base to be NULL there,
               and callers rely on it: Xlib's _XSend(dpy, NULL, 0) sends the
               buffered request plus a literal {NULL, 0} pair, and glibc's
               readv/writev pass such entries straight to the kernel. Rejecting
               them turned every X request flush into EFAULT. */
            if (gi[i].len == 0) {
                hi[i].iov_base = NULL;
                hi[i].iov_len = 0;
                continue;
            }
            uint8_t* b = GuestPtr(c, gi[i].base, gi[i].len);
            if (!b) {
                if (EnvOn("A64PORT_WRITEV_DIAG"))
                    fprintf(stderr, "[writev] fd=%d iov[%llu] BAD base=0x%llx len=%llu -> EFAULT\n",
                            fd, (unsigned long long)i,
                            (unsigned long long)gi[i].base, (unsigned long long)gi[i].len);
                ok = 0; break;
            }
            hi[i].iov_base = b;
            hi[i].iov_len = (size_t)gi[i].len;
        }
        c->x[0] = ok ? RetU(writev(fd, hi, (int)cnt)) : (uint64_t)(-EFAULT);
        if (ok && a64port_device_fdtype(fd)) {
            size_t total = 0;
            for (uint64_t i = 0; i < cnt; ++i) total += hi[i].iov_len;
            c->x[0] = (uint64_t)total;   /* fabricated devices drain writes */
        } else if (EnvOn("A64PORT_WRITEV_DIAG")) {
            fprintf(stderr, "[writev] fd=%d cnt=%llu ret=%lld (%s)\n", fd,
                    (unsigned long long)cnt, (long long)(int64_t)c->x[0],
                    (int64_t)c->x[0] < 0 ? strerror((int)-c->x[0]) : "ok");
            for (uint64_t i = 0; i < cnt && i < 8; ++i)
                fprintf(stderr, "[writev]   iov[%llu] base=0x%llx len=%llu\n",
                        (unsigned long long)i, (unsigned long long)gi[i].base,
                        (unsigned long long)gi[i].len);
        }
        break;
    }
    case 78: { /* readlinkat(dirfd, path, buf, bufsiz) */
        const char* gpath = (const char*)GuestPtr(c, c->x[1], 1);
        char* buf = (char*)GuestPtr(c, c->x[2], c->x[3]);
        if (!gpath || !buf) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(readlinkat((int)(int32_t)c->x[0], a64port_guest_path(gpath),
                                  buf, (size_t)c->x[3]));
        break;
    }
    case 79: { /* newfstatat(dirfd, path, statbuf, flags) */
        const char* path = (const char*)GuestPtr(c, c->x[1], 1);
        void* out = GuestPtr(c, c->x[2], sizeof(struct GuestStat));
        struct stat h;
        if (!out) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (device_is_fabricated(path)) {
            struct GuestStat* gs = (struct GuestStat*)out;
            memset(gs, 0, sizeof *gs);
            /* /dev/* nodes are character devices; fabricated sysfs files are regular files. */
            gs->st_mode = (!strncmp(path, "/dev/", 5) ? S_IFCHR : S_IFREG) | 0666u;
            gs->st_size = 0; gs->st_nlink = 1;
            c->x[0] = 0; break;
        }
        const int r = (c->x[1] == 0 || (path && path[0] == 0))
                          ? fstat((int)(int32_t)c->x[0], &h)
                          : fstatat((int)(int32_t)c->x[0], a64port_guest_path(path),
                                    &h, (int)c->x[3]);
        if (r < 0) { c->x[0] = (uint64_t)(-errno); break; }
        FillGuestStat((struct GuestStat*)out, &h);
        c->x[0] = 0;
        break;
    }
    case 80: { /* fstat(fd, statbuf) */
        void* out = GuestPtr(c, c->x[1], sizeof(struct GuestStat));
        struct stat h;
        if (!out) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (fstat((int)c->x[0], &h) < 0) { c->x[0] = (uint64_t)(-errno); break; }
        FillGuestStat((struct GuestStat*)out, &h);
        c->x[0] = 0;
        break;
    }
    case 81: /* sync() */
        sync();
        c->x[0] = 0;
        break;
    case 82: /* fsync(fd) */
        c->x[0] = RetU(fsync((int)c->x[0]));
        break;
    case 83: /* fdatasync(fd) */
        c->x[0] = RetU(fdatasync((int)c->x[0]));
        break;
    case 84: /* sync_file_range(fd, off, nbytes, flags) */
        c->x[0] = RetU(sync_file_range((int)c->x[0], (off64_t)(int64_t)c->x[1],
                                       (off64_t)(int64_t)c->x[2], (unsigned)c->x[3]));
        break;
    case 186: /* msgget(key, msgflg) */
        c->x[0] = RetU(msgget((key_t)(int32_t)c->x[0], (int)c->x[1]));
        break;
    case 187: { /* msgctl(msqid, cmd, buf) */
        void* buf = c->x[2] ? GuestPtr(c, c->x[2], sizeof(struct msqid_ds)) : NULL;
        c->x[0] = RetU(msgctl((int)c->x[0], (int)c->x[1], buf));
        break;
    }
    case 188: { /* msgrcv(msqid, msgp, msgsz, msgtyp, msgflg) */
        void* msgp = GuestPtr(c, c->x[1], c->x[2] + 8);
        if (!msgp) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(msgrcv((int)c->x[0], msgp, (size_t)c->x[2],
                              (long)(int64_t)c->x[3], (int)c->x[4]));
        break;
    }
    case 189: { /* msgsnd(msqid, msgp, msgsz, msgflg) */
        void* msgp = GuestPtr(c, c->x[1], c->x[2] + 8);
        if (!msgp) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(msgsnd((int)c->x[0], msgp, (size_t)c->x[2], (int)c->x[3]));
        break;
    }
    case 190: /* semget(key, nsems, semflg) */
        c->x[0] = RetU(semget((key_t)(int32_t)c->x[0], (int)c->x[1], (int)c->x[2]));
        break;
    case 191: { /* semctl(semid, semnum, cmd, arg)
                   `arg` is a union: an int for GETVAL/SETVAL/GETPID/GETNCNT/
                   GETZCNT, but a POINTER for IPC_STAT/IPC_SET/GETALL/SETALL and
                   the IPC_INFO/SEM_INFO family. A guest VA is never a host
                   pointer, so those must go through GuestPtr or the host kernel
                   would write into arbitrary host memory. */
        const int cmd = (int)c->x[2];
        void* arg;
        switch (cmd) {
        case 1:  /* IPC_SET  */
        case 2:  /* IPC_STAT */
            arg = GuestPtr(c, c->x[3], 128);        /* struct semid_ds */
            break;
        case 3:  /* IPC_INFO */
        case 4:  /* SEM_INFO */
        case 18: /* SEM_STAT */
            arg = GuestPtr(c, c->x[3], 128);        /* struct seminfo */
            break;
        case 13: /* GETALL  */
        case 14: /* SETALL  */
            arg = GuestPtr(c, c->x[3], 8192);       /* unsigned short[nsems] */
            break;
        default:
            arg = (void*)(uintptr_t)c->x[3];        /* plain integer */
            break;
        }
        if (c->x[3] && !arg) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(semctl((int)c->x[0], (int)c->x[1], cmd, (unsigned long)arg));
        break;
    }
    case 192: /* semtimedop(semid, sops, nsops, timeout) */
    case 193: { /* semop(semid, sops, nsops) */
        void* sops = GuestPtr(c, c->x[1], c->x[2] * 6);
        if (!sops && c->x[2]) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (n == 192) {
            int64_t* t = (int64_t*)GuestPtr(c, c->x[3], 16);
            struct timespec ts;
            if (t) { ts.tv_sec = (time_t)t[0]; ts.tv_nsec = (long)t[1]; }
            c->x[0] = RetU(semtimedop((int)c->x[0], sops, (unsigned)c->x[2], t ? &ts : NULL));
        } else {
            c->x[0] = RetU(semop((int)c->x[0], sops, (unsigned)c->x[2]));
        }
        break;
    }
    case 194: /* shmget(key, size, shmflg) */
        /* A64PORT_NO_XSHM=1: no SysV shm, so a client's MIT-SHM probe fails and it draws
           with XPutImage (A/B for the ShmCompletion round trip). */
        if (EnvOn("A64PORT_NO_XSHM")) { c->x[0] = (uint64_t)(-ENOSYS); break; }
        c->x[0] = RetU(shmget((key_t)(int32_t)c->x[0], (size_t)c->x[1], (int)c->x[2]));
        fprintf(stderr, "[a64port] shmget(size=%llu) -> %lld\n", (unsigned long long)c->x[1],
                (long long)c->x[0]);
        break;
    case 195: { /* shmctl(shmid, cmd, buf) */
        const int cmd195 = (int)c->x[1];
        void* buf = c->x[2] ? GuestPtr(c, c->x[2], sizeof(struct shmid_ds)) : NULL;
        c->x[0] = RetU(shmctl((int)c->x[0], cmd195, buf));
        /* AArch64's shmid_ds has `size_t shm_segsz` (8 bytes at offset 48); the
           host's has `int shm_segsz` (4 bytes there).  Total size and every
           later offset agree, but a guest 8-byte read would fold in 4 bytes of
           stale padding.  Xlib's MIT-SHM reads exactly this field, so widen the
           value the kernel just wrote. */
        if (c->x[0] == 0 && buf && cmd195 == 2 /* IPC_STAT */) {
            uint64_t segsz;
            memcpy(&segsz, (char*)buf + 48, sizeof segsz);
            segsz &= 0xffffffffULL;
            memcpy((char*)buf + 48, &segsz, sizeof segsz);
        }
        break;
    }
    case 196: { /* shmat(shmid, shmaddr, shmflg) — attach into the guest arena */
        const int shmid = (int)c->x[0];
        const uint64_t hint = c->x[1];
        struct shmid_ds ds;
        if (shmctl(shmid, IPC_STAT, &ds) < 0) { c->x[0] = (uint64_t)(-errno); break; }
        const uint64_t len = (uint64_t)ds.shm_segsz;
        /* The host attach address must be SHMLBA-aligned: 16 KB on 32-bit ARM
           (four pages, for the VIPT cache), a page on x86.  Reserve one SHMLBA
           extra and attach at the aligned address inside the reservation; the
           guest just sees that address.  (On a 32-bit ARM board a page-aligned 0x...d000
           failed with EINVAL, so the MIT-SHM probe failed and the client fell back to
           XPutImage.) */
#ifdef SHMLBA
        const uint64_t lba = (uint64_t)SHMLBA;
#else
        const uint64_t lba = 0x1000;
#endif
        const uint64_t rlen = hint ? 0 : len + lba;
        const uint64_t rva = hint ? 0 : a64port_guest_reserve(rlen);
        uint64_t va = hint ? (hint & ~UINT64_C(0xFFF)) : (rva + lba - 1) & ~(lba - 1);
        if (!va) { c->x[0] = (uint64_t)(-ENOMEM); break; }
        void* ptr = GuestPtr(c, va, len);
        if (!ptr) { if (rva) a64port_guest_release(rva, rlen); c->x[0] = (uint64_t)(-ENOMEM); break; }
        /* The range is guest address space the host has already MAPPED (the
           multi host's arena pool hands ranges out by memset), and shmat onto a
           mapped range is EINVAL without SHM_REMAP.  Without it the client's MIT-SHM
           probe (shmget/shmat/XShmAttach) failed, and every frame went through
           the X socket with XPutImage: on a 32-bit ARM board the GUI thread then spent
           ~30 % of its time blocked in libxcb's ppoll/writev. */
#ifndef SHM_REMAP
#define SHM_REMAP 040000
#endif
        void* r = (void*)syscall(SYS_shmat, shmid, ptr, (int)c->x[2] | SHM_REMAP);
        if (r == (void*)-1) {
            const int e = errno;
            fprintf(stderr, "[a64port] shmat(id=%d len=%llu at 0x%llx) failed: %s\n", shmid,
                    (unsigned long long)len, (unsigned long long)va, strerror(e));
            if (rva) a64port_guest_release(rva, rlen);
            c->x[0] = (uint64_t)(-e); break;
        }
        fprintf(stderr, "[a64port] shmat(id=%d len=%llu) -> 0x%llx\n", shmid, (unsigned long long)len,
                (unsigned long long)va);
        if (g_shm_n < A64PORT_MAX_SHM) {
            g_shm_attach[g_shm_n].shmid = shmid;
            g_shm_attach[g_shm_n].va = va;
            g_shm_attach[g_shm_n].len = len;
            g_shm_attach[g_shm_n].rva = rva;
            g_shm_attach[g_shm_n].rlen = rlen;
            g_shm_n++;
        }
        c->x[0] = va;
        break;
    }
    case 197: { /* shmdt(shmaddr) */
        const uint64_t va = c->x[0];
        void* p = GuestPtr(c, va, 1);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (syscall(SYS_shmdt, p) < 0) { c->x[0] = (uint64_t)(-errno); break; }
        for (int i = 0; i < g_shm_n; i++)
            if (g_shm_attach[i].va == va) {
                /* shmat replaced arena pages (SHM_REMAP); detaching leaves a hole
                   that the pool would hand out again and memset.  Put plain
                   zeroed pages back first. */
                const size_t rl = (size_t)((g_shm_attach[i].len + 0xFFF) & ~UINT64_C(0xFFF));
                if (mmap(p, rl, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED)
                    fprintf(stderr, "[a64port] shmdt: re-backing 0x%llx failed: %s\n",
                            (unsigned long long)va, strerror(errno));
                if (g_shm_attach[i].rva) a64port_guest_release(g_shm_attach[i].rva, g_shm_attach[i].rlen);
                g_shm_attach[i] = g_shm_attach[--g_shm_n];
                break;
            }
        c->x[0] = 0;
        break;
    }
    case 93:    /* exit(status) */
    case 94:    /* exit_group(status) */
        if (EnvOn("A64PORT_EXIT_TRACE")) {
            fprintf(stderr, "[a64port] exit(%d) pc=0x%llx; x29 chain:\n",
                    (int)(c->x[0] & 0xff), (unsigned long long)c->pc);
            uint64_t fp = c->x[29];
            for (int i = 0; i < 20; ++i) {
                uint64_t* f = (uint64_t*)GuestPtr(c, fp, 16);
                if (!f) break;
                fprintf(stderr, "    #%-2d fp=0x%-10llx ret=0x%llx\n", i,
                        (unsigned long long)f[0], (unsigned long long)f[1]);
                if (f[0] <= fp) break;
                fp = f[0];
            }
        }
        if (n == 94 || !a64port_sa_thread) g_exit_code = (int)(c->x[0] & 0xff);   /* a thread's plain exit() is not the process status */
        /* exit_group ends EVERY thread.  glibc's exit() has already run the
           atexit handlers and every C++ static destructor on this thread, so
           halting only the caller (the old behaviour, still right for exit(93))
           left the rest of the app running on destroyed globals.
           A simulated vfork child shares the parent's process and must
           only end itself.  The weak default keeps the single-image build's
           behaviour; the multi host ends the process. */
        if (n == 94 && !a64port_vfork_child && a64port_guest_exit_group(c, g_exit_code))
            break;   /* not reached when the host ends the process */
        c->halted = 1;
        break;
    case 96: /* set_tid_address(ptr) — per guest thread: the host thread's tid */
        c->x[0] = (uint64_t)shim_tid();
        break;
    case 98: { /* futex(uaddr, op, val, timeout, uaddr2, val3)
                  The op carries FUTEX_PRIVATE_FLAG (0x80) / CLOCK_REALTIME
                  (0x100) in its high bits, so mask before switching. */
        const uint32_t tid = shim_tid();
        const uint32_t op = (uint32_t)c->x[1] & 0x7fu;
        const uint64_t va = c->x[0];
        uint32_t* u = (uint32_t*)GuestPtr(c, va, 4);
        if (!u) { c->x[0] = (uint64_t)(-EFAULT); break; }
        /* Plain ops first: one host syscall instead of the emulated table. */
        {
            static int ftx_mode = -1;
            if (ftx_mode < 0) {
                ftx_mode = EnvOn("A64PORT_FUTEX_EMUL") ? 1 : 0;
                if (!ftx_mode)
                    fprintf(stderr, "[futex] plain ops -> host kernel "
                                    "(A64PORT_FUTEX_EMUL=1 restores the emulated table)\n");
            }
            if (!ftx_mode) {
                uint64_t out;
                if (futex_kernel_forward(c, u, (uint32_t)c->x[1], &out)) {
                    c->x[0] = out;
                    break;
                }
            }
        }
        switch (op) {
        case 0:  /* FUTEX_WAIT */
        case 9:  /* FUTEX_WAIT_BITSET */ {
            struct timespec ts, *tp = NULL;
            if (c->x[3]) {
                int64_t* g = (int64_t*)GuestPtr(c, c->x[3], 16);
                if (!g) { c->x[0] = (uint64_t)(-EFAULT); break; }
                struct timespec guest = { (time_t)g[0], (long)g[1] };
                struct timespec now;
                clock_gettime(CLOCK_REALTIME, &now);
                /* The shim's condvars are CLOCK_REALTIME and pthread_cond_timedwait
                   wants an absolute deadline. FUTEX_WAIT passes a RELATIVE timeout on
                   CLOCK_MONOTONIC; FUTEX_WAIT_BITSET passes an ABSOLUTE one whose
                   clock is CLOCK_REALTIME only when FUTEX_CLOCK_REALTIME (0x100) is
                   set. Passing the guest value through unchanged made small relative
                   timeouts look like 1970 deadlines (instant ETIMEDOUT -> busy spin)
                   and made monotonic deadlines meaningless. */
                if (op == 0) {
                    ts.tv_sec  = now.tv_sec  + guest.tv_sec;
                    ts.tv_nsec = now.tv_nsec + guest.tv_nsec;
                } else if (c->x[1] & 0x100u) {   /* FUTEX_CLOCK_REALTIME */
                    ts = guest;
                } else {
                    struct timespec mono;
                    clock_gettime(CLOCK_MONOTONIC, &mono);
                    ts.tv_sec  = now.tv_sec  + (guest.tv_sec  - mono.tv_sec);
                    ts.tv_nsec = now.tv_nsec + (guest.tv_nsec - mono.tv_nsec);
                }
                while (ts.tv_nsec >= 1000000000L) { ts.tv_nsec -= 1000000000L; ++ts.tv_sec; }
                while (ts.tv_nsec < 0) { ts.tv_nsec += 1000000000L; --ts.tv_sec; }
                tp = &ts;
            }
            c->x[0] = (uint64_t)(int64_t)futex_wait(c, va, (uint32_t)c->x[2], tp);
            break;
        }
        case 1:  /* FUTEX_WAKE */
        case 10: /* FUTEX_WAKE_BITSET */
            c->x[0] = (uint64_t)futex_wake(c, va, (int)c->x[2]);
            break;
        case 6:  /* FUTEX_LOCK_PI */
        case 7:  /* FUTEX_UNLOCK_PI */
        case 8:  /* FUTEX_TRYLOCK_PI */ {
            /* Priority-inheritance futexes go to the HOST KERNEL, on the host
               address of the guest word.  They used to be faked: a contended
               LOCK_PI returned -EAGAIN instead of blocking, and glibc 2.29's
               __pthread_mutex_lock_full treats every error except ESRCH and
               EDEADLK as "acquired" - so two threads entered every contended
               critical section (recursive + PTHREAD_PRIO_INHERIT).
               The kernel needs the lock word to hold real
               host tids, which the multi host now guarantees (pd->tid is the
               child's gettid(), see a64port_guest_clone).  PI words are only
               ever touched by PI ops and user-space CAS, so mixing them with
               the emulated plain futexes below is sound.  LOCK_PI's timeout
               is an absolute CLOCK_REALTIME timespec. */
            const int64_t* tp = NULL;      /* the guest's timespec, see host_futex_timed */
            if (op == 6 && c->x[3]) {
                tp = (const int64_t*)GuestPtr(c, c->x[3], 16);
                if (!tp) { c->x[0] = (uint64_t)(-EFAULT); break; }
            }
            /* glibc reaches FUTEX_LOCK_PI only after its user-space CAS on the
               lock word failed, i.e. the lock was HELD: each of these is an
               occasion on which the old shim (-EAGAIN, "acquired")
               put a second thread inside the critical section.  Counted on a
               log scale so it is visible in every run without flooding. */
            if (op == 6) {
                static uint64_t n_contended;
                const uint64_t k = __atomic_add_fetch(&n_contended, 1, __ATOMIC_RELAXED);
                if (k == 1 || k == 10 || k == 100 || k == 1000 || k == 10000 ||
                    k == 100000 || k == 1000000)
                    fprintf(stderr, "[futex] contended PI lock #%llu (va=0x%llx word=0x%x tid=%u"
                                    " caller x30=0x%llx)\n",
                            (unsigned long long)k, (unsigned long long)va,
                            __atomic_load_n(u, __ATOMIC_RELAXED), tid,
                            (unsigned long long)c->x[30]);
            }
            const long r = host_futex_timed(u, (int)(uint32_t)c->x[1],
                                            (int)(uint32_t)c->x[2], tp, NULL, 0);
            c->x[0] = r < 0 ? (uint64_t)(-errno) : (uint64_t)r;
            /* An unexpected PI error is worth seeing in every run: glibc parks
               the thread forever on ESRCH/EDEADLK (e.g. a lock word holding a
               tid that is not a live host thread).  EPERM from UNLOCK_PI is
               glibc's own prio_inherit_missing() probe, the first PI call. */
            if (r < 0 && errno != EAGAIN && errno != ETIMEDOUT && errno != EINTR) {
                static int n_err;
                const int e = errno;
                if (__atomic_add_fetch(&n_err, 1, __ATOMIC_RELAXED) <= 20)
                    fprintf(stderr, "[futex] PI op=%u va=0x%llx word=0x%x tid=%u x30=0x%llx -> %s\n",
                            op, (unsigned long long)va, *u, tid,
                            (unsigned long long)c->x[30], strerror(e));
                errno = e;
            }
            break;
        }
        case 3:  /* FUTEX_REQUEUE */
        case 4:  /* FUTEX_CMP_REQUEUE */
            /* Waiters live on per-address condvars, so they cannot be moved
               to uaddr2.  Waking every waiter on uaddr instead is correct:
               a futex waiter must tolerate a spurious wakeup and re-check. */
            if (op == 4 && __atomic_load_n(u, __ATOMIC_SEQ_CST) != (uint32_t)c->x[5]) {
                c->x[0] = (uint64_t)(-EAGAIN);
                break;
            }
            c->x[0] = (uint64_t)futex_wake(c, va, 0x7fffffff);
            break;
        case 11: /* FUTEX_WAIT_REQUEUE_PI */
        case 12: /* FUTEX_CMP_REQUEUE_PI */
        default:
            c->x[0] = (uint64_t)(-ENOSYS);
            break;
        }
        break;
    }
    case 99: /* set_robust_list(head, len)
                Accepted but NOT registered with the host kernel.  The list's
                `next` pointers are guest VAs, which the kernel would walk as
                host addresses at thread exit, and registering it replaced the
                host glibc's own list for this host thread.
                Robust mutexes only matter when an owner dies holding one. */
        c->x[0] = 0;
        break;
    case 101: { /* nanosleep(req, rem) — timespec is 2 x u64 to the guest */
        const int64_t* req = (const int64_t*)GuestPtr(c, c->x[0], 16);
        int64_t* rem = (int64_t*)GuestPtr(c, c->x[1], 16);
        if (!req) { c->x[0] = (uint64_t)(-EFAULT); break; }
        struct timespec ts, rs;
        ts.tv_sec = (time_t)req[0];
        ts.tv_nsec = (long)req[1];
        if (nanosleep(&ts, rem ? &rs : NULL) < 0) {
            const int e = errno;
            if (rem) { rem[0] = rs.tv_sec; rem[1] = rs.tv_nsec; }
            c->x[0] = (uint64_t)(-e);
            break;
        }
        c->x[0] = 0;
        break;
    }
    case 113: { /* clock_gettime(clk, ts) — no vDSO, so this is the real path */
        int64_t* out = (int64_t*)GuestPtr(c, c->x[1], 16);
        if (!out) { c->x[0] = (uint64_t)(-EFAULT); break; }
#if defined(__arm__)
        /* the kernel's __vdso_clock_gettime64 writes the guest's 16-byte
           layout directly; no trap into the kernel (see a64port_vdso_cgt64) */
        if (a64port_vdso_cgt64((int)c->x[0], out) == 0) { c->x[0] = 0; break; }
#endif
        struct timespec ts;
        if (clock_gettime((clockid_t)c->x[0], &ts) < 0) { c->x[0] = (uint64_t)(-errno); break; }
        out[0] = (int64_t)ts.tv_sec;
        out[1] = (int64_t)ts.tv_nsec;
        c->x[0] = 0;
        break;
    }
    case 123: { /* sched_getaffinity(pid, cpusetsize, mask) — one CPU */
        uint8_t* mask = GuestPtr(c, c->x[2], c->x[1]);
        if (!mask) { c->x[0] = (uint64_t)(-EFAULT); break; }
        memset(mask, 0, (size_t)c->x[1]);
        if (c->x[1] >= 1) mask[0] = 1;
        c->x[0] = 8;
        break;
    }
    case 134: { /* rt_sigaction(sig, act, old, sigsetsize)
                   kernel struct sigaction = {handler, flags, restorer, mask(8)} */
        const int sig = (int)c->x[0];
        if (sig <= 0 || sig >= A64PORT_NSIG) { c->x[0] = (uint64_t)(-EINVAL); break; }
        if (c->x[2]) {   /* old */
            uint64_t* o = (uint64_t*)GuestPtr(c, c->x[2], 32);
            if (!o) { c->x[0] = (uint64_t)(-EFAULT); break; }
            o[0] = g_guest_sigact[sig].handler;
            o[1] = g_guest_sigact[sig].flags;
            o[2] = g_guest_sigact[sig].restorer;
            o[3] = g_guest_sigact[sig].mask;
        }
        if (c->x[1]) {   /* act */
            const uint64_t* a = (const uint64_t*)GuestPtr(c, c->x[1], 32);
            if (!a) { c->x[0] = (uint64_t)(-EFAULT); break; }
            g_guest_sigact[sig].handler  = a[0];
            g_guest_sigact[sig].flags    = a[1];
            g_guest_sigact[sig].restorer = a[2];
            g_guest_sigact[sig].mask     = a[3];
            /* A guest handler address cannot be invoked by the host kernel, but
               SIG_DFL/SIG_IGN can - and ignoring SIGPIPE is what keeps a stray
               write to a closed socket from killing every translated thread. */
            /* Except for the signals the HOST owns: its crash reporter, the
               page-protection UAF detector and the SIGUSR1 backtrace must not
               be removed by a guest SIG_DFL/SIG_IGN. */
            const int host_owned = sig == SIGSEGV || sig == SIGBUS || sig == SIGABRT ||
                                   sig == SIGILL || sig == SIGFPE || sig == SIGTRAP ||
                                   (!g_sa_sig && (sig == SIGUSR1 || sig == SIGPROF));
            struct sigaction sa;
            memset(&sa, 0, sizeof sa);
            if (host_owned)     { /* recorded above only */ }
            else if (g_sa_sig && a[0] > 1) {          /* a guest handler: the host marks it pending (delivered at the next syscall return) */
                struct sigaction hs;
                memset(&hs, 0, sizeof hs);
                hs.sa_sigaction = sa_host_handler;
                hs.sa_flags = SA_SIGINFO | ((a[1] & UINT64_C(0x10000000)) ? SA_RESTART : 0) |
                              ((a[1] & UINT64_C(0x40000000)) ? SA_NODEFER : 0);
                sigaction(sig, &hs, NULL);
            }
            else if (a[0] == 0) { sa.sa_handler = SIG_DFL; sigaction(sig, &sa, NULL); }
            else if (a[0] == 1) { sa.sa_handler = SIG_IGN; sigaction(sig, &sa, NULL); }
            if (EnvOn("A64PORT_SIGNAL_TRACE"))
                fprintf(stderr, "[a64port] sigaction sig=%d handler=0x%llx flags=0x%llx%s\n",
                        sig, (unsigned long long)a[0], (unsigned long long)a[1],
                        a[0] > 1 ? " (guest handler not installable)" : "");
        }
        c->x[0] = 0;
        break;
    }
    case 139: { /* rt_sigreturn: the guest's sa_restorer ends a handler (standalone runtime) */
        if (!sa_sigreturn(c)) {
            fprintf(stderr, "[a64port] rt_sigreturn without a signal frame\n");
            c->halted = 1;
        }
        break;
    }
    case 135: { /* rt_sigprocmask(how, set, oldset, sigsetsize) */
        const uint64_t* kp = c->x[1] ? (const uint64_t*)GuestPtr(c, c->x[1], 8) : NULL;
        if (c->x[1] && !kp) { c->x[0] = (uint64_t)(-EFAULT); break; }
        sigset_t set, old;
        SigsetFromKernel(&set, kp);
        const int r = pthread_sigmask((int)c->x[0], kp ? &set : NULL, c->x[2] ? &old : NULL);
        if (r != 0) { c->x[0] = (uint64_t)(-r); break; }
        if (c->x[2]) {
            uint64_t* o = (uint64_t*)GuestPtr(c, c->x[2], 8);
            if (o) SigsetToKernel(o, &old);
        }
        /* Signals 32/33 are the host libc's (SIGCANCEL/SIGSETXID): pthread_sigmask leaves
           them out.  The guest's own libc uses 32 as its timer signal, which its helper
           thread must have BLOCKED to receive it through rt_sigtimedwait (137). */
        if (kp && getenv("A64PORT_TIMER_DIAG"))
            fprintf(stderr, "[sigmask] tid %ld how=%d set=%016llx\n", (long)syscall(SYS_gettid), (int)c->x[0], (unsigned long long)*kp);
        if (kp && (*kp & (UINT64_C(3) << 31))) {
            const uint64_t want = *kp & (UINT64_C(3) << 31);
            uint64_t m = want;
            int how = (int)c->x[0];
            if (how == SIG_SETMASK) {
                uint64_t cur = 0;
                syscall(SYS_rt_sigprocmask, SIG_BLOCK, NULL, &cur, 8);
                m = (cur & ~(UINT64_C(3) << 31)) | want;
            }
            syscall(SYS_rt_sigprocmask, how, &m, NULL, 8);
        }
        c->x[0] = 0;
        break;
    }
    case 137: { /* rt_sigtimedwait(set, info, timeout, sigsetsize): glibc's timer helper thread
                   and an application signal thread.  The kernel interface, not sigtimedwait():
                   the host libc hides signals 32/33 (SIGCANCEL/SIGSETXID), and the guest's
                   SIGTIMER is 32. */
        const uint64_t* kp = c->x[0] ? (const uint64_t*)GuestPtr(c, c->x[0], 8) : NULL;
        if (!kp) { c->x[0] = (uint64_t)(-EFAULT); break; }
        const int64_t* g = c->x[2] ? (const int64_t*)GuestPtr(c, c->x[2], 16) : NULL;   /* {int64 sec, nsec} */
        if (c->x[2] && !g) { c->x[0] = (uint64_t)(-EFAULT); break; }
        uint8_t ki[128];
        memset(ki, 0, sizeof ki);
        if (getenv("A64PORT_TIMER_DIAG")) {
            char line[128], blk[64] = "?";
            FILE* f = fopen("/proc/thread-self/status", "r");
            while (f && fgets(line, sizeof line, f)) if (!strncmp(line, "SigBlk:", 7)) { snprintf(blk, sizeof blk, "%s", line + 8); blk[strcspn(blk, "\n")] = 0; }
            if (f) fclose(f);
            fprintf(stderr, "[sigwait] tid %ld waits set=%016llx blocked=%s timeout=%s\n", (long)syscall(SYS_gettid), (unsigned long long)*kp, blk, g ? "yes" : "none");
        }
#if UINTPTR_MAX == 0xffffffffu
        const long r = syscall(A64PORT_SYS_rt_sigtimedwait_time64, kp, ki, g, 8);   /* timespec64 == the guest's */
#else
        const long r = syscall(SYS_rt_sigtimedwait, kp, ki, g, 8);
#endif
        if (r < 0) { c->x[0] = (uint64_t)(-errno); break; }
        if (c->x[1]) {
            int32_t* gi = (int32_t*)GuestPtr(c, c->x[1], 128);
            if (gi) {                       /* aarch64 siginfo: signo, errno, code, pad, pid, uid */
                int32_t k[8];
                memcpy(k, ki, sizeof k);    /* the kernel's layout: 12-byte header on ILP32, 16 on LP64 */
                memset(gi, 0, 128);
                gi[0] = k[0]; gi[1] = k[1]; gi[2] = k[2];
#if UINTPTR_MAX == 0xffffffffu
                gi[4] = k[3]; gi[5] = k[4];
#else
                gi[4] = k[4]; gi[5] = k[5];
#endif
            }
        }
        c->x[0] = (uint64_t)r;
        break;
    }
    case 107: { /* timer_create(clockid, sigevent, timer_t*): the guest libc's SIGEV_THREAD
                   timers arrive as SIGEV_THREAD_ID + SIGTIMER, delivered to its helper
                   thread's rt_sigtimedwait (137) - no handler runs. */
        struct sigevent hev;
        memset(&hev, 0, sizeof hev);
        if (c->x[1]) {
            const uint8_t* ge = (const uint8_t*)GuestPtr(c, c->x[1], 64);   /* value(8) signo(4) notify(4) tid(4) */
            if (!ge) { c->x[0] = (uint64_t)(-EFAULT); break; }
            uint64_t val; int32_t signo, notify, tid;
            memcpy(&val, ge, 8); memcpy(&signo, ge + 8, 4); memcpy(&notify, ge + 12, 4); memcpy(&tid, ge + 16, 4);
            hev.sigev_value.sival_ptr = (void*)(uintptr_t)val;
            hev.sigev_signo = signo;
            hev.sigev_notify = notify;
            if (notify == 4 /* SIGEV_THREAD_ID */) hev._sigev_un._tid = tid;
            if (getenv("A64PORT_TIMER_DIAG"))
                fprintf(stderr, "[timer] create clock=%d notify=%d signo=%d tid=%d (this tid %ld)\n",
                        (int)c->x[0], notify, signo, tid, (long)syscall(SYS_gettid));
        }
        int kid = 0;
        const long r = syscall(SYS_timer_create, (clockid_t)c->x[0], c->x[1] ? &hev : NULL, &kid);
        if (r < 0) { c->x[0] = (uint64_t)(-errno); break; }
        int32_t* out = (int32_t*)GuestPtr(c, c->x[2], 4);
        if (!out) { c->x[0] = (uint64_t)(-EFAULT); break; }
        *out = kid;
        c->x[0] = 0;
        break;
    }
    case 108: { /* timer_gettime(id, curr): itimerspec = 4 x int64 in the guest and in timespec64 */
        void* cur = GuestPtr(c, c->x[1], 32);
        if (!cur) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(syscall(A64PORT_SYS_timer_gettime, (int)c->x[0], cur));
        break;
    }
    case 109: /* timer_getoverrun(id) */
        c->x[0] = RetU(syscall(SYS_timer_getoverrun, (int)c->x[0]));
        break;
    case 110: { /* timer_settime(id, flags, new, old) */
        void* nv = GuestPtr(c, c->x[2], 32);
        void* ov = c->x[3] ? GuestPtr(c, c->x[3], 32) : NULL;
        if (!nv || (c->x[3] && !ov)) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU(syscall(A64PORT_SYS_timer_settime, (int)c->x[0], (int)c->x[1], nv, ov));
        break;
    }
    case 111: /* timer_delete(id) */
        c->x[0] = RetU(syscall(SYS_timer_delete, (int)c->x[0]));
        break;
    case 140: /* setpriority(which, who, prio) — scheduling hint only */
    case 141: /* getpriority(which, who) */
        c->x[0] = 0;
        break;
    case 160: { /* uname(buf) — same 6x65 layout, but the machine must be aarch64
                   and nodename must be REAL: glibc's gethostname() is uname(),
                   and libXau/libxcb key the ~/.Xauthority lookup on the host
                   name. Leaving nodename empty made every X cookie lookup miss,
                   so the client sent an unauthenticated setup and the server
                   answered "Authorization required". */
        char* out = (char*)GuestPtr(c, c->x[0], 390);
        if (!out) { c->x[0] = (uint64_t)(-EFAULT); break; }
        memset(out, 0, 390);
        snprintf(out + 0 * 65, 65, "Linux");
        if (gethostname(out + 1 * 65, 65) < 0) snprintf(out + 1 * 65, 65, "localhost");
        out[1 * 65 + 64] = 0;
        snprintf(out + 2 * 65, 65, "6.1.0-a64port");
        snprintf(out + 3 * 65, 65, "#1 SMP");
        snprintf(out + 4 * 65, 65, "aarch64");
        snprintf(out + 5 * 65, 65, "localdomain");
        c->x[0] = 0;
        break;
    }
    case 169: { /* gettimeofday(tv, tz) */
        int64_t* tv = (int64_t*)GuestPtr(c, c->x[0], 16);
        if (!tv) { c->x[0] = (uint64_t)(-EFAULT); break; }
        struct timeval h;
        if (gettimeofday(&h, NULL) < 0) { c->x[0] = (uint64_t)(-errno); break; }
        tv[0] = (int64_t)h.tv_sec;
        tv[1] = (int64_t)h.tv_usec;
        if (c->x[1]) {
            int32_t* tz = (int32_t*)GuestPtr(c, c->x[1], 8);
            if (tz) { tz[0] = 0; tz[1] = 0; }
        }
        c->x[0] = 0;
        break;
    }
    case 157: /* setsid (libfuse's fuse_daemonize, in a real fork() child) */
        c->x[0] = RetU(setsid());
        break;
    case 172: /* getpid */
    case 174: /* getuid */
    case 175: /* geteuid */
    case 176: /* getgid */
    case 177: /* getegid */
    case 178: /* gettid — must agree with set_tid_address and with the owner
                 value FUTEX_LOCK_PI writes, or glibc's mutex owner checks fail */
        if (n == 178) {
            c->x[0] = (uint64_t)shim_tid();
        } else {
            c->x[0] = (n == 172) ? 1 : 0;
        }
        break;
    case 214: { /* brk(addr) — grows up from the end of the image */
        const uint64_t want = c->x[0];
        if (want == 0) { c->x[0] = g_brk_cur; break; }
        if (want < g_brk_cur) { g_brk_cur = want; c->x[0] = want; break; } /* shrink */
        if (want > a64port_guest_brk_limit() || !GuestPtr(c, g_brk_cur, want - g_brk_cur)) {
            c->x[0] = g_brk_cur; /* failure: return the current break, never a bogus one */
            break;
        }
        g_brk_cur = want;
        c->x[0] = want;
        break;
    }
    case 215: /* munmap(addr, len) — the multi-module host tracks its own pool */
        a64port_guest_munmap(c->x[0], c->x[1]);
        c->x[0] = 0;
        break;
    case 216: /* mremap — not needed by the targets so far */
        c->x[0] = (uint64_t)(-ENOMEM);
        break;
    case 227: { /* msync(addr, len, flags) — guest file maps are host file maps
                   in the multi host, so the host's msync is the real one;
                   on a pread'd range it is a harmless no-op. */
        void* p = GuestPtr(c, c->x[0], c->x[1] ? c->x[1] : 1);
        if (!p) { c->x[0] = (uint64_t)(-ENOMEM); break; }
        c->x[0] = RetU(msync(p, (size_t)c->x[1], (int)c->x[2]));
        if ((int64_t)c->x[0] == -ENOMEM) c->x[0] = 0;   /* anonymous range */
        break;
    }
    case 435:   /* clone3: not provided; glibc >= 2.34 falls back to clone() when it gets ENOSYS */
        c->x[0] = (uint64_t)(-ENOSYS);
        break;
    case 220: { /* clone(flags, stack, parent_tid, tls, child_tid) */
        const uint64_t flags = c->x[0];
        GuestContext child = *c;          /* copy all registers + the memory refs */
        child.x[0] = 0;                   /* the child sees 0 as clone's return */
        /* the new stack (== parent's for vfork).  0 means "keep the parent's
           sp", which is what glibc's fork() passes: setting the child's sp to 0
           made every stack access of a forked child miss the arena (silently,
           behind the checked helpers - a fault once loads/stores are direct). */
        child.x[31] = c->x[1] ? c->x[1] : c->x[31];
        child.pc = c->pc;                 /* resume at the instruction after svc:
                                             vfork's error check, or __clone's
                                             `cmp x0,#0; blr start_thread` */
        child.halted = 0;
        const int64_t tid = a64port_guest_clone(c, &child, flags, c->x[2], c->x[3], c->x[4]);
        if (flags & 0x10000 /* CLONE_THREAD */)
            __atomic_store_n(&g_last_clone_ms, in_now_ms(), __ATOMIC_RELAXED);
        /* -1 is the weak default's "not handled"; any other negative value is
           a -errno from the host (e.g. -EAGAIN when no host thread could be
           created) and is passed through. */
        c->x[0] = (uint64_t)(tid == -1 ? (int64_t)-ENOSYS : tid);
        break;
    }
    case 221: { /* execve(path, argv, envp) — a full program replacement is not
                   implemented yet; report exactly what the guest tried to run
                   and fail, so a vfork child's exec helper takes its error
                   path instead of hanging the parent. */
        const char* p = (const char*)GuestPtr(c, c->x[0], 1);
        fprintf(stderr, "[a64port] execve: %s", p ? p : "?");
        const uint64_t* av = (const uint64_t*)GuestPtr(c, c->x[1], 8);
        if (av) {
            for (int i = 0; i < 16 && av[i]; ++i) {
                const char* a = (const char*)GuestPtr(c, av[i], 1);
                fprintf(stderr, " [%s]", a ? a : "?");
            }
        }
        fprintf(stderr, "\n");
        if (p && EnvOn("A64PORT_SHELL_STUB") &&
            (!strcmp(p, "/bin/sh") || !strcmp(p, "/usr/bin/sh")) && av && av[1] && av[2]) {
            const char* opt = (const char*)GuestPtr(c, av[1], 1);
            const char* cmd = (const char*)GuestPtr(c, av[2], 1);
            if (opt && cmd && !strcmp(opt, "-c") && sandbox_shell_command(cmd)) {
                fprintf(stderr, "[a64port] sandbox exec stub handled shell probe\n");
                c->x[0] = 0;
                c->halted = 1; /* the simulated vfork child completed successfully */
                break;
            }
        }
        c->x[0] = (uint64_t)(-ENOSYS);
        break;
    }
    case 260: { /* wait4(pid, stat_addr, options, rusage) — the vfork child has
                   already run to completion synchronously, so report its exit. */
        int32_t* st = (int32_t*)GuestPtr(c, c->x[1], 4);
        if (g_child_pid) {
            /* The multi host hands real fork() children to the kernel, so reap
               them for real - the guest sees an ordinary child status. */
            int wstatus = 0;
            const pid_t got = waitpid((pid_t)g_child_pid, &wstatus, (int)c->x[2]);
            if (got > 0) {
                if (st) *st = (int32_t)wstatus;
                c->x[0] = (uint64_t)got;
                g_child_pid = 0;
                break;
            }
            if (st) *st = (int32_t)(g_child_status << 8);
            c->x[0] = (uint64_t)g_child_pid;
            g_child_pid = 0;
        } else {
            c->x[0] = (uint64_t)(-ECHILD);
        }
        break;
    }
    case 222: { /* mmap(addr, len, prot, flags, fd, offset) — grows down */
        const uint64_t addr = c->x[0], len = c->x[1], flags = c->x[3];
        const int64_t fd = (int64_t)c->x[4];
        const uint64_t off = c->x[5];
        if ((flags & 0x4000) && len >= 0x4000000 && g_mmap_diag < 4) { /* arena reserve */
            uint64_t fp = c->x[29];
            g_mmap_diag++;
            fprintf(stderr, "[a64port] arena mmap len=0x%llx prot=%d pc=0x%llx x30=0x%llx\n",
                    (unsigned long long)len, (int)c->x[2],
                    (unsigned long long)c->pc, (unsigned long long)c->x[30]);
            for (int i = 0; i < 10 && fp; i++) {
                uint64_t* f = GuestPtr(c, fp, 16);
                if (!f) break;
                fprintf(stderr, "    #%d fp=0x%llx ret=0x%llx\n", i,
                        (unsigned long long)f[0], (unsigned long long)f[1]);
                fp = f[0];
            }
        }
        /* The multi-module host owns the address space (ld.so maps the DSOs
           through here); its hook handles the call entirely when present. */
        {
            uint64_t want = addr;
            const int h = a64port_guest_mmap(&want, len, (int)c->x[2], flags, (int)fd, off);
            if (h > 0) { c->x[0] = want; break; }
            if (h < 0) { c->x[0] = (uint64_t)(-errno); break; }
        }
        const uint64_t kMapFixed = 0x10, kMapAnon = 0x20;
        uint64_t rounded = (len + 0xFFF) & ~UINT64_C(0xFFF);
        if (rounded == 0) rounded = 0x1000;
        uint64_t va;
        if (flags & kMapFixed) {
            va = addr & ~UINT64_C(0xFFF);
            pthread_mutex_lock(&g_sa_mu);
            sa_free_remove(va, va + rounded);
            pthread_mutex_unlock(&g_sa_mu);
        } else {
            va = sa_alloc(rounded);
            if (!va) { c->x[0] = (uint64_t)(-ENOMEM); break; }
        }
        uint8_t* dst = GuestPtr(c, va, rounded);
        if (!dst) { c->x[0] = (uint64_t)(-ENOMEM); break; }
        if (!(flags & kMapAnon) && fd >= 0) {
            const ssize_t got = pread((int)fd, dst, (size_t)rounded, (off_t)off);
            if (got < 0) { c->x[0] = (uint64_t)(-errno); break; }
        } else {
            memset(dst, 0, (size_t)rounded);
        }
        c->x[0] = va;
        break;
    }
    case 226: /* mprotect — host pages are already RW and never relied upon */
    case 233: /* madvise */
        c->x[0] = 0;
        break;
    case 261: { /* prlimit64(pid, resource, new, old) */
        const int resource = (int)c->x[1];
        void* newp = c->x[2] ? GuestPtr(c, c->x[2], 16) : NULL;
        void* oldp = c->x[3] ? GuestPtr(c, c->x[3], 16) : NULL;
        if (c->x[2] && !newp) { c->x[0] = (uint64_t)(-EFAULT); break; }
        if (c->x[3] && !oldp) { c->x[0] = (uint64_t)(-EFAULT); break; }
#if UINTPTR_MAX == 0xffffffffu
        /* ILP32 host: rlim_t may be 32 bits, which would turn the guest's
           RLIM64_INFINITY into 4 GB - use the 64-bit interface.  RLIMIT_STACK
           is also what the guest's glibc sizes every pthread stack from, and
           ~250 guest threads at the host's 8 MB each do not fit the 32-bit
           arena, so the guest is shown a smaller soft limit (main-thread stack
           is ours and unaffected).  Measured on x86-64: 255 of 260 threads
           touch <= 4 KB of stack; the other five (I/O workers) touch
           ALL of it whatever its size (a pre-fault), and the threads that need
           more set an explicit size (10 MB, 32 MB) that this does not affect.
           A64PORT_GUEST_STACK_KB tunes it. */
        if (newp && resource != RLIMIT_STACK) {
            struct rlimit64 nr;
            nr.rlim_cur = (rlim64_t)((const uint64_t*)newp)[0];
            nr.rlim_max = (rlim64_t)((const uint64_t*)newp)[1];
            if (setrlimit64(resource, &nr) < 0) { c->x[0] = (uint64_t)(-errno); break; }
        }
        if (oldp) {
            struct rlimit64 orl;
            if (getrlimit64(resource, &orl) < 0) { c->x[0] = (uint64_t)(-errno); break; }
            if (resource == RLIMIT_STACK) {
                const char* e = getenv("A64PORT_GUEST_STACK_KB");
                const uint64_t cap = (uint64_t)((e && *e) ? strtoull(e, 0, 0) : 1024) << 10;
                if (orl.rlim_cur > cap) orl.rlim_cur = cap;
            }
            ((uint64_t*)oldp)[0] = (uint64_t)orl.rlim_cur;
            ((uint64_t*)oldp)[1] = (uint64_t)orl.rlim_max;
        }
#else
        if (newp) {
            struct rlimit nr;
            nr.rlim_cur = (rlim_t)((const uint64_t*)newp)[0];
            nr.rlim_max = (rlim_t)((const uint64_t*)newp)[1];
            if (setrlimit(resource, &nr) < 0) { c->x[0] = (uint64_t)(-errno); break; }
        }
        if (oldp) {
            struct rlimit orl;
            if (getrlimit(resource, &orl) < 0) { c->x[0] = (uint64_t)(-errno); break; }
            ((uint64_t*)oldp)[0] = (uint64_t)orl.rlim_cur;
            ((uint64_t*)oldp)[1] = (uint64_t)orl.rlim_max;
        }
#endif
        c->x[0] = 0;
        break;
    }
    case 278: { /* getrandom(buf, len, flags) */
        uint8_t* p = GuestPtr(c, c->x[0], c->x[1]);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        const ssize_t r = (ssize_t)syscall(SYS_getrandom, p, (size_t)c->x[1], (unsigned)c->x[2]);
        if (r >= 0) { c->x[0] = (uint64_t)r; break; }
        /* Fallback if the host does not implement it: still not all-zero. */
        uint64_t x = (uint64_t)time(NULL) * 6364136223846793005ULL + 1442695040888963407ULL;
        for (uint64_t i = 0; i < c->x[1]; ++i) {
            x = x * 6364136223846793005ULL + 1442695040888963407ULL;
            p[i] = (uint8_t)(x >> 33);
        }
        c->x[0] = c->x[1];
        break;
    }
    case 26: /* inotify_init1(flags) */
        c->x[0] = RetU((ssize_t)syscall(SYS_inotify_init1, (int)c->x[0]));
        break;
    case 27: { /* inotify_add_watch(fd, path, mask) */
        const char* p = (const char*)GuestPtr(c, c->x[1], 1);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU((ssize_t)syscall(SYS_inotify_add_watch, (int)c->x[0],
                                        a64port_guest_path(p), (uint32_t)c->x[2]));
        break;
    }
    case 28: /* inotify_rm_watch(fd, wd) */
        c->x[0] = RetU((ssize_t)syscall(SYS_inotify_rm_watch, (int)c->x[0], (int)c->x[1]));
        break;
    case 61: { /* getdents64(fd, dirp, count) — linux_dirent64 is the same layout */
        void* p = GuestPtr(c, c->x[1], c->x[2]);
        if (!p) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU((ssize_t)syscall(SYS_getdents64, (int)c->x[0], p, (size_t)c->x[2]));
        break;
    }
    case 74: { /* signalfd4(fd, mask, sizemask, flags) */
        void* m = GuestPtr(c, c->x[1], c->x[2] ? c->x[2] : 8);
        if (!m) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU((ssize_t)syscall(SYS_signalfd4, (int)c->x[0], m,
                                        (size_t)c->x[2], (int)c->x[3]));
        break;
    }
    case 115: { /* clock_nanosleep(clk, flags, req, rem) — returns errno directly */
        const int64_t* req = (const int64_t*)GuestPtr(c, c->x[2], 16);
        int64_t* rem = c->x[3] ? (int64_t*)GuestPtr(c, c->x[3], 16) : NULL;
        if (!req) { c->x[0] = (uint64_t)(-EFAULT); break; }
        struct timespec ts = { (time_t)req[0], (long)req[1] }, rs;
        const int r = clock_nanosleep((clockid_t)c->x[0], (int)c->x[1], &ts, rem ? &rs : NULL);
        if (r == EINTR && rem) { rem[0] = rs.tv_sec; rem[1] = rs.tv_nsec; }
        c->x[0] = (uint64_t)r;
        break;
    }
    case 279: { /* memfd_create(name, flags) */
        const char* p = (const char*)GuestPtr(c, c->x[0], 1);
        c->x[0] = RetU((ssize_t)syscall(SYS_memfd_create, p ? p : "memfd", (unsigned)c->x[1]));
        break;
    }
    case 291: { /* statx(dirfd, path, flags, mask, buf) — struct statx is ABI-stable */
        const char* p = (const char*)GuestPtr(c, c->x[1], 1);
        void* b = GuestPtr(c, c->x[4], 256);
        if (!p || !b) { c->x[0] = (uint64_t)(-EFAULT); break; }
        c->x[0] = RetU((ssize_t)syscall(SYS_statx, (int)c->x[0], a64port_guest_path(p),
                                        (int)c->x[2], (unsigned)c->x[3], b));
        break;
    }
    case 293: /* rseq — no restartable sequences here. ENOSYS is exactly what
                 glibc handles when the running kernel lacks support, so the
                 fallback path it already carries is the one that runs. */
        c->x[0] = (uint64_t)(-ENOSYS);
        break;
    default:
        if (EnvOn("A64PORT_HALT_UNIMPLEMENTED")) { HaltUnimplemented(c, n); break; }
        {   /* what the kernel does for a syscall it does not have; programs probe for newer ones and fall back */
            static unsigned char seen[512];
            if (n < sizeof seen && !__atomic_exchange_n(&seen[n], 1, __ATOMIC_RELAXED))
                fprintf(stderr, "[a64port] unimplemented aarch64 syscall %llu: returning ENOSYS "
                                "(A64PORT_HALT_UNIMPLEMENTED=1 halts instead)\n", (unsigned long long)n);
            c->x[0] = (uint64_t)(-ENOSYS);
        }
        break;
    }

    /* Which guest function is blocked, and for how long?  Anything that takes
       more than a second is a stall, not work - name it with its call chain. */
    if (_slow) {
        struct timespec _t1;
        clock_gettime(CLOCK_MONOTONIC, &_t1);
        const double dt = (double)(_t1.tv_sec - _t0.tv_sec) +
                          (double)(_t1.tv_nsec - _t0.tv_nsec) / 1e9;
        if ((_slow & 8) && (int64_t)c->x[0] < 0 && (int64_t)c->x[0] > -4096) {
            /* A64PORT_SYSCALL_ERR: every distinct (syscall, errno, caller) once -
               a 32-bit-kernel ABI slip shows up as an error x86 never returns */
            static struct { uint32_t nr, err; uint64_t x30; } seen[512];
            static int nseen;
            const uint32_t err = (uint32_t)-(int64_t)c->x[0];
            int k = 0;
            while (k < nseen && !(seen[k].nr == (uint32_t)n && seen[k].err == err && seen[k].x30 == _x30)) ++k;
            if (k == nseen && nseen < 512) {
                seen[nseen].nr = (uint32_t)n; seen[nseen].err = err; seen[nseen].x30 = _x30; ++nseen;
                char tn[20] = "";
                prctl(PR_GET_NAME, tn);
                fprintf(stderr, "[serr] nr %3u errno %3u (%s) thread '%s' x30=0x%llx up=0x%llx\n",
                        (unsigned)n, err, strerror((int)err), tn,
                        (unsigned long long)_x30, (unsigned long long)_up);
            }
        }
        if (_slow & 2) waitprof_add((unsigned)n, _x30, _up, dt, (double)_t1.tv_sec + (double)_t1.tv_nsec / 1e9);
        if (_slow & 4) {
            const double now = (double)_t1.tv_sec + (double)_t1.tv_nsec / 1e9;
            if (g_tl.trig) {                                     /* armed: look for the trigger file every 20 ms */
                if (now - __atomic_load_n(&g_tl.trig_seen, __ATOMIC_RELAXED) >= 0.02) {
                    __atomic_store_n(&g_tl.trig_seen, now, __ATOMIC_RELAXED);
                    struct stat st;
                    if (stat(g_tl.trig, &st) == 0) { g_tl.t0 = now; g_tl.start = 0; g_tl.trig = 0; }
                }
            } else {
                const double ts = (double)_t0.tv_sec + (double)_t0.tv_nsec / 1e9 - g_tl.t0 - g_tl.start;
                if (ts + dt >= 0 && ts < g_tl.len && tl_match()) {
                    char tn[20] = "";
                    prctl(PR_GET_NAME, tn);
                    /* path syscalls (faccessat, openat, newfstatat, ...): the guest path - x1 is still the argument */
                    const char* gp = (n == 48 || n == 56 || n == 79 || n == 34 || n == 35 || n == 38 || n == 78)
                                         ? (const char*)GuestPtr(c, c->x[1], 1) : 0;
                    fprintf(stderr, "[tl] %9.3f ms  %7.3f ms  nr %3u  %-15s x30=0x%llx up=0x%llx x0=0x%llx abs=%.4f%s%s\n", ts * 1e3, dt * 1e3,
                            (unsigned)n, tn, (unsigned long long)_x30, (unsigned long long)_up, (unsigned long long)c->x[0],
                            (double)_t0.tv_sec + (double)_t0.tv_nsec / 1e9, gp ? "  path=" : "", gp ? gp : "");
                }
            }
        }
        if ((_slow & 1) && dt >= 1.0) {
            fprintf(stderr, "[slow] syscall %llu blocked %.2fs (x0=0x%llx x1=0x%llx x2=0x%llx) tid=%u x30=0x%llx\n",
                    (unsigned long long)n, dt, (unsigned long long)c->x[0],
                    (unsigned long long)c->x[1], (unsigned long long)c->x[2],
                    (unsigned)gettid(), (unsigned long long)c->x[30]);
            uint64_t fp = c->x[29];
            for (int k = 0; k < 20; ++k) {
                uint64_t* fr = (uint64_t*)GuestPtr(c, fp, 16);
                if (!fr) break;
                fprintf(stderr, "[slow]   bt#%-2d ret=0x%llx\n", k,
                        (unsigned long long)fr[1]);
                if (fr[0] <= fp) break;
                fp = fr[0];
            }
            fflush(stderr);
        }
    }
}

/* ── initial process stack ────────────────────────────────────────────────── */

#define AT_NULL 0
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_FLAGS 8
#define AT_ENTRY 9
#define AT_UID 11
#define AT_EUID 12
#define AT_GID 13
#define AT_EGID 14
#define AT_PLATFORM 15
#define AT_HWCAP 16
#define AT_CLKTCK 17
#define AT_SECURE 23
#define AT_RANDOM 25
#define AT_HWCAP2 26
#define AT_EXECFN 31
#define AT_SYSINFO_EHDR 33

static uint64_t PushStr(uint8_t* mem, uint64_t* cur, const char* s) {
    const size_t n = strlen(s) + 1;
    *cur -= n;
    memcpy(mem + (*cur - A64PORT_MEM_BASE), s, n);
    return *cur;
}

/* Builds the stack the way the kernel would: [argc][argv..][0][envp..][0]
   [auxv..][AT_NULL,0]. Static glibc reads AT_HWCAP to pick an implementation
   (we advertise only FP|ASIMD, the baseline), AT_PHDR to find its own program
   headers, and AT_RANDOM for the stack guard. */
static uint64_t BuildEntryStack(GuestContext* c, int hargc, char** hargv) {
    uint8_t* mem = c->mem;
    uint64_t cur = A64PORT_STACK_TOP;
    extern char** environ;

    const char* argv0 = hargc > 0 && hargv[0] && *hargv[0] ? hargv[0] : "guest";
    const uint64_t s_name = PushStr(mem, &cur, argv0);
    const uint64_t s_platform = PushStr(mem, &cur, "aarch64");
    /* the program's own arguments and the host environment (A64PORT_* switches stay host-side); a minimal
       PATH/LANG when the host has none */
    enum { kMaxArgs = 64, kMaxEnv = 96 };
    uint64_t s_arg[kMaxArgs]; int nargs = 0;
    for (int i = 1; i < hargc && nargs < kMaxArgs; ++i) s_arg[nargs++] = PushStr(mem, &cur, hargv[i]);
    uint64_t s_env[kMaxEnv]; int nenv = 0;
    for (char** e = environ; e && *e && nenv < kMaxEnv; ++e)
        if (strncmp(*e, "A64PORT_", 8) != 0 && strlen(*e) < 4096) s_env[nenv++] = PushStr(mem, &cur, *e);
    if (!nenv) {
        s_env[nenv++] = PushStr(mem, &cur, "PATH=/usr/bin:/bin");
        s_env[nenv++] = PushStr(mem, &cur, "LANG=C");
    }

    cur -= 16;
    const uint64_t s_random = cur;
    uint64_t seed = (uint64_t)time(NULL) ^ (uint64_t)(uintptr_t)c;
    for (int i = 0; i < 2; ++i) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        memcpy(mem + (s_random - A64PORT_MEM_BASE) + i * 8, &seed, 8);
    }

    const uint64_t aux[][2] = {
        {AT_PHDR, A64PORT_PHDR},   {AT_PHENT, A64PORT_PHENT}, {AT_PHNUM, A64PORT_PHNUM},
        {AT_BASE, 0},             {AT_ENTRY, A64PORT_ENTRY}, {AT_FLAGS, 0},
        {AT_PAGESZ, 4096},        {AT_CLKTCK, 100},         {AT_UID, 0},
        {AT_EUID, 0},             {AT_GID, 0},              {AT_EGID, 0},
        {AT_SECURE, 0},           {AT_RANDOM, s_random},    {AT_HWCAP, 3 /* FP|ASIMD */},
        {AT_HWCAP2, 0},           {AT_PLATFORM, s_platform}, {AT_EXECFN, s_name},
        {AT_SYSINFO_EHDR, 0},
    };
    const size_t naux = sizeof(aux) / sizeof(aux[0]);
    uint64_t block[1 + 1 + kMaxArgs + 1 + kMaxEnv + 1 + 2 * 20 + 2];
    size_t k = 0;
    block[k++] = (uint64_t)(1 + nargs);                      /* argc */
    block[k++] = s_name;                                     /* argv[0] */
    for (int i = 0; i < nargs; ++i) block[k++] = s_arg[i];
    block[k++] = 0;                                          /* argv terminator */
    for (int i = 0; i < nenv; ++i) block[k++] = s_env[i];
    block[k++] = 0;                                          /* envp terminator */
    for (size_t i = 0; i < naux; ++i) {
        block[k++] = aux[i][0];
        block[k++] = aux[i][1];
    }
    block[k++] = AT_NULL;
    block[k++] = 0;

    const uint64_t addr = (cur - k * 8) & ~UINT64_C(0xF);
    memcpy(mem + (addr - A64PORT_MEM_BASE), block, k * 8);
    return addr;
}

/* ── relocations ──────────────────────────────────────────────────────────── */

static int ApplyRelativeRelocs(GuestContext* c) {
    for (size_t i = 0; i < (size_t)A64PORT_RELOC_COUNT; ++i) {
        uint8_t* p = GuestPtr(c, A64PORT_RELOCS[i].va, 8);
        if (!p) {
            fprintf(stderr, "[a64port] relocation at 0x%llx outside guest memory\n",
                    (unsigned long long)A64PORT_RELOCS[i].va);
            return -1;
        }
        const uint64_t v = A64PORT_RELOCS[i].value;
        memcpy(p, &v, 8);
    }
    return 0;
}

static void ReportRelocs(void) {
    if (A64PORT_IRELOC_COUNT)
        fprintf(stderr,
                "[a64port] %d IRELATIVE relocations: left to the guest's own startup (a static\n"
                "         glibc binary applies these itself in apply_irel; a dynamic one via its\n"
                "         ld.so, which we do not translate yet)\n",
                (int)A64PORT_IRELOC_COUNT);
    if (A64PORT_UNRESOLVED_COUNT) {
        fprintf(stderr, "[a64port] %d unresolvable symbol relocations (no linker for the guest's\n"
                        "         own DSOs yet); first few:\n",
                (int)A64PORT_UNRESOLVED_COUNT);
        for (size_t i = 0; i < (size_t)A64PORT_UNRESOLVED_COUNT && i < 8; ++i)
            fprintf(stderr, "          0x%llx type=%u sym=%u addend=0x%llx in %s\n",
                    (unsigned long long)A64PORT_UNRESOLVED[i].va, A64PORT_UNRESOLVED[i].type,
                    A64PORT_UNRESOLVED[i].sym, (unsigned long long)A64PORT_UNRESOLVED[i].addend,
                    A64PORT_UNRESOLVED[i].section);
    }
}

/* ── main ─────────────────────────────────────────────────────────────────── */

/* The directory that holds the program's sections: $A64PORT_ROOT/a64port, else <binary>.a64port next to the
   binary (build-guest.sh links it, so several programs can share one directory), else a64port/ beside it. */
static const char* BaseDir(char* buf, size_t n, const char* argv0) {
    struct stat st;
    const char* env = getenv("A64PORT_ROOT");
    if (env && *env) { snprintf(buf, n, "%s/a64port", env); return buf; }
    char exe[1024];
    const ssize_t k = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (k > 0) {
        exe[k] = 0;
        snprintf(buf, n, "%s.a64port", exe);
        if (stat(buf, &st) == 0 && S_ISDIR(st.st_mode)) return buf;
    }
    snprintf(buf, n, "%s.a64port", argv0);
    if (stat(buf, &st) == 0 && S_ISDIR(st.st_mode)) return buf;
    const char* slash = strrchr(argv0, '/');
    if (slash) snprintf(buf, n, "%.*s/a64port", (int)(slash - argv0), argv0);
    else snprintf(buf, n, "a64port");
    return buf;
}

int main(int argc, char** argv) {
    GuestContext c;
    memset(&c, 0, sizeof c);

#ifdef A64PORT_FASTMEM
    /* neon_structs.h's fastmem accessors use the guest address as the host
       address: the guest's memory must sit at its own addresses (link this
       binary above A64PORT_MEM_BASE + A64PORT_MEM_SIZE). */
    uint8_t* mem = (uint8_t*)mmap((void*)(uintptr_t)A64PORT_MEM_BASE, (size_t)A64PORT_MEM_SIZE,
                                  PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | 0x100000 /* FIXED_NOREPLACE */, -1, 0);
    if (mem != (uint8_t*)(uintptr_t)A64PORT_MEM_BASE) {
        fprintf(stderr, "[a64port] fastmem build: guest memory cannot sit at 0x%llx\n",
                (unsigned long long)A64PORT_MEM_BASE);
        return 1;
    }
#define free(p) munmap((p), (size_t)A64PORT_MEM_SIZE)   /* the cleanups below */
#else
    uint8_t* mem = (uint8_t*)calloc(1, (size_t)A64PORT_MEM_SIZE);
#endif
    if (!mem) {
        fprintf(stderr, "[a64port] cannot allocate %llu MB of guest memory\n",
                (unsigned long long)(A64PORT_MEM_SIZE >> 20));
        return 1;
    }
    c.mem = mem;
    c.mem_size = A64PORT_MEM_SIZE;
    c.mem_base_vaddr = A64PORT_MEM_BASE;
    c.heap_base = A64PORT_ALLOC_MID;
    c.heap_cur = A64PORT_IMAGE_END;
    c.heap_end = A64PORT_ALLOC_MID;
    g_module_base = 0; /* emitted addresses are absolute guest VAs */

    char dir[1024];
    BaseDir(dir, sizeof dir, argv[0]);
    for (size_t i = 0; i < (size_t)A64PORT_SEGMENT_COUNT; ++i) {
        const A64portSegment* s = &A64PORT_SEGMENTS[i];
        char path[1400];
        snprintf(path, sizeof path, "%s/%s", dir, s->file);
        FILE* f = fopen(path, "rb");
        if (!f) {
            fprintf(stderr, "[a64port] missing segment file %s\n", path);
            free(mem);
            return 1;
        }
        uint8_t* dst = GuestPtr(&c, s->va, s->size);
        if (!dst) {
            fprintf(stderr, "[a64port] segment %s at 0x%llx+0x%llx outside guest memory\n",
                    s->file, (unsigned long long)s->va, (unsigned long long)s->size);
            fclose(f);
            free(mem);
            return 1;
        }
        const size_t got = fread(dst, 1, (size_t)s->size, f);
        fclose(f);
        if (got != (size_t)s->size) {
            fprintf(stderr, "[a64port] short read on %s (%zu of %llu)\n", s->file, got,
                    (unsigned long long)s->size);
            free(mem);
            return 1;
        }
    }

    for (size_t i = 0; i < (size_t)A64PORT_NOBITS_COUNT; ++i)
        if (!GuestPtr(&c, A64PORT_NOBITS[i].va, A64PORT_NOBITS[i].size)) {
            fprintf(stderr, "[a64port] nobits %s at 0x%llx outside guest memory\n",
                    A64PORT_NOBITS[i].name, (unsigned long long)A64PORT_NOBITS[i].va);
            free(mem);
            return 1;
        }

    if (ApplyRelativeRelocs(&c) != 0) { free(mem); return 1; }

    const uint64_t sp = BuildEntryStack(&c, argc, argv);
    c.x[31] = sp;
    c.pc = A64PORT_ENTRY;

    fprintf(stderr,
            "[a64port] base=0x%llx size=%llu MB entry=0x%llx sp=0x%llx\n"
            "         %d sections, %d nobits, %d relative relocs\n",
            (unsigned long long)A64PORT_MEM_BASE, (unsigned long long)(A64PORT_MEM_SIZE >> 20),
            (unsigned long long)A64PORT_ENTRY, (unsigned long long)sp, (int)A64PORT_SEGMENT_COUNT,
            (int)A64PORT_NOBITS_COUNT, (int)A64PORT_RELOC_COUNT);
    ReportRelocs();
    fflush(stderr);

    recomp_build_index();
    g_sa_sig = 1;                            /* guest signal handlers run (standalone runtime only) */
    sa_run(&c);

    fprintf(stderr, "[a64port] halted pc=0x%llx exit=%d%s\n", (unsigned long long)c.pc,
            g_exit_code, c.halted == RECOMP_HALT_UNHANDLED ? " (unhandled instruction)" : "");
    free(mem);
    return g_exit_code;
}
#ifdef A64PORT_FASTMEM
#undef free
#endif
