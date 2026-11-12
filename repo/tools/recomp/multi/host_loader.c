/* SPDX-License-Identifier: GPL-2.0-or-later */
/* host_loader.c — kernel-faithful host for a64port (AArch64 -> C -> native).
 *
 * NOT an emulator. Every guest instruction — the executable's, libc's, libstdc++'s, and
 * ld.so's — was decoded ahead of time, emitted as C, and compiled to native
 * machine code by the host compiler. There is no interpreter, no JIT, no
 * runtime decode. This file only does what the *kernel* does before a
 * dynamically linked program starts:
 *
 *   1. map the main executable's PT_LOAD segments at its link addresses
 *   2. map its PT_INTERP (ld-2.29.so) at a base
 *   3. build the initial stack: [argc][argv][envp][auxv], with
 *      AT_PHDR/AT_PHENT/AT_PHNUM/AT_ENTRY describing the *executable* and
 *      AT_BASE the interpreter's load address
 *   4. jump to the *interpreter's* entry point
 *
 * ld.so then does everything else, exactly as on the real device: loads the
 * DT_NEEDED graph, verifies versions, assigns TLS, applies every relocation,
 * runs the initializers, and finally branches to the executable's entry with
 * x0 = _dl_fini.
 *
 * Why this shape, and not a hand-written pre-binder (which is what this file
 * used to be): measured on the real guest, pre-binding cannot substitute for
 * rtld. libc reads ld.so's own state on ordinary paths; the crash was
 *
 *     _dl_addr:  blr x1    with   x1 = _rtld_global._dl_rtld_lock_recursive
 *
 * and that pointer is installed by libpthread's DT_INIT — the library carries
 * DF_1_INITFIRST (measured: DT_FLAGS_1 = 0x28) precisely so its initializer runs
 * first. Nothing short of running the initializers creates it. This also
 * matches mk8-recomp's hosted backend, whose default relocation policy is to
 * pre-apply only rtld's own relocations and leave the rest to rtld.
 *
 * Address space:
 *   0x00400000  main executable, at its link addresses (ET_EXEC, base 0)
 *   0x20000000  guest mmap pool (ld.so maps the DSOs here; also TLS + heap)
 *   TOP-32 MB   ld.so (the only DSO base we choose; ld.so picks the rest)
 *   TOP-16 MB   initial process stack (grows down)
 *   TOP-1 MB    native-trampoline VAs
 * TOP is ARENA_TOP: 0x400000000 on a 64-bit host, 0x68000000 on a 32-bit one.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h> /* setpriority: CPU pin rules with a nice value */
#include <sys/stat.h>
#include <sys/syscall.h>     /* SYS_gettid: 186 on x86-64, 224 on ARM EABI */
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <ucontext.h>
#include <dirent.h>
#include <sched.h>

/* The program-specific layer (see runtime/linux_syscalls.c): device/network/window hooks. */

#include "recomp_runtime.h"
#include "mods.h"
#include "layout.h"      /* the executable's: A64PORT_PHDR/PHNUM/PHENT/ENTRY */

/* from linux_syscalls.c, compiled into this binary with its main renamed away */
extern void recomp_svc(GuestContext*, unsigned);
void a64port_guest_child_exited(int pid, int status);
extern int a64port_device_is_drm(int fd);

/* Execution-time gap recording (recomp_runtime.c). The miss list is a ready
   a64recomp --roots file, written when A64PORT_GAP_DUMP names a path. */
void recomp_gap_note(uint32_t kind, uint64_t pc, uint32_t insn);
void recomp_gap_dump(void);

/* ld.so sits just under the stack (0x3fe000000 / 0x3ff000000 on a 64-bit
   host); the brk heap grows up from the image end and stops at the mmap
   pool's floor. */
uint64_t a64port_guest_brk_limit(void) { return UINT64_C(0x20000000); }

extern void recomp_build_index(void);
extern int _recomp_index_view(uint64_t*, uint64_t*, BlockFn**);

/* The whole guest address space is one host allocation, so its top bounds
   the host VA it costs.  A 64-bit host takes 16 GB.  A 32-bit host (ARMv7)
   has ~3 GB of user VA in total; the host image and the host thread stacks need about 1 GB of
   that for a large program, so the guest gets 1.625 GB there, most of it mmap pool.  Everything above the pool is placed relative to the top;
   on a 64-bit host these are exactly the old constants. */
#if UINTPTR_MAX == 0xffffffffu
#define A64PORT_ILP32_HOST 1
#endif
#ifndef A64PORT_ARENA_TOP
#if A64PORT_ILP32_HOST
#define A64PORT_ARENA_TOP 0x68000000ull
#else
#define A64PORT_ARENA_TOP 0x400000000ull
#endif
#endif
#define ARENA_BASE ((uint64_t)A64PORT_MEM_BASE)
#define ARENA_TOP  ((uint64_t)A64PORT_ARENA_TOP)
#define ARENA_SIZE (ARENA_TOP - ARENA_BASE)
/* The global block resolver's first level covers 4 GB (ILP32) / 64 GB in 4 MB
   steps; neon_structs.h has the same constant. */
#if A64PORT_ILP32_HOST
#define A64PORT_RX_L1_N 1024
#else
#define A64PORT_RX_L1_N 16384
#endif
#define MMAP_LO    UINT64_C(0x20000000)
#define MMAP_HI    (ARENA_TOP - UINT64_C(0x2000000))
#define STACK_TOP  (ARENA_TOP - UINT64_C(0x1000000))
#define LD_BASE    MMAP_HI        /* where we put the interpreter */
#ifndef A64PORT_ROOTFS
#define A64PORT_ROOTFS "/nonexistent"
#endif
#ifndef A64PORT_APPDIR
#define A64PORT_APPDIR "/"
#endif

static GuestContext g_c;
static uint8_t* g_mem;
static int g_identity;          /* the arena sits at its own guest VAs (bias 0) */
/* A host mapping inside the identity arena that cannot move (qemu-user puts a
   32-bit guest's stack and vdso at 0x40000000): the arena is mapped around it
   and the guest mmap pool never hands it out.  0/0 = none (a native host). */
static uint64_t g_hole_lo, g_hole_hi;

/* Shadow-memory overflow detector (A64PORT_ASAN=1); defined with the allocator
   watch, called from the store helpers above it. */
static inline void asan_check_store(uint64_t a, uint32_t size) { (void)a; (void)size; }

/* ── host page table ───────────────────────────────────────────────────────
   Without one, c->host_mem is null, so every guest load and store misses
   recomp_host_ptr_n's fast path, falls back to memload, and pays a second
   call plus another bounds check.  The guest address space here is a single
   host allocation, so every page entry carries the same bias and
   recomp_host_ptr resolves an address in a few instructions.

   2 MB pages keep the table tiny (8 KB) and page-crossing accesses - which
   must take the slow path - are vanishingly rare.  `load`/`store` still have
   to exist: memload/memstore call them unconditionally whenever host_mem is
   set, and the guard's per-word diagnostic loop does too. */
#define HOSTMEM_PAGE_BITS 21u
static uintptr_t g_hm_pages[(ARENA_TOP >> HOSTMEM_PAGE_BITS) + 2];

static uint64_t arena_load(uint64_t va, uint32_t size) {
    if (va < ARENA_BASE || va - ARENA_BASE >= ARENA_SIZE) return 0;
    if (size == 0) {                       /* guard-v2 probe: bit32 = mapped */
        if (va + 4 > ARENA_TOP) return 0;
        uint32_t w32 = 0;
        memcpy(&w32, g_mem + (va - ARENA_BASE), 4);
        return (uint64_t)w32 | (UINT64_C(1) << 32);
    }
    if (va + size > ARENA_TOP) return 0;
    uint64_t v = 0;
    memcpy(&v, g_mem + (va - ARENA_BASE), size);
    return v;
}

static void arena_store(uint64_t va, uint32_t size, uint64_t value) {
    if (va < ARENA_BASE || va + size > ARENA_TOP) return;
    memcpy(g_mem + (va - ARENA_BASE), &value, size);
}

static uint64_t hm_load(void* user, uint64_t va, uint32_t size) {
    (void)user;
    return arena_load(va, size);
}

/* ── exclusive monitor ─────────────────────────────────────────────────────
   The latch in the emitted runtime (`g_xa`) is documented as valid because
   "standalone there is exactly one guest thread".  This host runs one guest
   thread per host thread - hundreds of them in a large program - so that latch is
   not an approximation here, it is wrong: reservations live in each thread's
   own TLS, so a successful STXR clears only the storing thread's mark.  A
   second thread that reserved the same address keeps its mark, and its STXR
   then succeeds merely because the *value* still compares equal.  A lock built
   on two winners is not a lock.

   Reservations therefore live in a SHARED table, one slot per guest thread,
   so a peer's success can clear ours, and the decision and the store happen
   under a lock for that address's granule - upstream's wording for the same
   requirement: "the lock is held across the compare-and-write so two cores
   cannot both win the same reservation ... load-bearing, not an oversight."

   Three rules, and each needs its own mechanism:

     * two store-exclusives must not both win    -> slot table + stripe lock
     * a winner invalidates its competitors      -> clear the granule's slots
                                                    while still holding the lock
     * any plain store retires reservations      -> per-granule version bumped
                                                    by hm_store, checked by STXR

   The version is what catches a plain store landing between an LDXR and its
   STXR; without it the reservation still looks valid and the store-exclusive
   would wrongly succeed.  Stripes (rather than one lock) keep contention to
   addresses that actually share a granule, which is where hardware serialises
   too. */
#define EXCL_SLOTS   1024
#define EXCL_STRIPES 256
#define EXCL_VT_BITS 18
#define EXCL_VT_SIZE (1u << EXCL_VT_BITS)

typedef struct {
    uint64_t addr;                  /* reserved guest address */
    uint64_t val, val2;             /* what the load-exclusive observed */
    uint32_t ver;                   /* granule version the load observed */
    uint32_t valid;
    uint32_t busy;                  /* slot handed to a host thread */
} ExclSlot;

static ExclSlot g_excl[EXCL_SLOTS];
static pthread_mutex_t g_excl_stripe[EXCL_STRIPES];
static pthread_mutex_t g_excl_bind = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_excl_v[EXCL_VT_SIZE];
/* Threads currently holding a reservation. A plain store only pays for the
   version bump when one exists somewhere. */
static int g_excl_outstanding;
static __thread ExclSlot* t_excl;

/* Which granule buckets might hold a reservation -- so an ordinary store can skip
   the shared atomic version bump.  With 265 threads some LDXR is nearly always
   un-paired somewhere, so the global g_excl_outstanding test left every store
   paying a cross-core atomic read-modify-write (13 % of the GUI thread).

   Each bucket records the EPOCH in which it was last reserved; a store treats a
   bucket as reserved when that is the current or the previous epoch (epochs last
   ~1 s).  Marks are plain byte stores made under the stripe lock BEFORE the
   reservation reads its version, never decremented, and expire by themselves, so
   there is no counter to get wrong across threads: every error is an EXTRA bump
   (the old behaviour), never a missed one -- except a reservation held for more
   than ~1-2 s between its LDXR and its STXR, where a same-value store (ABA) could
   go unseen; a value-changing store is still caught by the STXR's value CAS. */
static uint8_t  g_excl_res[EXCL_VT_SIZE];
static uint8_t  g_excl_epoch = 2;           /* starts at 2 so a zeroed bucket is never "current" */
static uint64_t g_excl_epoch_ns;
static __thread unsigned t_excl_tick;
static inline uint8_t* excl_rslot(uint64_t va) {
#if UINTPTR_MAX == 0xffffffffu
    /* Every guest store runs this.  The arena is below 4 GB on a 32-bit host, so
       a 32-bit multiplicative hash sees the same granules for a third of the
       multiplies; a collision is only an extra version bump. */
    const uint32_t h = (uint32_t)(va >> 4) * 0x9E3779B1u;
    return &g_excl_res[(h >> (32 - EXCL_VT_BITS)) & (EXCL_VT_SIZE - 1)];
#else
    const uint64_t h = (va >> 4) * UINT64_C(0x9E3779B97F4A7C15);
    return &g_excl_res[(h >> (64 - EXCL_VT_BITS)) & (EXCL_VT_SIZE - 1)];
#endif
}
static void excl_epoch_tick(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    const uint64_t ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
    uint64_t last = __atomic_load_n(&g_excl_epoch_ns, __ATOMIC_RELAXED);
    if (ns - last >= 1000000000ull &&
        __atomic_compare_exchange_n(&g_excl_epoch_ns, &last, ns, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        __atomic_fetch_add(&g_excl_epoch, 1, __ATOMIC_RELAXED);
}
/* Call under the stripe lock, before the version / value are read. */
static inline void excl_mark(uint64_t va) {
    if ((++t_excl_tick & 63u) == 0) excl_epoch_tick();
    __atomic_store_n(excl_rslot(va), __atomic_load_n(&g_excl_epoch, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);   /* the mark is visible before the value is read */
}

static inline pthread_mutex_t* excl_stripe(uint64_t va) {
    return &g_excl_stripe[((va >> 4) * UINT32_C(2654435761)) & (EXCL_STRIPES - 1)];
}
static inline uint32_t* excl_vslot(uint64_t va) {
    const uint64_t h = (va >> 4) * UINT64_C(0x9E3779B97F4A7C15);
    return &g_excl_v[(h >> (64 - EXCL_VT_BITS)) & (EXCL_VT_SIZE - 1)];
}

static int g_excl_hwm;               /* 1 + highest slot index ever bound: the scans stop here */
static ExclSlot* excl_slot(void) {
    if (t_excl) return t_excl;
    pthread_mutex_lock(&g_excl_bind);
    for (int i = 0; i < EXCL_SLOTS; ++i) {
        if (!g_excl[i].busy) {
            g_excl[i].busy = 1; t_excl = &g_excl[i];
            if (i + 1 > g_excl_hwm) __atomic_store_n(&g_excl_hwm, i + 1, __ATOMIC_RELEASE);
            break;
        }
    }
    pthread_mutex_unlock(&g_excl_bind);
    if (!t_excl) {
        fprintf(stderr, "[a64port] exclusive monitor: all %d slots in use\n", EXCL_SLOTS);
        abort();
    }
    return t_excl;
}

static void excl_release(ExclSlot* s) {
    if (s->valid) {
        s->valid = 0;
        __atomic_fetch_sub(&g_excl_outstanding, 1, __ATOMIC_RELAXED);
    }
}

/* Clear every reservation whose granule the access spans. Caller holds the
   stripe lock for `va`, and the stripe is a function of the granule, so every
   slot we touch belongs to that same stripe. */
static void excl_clear_granule(uint64_t va, uint32_t size) {
    const uint64_t lo = va & ~UINT64_C(15);
    const uint64_t hi = (va + (size ? size : 1) - 1) & ~UINT64_C(15);
    const int n = __atomic_load_n(&g_excl_hwm, __ATOMIC_ACQUIRE);
    for (int i = 0; i < n; ++i) {
        if (!g_excl[i].valid) continue;
        const uint64_t a = g_excl[i].addr & ~UINT64_C(15);
        if (a >= lo && a <= hi) excl_release(&g_excl[i]);
    }
}

static uint64_t hm_excl_load(void* user, uint64_t va, uint32_t size) {
    (void)user;
    ExclSlot* s = excl_slot();
    pthread_mutex_t* lk = excl_stripe(va);
    pthread_mutex_lock(lk);
    excl_mark(va);
    const uint32_t ver = __atomic_load_n(excl_vslot(va), __ATOMIC_RELAXED);
    const uint64_t val = arena_load(va, size);
    if (!s->valid) __atomic_fetch_add(&g_excl_outstanding, 1, __ATOMIC_RELAXED);
    s->addr = va; s->ver = ver; s->val = val; s->valid = 1;
    pthread_mutex_unlock(lk);
    return val;
}

static inline void excl_invalidate_on_store(uint64_t va, uint32_t size) __attribute__((always_inline));   /* defined below */

/* The SHARED half of the store rule, exported so the emitted runtime's store
   helpers can call it: a store by one thread must retire a peer's reservation
   on that granule, or two threads' store-exclusives can both win.  The runtime
   keeps the LOCAL (per-thread) half itself.  Lock-free and gated on there being
   any reservation outstanding, because it runs on every guest store. */
static int g_excl_value;                  /* the value-CAS monitor is installed */
enum { asan_on = 0 };
void recomp_excl_store_touch(uint64_t a, uint32_t size) {
    if (__builtin_expect(asan_on != 0, 0))
        asan_check_store(a, size);   /* shadow-memory overflow check, when enabled (-1 = not yet decided) */
    if (g_excl_value) return;        /* value-CAS monitor: stores retire nothing */
    excl_invalidate_on_store(a, size);
}

static uint32_t hm_excl_store(void* user, uint64_t va, uint32_t size, uint64_t value) {
    (void)user;
    ExclSlot* s = excl_slot();
    pthread_mutex_t* lk = excl_stripe(va);
    uint32_t status = 1;
    pthread_mutex_lock(lk);
    /* The version catches every store that went through the guest's own store
       helpers.  It cannot see a write made OUTSIDE them - above all the host
       KERNEL, which sets FUTEX_WAITERS / hands a PI lock word over with its own
       cmpxchg now that PI futexes are real.  A plain store here
       then wiped the kernel's update (glibc's PI unlock is LDXR word; STXR 0),
       desynchronising the word from the kernel's PI state.  So the store itself
       is a host compare-and-swap against the value the load-exclusive saw:
       hardware fails that STXR (any store clears the monitor) and so does qemu
       (its STXR is a value-CAS); the version keeps catching same-value ABA. */
    if (s->valid && s->addr == va &&
        s->ver == __atomic_load_n(excl_vslot(va), __ATOMIC_RELAXED) &&
        va >= ARENA_BASE && va + size <= ARENA_TOP) {
        void* p = g_mem + (va - ARENA_BASE);
        int ok;
        switch (size) {                        /* store iff nothing else wrote */
        case 1: { uint8_t  e = (uint8_t)s->val;
                  ok = __atomic_compare_exchange_n((uint8_t*)p, &e, (uint8_t)value, 0,
                                                   __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); break; }
        case 2: { uint16_t e = (uint16_t)s->val;
                  ok = ((uintptr_t)p & 1) == 0
                     ? __atomic_compare_exchange_n((uint16_t*)p, &e, (uint16_t)value, 0,
                                                   __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
                     : (arena_load(va, 2) == (uint16_t)s->val && (arena_store(va, 2, value), 1));
                  break; }
        case 4: { uint32_t e = (uint32_t)s->val;
                  ok = ((uintptr_t)p & 3) == 0
                     ? __atomic_compare_exchange_n((uint32_t*)p, &e, (uint32_t)value, 0,
                                                   __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
                     : (arena_load(va, 4) == (uint32_t)s->val && (arena_store(va, 4, value), 1));
                  break; }
        default: { uint64_t e = s->val;
                  ok = ((uintptr_t)p & 7) == 0
                     ? __atomic_compare_exchange_n((uint64_t*)p, &e, value, 0,
                                                   __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
                     : (arena_load(va, 8) == s->val && (arena_store(va, 8, value), 1));
                  break; }
        }
        if (ok) {
            /* Competitors must take this stripe lock to store-exclusive, so
               clearing them after the CAS (and only when it won) is the same
               as before for them and leaves a FAILED store harmless to them,
               as on hardware. */
            excl_clear_granule(va, size);
            __atomic_fetch_add(excl_vslot(va), 1, __ATOMIC_RELAXED);
            status = 0;
        }
        excl_release(s);
    } else {
        /* Hardware clears the local monitor on a FAILED store-exclusive too:
           without this, ldxr; stxr(fail); stxr could succeed without a reload. */
        excl_release(s);
    }
    pthread_mutex_unlock(lk);
    return status;
}

/* ── value-CAS monitor (A64PORT_EXCL_MONITOR=2; the default of a -DA64PORT_FASTMEM
   build, whose inline stores do not retire reservations) ────────────────────
   qemu-user's model: LDXR records {address, value} in the thread's slot, and
   STXR succeeds iff memory still holds that value, as ONE host compare-and-swap.
   No stripe lock, no version table, nothing on plain stores.  What it gives up
   is only an intervening store of the SAME value (ABA), which no lock-free
   structure in glibc/libstdc++/typical GUI toolkits depends on.  The kernel's own futex-word
   updates are still seen (they change the value).  Pairs: one CAS where the
   host has one that wide (2x4 bytes everywhere, 2x8 on x86-64 via cmpxchg16b);
   otherwise compare-and-store under the granule's stripe lock. */

static inline int vm_cas(uint64_t va, uint32_t size, uint64_t expect, uint64_t value) {
    void* p = g_mem + (va - ARENA_BASE);
    switch (size) {
    case 1: { uint8_t e = (uint8_t)expect;
              return __atomic_compare_exchange_n((uint8_t*)p, &e, (uint8_t)value, 0,
                                                 __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); }
    case 2: { uint16_t e = (uint16_t)expect;
              if ((uintptr_t)p & 1) break;
              return __atomic_compare_exchange_n((uint16_t*)p, &e, (uint16_t)value, 0,
                                                 __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); }
    case 4: { uint32_t e = (uint32_t)expect;
              if ((uintptr_t)p & 3) break;
              return __atomic_compare_exchange_n((uint32_t*)p, &e, (uint32_t)value, 0,
                                                 __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); }
    default: { uint64_t e = expect;
              if ((uintptr_t)p & 7) break;
              return __atomic_compare_exchange_n((uint64_t*)p, &e, value, 0,
                                                 __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); }
    }
    /* misaligned exclusive (the architecture faults on these): best effort */
    pthread_mutex_t* lk = excl_stripe(va);
    pthread_mutex_lock(lk);
    const int ok = arena_load(va, size) == (size == 8 ? expect : (expect & ((UINT64_C(1) << (8 * size)) - 1)));
    if (ok) arena_store(va, size, value);
    pthread_mutex_unlock(lk);
    return ok;
}

static uint64_t vm_excl_load(void* user, uint64_t va, uint32_t size) {
    (void)user;
    ExclSlot* s = excl_slot();
    uint64_t val;
    if (va >= ARENA_BASE && va + size <= ARENA_TOP) {
        const void* p = g_mem + (va - ARENA_BASE);
        switch (size) {
        case 1: val = __atomic_load_n((const uint8_t*)p, __ATOMIC_SEQ_CST); break;
        case 2: val = ((uintptr_t)p & 1) ? arena_load(va, 2) : __atomic_load_n((const uint16_t*)p, __ATOMIC_SEQ_CST); break;
        case 4: val = ((uintptr_t)p & 3) ? arena_load(va, 4) : __atomic_load_n((const uint32_t*)p, __ATOMIC_SEQ_CST); break;
        default: val = ((uintptr_t)p & 7) ? arena_load(va, 8) : __atomic_load_n((const uint64_t*)p, __ATOMIC_SEQ_CST); break;
        }
    } else {
        val = arena_load(va, size);
    }
    s->addr = va; s->val = val; s->valid = 1;
    return val;
}

static uint32_t vm_excl_store(void* user, uint64_t va, uint32_t size, uint64_t value) {
    (void)user;
    ExclSlot* s = excl_slot();
    uint32_t status = 1;
    if (s->valid && s->addr == va && va >= ARENA_BASE && va + size <= ARENA_TOP &&
        vm_cas(va, size, s->val, value))
        status = 0;
    s->valid = 0;                         /* success or failure clears the monitor */
    return status;
}

static void vm_clear_excl(void* user) {
    (void)user;
    excl_slot()->valid = 0;
}

static void vm_excl_load_pair(void* user, uint64_t va, uint32_t size, uint64_t* lo, uint64_t* hi) {
    (void)user;
    ExclSlot* s = excl_slot();
    uint64_t a, b;
    const void* p = g_mem + (va - ARENA_BASE);
    if (size == 4 && !((uintptr_t)p & 7) && va >= ARENA_BASE && va + 8 <= ARENA_TOP) {
        const uint64_t w = __atomic_load_n((const uint64_t*)p, __ATOMIC_SEQ_CST);
        a = (uint32_t)w; b = w >> 32;            /* little-endian: lo word first */
    } else {
        pthread_mutex_t* lk = excl_stripe(va);  /* a consistent 16-byte snapshot */
        pthread_mutex_lock(lk);
        a = arena_load(va, size); b = arena_load(va + size, size);
        pthread_mutex_unlock(lk);
    }
    s->addr = va; s->val = a; s->val2 = b; s->valid = 1;
    *lo = a; *hi = b;
}

static uint32_t vm_excl_store_pair(void* user, uint64_t va, uint32_t size, uint64_t lo, uint64_t hi) {
    (void)user;
    ExclSlot* s = excl_slot();
    uint32_t status = 1;
    if (s->valid && s->addr == va && va >= ARENA_BASE && va + 2 * size <= ARENA_TOP) {
        void* p = g_mem + (va - ARENA_BASE);
        if (size == 4 && !((uintptr_t)p & 7)) {
            uint64_t e = (uint32_t)s->val | ((uint64_t)(uint32_t)s->val2 << 32);
            const uint64_t n = (uint32_t)lo | ((uint64_t)(uint32_t)hi << 32);
            status = __atomic_compare_exchange_n((uint64_t*)p, &e, n, 0,
                                                 __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST) ? 0 : 1;
#if defined(__x86_64__)
        } else if (size == 8 && !((uintptr_t)p & 15)) {
            uint64_t elo = s->val, ehi = s->val2;
            unsigned char ok;
            __asm__ __volatile__("lock cmpxchg16b %1; sete %0"
                                 : "=q"(ok), "+m"(*(volatile unsigned __int128*)p), "+a"(elo), "+d"(ehi)
                                 : "b"(lo), "c"(hi) : "memory", "cc");
            status = ok ? 0 : 1;
#endif
        } else {
            pthread_mutex_t* lk = excl_stripe(va);
            pthread_mutex_lock(lk);
            if (arena_load(va, size) == s->val && arena_load(va + size, size) == s->val2) {
                arena_store(va, size, lo);
                arena_store(va + size, size, hi);
                status = 0;
            }
            pthread_mutex_unlock(lk);
        }
    }
    s->valid = 0;
    return status;
}

static void hm_clear_excl(void* user) {
    (void)user;
    ExclSlot* s = excl_slot();
    if (!s->valid) return;
    pthread_mutex_t* lk = excl_stripe(s->addr);
    pthread_mutex_lock(lk);
    excl_release(s);
    pthread_mutex_unlock(lk);
}

/* Pair forms reserve 2*size bytes; both words must land together, because a
   128-bit compare-and-swap is how the guest builds its mutexes. */
static void hm_excl_load_pair(void* user, uint64_t va, uint32_t size, uint64_t* lo,
                              uint64_t* hi) {
    (void)user;
    ExclSlot* s = excl_slot();
    pthread_mutex_t* lk = excl_stripe(va);
    pthread_mutex_lock(lk);
    excl_mark(va);
    const uint32_t ver = __atomic_load_n(excl_vslot(va), __ATOMIC_RELAXED);
    const uint64_t a = arena_load(va, size), b = arena_load(va + size, size);
    if (!s->valid) __atomic_fetch_add(&g_excl_outstanding, 1, __ATOMIC_RELAXED);
    s->addr = va; s->ver = ver; s->val = a; s->val2 = b; s->valid = 1;
    pthread_mutex_unlock(lk);
    *lo = a; *hi = b;
}

static uint32_t hm_excl_store_pair(void* user, uint64_t va, uint32_t size, uint64_t lo,
                                   uint64_t hi) {
    (void)user;
    ExclSlot* s = excl_slot();
    pthread_mutex_t* lk = excl_stripe(va);
    uint32_t status = 1;
    pthread_mutex_lock(lk);
    /* No portable 16-byte CAS: compare both words under the stripe lock, which
       still catches an outside writer that changed either (see hm_excl_store). */
    if (s->valid && s->addr == va &&
        s->ver == __atomic_load_n(excl_vslot(va), __ATOMIC_RELAXED) &&
        arena_load(va, size) == s->val && arena_load(va + size, size) == s->val2) {
        excl_clear_granule(va, size * 2);
        arena_store(va, size, lo);
        arena_store(va + size, size, hi);
        __atomic_fetch_add(excl_vslot(va), 1, __ATOMIC_RELAXED);
        status = 0;
    } else {
        excl_release(s);        /* as above: failure clears the monitor */
    }
    pthread_mutex_unlock(lk);
    return status;
}

/* Any store to the granule retires reservations on it, which is what hardware
   does and what upstream records as a divergence it does not implement.
   Bumping a version, rather than walking the slots, keeps this off the stripe
   lock: a store only has to be *visible* to a concurrent STXR. */
static inline void excl_invalidate_on_store(uint64_t va, uint32_t size) {
    const uint64_t lo = va & ~UINT64_C(15);
    const uint64_t hi = (va + (size ? size : 1) - 1) & ~UINT64_C(15);
    const uint8_t e = __atomic_load_n(&g_excl_epoch, __ATOMIC_RELAXED), e1 = (uint8_t)(e - 1u);
    int hit = 0;
    for (uint64_t g = lo; g <= hi; g += 16) {
        const uint8_t m = __atomic_load_n(excl_rslot(g), __ATOMIC_RELAXED);
        hit |= (m == e) | (m == e1);
    }
    if (__builtin_expect(!hit, 1)) return;          /* nobody reserved this granule recently */
    static int on = -1;
    if (on < 0) {
        const char* v = getenv("A64PORT_EXCL_STORE_INVAL");
        on = !(v && *v && strcmp(v, "0") == 0);
    }
    if (!on) return;
    for (uint64_t g = lo; g <= hi; g += 16)
        __atomic_fetch_add(excl_vslot(g), 1, __ATOMIC_RELAXED);
}

static void hm_store(void* user, uint64_t va, uint32_t size, uint64_t value) {
    (void)user;
    asan_check_store(va, size);
    if (va < ARENA_BASE || va + size > ARENA_TOP) return;
    arena_store(va, size, value);
    excl_invalidate_on_store(va, size);
}

static RecompHostMem g_host_mem;

/* CNTPCT_EL0/CNTVCT_EL0 at the guest's advertised 19.2 MHz, from the
   monotonic clock.  Without this hook the emitted runtime falls back to
   clock(), which is process CPU time. */
static uint64_t hm_cntpct(void* user) {
    (void)user;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
#if defined(__SIZEOF_INT128__)
    const unsigned __int128 ns = (unsigned __int128)ts.tv_sec * 1000000000u + (unsigned)ts.tv_nsec;
    return (uint64_t)(ns * 12u / 625u);              /* ns * 19.2e6 / 1e9 */
#else
    /* The same value without 128-bit arithmetic: 1e9 * 12 is a multiple of
       625, so the seconds term divides exactly and only nsec is floored. */
    return (uint64_t)ts.tv_sec * UINT64_C(19200000) +
           (uint64_t)(unsigned)ts.tv_nsec * 12u / 625u;
#endif
}

static void hostmem_install(void) {
    /* A64PORT_PAGETABLE=0 runs the whole guest on the flat path instead. The
       page table and recomp_host_ptr are a fast path that no differential test
       covers - the fuzz guests are built without a host_mem - so this is the
       A/B that tells us whether that path, rather than the runtime, is where a
       mis-addressed access comes from. */
    const char* pt = getenv("A64PORT_PAGETABLE");
    if (pt && *pt && strcmp(pt, "0") == 0) {
        g_c.host_mem = NULL;
        fprintf(stderr, "[a64port] host page table DISABLED (flat path)\n");
        return;
    }
    const uintptr_t bias = (uintptr_t)g_mem - (uintptr_t)ARENA_BASE;
    for (size_t i = 0; i < sizeof g_hm_pages / sizeof g_hm_pages[0]; ++i)
        g_hm_pages[i] = bias;
    g_host_mem.user = NULL;
    g_host_mem.load = hm_load;
    g_host_mem.store = hm_store;
    /* Install the monitor. A64PORT_EXCL_MONITOR=0 falls back to the emitted
       runtime's per-thread latch, which is only valid when the runtime drives a
       single guest thread - useful as an A/B and as insurance, not as the
       default. */
    {
        const char* v = getenv("A64PORT_EXCL_MONITOR");
#ifdef A64PORT_FASTMEM
        const int mon = (v && *v) ? atoi(v) : 2;   /* inline stores retire nothing */
#else
        const int mon = (v && *v) ? atoi(v) : 1;
#endif
        if (mon == 2) {
            g_excl_value = 1;
            g_host_mem.excl_load = vm_excl_load;
            g_host_mem.excl_store = vm_excl_store;
            g_host_mem.clear_excl = vm_clear_excl;
            g_host_mem.read_cntpct = hm_cntpct;
            g_host_mem.excl_load_pair = vm_excl_load_pair;
            g_host_mem.excl_store_pair = vm_excl_store_pair;
            fprintf(stderr, "[a64port] exclusive monitor: value-CAS (qemu model)\n");
        } else {
        g_host_mem.excl_load = mon ? hm_excl_load : NULL;
        g_host_mem.excl_store = mon ? hm_excl_store : NULL;
        g_host_mem.clear_excl = mon ? hm_clear_excl : NULL;
        g_host_mem.read_cntpct = hm_cntpct;
        g_host_mem.excl_load_pair = mon ? hm_excl_load_pair : NULL;
        g_host_mem.excl_store_pair = mon ? hm_excl_store_pair : NULL;
    }
    }
    g_host_mem.page_entries = g_hm_pages;
    g_host_mem.page_entry_stride = sizeof(uintptr_t);
    g_host_mem.page_bits = HOSTMEM_PAGE_BITS;
    g_host_mem.pointer_mask = ~(uintptr_t)0;
    g_host_mem.address_space_max = ARENA_TOP;
    g_host_mem.guard_generation = NULL;
    g_c.host_mem = &g_host_mem;
    fprintf(stderr, "[a64port] host page table installed (%zu entries, %u KB pages)\n",
            sizeof g_hm_pages / sizeof g_hm_pages[0], 1u << (HOSTMEM_PAGE_BITS - 10));
}

/* per-module load addresses. The executable is 0 and ld.so is what we mapped it at;
   every other module starts unknown and is filled in when ld.so maps it. */
static uint64_t g_mod_base[R_NMODULES];
/* Module index of the executable, the only module whose base is 0. */
static unsigned g_m_exe;
static uint64_t g_pool_top = MMAP_HI;
static uint64_t g_interp_base;      /* AT_BASE, set once we know which is ld.so */

/* One load-address variable per module. The generated code addresses its own
   image as `g_mb_<mod> + <link-time offset>`, which is what lets 26 separately
   compiled modules share one address space. */
uint64_t R_MODULE_BASE_VARS
    ;

/* fd -> module index, learned from the open() that ld.so does before mmap */
#define A64PORT_MAXFD 4096
static short g_fd_mod[A64PORT_MAXFD];

static char g_rootfs[1024];

/* trace ring so a bad jump names the block that made it.  PER-THREAD: this is
   written on every block transition, so a shared array plus a shared cursor had
   every core ping-ponging the same cache lines for the whole run. */
#define TRACE_N 256
static __thread uint64_t t_trace[TRACE_N];
static __thread unsigned t_tpos;
static uint64_t g_blocks;               /* aggregate, refreshed rarely */
static __thread uint64_t t_blocks;      /* authoritative per-thread count */

static inline void* P(uint64_t va) { return g_mem + (va - ARENA_BASE); }
/* Same address translation as P(), but for a pointer the GUEST supplied (a
   clone parent_tid/child_tid, say).  P() subtracts unsigned, so a VA below the
   arena wraps to a huge offset and the result lands outside the allocation -
   fine for the loader's own addresses, not for one the guest chose.  NULL means
   the caller must fail the syscall instead of writing. */
static inline void* PG(uint64_t va) {
    if (va < ARENA_BASE || va - ARENA_BASE >= ARENA_SIZE) return NULL;
    return g_mem + (va - ARENA_BASE);
}

static const char* mod_of(uint64_t pc) {
    const char* best = "?";
    uint64_t best_base = 0;
    for (unsigned m = 0; m < R_NMODULES; ++m) {
        const uint64_t b = g_mod_base[m];
        if (b && b <= pc && b >= best_base) { best_base = b; best = R_MODULES[m].name; }
    }
    if (pc >= ARENA_BASE && pc < UINT64_C(0x04000000)) return R_EXE_MODULE;
    return best;
}

/* Block dispatch.  This runs once per block transition - billions of times -
   so the common case must not scan all 26 modules.  Almost every transition
   stays inside the module that was used last, so cache it; g_base_gen
   invalidates the cache when a DSO base is learned from an mmap. */
static uint64_t g_base_gen;
#if defined(RECOMP_FEATURE_GUARD_GEN1)
/* GG1 generation. Bumped whenever a module base moves, so every block verifies
   its instruction words again at the new base instead of trusting a check made
   somewhere else. Starts at 1; RECOMP_GG_VERIFY_ALWAYS is never stored. */
static uint32_t g_gg_gen = 1;
#endif

/* ── host-library trampolines ──────────────────────────────────────────────
   Route selected imported symbols to the HOST's implementation instead of the
   translated one.  The translated ld.so fills each module's GOT with a guest
   VA; the moment the guest branches to AT_ENTRY every eager relocation has been
   applied, so we overwrite the GOT slots we claim with a trampoline VA.

   A trampoline is an ordinary guest-ABI function (args in c->x[0..7], result in
   c->x[0], return via c->x[30]) that converts pointers with the arena bias and
   calls the host function.  There is no per-block cost: dispatch() only knows
   the reserved trampoline range, and the guest reaches it solely through a
   patched GOT slot.

   Safety net: each trampoline falls back to the guest VA it replaced when an
   argument is not wholly inside the arena, so a pointer to device memory or to
   a region the host call cannot treat as an array degrades to the translated
   implementation instead of faulting the host.  Gated by A64PORT_HOSTLIBS=1.

   NOTE: this is a mechanism, not (yet) a win.  Our own profile puts each of
   these libc leaves at ~0.4 % of busy time, so expect the latency to move very
   little.  The value is that the facility generalises to whole platform
   libraries, which is a size/maintenance change and a
   separate project -- libX11 in particular hands the app an XImage whose `data`
   field the guest dereferences, which no generic pointer marshalling fixes. */
#define R_AARCH64_GLOB_DAT  1025u
#define R_AARCH64_JUMP_SLOT 1026u
#define R_AARCH64_IRELATIVE 1032u
#define STT_GNU_IFUNC       10u
#define NAT_VA_BASE   (ARENA_TOP - UINT64_C(0x100000))   /* above the guest stack */
#define NAT_VA_STRIDE 8u

static int g_hostlibs;

static int nat_in(uint64_t a, uint64_t n) {
    return a >= ARENA_BASE && a <= ARENA_TOP && n <= ARENA_TOP - a;
}
/* host pointer -> guest VA (the arena is one allocation, so this is a bias) */
#define GV(p) ((uint64_t)((const uint8_t*)(p) - g_mem) + ARENA_BASE)

enum { N_memcpy, N_memset, N_memmove, N_memcmp, N_memchr,
       N_strlen, N_strcmp, N_strncmp, N_strcpy, N_strchr,
       N_rawmemchr,
       N_N };
static const char* const g_nat_name[N_N] = {
    "memcpy", "memset", "memmove", "memcmp", "memchr",
    "strlen", "strcmp", "strncmp", "strcpy", "strchr",
    "rawmemchr",
};

/* Byte-at-a-time access through the same helpers the emitted code uses, for
   the case where an argument is not wholly inside the arena. This is what the
   translated function would do anyway, and -- crucially -- it means a
   trampoline never has to re-enter guest code. Falling back to the old GOT
   value would NOT work: for a lazily bound symbol that value is the PLT
   resolver stub, which reads the slot we just patched and would jump straight
   back into the trampoline. */
static unsigned long g_nat_calls[N_N];    /* trampoline entries per symbol */
static unsigned long g_nat_slow_bytes;    /* bytes that took the byte loop */

static uint64_t nat_ld8(uint64_t a) { ++g_nat_slow_bytes; return hm_load(NULL, a, 1); }
static void nat_st8(uint64_t a, uint64_t v) { ++g_nat_slow_bytes; hm_store(NULL, a, 1, v & 0xffu); }

/* Length of a NUL-terminated object that lies wholly inside the arena; 0 if no
   terminator is reachable (so caller must use the byte loop).

   This MUST use a bulk host scan, not the per-byte helper: strlen/strcmp are
   hot, and hm_load() per byte made the whole host-libs path ~13% slower than
   the translated code it replaced.  Bounded by the arena end, so the host scan
   can never read past the mapping. */
static int nat_zlen(uint64_t s, uint64_t* out) {
    if (s < ARENA_BASE || s >= ARENA_TOP) return 0;
    const uint8_t* p = (const uint8_t*)P(s);
    const uint8_t* z = (const uint8_t*)memchr(p, 0, (size_t)(ARENA_TOP - s));
    if (!z) return 0;
    *out = (uint64_t)(z - p);
    return 1;
}

static void nat_memcpy(GuestContext* c) {
    const uint64_t d = c->x[0], s = c->x[1], n = c->x[2];
    if (nat_in(d, n) && nat_in(s, n)) memcpy(P(d), P(s), (size_t)n);
    else for (uint64_t i = 0; i < n; ++i) nat_st8(d + i, nat_ld8(s + i));
    c->x[0] = d;                       /* AArch64 ABI: memcpy returns dest */
    c->pc = c->x[30];
}
static void nat_memset(GuestContext* c) {
    const uint64_t d = c->x[0], n = c->x[2];
    if (nat_in(d, n)) memset(P(d), (int)c->x[1], (size_t)n);
    else for (uint64_t i = 0; i < n; ++i) nat_st8(d + i, c->x[1]);
    c->x[0] = d;                       /* memset returns dest */
    c->pc = c->x[30];
}
static void nat_memmove(GuestContext* c) {
    const uint64_t d = c->x[0], s = c->x[1], n = c->x[2];
    if (nat_in(d, n) && nat_in(s, n)) {
        memmove(P(d), P(s), (size_t)n);
    } else if (d <= s) {
        for (uint64_t i = 0; i < n; ++i) nat_st8(d + i, nat_ld8(s + i));
    } else {
        for (uint64_t i = n; i-- > 0;) nat_st8(d + i, nat_ld8(s + i));
    }
    c->x[0] = d;                       /* memmove returns dest */
    c->pc = c->x[30];
}
static void nat_memcmp(GuestContext* c) {
    const uint64_t a = c->x[0], b = c->x[1], n = c->x[2];
    int64_t r = 0;
    if (nat_in(a, n) && nat_in(b, n)) {
        r = memcmp(P(a), P(b), (size_t)n);
    } else {
        for (uint64_t i = 0; i < n; ++i) {
            const int x = (int)nat_ld8(a + i), y = (int)nat_ld8(b + i);
            if (x != y) { r = x - y; break; }
        }
    }
    c->x[0] = (uint64_t)r;
    c->pc = c->x[30];
}
static void nat_memchr(GuestContext* c) {
    const uint64_t s = c->x[0], n = c->x[2];
    if (nat_in(s, n)) {
        const void* r = memchr(P(s), (int)c->x[1], (size_t)n);
        c->x[0] = r ? GV(r) : 0;
    } else {
        c->x[0] = 0;
        for (uint64_t i = 0; i < n; ++i)
            if (nat_ld8(s + i) == (c->x[1] & 0xffu)) { c->x[0] = s + i; break; }
    }
    c->pc = c->x[30];
}
static void nat_strlen(GuestContext* c) {
    uint64_t n = 0;
    c->x[0] = nat_zlen(c->x[0], &n) ? n : 0;
    c->pc = c->x[30];
}
static void nat_strcmp(GuestContext* c) {
    const uint64_t a = c->x[0], b = c->x[1];
    uint64_t la, lb;
    int64_t r = 0;
    if (nat_zlen(a, &la) && nat_zlen(b, &lb)) {
        r = strcmp((const char*)P(a), (const char*)P(b));
    } else {
        for (uint64_t i = 0;; ++i) {
            const int x = (int)nat_ld8(a + i), y = (int)nat_ld8(b + i);
            if (x != y) { r = x - y; break; }
            if (!x) break;
        }
    }
    c->x[0] = (uint64_t)r;
    c->pc = c->x[30];
}
static void nat_strncmp(GuestContext* c) {
    const uint64_t a = c->x[0], b = c->x[1], n = c->x[2];
    uint64_t la, lb;
    int64_t r = 0;
    if (nat_zlen(a, &la) && nat_zlen(b, &lb)) {
        r = strncmp((const char*)P(a), (const char*)P(b), (size_t)n);
    } else {
        for (uint64_t i = 0; i < n; ++i) {
            const int x = (int)nat_ld8(a + i), y = (int)nat_ld8(b + i);
            if (x != y) { r = x - y; break; }
            if (!x) break;
        }
    }
    c->x[0] = (uint64_t)r;
    c->pc = c->x[30];
}
static void nat_strcpy(GuestContext* c) {
    const uint64_t d = c->x[0], s = c->x[1];
    uint64_t ls;
    if (nat_zlen(s, &ls) && nat_in(d, ls + 1)) {
        strcpy((char*)P(d), (const char*)P(s));
    } else {
        for (uint64_t i = 0;; ++i) {
            const uint64_t b = nat_ld8(s + i);
            nat_st8(d + i, b);
            if (!b) break;
        }
    }
    c->x[0] = d;                       /* strcpy returns dest */
    c->pc = c->x[30];
}
static void nat_strchr(GuestContext* c) {
    const uint64_t s = c->x[0];
    const uint64_t ch = c->x[1] & 0xffu;
    uint64_t ls;
    if (nat_zlen(s, &ls)) {
        const char* r = strchr((const char*)P(s), (int)c->x[1]);
        c->x[0] = r ? GV(r) : 0;
    } else {
        c->x[0] = 0;
        for (uint64_t i = 0;; ++i) {
            const uint64_t b = nat_ld8(s + i);
            if (b == ch) { c->x[0] = s + i; break; }
            if (!b) break;
        }
    }
    c->pc = c->x[30];
}
static int g_nat_range_on;     /* set by the other host-library trampolines to enable the range */

/* rawmemchr: the guest SIMD implementation spins (it can spin on an
   unterminated string).  Redirect it to a
   bounded host scan.  Always installed. */
static void nat_rawmemchr(GuestContext* c) {
    const uint64_t s = c->x[0];
    const int ch = (int)(c->x[1] & 0xffu);
    if (s >= ARENA_BASE && s < ARENA_TOP) {
        const uint8_t* z = (const uint8_t*)memchr(P(s), ch, (size_t)(ARENA_TOP - s));
        c->x[0] = z ? GV(z) : 0;
    } else {
        c->x[0] = 0;
        for (uint64_t i = 0; s + i < ARENA_TOP; ++i)
            if (nat_ld8(s + i) == (uint64_t)ch) { c->x[0] = s + i; break; }
    }
    c->pc = c->x[30];
}


static BlockFn g_nat_fn[N_N] = {
    nat_memcpy, nat_memset, nat_memmove, nat_memcmp, nat_memchr,
    nat_strlen, nat_strcmp, nat_strncmp, nat_strcpy, nat_strchr,
    nat_rawmemchr,
};

static int g_nat_patched;

/* Resolve a *defined* symbol to its guest VA from the module symbol tables.
   The GOT slot of a lazily bound import still holds the PLT resolver stub when
   nat_patch_got() runs, so the real implementation has to come from the
   dynsym of the module that defines it. */
static uint64_t guest_sym_addr(const char* name) {
    for (unsigned m = 0; m < R_NMODULES; ++m) {
        if (!g_mod_base[m]) continue;
        for (unsigned s = 0; s < R_MODULES[m].nsym; ++s) {
            const RModSym* sy = &R_MODULES[m].syms[s];
            if (sy->name && sy->shndx && sy->value && !strcmp(sy->name, name))
                return g_mod_base[m] + sy->value;
        }
    }
    return 0;
}

/* Rewrite the GOT slots we claim.  Called once, when the guest reaches the
   executable's entry -- by then ld.so has applied every eager relocation, and
   for lazy ones the overwritten slot simply means the resolver is never
   needed.  only >= 0: claim just that symbol. */
static void nat_patch_got(int only) {
    unsigned n = 0;
    for (unsigned m = 0; m < R_NMODULES; ++m) {
        const uint64_t base = g_mod_base[m];
        /* base 0 = not loaded - except the executable, which runs at its link
           addresses; its GOT is only claimed for a single-symbol patch */
        if (!base && !(m == 0 && only >= 0)) continue;
        for (unsigned r = 0; r < R_MODULES[m].nrel; ++r) {
            const RModRel* rel = &R_MODULES[m].rels[r];
            const char* nm = NULL;
            if (rel->type == R_AARCH64_JUMP_SLOT || rel->type == R_AARCH64_GLOB_DAT) {
                if (rel->sym >= R_MODULES[m].nsym) continue;
                nm = R_MODULES[m].syms[rel->sym].name;
            } else if (rel->type == R_AARCH64_IRELATIVE) {
                /* IFUNC (strlen/memcpy/memset/memmove): there is no symbol index,
                   the addend is the resolver VA.  ld.so resolved the slot to a
                   guest implementation; libc-internal calls bypass the named-GOT
                   patch above, and the guest SIMD strlen can spin on an
                   unterminated string.  Match the resolver address back to the
                   IFUNC symbol and redirect the slot to the host helper. */
                for (unsigned s = 0; s < R_MODULES[m].nsym; ++s) {
                    if (R_MODULES[m].syms[s].value == (uint64_t)rel->addend &&
                        R_MODULES[m].syms[s].type == STT_GNU_IFUNC) {
                        nm = R_MODULES[m].syms[s].name;
                        break;
                    }
                }
                if (!nm) continue;
            } else {
                continue;
            }
            const uint64_t slot_va = base + rel->off;
            if (!nat_in(slot_va, 8)) continue;
            for (unsigned k = 0; k < N_N; ++k) {
                if (only >= 0 && k != (unsigned)only) continue;
                if (strcmp(nm, g_nat_name[k])) continue;
                /* The rawmemchr fix is installed
                   whether or not the host libs are on; the other memory
                   leaves only with A64PORT_HOSTLIBS. */
                if (k != N_rawmemchr && !g_hostlibs) break;
                if (k == N_rawmemchr) {
                    g_nat_range_on = 1;      /* enable the trampoline range */
                    fprintf(stderr, "[a64port] rawmemchr: GOT 0x%llx -> host scan\n",
                            (unsigned long long)slot_va);
                }
                *(uint64_t*)P(slot_va) = NAT_VA_BASE + (uint64_t)k * NAT_VA_STRIDE;
                ++n;
                break;
            }
        }
    }
    if (only < 0) fprintf(stderr, "[a64port] host libs: %u GOT slot(s) redirected to the host\n", n);
}


/* ── global block resolver ─────────────────────────────────────────────────
   One two-level table for every module: g_rx_l1[pc >> 22] -> 1024 pages ->
   1024 BlockFn (one per instruction word of a 4 KB page).  Leaf pages point
   straight into a module's own flat index where the page lies wholly inside
   it; edge pages get a private copy.  A module is entered on its first
   dispatch() miss; a base change (ld.so still mapping) drops the table, and
   old pages are leaked, never freed, so a racing reader is always safe.
   neon_structs.h inlines the lookup for --callret code (RECOMP_RESOLVE), and
   dispatch() uses it first - no per-module scan on a module switch. */
BlockFn** g_rx_l1[A64PORT_RX_L1_N];
static pthread_mutex_t g_rx_mu = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_rx_gen = ~UINT64_C(0);
static uint8_t g_rx_done[R_NMODULES];

static void rx_register(unsigned m, uint64_t b, uint64_t lo, uint64_t hi, BlockFn* idx) {
    pthread_mutex_lock(&g_rx_mu);
    if (g_rx_gen != g_base_gen) {                 /* bases moved: start over */
        for (size_t i = 0; i < A64PORT_RX_L1_N; ++i) __atomic_store_n(&g_rx_l1[i], NULL, __ATOMIC_RELEASE);
        memset(g_rx_done, 0, sizeof g_rx_done);
        g_rx_gen = g_base_gen;
    }
    if (g_rx_done[m]) { pthread_mutex_unlock(&g_rx_mu); return; }
    g_rx_done[m] = 1;
    const uint64_t first = b + lo, last = b + hi;  /* inclusive word addresses */
    for (uint64_t ps = first & ~UINT64_C(0xFFF); ps <= last; ps += 0x1000) {
        const uint64_t l1 = ps >> 22;
        if (l1 >= A64PORT_RX_L1_N) break;
        BlockFn** l2 = __atomic_load_n(&g_rx_l1[l1], __ATOMIC_ACQUIRE);
        if (!l2) {
            l2 = (BlockFn**)calloc(1024, sizeof(BlockFn*));
            if (!l2) break;
            __atomic_store_n(&g_rx_l1[l1], l2, __ATOMIC_RELEASE);
        }
        BlockFn* pg;
        if (ps >= first && ps + 0xFFC <= last) {
            pg = idx + (size_t)((ps - first) >> 2);
        } else {
            pg = (BlockFn*)calloc(1024, sizeof(BlockFn));
            if (!pg) break;
            for (unsigned k = 0; k < 1024; ++k) {
                const uint64_t va = ps + 4u * k;
                if (va >= first && va <= last) pg[k] = idx[(size_t)((va - first) >> 2)];
            }
        }
        __atomic_store_n(&l2[(ps >> 12) & 1023], pg, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&g_rx_mu);
}

static inline BlockFn rx_lookup(uint64_t pc) {
    if ((pc >> 22) >= A64PORT_RX_L1_N || (pc & 3)) return NULL;
    BlockFn** l2 = __atomic_load_n(&g_rx_l1[pc >> 22], __ATOMIC_ACQUIRE);
    if (!l2) return NULL;
    BlockFn* pg = __atomic_load_n(&l2[(pc >> 12) & 1023], __ATOMIC_ACQUIRE);
    return pg ? pg[(pc & 0xFFF) >> 2] : NULL;
}

static BlockFn dispatch_slow(uint64_t pc);
static inline BlockFn dispatch(uint64_t pc) {
    BlockFn f = rx_lookup(pc);
    return f ? f : dispatch_slow(pc);
}
/* For emitted --callret code: the out-of-line half of RECOMP_RESOLVE. */
BlockFn a64port_resolve_slow(uint64_t pc) { return dispatch_slow(pc); }

static BlockFn dispatch_slow(uint64_t pc) {
    static __thread struct { uint64_t lo, hi, gen; BlockFn* idx; } cache;
    if (cache.idx && cache.gen == g_base_gen && pc >= cache.lo && pc <= cache.hi)
        return cache.idx[(size_t)((pc - cache.lo) >> 2)];
    if (g_hostlibs || g_nat_range_on) {
        /* Only reachable through a GOT slot we patched, so this test is never
           taken on the normal path. */
        const uint64_t t = pc - NAT_VA_BASE;
        if (t < (uint64_t)N_N * NAT_VA_STRIDE) {
            const unsigned k = (unsigned)(t / NAT_VA_STRIDE);
            ++g_nat_calls[k];
            return g_nat_fn[k];
        }
    }
    for (unsigned m = 0; m < R_NMODULES; ++m) {
        uint64_t lo, hi; BlockFn* idx;
        const uint64_t b = g_mod_base[m];
        /* A DSO whose base is still 0 is not mapped: its module-relative index
           must not answer for an absolute pc. */
        if (!b && m != g_m_exe) continue;
        if (!R_MODULES[m].index_view(&lo, &hi, &idx)) continue;
        if (pc >= b + lo && pc <= b + hi) {
            cache.lo = b + lo; cache.hi = b + hi;
            cache.idx = idx; cache.gen = g_base_gen;
            if (g_rx_gen != g_base_gen || !g_rx_done[m]) rx_register(m, b, lo, hi, idx);
            return idx[(size_t)((pc - cache.lo) >> 2)];
        }
    }
    return NULL;
}

/* ── guest threads ───────────────────────────────────────────────────────── */
/* A guest thread's tid is its HOST thread's gettid().  It
   used to be a counter (g_next_tid++, unsynchronized), which disagreed with
   what gettid/set_tid_address/the PI futexes report and could hand two threads
   the same tid - and glibc's recursive-mutex owner check compares the lock word
   with pd->tid, so a duplicate let a second thread "re-enter" a lock the first
   one held.  Real tids are also what the host kernel's PI futexes require. */
typedef struct GuestThread {
    GuestContext ctx;
    pthread_t host;
    uint32_t tid;
    uint64_t flags;                  /* the guest's clone flags */
    uint64_t ptid, ctid;             /* guest VAs from clone */
    pthread_mutex_t ready_mu;        /* child -> parent: tid published */
    pthread_cond_t ready_cv;
    int ready;
    uint64_t sigmask_rt;             /* creator's blocked state of signals 32/33 (clone inherits the mask) */
    struct GuestThread* next;
} GuestThread;
static GuestThread* g_threads;       /* push under g_threads_mu; readers walk lock-free */
static pthread_mutex_t g_threads_mu = PTHREAD_MUTEX_INITIALIZER;
#define K_CLONE_PARENT_SETTID  UINT64_C(0x00100000)
#define K_CLONE_CHILD_CLEARTID UINT64_C(0x00200000)
#define K_CLONE_CHILD_SETTID   UINT64_C(0x01000000)
/* linux_syscalls.c */
extern __thread int a64port_vfork_child;
int a64port_futex_wake(uint64_t va, int n);

/* The launchers export every diagnostic switch even when off (as "0"), so a
   bare getenv() truthiness test leaves them all on. Treat "" and "0" as off. */
static int EnvOn(const char* name) {
    const char* v = getenv(name);
    return v && *v && strcmp(v, "0") != 0;
}
/* Running a signal handler to dump the host call stack (the generated
   functions are global symbols named blk_<mod>_<addr>). */
static void dump_backtrace(int sig) {
    (void)sig;
    void* bt[64];
    const int n = backtrace(bt, 64);
    char hdr[64];
    const int m = snprintf(hdr, sizeof hdr, "=== SIGUSR1 backtrace (%d frames) ===\n", n);
    (void)!write(2, hdr, (size_t)m);
    backtrace_symbols_fd(bt, n, 2);
    /* A hang is exactly when the recorded miss list is worth keeping. */
    recomp_gap_dump();
}

int a64port_dbg_ms(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return (int)(ts.tv_sec % 100000 * 1000 + ts.tv_nsec / 1000000); }
/* Guest backtrace on demand (debug instrumentation hook for emitted code). */
void a64port_dbg_bt(GuestContext* c, const char* tag) {
    fprintf(stderr, "[bt %s] x0=0x%llx x30=0x%llx(%s)\n", tag, (unsigned long long)c->x[0],
            (unsigned long long)c->x[30], mod_of(c->x[30]));
    uint64_t fp = c->x[29];
    for (int k = 0; k < 24; ++k) {
        if (fp < ARENA_BASE || fp + 16 > ARENA_TOP) break;
        const uint64_t* fr = (const uint64_t*)P(fp);
        if (!fr[1]) break;
        fprintf(stderr, "[bt]   #%-2d ret=0x%llx %s\n", k, (unsigned long long)fr[1], mod_of(fr[1]));
        if (fr[0] <= fp) break;
        fp = fr[0];
    }
    fflush(stderr);
}

/* ── flat sampling profiler ────────────────────────────────────────────────
   There is no `perf` on this host (perf_event_paranoid=2), so sample each guest
   thread's PC every 10 ms and accumulate a histogram.  Every sample is a guest
   address, so ranking it answers both "where does it hang" and "what costs the
   most", and the block addresses resolve to functions through
   the modules' .eh_frame (scripts/guest-hot.py).  Enabled with A64PORT_PROF=1.
   A64PORT_PROF_US=<n> samples every n us (default 10000).  A64PORT_PROF_OUT=<file>
   also writes the WHOLE cumulative table at every dump as `module 0xoffset hits`
   (offset = the block-symbol hex of blk_<module>_..._<hex>: absolute for app,
   module-relative for a DSO), which is what scripts/hot-order.py turns into a
   link order.  The top-30 log lines are unchanged (they still reset). */
#define PROF_BITS 17
#define PROF_SIZE (1u << PROF_BITS)
#define PROF_MASK (PROF_SIZE - 1u)
static struct { uint64_t pc; uint64_t hits, cum; } g_prof[PROF_SIZE];
static uint64_t g_prof_total, g_prof_lost, g_prof_idle;

/* A parked thread is sampled too, and with 260 guest threads the parked ones
   swamp the histogram - so drop samples that are sitting on a known park point.
   libpthread is nothing but park points; in libc these three offsets are
   __lll_lock_wait / __futex_abstimed_wait and the condvar wait. */
static int prof_is_idle(uint64_t pc) {
    const char* m = mod_of(pc);
    if (!strcmp(m, "libpthread")) return 1;
    if (g_mb_libc && !strcmp(m, "libc")) {
        const uint64_t off = pc - g_mb_libc;
        if (off == 0xC3870ULL || off == 0xC1694ULL || off == 0x7FDE0ULL) return 1;
    }
    return 0;
}

static void prof_sample(uint64_t pc) {
    if (pc < ARENA_BASE || pc >= ARENA_TOP) return;
    if (prof_is_idle(pc)) { g_prof_idle++; return; }
    uint32_t h = (uint32_t)((pc >> 2) * 2654435761u) & PROF_MASK;
    for (uint32_t i = 0; i < 64; ++i, h = (h + 1) & PROF_MASK) {
        if (g_prof[h].pc == pc) { g_prof[h].hits++; g_prof[h].cum++; g_prof_total++; return; }
        if (g_prof[h].pc == 0) { g_prof[h].pc = pc; g_prof[h].hits = 1; g_prof[h].cum = 1; g_prof_total++; return; }
    }
    g_prof_lost++;
}

static void prof_dump(void);

static void* prof_thread(void* arg) {
    (void)arg;
    int dumps = 0;
    const char* us_env = getenv("A64PORT_PROF_US");
    const long us = (us_env && *us_env) ? strtol(us_env, 0, 0) : 10000;
    const int per_dump = us > 0 && us < 10000 ? (int)(250000 / us) : 25;   /* ~250 ms windows */
    while (1) {
        usleep((useconds_t)(us > 0 ? us : 10000));
        prof_sample(__atomic_load_n(&g_c.pc, __ATOMIC_RELAXED));
        for (GuestThread* t = g_threads; t; t = t->next)
            prof_sample(__atomic_load_n(&t->ctx.pc, __ATOMIC_RELAXED));
        /* Dump from HERE, not from main: a sleep loop in main would block
           guest_run and the profile would only ever see the entry PC. */
        if (++dumps % per_dump == 0) prof_dump();   /* DIAG: 250 ms windows */
    }
    return NULL;
}

/* A64PORT_PROF_OUT: the whole cumulative table, rewritten atomically. */
static void prof_write_table(void) {
    static const char* out = (const char*)1;
    if (out == (const char*)1) out = getenv("A64PORT_PROF_OUT");
    if (!out || !*out) return;
    char tmp[4096];
    snprintf(tmp, sizeof tmp, "%s.tmp", out);
    FILE* f = fopen(tmp, "w");
    if (!f) return;
    for (uint32_t i = 0; i < PROF_SIZE; ++i) {
        const uint64_t pc = g_prof[i].pc;
        if (!pc || !g_prof[i].cum) continue;
        const char* m = mod_of(pc);
        uint64_t base = 0;
        if (strcmp(m, R_EXE_MODULE) != 0)
            for (unsigned k = 0; k < R_NMODULES; ++k)
                if (!strcmp(R_MODULES[k].name, m)) { base = g_mod_base[k]; break; }
        fprintf(f, "%s 0x%llx %llu\n", m, (unsigned long long)(pc - base),
                (unsigned long long)g_prof[i].cum);
    }
    fclose(f);
    rename(tmp, out);
}

static void prof_dump(void) {
    prof_write_table();
    struct timespec _pts; clock_gettime(CLOCK_MONOTONIC, &_pts);
    fprintf(stderr, "[prof] t=%.3f %llu busy samples, %llu idle/parked, %llu lost\n",
            _pts.tv_sec + 1e-9 * _pts.tv_nsec,
            (unsigned long long)g_prof_total, (unsigned long long)g_prof_idle,
            (unsigned long long)g_prof_lost);
    /* Top 30 by hits: repeated selection, fine for a dump. */
    for (int n = 0; n < 30; ++n) {
        uint32_t best = 0;
        for (uint32_t i = 0; i < PROF_SIZE; ++i)
            if (g_prof[i].hits > g_prof[best].hits) best = i;
        if (!g_prof[best].hits) break;
        fprintf(stderr, "[prof]   %8llu  %5.1f%%  pc=0x%-10llx %s\n",
                (unsigned long long)g_prof[best].hits,
                g_prof_total ? 100.0 * (double)g_prof[best].hits / (double)g_prof_total : 0.0,
                (unsigned long long)g_prof[best].pc, mod_of(g_prof[best].pc));
        g_prof[best].hits = 0;
    }
}


/* ── CPU-aware per-thread profiler (A64PORT_PROF_CPU=1) ─────────────────────
   The flat profiler above counts a thread parked in a syscall as "busy" and
   cannot say WHICH thread is hot.  This one weights each sample by the CPU
   time the thread was actually scheduled for since the last sample
   (/proc/self/task/<tid>/schedstat), and keys it by (thread name, guest pc).
   Output every 5 s: "[profT] <thread> <cpu_ms> pc=0x.. <module>" (cumulative). */
#define PT_SLOTS 1024
#define PT_HBITS 17
static struct { int tid; uint64_t last_ns, total_us; char comm[20]; } g_pt[PT_SLOTS];
static struct { uint64_t key; uint64_t us; } g_pth[1u << PT_HBITS];

static int pt_slot(int tid) {
    unsigned h = ((unsigned)tid * 2654435761u) % PT_SLOTS;
    for (int i = 0; i < PT_SLOTS; ++i, h = (h + 1) % PT_SLOTS) {
        if (g_pt[h].tid == tid) return (int)h;
        if (g_pt[h].tid == 0) {
            g_pt[h].tid = tid;
            char path[64]; snprintf(path, sizeof path, "/proc/self/task/%d/comm", tid);
            FILE* f = fopen(path, "r");
            if (f) { if (fgets(g_pt[h].comm, sizeof g_pt[h].comm, f)) g_pt[h].comm[strcspn(g_pt[h].comm, "\n")] = 0; fclose(f); }
            return (int)h;
        }
    }
    return -1;
}

static void pt_sample(int tid, uint64_t pc) {
    char path[64]; snprintf(path, sizeof path, "/proc/self/task/%d/schedstat", tid);
    FILE* f = fopen(path, "r");
    if (!f) return;
    unsigned long long run = 0;
    if (fscanf(f, "%llu", &run) != 1) run = 0;
    fclose(f);
    int s = pt_slot(tid);
    if (s < 0) return;
    uint64_t d = run > g_pt[s].last_ns ? run - g_pt[s].last_ns : 0;
    if (!g_pt[s].last_ns) d = 0;
    g_pt[s].last_ns = run;
    if (d < 100000) return;                       /* < 0.1 ms of CPU: not running */
    uint64_t us = d / 1000;
    g_pt[s].total_us += us;
    uint64_t key = ((uint64_t)(s + 1) << 40) | (pc & 0xffffffffffULL);
    uint32_t h = (uint32_t)((key >> 2) * 2654435761u) & ((1u << PT_HBITS) - 1);
    for (int i = 0; i < 64; ++i, h = (h + 1) & ((1u << PT_HBITS) - 1)) {
        if (g_pth[h].key == key) { g_pth[h].us += us; return; }
        if (g_pth[h].key == 0) { g_pth[h].key = key; g_pth[h].us = us; return; }
    }
}

static void pt_dump(void) {
    fprintf(stderr, "[profT] ---- cumulative CPU by thread ----\n");
    for (int i = 0; i < PT_SLOTS; ++i)
        if (g_pt[i].total_us > 200000)
            fprintf(stderr, "[profT] THREAD %-18s %8llu ms\n", g_pt[i].comm,
                    (unsigned long long)(g_pt[i].total_us / 1000));
    static uint8_t used[1u << PT_HBITS];
    memset(used, 0, sizeof used);
    for (int n = 0; n < 400; ++n) {
        uint32_t best = 0; uint64_t bu = 0;
        for (uint32_t i = 0; i < (1u << PT_HBITS); ++i)
            if (!used[i] && g_pth[i].us > bu) { bu = g_pth[i].us; best = i; }
        if (!bu) break;
        used[best] = 1;
        int s = (int)(g_pth[best].key >> 40) - 1;
        uint64_t pc = g_pth[best].key & 0xffffffffffULL;
        fprintf(stderr, "[profT] %-18s %8llu pc=0x%llx %s\n", g_pt[s].comm,
                (unsigned long long)(g_pth[best].us / 1000), (unsigned long long)pc, mod_of(pc));
    }
    fflush(stderr);
}

static void* prof_cpu_thread(void* arg) {
    (void)arg;
    int n = 0;
    while (1) {
        usleep(5000);
        pt_sample((int)getpid(), __atomic_load_n(&g_c.pc, __ATOMIC_RELAXED));
        for (GuestThread* t = g_threads; t; t = t->next)
            pt_sample((int)t->tid, __atomic_load_n(&t->ctx.pc, __ATOMIC_RELAXED));
        if (++n % 1000 == 0) pt_dump();            /* every ~5 s+ */
    }
    return NULL;
}

/* Name a HOST address (0x55../0x7f..) so a "no block at" halt says which
   host object the guest jumped into instead of leaving a bare number. */
static void host_sym(const char* tag, uint64_t a) {
    Dl_info di;
    if (dladdr((void*)(uintptr_t)a, &di))
        fprintf(stderr, "[recomp]   %s 0x%llx = %s+0x%llx (%s)\n", tag,
                (unsigned long long)a,
                di.dli_sname ? di.dli_sname : "?",
                (unsigned long long)(a - (uint64_t)(uintptr_t)di.dli_saddr),
                di.dli_fname ? di.dli_fname : "?");
    else
        fprintf(stderr, "[recomp]   %s 0x%llx = <no host object>\n", tag,
                (unsigned long long)a);
}

/* Watchdog: fire when a guest thread has executed this many blocks.  A raw
   count (not a stall detector) — a busy GUI thread legitimately runs billions
   of blocks, so long interactive runs raise it via A64PORT_WATCHDOG_BLOCKS. */
/* 0 = off (the default: a busy thread legitimately runs
   billions of blocks, and on expiry the watchdog now ends the process). */
static uint64_t g_watchdog_blocks = 0;
/* Any diagnostic armed?  Read once in main(); gates the per-block checks. */
static int g_diag;


/* R5 step -1 (--chain): with chaining, a block tail-calls the next one instead
   of returning to this dispatcher, so the dispatcher must supply a chain
   budget.  -1 = not read yet; 0 (the default) leaves c->chain_budget as it is,
   which makes the emitted ChainTo behave exactly like the old RCJ.  Set
   A64PORT_CHAIN_BUDGET=256 to turn chaining on for a --chain emit. */
static int g_chain_budget = -1;

static __thread GuestContext* t_uaf_ctx;            /* set by guest_run; read by the crash reporter */
static __thread const GuestContext* t_aw_ctx;
/* ── host-PC sampler (A64PORT_HPROF=1) ─────────────────────────────────────
   The guest-pc profilers above say WHICH guest code is hot; they cannot say
   what the host pays for it (dispatcher, load/store helpers, flag code, the
   block bodies, the shim).  There is often no perf on the target, so
   each guest thread arms its own CPU-time timer (CLOCK_THREAD_CPUTIME_ID,
   SIGEV_THREAD_ID): SIGPROF then fires only while that thread is on a CPU,
   and the handler records {host pc, guest pc, tid} into one global buffer.
   A64PORT_HPROF_US = period (default 1000), A64PORT_HPROF_OUT = file (default
   /tmp/a64port-hprof.bin), rewritten every 10 s with /proc/self/maps and the
   thread names appended; scripts/hprof.py symbolizes it. */
typedef struct { uint64_t hpc, gpc; uint32_t tid, pad; } HpRec;
#define HP_MAX (1u << 22)
static HpRec* g_hp;
static uint32_t g_hp_n;
static int g_hp_on = -1;
static long g_hp_us = 1000;
static __thread GuestContext* t_hp_ctx;
static __thread uint32_t t_hp_tid;

static void hp_handler(int sig, siginfo_t* si, void* uc_) {
    (void)sig; (void)si;
    const int saved = errno;
    const ucontext_t* uc = (const ucontext_t*)uc_;
    uint64_t pc = 0;
#if defined(__x86_64__)
    pc = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__arm__)
    pc = (uint64_t)uc->uc_mcontext.arm_pc;
#elif defined(__aarch64__)
    pc = (uint64_t)uc->uc_mcontext.pc;
#endif
    const uint32_t i = __atomic_fetch_add(&g_hp_n, 1u, __ATOMIC_RELAXED);
    if (i < HP_MAX) {
        g_hp[i].hpc = pc;
        g_hp[i].gpc = t_hp_ctx ? t_hp_ctx->pc : 0;
        g_hp[i].tid = t_hp_tid;
    }
    errno = saved;
}

static void hp_dump(void) {
    const char* out = getenv("A64PORT_HPROF_OUT");
    if (!out || !*out) out = "/tmp/a64port-hprof.bin";
    /* "%p" in the name = this process's pid, so helper daemons inheriting the env keep their own file */
    char named[480];
    const char* pp = strstr(out, "%p");
    if (pp) { snprintf(named, sizeof named, "%.*s%d%s", (int)(pp - out), out, (int)getpid(), pp + 2); out = named; }
    char tmp[512]; snprintf(tmp, sizeof tmp, "%s.tmp", out);
    FILE* f = fopen(tmp, "wb");
    if (!f) return;
    uint32_t n = __atomic_load_n(&g_hp_n, __ATOMIC_RELAXED);
    if (n > HP_MAX) n = HP_MAX;
    const uint64_t hdr[3] = { 0x31464f5250484252ull /* "RBHPROF1" */, n, (uint64_t)g_hp_us };
    fwrite(hdr, sizeof hdr, 1, f);
    fwrite(g_hp, sizeof(HpRec), n, f);
    /* maps, then "tid name" lines, as text after the records */
    FILE* m = fopen("/proc/self/maps", "r");
    if (m) { char b[4096]; size_t k; fputs("\n#maps\n", f);
             while ((k = fread(b, 1, sizeof b, m)) > 0) fwrite(b, 1, k, f); fclose(m); }
    fputs("#mods\n", f);
    for (unsigned k = 0; k < R_NMODULES; ++k)
        fprintf(f, "%s 0x%llx\n", R_MODULES[k].name, (unsigned long long)g_mod_base[k]);
    fputs("#threads\n", f);
    DIR* d = opendir("/proc/self/task");
    if (d) {
        struct dirent* e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            char p[96], nm[32] = "";
            snprintf(p, sizeof p, "/proc/self/task/%s/comm", e->d_name);
            FILE* cf = fopen(p, "r");
            if (cf) { if (fgets(nm, sizeof nm, cf)) nm[strcspn(nm, "\n")] = 0; fclose(cf); }
            fprintf(f, "%s %s\n", e->d_name, nm);
        }
        closedir(d);
    }
    fclose(f);
    rename(tmp, out);
}

static void* hp_dump_thread(void* arg) {
    (void)arg;
    for (;;) { sleep(10); hp_dump(); }
    return NULL;
}

static void hp_arm_thread(GuestContext* c) {
    if (g_hp_on < 0) {
        /* first caller is the main thread, before any guest thread exists */
        g_hp_on = EnvOn("A64PORT_HPROF") ? 1 : 0;
        if (g_hp_on) {
            const char* e = getenv("A64PORT_HPROF_US");
            if (e && *e) g_hp_us = strtol(e, 0, 0);
            if (g_hp_us < 100) g_hp_us = 100;
            g_hp = (HpRec*)calloc(HP_MAX, sizeof(HpRec));
            struct sigaction sa;
            memset(&sa, 0, sizeof sa);
            sa.sa_sigaction = hp_handler;
            sa.sa_flags = SA_SIGINFO | SA_RESTART;
            sigemptyset(&sa.sa_mask);
            if (!g_hp || sigaction(SIGPROF, &sa, NULL) != 0) g_hp_on = 0;
            else {
                pthread_t pt;
                if (pthread_create(&pt, NULL, hp_dump_thread, NULL) == 0) pthread_detach(pt);
                fprintf(stderr, "[hprof] host-pc sampler ON, every %ld us of thread CPU\n", g_hp_us);
            }
        }
    }
    if (!g_hp_on) return;
    t_hp_ctx = c;
    t_hp_tid = (uint32_t)syscall(SYS_gettid);
    struct sigevent sev;
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_signo = SIGPROF;
    sev._sigev_un._tid = (int)t_hp_tid;
    timer_t tm;
    if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &tm) != 0) return;
    struct itimerspec its;
    its.it_interval.tv_sec = g_hp_us / 1000000;
    its.it_interval.tv_nsec = (g_hp_us % 1000000) * 1000;
    its.it_value = its.it_interval;
    timer_settime(tm, 0, &its, NULL);
}

static void guest_run(GuestContext* c) {
    t_uaf_ctx = c;
    t_aw_ctx = c;
    hp_arm_thread(c);
    if (g_chain_budget < 0) {
        const char* e = getenv("A64PORT_CHAIN_BUDGET");
        g_chain_budget = (e && *e) ? (int)strtol(e, 0, 0) : 256;   /* inert for an emit without --chain */
    }
#if defined(RECOMP_FPX_HOST)
    /* The FPX1 fast paths require this thread's host FP mode; another library
       on this thread may have changed it. */
    recomp_fpx_ensure_env();
#endif
    while (!c->halted) {
        /* One-time GOT rewrite: the guest reaches the executable's entry only
           after ld.so has linked everything.  Runs even without A64PORT_HOSTLIBS
           because the rawmemchr fix is always wanted. */
        if (!g_nat_patched && c->pc == (uint64_t)A64PORT_ENTRY) {
            g_nat_patched = 1;
            nat_patch_got(-1);
        }
        /* Every diagnostic below is off in a normal run, and this loop runs
           once per guest block (blocks of compiled C++ average ~3.5 instructions), so
           they are all behind one predictable branch.  g_diag
           is computed once in main(), after every switch has been read. */
        static __thread uint64_t t_prev_pc;
        static __thread uint64_t t_stall;   /* consecutive blocks at one pc */
        t_trace[t_tpos++ & (TRACE_N - 1)] = c->pc;
        BlockFn f = dispatch(c->pc);
        if (!f) {
            recomp_gap_note(1u, c->pc, 0);
            fprintf(stderr, "[recomp] no block at 0x%llx (module %s); previous block 0x%llx (%s)\n",
                    (unsigned long long)c->pc, mod_of(c->pc),
                    (unsigned long long)t_prev_pc, mod_of(t_prev_pc));
            /* A jump to 0 is a virtual call through a NULL slot (or a NULL
               vtable).  The registers alone do not say which, so dump the
               object the call was made on: its vptr, then the vtable words
               around the slot, then a little of the object itself. */
            if (c->x[0] >= ARENA_BASE && c->x[0] + 64 <= ARENA_TOP) {
                const uint64_t* o = (const uint64_t*)P(c->x[0]);
                const uint64_t vt = o[0];
                fprintf(stderr, "[a64port] suspect object at 0x%llx: vptr=0x%llx\n",
                        (unsigned long long)c->x[0], (unsigned long long)vt);
                for (int q = 0; q < 4; ++q)
                    fprintf(stderr, "[a64port]   obj[%d]=0x%llx\n", q, (unsigned long long)o[q]);
                if (vt >= ARENA_BASE && vt + 0x40 <= ARENA_TOP) {
                    const uint64_t* v = (const uint64_t*)P(vt);
                    for (int q = 0; q < 8; ++q)
                        fprintf(stderr, "[a64port]   vptr[%d]=0x%llx\n", q, (unsigned long long)v[q]);
                }
            }
            fprintf(stderr, "[a64port] module bases:\n");
            for (unsigned m = 0; m < R_NMODULES; ++m)
                fprintf(stderr, "  %-11s %s0x%llx\n", R_MODULES[m].name,
                        g_mod_base[m] ? "" : "(unmapped) ",
                        (unsigned long long)g_mod_base[m]);
            for (unsigned k = 16; k-- > 0;) {
                const uint64_t pc = t_trace[(t_tpos - 2 - k) & (TRACE_N - 1)];
                fprintf(stderr, "         0x%-10llx %s\n", (unsigned long long)pc, mod_of(pc));
            }
            fprintf(stderr, "[recomp]   own x29 chain:\n");
            {
                uint64_t fp = c->x[29];
                for (int k = 0; k < 24 && fp >= ARENA_BASE && fp + 16 <= ARENA_TOP; ++k) {
                    const uint64_t* fr = (const uint64_t*)P(fp);
                    fprintf(stderr, "[recomp]   bt#%-2d ret=0x%-10llx %s\n",
                            k, (unsigned long long)fr[1], mod_of(fr[1]));
                    if (fr[0] <= fp) break;
                    fp = fr[0];
                }
            }
            fprintf(stderr, "[recomp]   x19=0x%llx x20=0x%llx x21=0x%llx x22=0x%llx x23=0x%llx x24=0x%llx\n",
                    (unsigned long long)c->x[19], (unsigned long long)c->x[20],
                    (unsigned long long)c->x[21], (unsigned long long)c->x[22],
                    (unsigned long long)c->x[23], (unsigned long long)c->x[24]);
            fprintf(stderr, "[recomp]   x25=0x%llx x26=0x%llx x27=0x%llx x28=0x%llx\n",
                    (unsigned long long)c->x[25], (unsigned long long)c->x[26],
                    (unsigned long long)c->x[27], (unsigned long long)c->x[28]);
            for (int r = 25; r <= 28; ++r) {
                const uint64_t a = c->x[r];
                if (a < ARENA_BASE || a + 32 > ARENA_TOP) continue;
                const uint64_t* o = (const uint64_t*)P(a);
                fprintf(stderr, "[recomp]   [x%d] = 0x%llx 0x%llx 0x%llx 0x%llx\n",
                        r, (unsigned long long)o[0], (unsigned long long)o[1],
                        (unsigned long long)o[2], (unsigned long long)o[3]);
            }
            fprintf(stderr, "[a64port] x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx "
                            "x8=0x%llx x30=0x%llx sp=0x%llx\n",
                    (unsigned long long)c->x[0], (unsigned long long)c->x[1],
                    (unsigned long long)c->x[2], (unsigned long long)c->x[3],
                    (unsigned long long)c->x[8], (unsigned long long)c->x[30],
                    (unsigned long long)c->x[31]);
            /* If the guest jumped into a host object, name it. */
            if (c->pc < ARENA_BASE || c->pc >= ARENA_TOP) {
                host_sym("pc", c->pc);
                for (int r = 0; r <= 3; ++r)
                    if (c->x[r] && (c->x[r] < ARENA_BASE || c->x[r] >= ARENA_TOP)) {
                        char t[8]; snprintf(t, sizeof t, "x%d", r);
                        host_sym(t, c->x[r]);
                    }
                if (c->x[30] && (c->x[30] < ARENA_BASE || c->x[30] >= ARENA_TOP))
                    host_sym("x30", c->x[30]);
            }
            break;
        }
        t_prev_pc = c->pc;
        if (g_chain_budget > 0) c->chain_budget = g_chain_budget;
        f(c);
        /* Count per thread.  A global atomic per block had every core fighting
           over one cache line; fold it in every 4096 blocks instead. */
        if ((++t_blocks & 0xFFFu) == 0)
            __atomic_add_fetch(&g_blocks, 0x1000u, __ATOMIC_RELAXED);
        /* Consecutive blocks that re-entered at the same pc: a genuine
           livelock (e.g. an LDAXR/STXR retry that never commits) shows a
           huge count here, while a merely busy thread (a GUI message
           pump / vsync poll easily burns >4e9 blocks in a few minutes)
           almost never re-enters the same block twice in a row. */
        if (c->pc == t_prev_pc) ++t_stall; else t_stall = 0;
        /* One-shot spin report: the same block re-entered 100M times in a
           row is a guest infinite loop at one pc (e.g. a run-off scan over
           an unterminated string, as rawmemchr can).  Printed once
           per episode so it is cheap. */
        if (t_stall == 100000000ULL)
            fprintf(stderr, "[spin] pc=0x%llx x0=0x%llx x1=0x%llx x20=0x%llx x21=0x%llx x30=0x%llx\n",
                    (unsigned long long)c->pc, (unsigned long long)c->x[0],
                    (unsigned long long)c->x[1], (unsigned long long)c->x[20],
                    (unsigned long long)c->x[21], (unsigned long long)c->x[30]);
        if (__builtin_expect(g_watchdog_blocks != 0, 0) && t_blocks > g_watchdog_blocks) {
            fprintf(stderr, "[a64port] watchdog pc=0x%llx same-pc=%llu x0=0x%llx x20=0x%llx x26=0x%llx x28=0x%llx sp=0x%llx x30=0x%llx\n",
                    (unsigned long long)c->pc, (unsigned long long)t_stall,
                    (unsigned long long)c->x[0],
                    (unsigned long long)c->x[20], (unsigned long long)c->x[26],
                    (unsigned long long)c->x[28], (unsigned long long)c->x[31],
                    (unsigned long long)c->x[30]);
            {
                uint64_t a = c->x[26];
                if (a >= ARENA_BASE && a + 32 <= ARENA_TOP) {
                    const uint64_t* o = (const uint64_t*)P(a);
                    fprintf(stderr, "[a64port]   [x26] = 0x%llx 0x%llx 0x%llx 0x%llx\n",
                            (unsigned long long)o[0], (unsigned long long)o[1],
                            (unsigned long long)o[2], (unsigned long long)o[3]);
                } else {
                    fprintf(stderr, "[a64port]   x26=0x%llx is OUTSIDE the arena (host pointer!)\n",
                            (unsigned long long)a);
                    host_sym("x26", a);
                }
                uint64_t b = c->x[20];
                if (b >= ARENA_BASE && b + 0x38 <= ARENA_TOP)
                    fprintf(stderr, "[a64port]   [[x20+0x30]] = 0x%llx\n",
                            (unsigned long long)*(const uint64_t*)P(b + 0x30));
            }
            /* End the PROCESS, loudly.  Stopping only this thread (the old
               `break`) left the app running with one thread silently gone,
               possibly holding locks. */
            fprintf(stderr, "[a64port] watchdog: ending the process (A64PORT_WATCHDOG_BLOCKS=%llu)\n",
                    (unsigned long long)g_watchdog_blocks);
            fflush(NULL);
            _exit(124);
        }
    }
    __atomic_add_fetch(&g_blocks, t_blocks & 0xFFFu, __ATOMIC_RELAXED);
}

/* ── CPU placement for kernels that isolate cores (A64PORT_CPU_PIN) ─────────
   Some boards boot with isolcpus=1,2,3: the scheduler then never places an ordinary thread
   on CPUs 1-3, and every thread of a large program shares CPU 0 while three cores idle.
   This does it by thread NAME: a host thread checks /proc/self/task/<tid>/comm
   for every new thread once a second and applies the first matching rule;
   unmatched threads keep the original mask.  Every new guest thread starts on
   the original mask (guest_thread_entry), so nothing inherits the GUI thread's
   core before it is named.
     A64PORT_CPU_PIN="main=1;render=1;worker,io=2;compute=3"   (an example plan; thread names are prefixes)
   names are prefixes of the 15-char comm; "main" is the process's first thread
   (usually the GUI thread).  Default: no plan; set A64PORT_CPU_PIN to use one.
   A64PORT_CPU_PIN=0 turns it off.
   "name=cpus@nice" also sets the thread's nice value, and keeps it when the guest
   later asks for another priority (a64port_pin_nice, consulted by the shim's
   sched_setscheduler). */
#define PIN_RULES 16
static struct { char name[32], cpus[16]; cpu_set_t set; int has_nice, nice; } g_pin_rule[PIN_RULES];
static int g_pin_n, g_pin_main_on, g_pin_on;
static cpu_set_t g_pin_main, g_pin_orig;
static char g_pin_main_cpus[16];
static int pin_cpus(const char* s, cpu_set_t* set) {
    CPU_ZERO(set);
    int any = 0;
    while (*s) {
        char* e; long a = strtol(s, &e, 10), b = a;
        if (e == s) break;
        if (*e == '-') { s = e + 1; b = strtol(s, &e, 10); }
        for (long k = a; k <= b && k >= 0 && k < CPU_SETSIZE; ++k) { CPU_SET((int)k, set); any = 1; }
        s = *e == '+' ? e + 1 : e;
        if (*s && *s != '+') break;
    }
    return any;
}
static void pin_parse(const char* spec) {
    char buf[512];
    snprintf(buf, sizeof buf, "%s", spec);
    for (char* rule = strtok(buf, ";"); rule; rule = strtok(NULL, ";")) {
        char* eq = strchr(rule, '=');
        if (!eq) continue;
        *eq = 0;
        cpu_set_t set;
        if (!pin_cpus(eq + 1, &set)) continue;
        char* at = strchr(eq + 1, '@');
        const int has_nice = at != NULL, nice = at ? atoi(at + 1) : 0;
        if (at) *at = 0;
        for (char* nm = rule; nm && *nm; ) {
            char* comma = strchr(nm, ',');
            if (comma) *comma = 0;
            if (!strcmp(nm, "main")) {
                g_pin_main = set; g_pin_main_on = 1;
                snprintf(g_pin_main_cpus, sizeof g_pin_main_cpus, "%s", eq + 1);
            } else if (g_pin_n < PIN_RULES) {
                snprintf(g_pin_rule[g_pin_n].name, sizeof g_pin_rule[0].name, "%s", nm);
                snprintf(g_pin_rule[g_pin_n].cpus, sizeof g_pin_rule[0].cpus, "%s", eq + 1);
                g_pin_rule[g_pin_n].has_nice = has_nice;
                g_pin_rule[g_pin_n].nice = nice;
                g_pin_rule[g_pin_n++].set = set;
            }
            nm = comma ? comma + 1 : NULL;
        }
    }
}
/* The rule for a thread name, or -1. */
static int pin_rule_of(const char* comm) {
    for (int i = 0; i < g_pin_n; ++i)
        if (!strncmp(comm, g_pin_rule[i].name, strlen(g_pin_rule[i].name))) return i;
    return -1;
}
/* For the shim: 1 and *nice when a rule fixes this thread's nice value. */
int a64port_pin_nice(int tid, int* nice) {
    if (!g_pin_on) return 0;
    char path[64], comm[32] = "";
    snprintf(path, sizeof path, "/proc/self/task/%d/comm", tid);
    FILE* f = fopen(path, "r");
    if (!f) return 0;
    if (fgets(comm, sizeof comm, f)) comm[strcspn(comm, "\n")] = 0;
    fclose(f);
    const int i = pin_rule_of(comm);
    if (i < 0 || !g_pin_rule[i].has_nice) return 0;
    *nice = g_pin_rule[i].nice;
    return 1;
}
static void* pin_thread(void* arg) {
    (void)arg;
    static int seen[1 << 15];                       /* tid -> generation done (tids < 2^22; hashed) */
    const pid_t pid = getpid();
    for (int pass = 1;; ++pass) {
        DIR* d = opendir("/proc/self/task");
        if (d) {
            struct dirent* e;
            while ((e = readdir(d))) {
                const int tid = atoi(e->d_name);
                if (tid <= 0 || seen[tid & 0x7fff] == tid) continue;
                char path[64], comm[32] = "";
                snprintf(path, sizeof path, "/proc/self/task/%d/comm", tid);
                FILE* f = fopen(path, "r");
                if (!f) continue;
                if (fgets(comm, sizeof comm, f)) comm[strcspn(comm, "\n")] = 0;
                fclose(f);
                const cpu_set_t* set = NULL;
                const char* cpus = "";
                int ri = -1;
                if (tid == pid) { if (g_pin_main_on) { set = &g_pin_main; cpus = g_pin_main_cpus; } }
                else if ((ri = pin_rule_of(comm)) >= 0) { set = &g_pin_rule[ri].set; cpus = g_pin_rule[ri].cpus; }
                if (set) {
                    const int r = sched_setaffinity(tid, sizeof *set, set);
                    char nice[24] = "";
                    if (ri >= 0 && g_pin_rule[ri].has_nice)
                        snprintf(nice, sizeof nice, ", nice %d%s", g_pin_rule[ri].nice,
                                 setpriority(PRIO_PROCESS, (id_t)tid, g_pin_rule[ri].nice) ? " (failed)" : "");
                    fprintf(stderr, "[a64port] cpu pin: %-15s tid %d -> cpus %s%s%s\n", comm, tid, cpus,
                            r ? " (failed)" : "", nice);
                }
                /* A thread is named right after it starts; give it a few passes. */
                if (*comm && strncmp(comm, program_invocation_short_name, 15)) seen[tid & 0x7fff] = tid;
                else if (tid == pid) seen[tid & 0x7fff] = tid;
            }
            closedir(d);
        }
        sleep(1);
    }
    return NULL;
}
static void pin_start(void) {
    const char* spec = getenv("A64PORT_CPU_PIN");
    if (spec && !strcmp(spec, "0")) return;
    if (!spec || !*spec) {
        char iso[64] = "";
        FILE* f = fopen("/sys/devices/system/cpu/isolated", "r");
        if (f) { if (!fgets(iso, sizeof iso, f)) iso[0] = 0; fclose(f); }
        iso[strcspn(iso, "\n")] = 0;
        cpu_set_t set;
        if (!*iso || !pin_cpus(iso, &set) || CPU_COUNT(&set) < 3) return;
        return;                 /* no default plan without an application layer */
    }
    if (sched_getaffinity(0, sizeof g_pin_orig, &g_pin_orig) != 0) return;
    pin_parse(spec);
    if (!g_pin_n && !g_pin_main_on) return;
    g_pin_on = 1;
    pthread_t pt;
    if (pthread_create(&pt, NULL, pin_thread, NULL) == 0) pthread_detach(pt);
}

/* ── Real-time safety: page cache prefault + priority-inheriting atomics locks ──────────────────────────
   A real-time thread (SCHED_FIFO) stalled 45-60 ms in code that must not block.  It had 14 major
   page faults in 25 min: the host image (hundreds of MB) and the guest's file mappings are
   paged in from flash on first use, so rarely run code costs a flash read on whichever thread gets there
   first.  A64PORT_PREFAULT (default on; 0 = off): an idle-priority thread asks the kernel to read every
   private file mapping into the page cache (MADV_WILLNEED, 2 MB at a time) 5 s and 60 s after start, so a
   later first touch is a minor fault.  The pages stay evictable; nothing is locked. */
static void prefault_pass(void) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char line[600]; unsigned long long bytes = 0; int maps = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long lo, hi; char perm[8] = "", path[512] = "";
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %511[^\n]", &lo, &hi, perm, path) < 3) continue;
        if (perm[0] != 'r' || perm[3] != 'p' || path[0] != '/') continue;      /* readable, private, a file */
        if (!strncmp(path, "/dev/", 5) || !strncmp(path, "/proc/", 6) || !strncmp(path, "/sys/", 5) || strstr(path, "(deleted)")) continue;
        for (unsigned long a = lo; a < hi; a += 2u << 20) {
            const unsigned long n = hi - a < (2u << 20) ? hi - a : (2u << 20);
            madvise((void*)a, n, MADV_WILLNEED);
            struct timespec ts = { 0, 2000000 }; nanosleep(&ts, NULL);
        }
        bytes += hi - lo; ++maps;
    }
    fclose(f);
    fprintf(stderr, "[a64port] prefault: %d file mappings, %.0f MB asked into the page cache\n", maps, bytes / 1048576.0);
}
static void* prefault_thread(void* arg) {
    (void)arg;
    struct sched_param sp = { 0 };
    pthread_setschedparam(pthread_self(), SCHED_IDLE, &sp);
    syscall(SYS_ioprio_set, 1 /* IOPRIO_WHO_PROCESS */, 0, (3 << 13) /* IOPRIO_CLASS_IDLE */);
    sleep(5); prefault_pass();
    sleep(55); prefault_pass();                        /* libraries the guest mapped later */
    return NULL;
}
static void prefault_start(void) {
    const char* e = getenv("A64PORT_PREFAULT");
    if (e && !strcmp(e, "0")) return;
    pthread_t pt;
    if (pthread_create(&pt, NULL, prefault_thread, NULL) == 0) pthread_detach(pt);
}

/* The exclusive-monitor locks (g_excl_stripe, g_excl_bind) are taken by every guest thread's LDXR/STXR.
   Most of the ~265 threads run at normal priority on an overloaded CPU 0 (isolcpus): one preempted while
   holding a stripe used to make a SCHED_FIFO thread wait for CPU 0.  PTHREAD_PRIO_INHERIT boosts
   the holder instead; the uncontended path stays a user-space CAS.  A64PORT_EXCL_PI=0 keeps plain mutexes. */
static void excl_pi_init(void) {
    const char* e = getenv("A64PORT_EXCL_PI");
    if (e && !strcmp(e, "0")) return;
    pthread_mutexattr_t at;
    if (pthread_mutexattr_init(&at) || pthread_mutexattr_setprotocol(&at, PTHREAD_PRIO_INHERIT)) return;
    for (int i = 0; i < EXCL_STRIPES; ++i) pthread_mutex_init(&g_excl_stripe[i], &at);
    pthread_mutex_init(&g_excl_bind, &at);
    pthread_mutexattr_destroy(&at);
}

static void* guest_thread_entry(void* arg) {
    GuestThread* t = (GuestThread*)arg;
    /* The host libc starts every thread with signals 32/33 (its own SIGCANCEL/SIGSETXID)
       unblocked, but a guest clone inherits the creator's mask - and the guest's libc
       relies on that for its timer helper thread, which must have SIGTIMER (32) blocked. */
    {
        uint64_t cur = 0;
        syscall(SYS_rt_sigprocmask, SIG_BLOCK, NULL, &cur, 8);
        const uint64_t rt = UINT64_C(3) << 31;
        cur = (cur & ~rt) | t->sigmask_rt;
        syscall(SYS_rt_sigprocmask, SIG_SETMASK, &cur, NULL, 8);
    }
    /* Never inherit the creator's pinned core (A64PORT_CPU_PIN); the pin thread
       places this one by name once it has one. */
    if (g_pin_on) sched_setaffinity(0, sizeof g_pin_orig, &g_pin_orig);
    /* What the kernel does for clone(): the child's tid is published in the
       parent's memory (PARENT_SETTID) and/or the child's (CHILD_SETTID) before
       either side runs guest code.  glibc's pd->tid is the PARENT_SETTID word. */
    const uint32_t tid = (uint32_t)syscall(SYS_gettid);
    t->tid = tid;
    if (t->flags & K_CLONE_PARENT_SETTID) {
        uint32_t* p = (uint32_t*)PG(t->ptid);
        if (p) __atomic_store_n(p, tid, __ATOMIC_SEQ_CST);
    }
    if (t->flags & K_CLONE_CHILD_SETTID) {
        uint32_t* p = (uint32_t*)PG(t->ctid);
        if (p) __atomic_store_n(p, tid, __ATOMIC_SEQ_CST);
    }
    pthread_mutex_lock(&t->ready_mu);
    t->ready = 1;
    pthread_cond_signal(&t->ready_cv);
    pthread_mutex_unlock(&t->ready_mu);

    guest_run(&t->ctx);

    /* The guest thread has executed its exit svc, so it no longer touches its
       stack: do what the kernel does for CLONE_CHILD_CLEARTID - zero the word
       and wake it.  pthread_join waits on it, and glibc's stack cache only
       reuses a stack whose pd->tid is 0 (without this, every one of the
       thousands of thread creations mapped a fresh stack). */
    if ((t->flags & K_CLONE_CHILD_CLEARTID) && t->ctid) {
        uint32_t* p = (uint32_t*)PG(t->ctid);
        if (p) {
            __atomic_store_n(p, 0u, __ATOMIC_SEQ_CST);
            recomp_excl_store_touch(t->ctid, 4);
            a64port_futex_wake(t->ctid, 0x7fffffff);
        }
    }
    return NULL;
}

/* Diagnostic: print every guest thread's PC so a startup stall can be blamed
   on a specific translated function. Enabled with A64PORT_PC_DUMP=1. */
extern uint64_t g_mb_libasound;
static void dump_pcs(void) {
    { struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
      fprintf(stderr, "[pc] t=%.3f\n", _ts.tv_sec + 1e-9 * _ts.tv_nsec); }
    if (g_mb_libasound) {
        const volatile int32_t* o = (const volatile int32_t*)P(g_mb_libasound + 0xfd788);
        const volatile int32_t* m = (const volatile int32_t*)P(g_mb_libasound + 0xfd790);
        fprintf(stderr, "[alsa] once=%d | cfg-mutex lock=%d count=%u owner=%d nusers=%u kind=%d\n",
                o[0], m[0], (unsigned)m[1], m[2], (unsigned)m[3], m[4]);
    }
    const uint64_t m = __atomic_load_n(&g_c.pc, __ATOMIC_RELAXED);
    fprintf(stderr, "[pc] main  pc=0x%-10llx %s   blocks=%llu\n",
            (unsigned long long)m, mod_of(m),
            (unsigned long long)__atomic_load_n(&g_blocks, __ATOMIC_RELAXED));
    uint64_t fp = g_c.x[29];
    for (int i = 0; i < 20 && fp >= ARENA_BASE && fp + 16 <= ARENA_TOP; ++i) {
        const uint64_t* f = (const uint64_t*)P(fp);
        const uint64_t ret = f[1];
        fprintf(stderr, "[pc]   bt#%-2d ret=0x%-10llx %s\n",
                i, (unsigned long long)ret, mod_of(ret));
        const uint64_t nfp = f[0];
        if (nfp <= fp) break;
        fp = nfp;
    }
    for (GuestThread* t = g_threads; t; t = t->next) {
        const uint64_t p = __atomic_load_n(&t->ctx.pc, __ATOMIC_RELAXED);
        if (p < ARENA_BASE || p >= ARENA_TOP) continue;   /* stale */
        if (!strcmp(mod_of(p), "?")) continue;            /* not a code PC */
        fprintf(stderr, "[pc] tid=%-3u pc=0x%-10llx %s\n",
                t->tid, (unsigned long long)p, mod_of(p));
        uint64_t tfp = t->ctx.x[29];
        for (int i = 0; i < 8 && tfp >= ARENA_BASE && tfp + 16 <= ARENA_TOP; ++i) {
            const uint64_t* f = (const uint64_t*)P(tfp);
            fprintf(stderr, "[pc]   tid=%-3u bt#%-2d ret=0x%-10llx %s\n",
                    t->tid, i, (unsigned long long)f[1], mod_of(f[1]));
            if (f[0] <= tfp) break;
            tfp = f[0];
        }
    }
}

static void* pc_monitor(void* arg) {
    (void)arg;
    while (1) { usleep(300000); dump_pcs(); }   /* DIAG: 300 ms */
    return NULL;
}

/* exit_group(2) from any guest thread ends the whole process, as on Linux.
   glibc's exit() has already run the guest's atexit handlers and C++ static
   destructors on the calling thread; letting the other threads run on after
   that is what the old "halt only the caller" did.  Strong
   definition of the shim's weak hook; never returns. */
int a64port_guest_exit_group(GuestContext* c, int status) {
    static int once;
    if (__atomic_exchange_n(&once, 1, __ATOMIC_SEQ_CST)) {
        for (;;) pause();                  /* another thread is already exiting */
    }
    fprintf(stderr, "[a64port] exit_group(%d) on %s tid %d (guest pc=0x%llx x30=0x%llx %s):"
                    " ending the process\n",
            status, c == &g_c ? "the main" : "a WORKER", (int)syscall(SYS_gettid),
            (unsigned long long)c->pc, (unsigned long long)c->x[30], mod_of(c->x[30]));
    if (c != &g_c) {
        uint64_t fp = c->x[29];
        for (int k = 0; k < 16 && fp >= ARENA_BASE && fp + 16 <= ARENA_TOP; ++k) {
            const uint64_t* fr = (const uint64_t*)P(fp);
            fprintf(stderr, "[a64port]   bt#%-2d ret=0x%-10llx %s\n",
                    k, (unsigned long long)fr[1], mod_of(fr[1]));
            if (fr[0] <= fp) break;
            fp = fr[0];
        }
    }
    recomp_gap_dump();
    fflush(NULL);
    _exit(status);
}

/* Called by the shim's clone syscall. Strong definition overriding the weak
   one in linux_syscalls.c. */
int64_t a64port_guest_clone(GuestContext* parent, GuestContext* child, uint64_t flags,
                           uint64_t ptid, uint64_t tls, uint64_t ctid) {
    const uint64_t kCloneThread = 0x10000, kCloneSetTls = 0x80000;
    if (flags & kCloneThread) {
        GuestThread* t = (GuestThread*)calloc(1, sizeof *t);
        if (!t) return -EAGAIN;
        t->ctx = *child;
#ifdef RECOMP_HAS_CALL_DEPTH
        t->ctx.call_depth = 0;          /* a new thread has no host call frames */
#endif
        t->ctx.mem = g_mem;
        t->ctx.mem_size = ARENA_SIZE;
        t->ctx.mem_base_vaddr = ARENA_BASE;
        t->flags = flags;
        t->ptid = ptid;
        t->ctid = ctid;
        {   /* the creator's blocked state of signals 32/33, which the host libc hides */
            uint64_t cur = 0;
            syscall(SYS_rt_sigprocmask, SIG_BLOCK, NULL, &cur, 8);
            t->sigmask_rt = cur & (UINT64_C(3) << 31);
        }
        pthread_mutex_init(&t->ready_mu, NULL);
        pthread_cond_init(&t->ready_cv, NULL);
        if (flags & kCloneSetTls) t->ctx.tpidr_el0 = tls;
#if A64PORT_ILP32_HOST
        /* The host default (8 MB, from RLIMIT_STACK) times ~250 guest threads
           is ~2 GB - most of a 32-bit address space; 512 KB each is ~130 MB.
           Blocks return to the
           dispatcher instead of nesting, so host frames stay shallow; the guest
           stack is in the arena and is not this.  A64PORT_HOST_STACK_KB tunes it. */
        pthread_attr_t hattr;
        pthread_attr_init(&hattr);
        {
            static size_t kb;
            if (!kb) {
                const char* e = getenv("A64PORT_HOST_STACK_KB");
                kb = (e && *e) ? (size_t)strtoul(e, 0, 0) : 512;
                if (kb < 256) kb = 256;
            }
            pthread_attr_setstacksize(&hattr, kb << 10);
        }
        const int pcerr = pthread_create(&t->host, &hattr, guest_thread_entry, t);
        pthread_attr_destroy(&hattr);
#else
        const int pcerr = pthread_create(&t->host, NULL, guest_thread_entry, t);
#endif
        if (pcerr != 0) {
            fprintf(stderr, "[a64port] clone: pthread_create failed: %s\n", strerror(pcerr));
            pthread_cond_destroy(&t->ready_cv);
            pthread_mutex_destroy(&t->ready_mu);
            free(t);
            return -EAGAIN;
        }
        /* clone() returns in the parent only after the tid is published. */
        pthread_mutex_lock(&t->ready_mu);
        while (!t->ready) pthread_cond_wait(&t->ready_cv, &t->ready_mu);
        pthread_mutex_unlock(&t->ready_mu);
        pthread_detach(t->host);
        pthread_mutex_lock(&g_threads_mu);
        t->next = g_threads;
        __atomic_store_n(&g_threads, t, __ATOMIC_RELEASE);
        pthread_mutex_unlock(&g_threads_mu);
        fprintf(stderr, "[a64port] clone thread tid=%u parent_tid=%d tls=0x%llx flags=0x%llx parent_x30=0x%llx t=%.3f\n",
                t->tid, (int)syscall(SYS_gettid),
                (unsigned long long)t->ctx.tpidr_el0, (unsigned long long)flags,
                (unsigned long long)parent->x[30],
                (double)clock() / CLOCKS_PER_SEC);
        {   /* where was this thread spawned from? */
            uint64_t fp = parent->x[29];
            for (int k = 0; k < 12; ++k) {
                if (fp < ARENA_BASE || fp + 16 > ARENA_TOP) break;
                const uint64_t* fr = (const uint64_t*)P(fp);
                if (!fr[1]) break;
                fprintf(stderr, "[a64port]   spawn bt#%-2d ret=0x%-10llx %s\n",
                        k, (unsigned long long)fr[1], mod_of(fr[1]));
                if (fr[0] <= fp) break;
                fp = fr[0];
            }
        }
        return t->tid;
    }
    /* vfork (CLONE_VM|CLONE_VFORK) or plain fork: run the child synchronously.
       The child shares the arena and the stack, matching vfork's contract that
       the parent waits until the child execs or _exits. */
    fprintf(stderr, "[a64port] clone proc flags=0x%llx%s\n",
            (unsigned long long)flags, (flags & 0x4000) ? " (VFORK)" : " (FORK)");
    if (flags & kCloneSetTls) child->tpidr_el0 = tls;
    (void)parent;

    /* A real fork() (no CLONE_VM) is copy-on-write in the kernel, and the child
       runs __malloc_fork_unlock_child, which rewrites the arena free_list and
       attached_threads counters.  Running that against the parent's arena
       corrupts the parent, so the child needs a private copy.

       This used to be malloc(16 GB) + memcpy(16 GB) - measured ~16 s, and
       a program that forks twice during startup to run helper processes spent
       ~33 s of its startup in it.  A sparse mincore-guided copy does
       not help (the arena is fully committed).  Let the HOST KERNEL do it: a
       real fork() gives the child true COW semantics for free, which is both
       correct and what the guest is actually asking for. */
    if (!(flags & 0x100)) {                 /* fork, not vfork */
        fflush(NULL);
        const pid_t p = fork();
        if (p < 0) { errno = EAGAIN; return -1; }
        if (p == 0) {
            /* glibc's fork() passes CLONE_CHILD_SETTID with &THREAD_SELF->tid:
               the child's pd->tid must be its OWN tid, not the parent's. */
            if ((flags & K_CLONE_CHILD_SETTID) && ctid) {
                uint32_t* cp = (uint32_t*)PG(ctid);
                if (cp) *cp = (uint32_t)syscall(SYS_gettid);
            }
            /* Child process: run the guest's fork-return path to completion,
               then leave for real so the parent's wait4 sees a genuine status.
               The budget is a guard against the child running the whole
               application; a real helper reaches execve or _exit quickly. */
            uint64_t it = 0;
            while (!child->halted && it < 3000000ULL) {
                BlockFn f = dispatch(child->pc);
                if (!f) break;
                f(child);
                ++it;
            }
            _exit((int)(child->x[0] & 0xff));
        }
        fprintf(stderr, "[a64port] fork -> real child pid %d (kernel COW)\n", (int)p);
        a64port_guest_child_exited((int)p, 0);   /* so wait4 can report it */
        return p;
    }

    /* vfork / CLONE_VM: the child shares the arena by contract, so there is
       nothing to copy. */
    uint64_t iters = 0;
    const uint64_t kChildBudget = 3000000ULL;
    /* The child's exit_group must end only the child (see linux_syscalls.c). */
    ++a64port_vfork_child;
    while (!child->halted && iters < kChildBudget) {
        BlockFn f = dispatch(child->pc);
        if (!f) {
            fprintf(stderr, "[a64port] vfork child: no block at 0x%llx\n",
                    (unsigned long long)child->pc);
            child->halted = 1;
            break;
        }
        f(child);
        ++iters;
    }
    --a64port_vfork_child;
    if (iters >= kChildBudget)
        fprintf(stderr, "[a64port] vfork child: watchdog after %llu blocks (pc=0x%llx)\n",
                (unsigned long long)iters, (unsigned long long)child->pc);
    a64port_guest_child_exited(12345, (int)(child->x[0] & 0xff));
    return 12345;    /* a fake child pid for the parent */
}

/* ── guest path resolution ─────────────────────────────────────────────────
   Every path the guest opens is resolved inside the guest rootfs, and ".."
   can never climb out of it. Relative paths resolve against the program's directory (A64PORT_APPDIR). */
const char* a64port_host_link_iface(void);
static void resolve_path(const char* p, char* out, size_t n) {
    /* Host-owned namespaces: the X11 socket directory, device nodes and procfs
       belong to the machine the guest is running on, not to the guest rootfs.
       This is how such a program usually runs on its own hardware - a chroot with /tmp,
       /dev and /proc bind-mounted - so those pass through untouched. */
    if (p[0] == '/') {
        static const char* const kHost[] = { "/tmp", "/dev", "/proc", "/sys" };
        for (int i = 0; i < 4; ++i) {
            const size_t l = strlen(kHost[i]);
            if (!strncmp(p, kHost[i], l) && (p[l] == '/' || p[l] == 0)) {
                snprintf(out, n, "%s", p);
                return;
            }
        }
    }
    char raw[4096];
    if (p[0] == '/') snprintf(raw, sizeof raw, "%s%s", g_rootfs, p);
    else             snprintf(raw, sizeof raw, "%s%s/%s", g_rootfs, A64PORT_APPDIR, p);
    const size_t bl = strlen(g_rootfs);
    if (bl + 2 >= n) { out[0] = 0; return; }
    memcpy(out, g_rootfs, bl + 1);
    size_t o = bl;
    if (o == 0 || out[o - 1] != '/') out[o++] = '/';
    out[o] = 0;     /* "/" has no components: without this the result ran on into the buffer's previous path */
    const char* q = raw + bl;
    while (*q) {
        while (*q == '/') ++q;
        if (!*q) break;
        const char* s = q;
        while (*q && *q != '/') ++q;
        const size_t l = (size_t)(q - s);
        if (l == 1 && s[0] == '.') continue;
        if (l == 2 && s[0] == '.' && s[1] == '.') {
            while (o > bl + 1 && out[o - 1] != '/') --o;
            if (o > bl + 1) --o;
            out[o] = 0;
            continue;
        }
        if (o + l + 2 > n) break;
        memcpy(out + o, s, l);
        o += l;
        out[o++] = '/';
        out[o] = 0;
    }
    if (o > bl + 1) out[o - 1] = 0;      /* drop the trailing slash */
}

/* ── hooks that linux_syscalls.c calls (weak defaults there) ─────────────────── */

const char* a64port_guest_path(const char* p) {
    /* per thread: a shared ring let another thread's path overwrite this one between the translation and the syscall
       (ftok("/etc") stat'ed a stranger's path -> semget ENOENT) */
    static __thread char buf[8][4096];
    static __thread unsigned k;
    if (!p || !*p) return p;
    char* b = buf[k++ & 7];
    resolve_path(p, b, 4096);
    return b;
}

void a64port_guest_note_open(int fd, const char* guest_path) {
    if (fd < 0 || fd >= A64PORT_MAXFD) return;
    g_fd_mod[fd] = -1;
    char host[4096];
    resolve_path(guest_path, host, sizeof host);
    /* ld.so asks for the SONAME (`libX11.so.6`), which in this rootfs is a
       symlink to the real file (`libX11.so.6.3.0`), so compare the *resolved*
       basename or every module goes unrecognised. */
    char real[4096];
    const char* use = realpath(host, real) ? real : host;
    const char* base = strrchr(use, '/');
    base = base ? base + 1 : use;
    for (unsigned m = 0; m < R_NMODULES; ++m)
        if (!strcmp(R_MODULES[m].file, base)) { g_fd_mod[fd] = (short)m; return; }
}

/* True only for the DSOs the emitter translated (see linux_syscalls.c). */
int a64port_known_dso(const char* guest_path) {
    if (!guest_path || !*guest_path) return 1;
    char host[4096];
    resolve_path(guest_path, host, sizeof host);
    char real[4096];
    const char* use = realpath(host, real) ? real : host;
    const char* base = strrchr(use, '/');
    base = base ? base + 1 : use;
    for (unsigned m = 0; m < R_NMODULES; ++m)
        if (!strcmp(R_MODULES[m].file, base)) return 1;
    return 0;
}

/* ── mmap pool with free-list ───────────────────────────────────────────
   glibc frees the alignment waste of its arena reservations (new_heap mmaps
   128 MB, uses 64 MB, munmaps the rest) and frees thread stacks; without
   honouring munmap the ~1.4 GB pool is exhausted by ~11 secondary arenas.
   A sorted, coalescing free-list reclaims those holes. */
typedef struct PoolFree { uint64_t va, len; struct PoolFree* next; } PoolFree;
static PoolFree* g_free_pool;
/* Defined with the live-range records below: report a range handed out while a
   live mapping already covers it (the corruption this pool can cause). */
static void pool_report_overlap(uint64_t va, uint64_t r);

/* The pool is process-global mutable state and is reached from mmap/munmap on
   every guest thread at once - thread stacks, TLS blocks and glibc's arena
   reservations all go through here.  Without this lock a lost update can splice
   the free list into a cycle, and pool_alloc() then walks it forever in *host*
   code: no syscall is ever slow, the guest PC still reads libc (the mmap call
   site), and the thread appears merely "parked" while it burns a core.  That is
   what stalled a large program's main thread inside pthread_create/_dl_allocate_tls for
   ~33 s while 222 other threads sat behind it. */
static pthread_mutex_t g_pool_mu = PTHREAD_MUTEX_INITIALIZER;

static void pool_free_add(uint64_t va, uint64_t len) {
    uint64_t v = va & ~UINT64_C(0xFFF);
    uint64_t l = (len + 0xFFF) & ~UINT64_C(0xFFF);
    if (!l) return;
    if (v < MMAP_LO) { const uint64_t d = MMAP_LO - v; if (d >= l) return; v = MMAP_LO; l -= d; }
    if (v + l > MMAP_HI) { if (v >= MMAP_HI) return; l = MMAP_HI - v; }
    pthread_mutex_lock(&g_pool_mu);
    PoolFree* f = (PoolFree*)malloc(sizeof *f);
    f->va = v; f->len = l; f->next = NULL;
    if (!g_free_pool || g_free_pool->va > v) { f->next = g_free_pool; g_free_pool = f; }
    else {
        PoolFree* p = g_free_pool;
        while (p->next && p->next->va <= v) p = p->next;
        f->next = p->next; p->next = f;
    }
    /* merge adjacent/overlapping neighbours */
    PoolFree** pp = &g_free_pool;
    while (*pp) {
        PoolFree* a = *pp;
        PoolFree* b = a->next;
        if (b && a->va + a->len >= b->va) {
            const uint64_t end = (a->va + a->len > b->va + b->len) ? (a->va + a->len) : (b->va + b->len);
            a->len = end - a->va;
            a->next = b->next;
            free(b);
        } else {
            pp = &a->next;
        }
    }
    pthread_mutex_unlock(&g_pool_mu);
}

static uint64_t pool_alloc(uint64_t r) {
    pthread_mutex_lock(&g_pool_mu);
    PoolFree** pp = &g_free_pool;
    uint64_t walks = 0;
    while (*pp) {
        PoolFree* f = *pp;
        if (++walks > 4096) {   /* corrupt list: bail out instead of spinning forever */
            fprintf(stderr, "[a64port] mmap pool free-list looks cyclic; ignoring it\n");
            g_free_pool = NULL;
            break;
        }
        if (f->len >= r) {
            const uint64_t va = f->va + f->len - r;   /* carve from the top */
            f->len -= r;
            if (f->len == 0) { *pp = f->next; free(f); }
            pthread_mutex_unlock(&g_pool_mu);
            pool_report_overlap(va, r);
            return va;
        }
        pp = &(*pp)->next;
    }
    if (g_hole_hi && g_pool_top > g_hole_lo && g_pool_top - r < g_hole_hi)
        g_pool_top = g_hole_lo;               /* skip the host hole */
    if (g_pool_top < MMAP_LO + r) { pthread_mutex_unlock(&g_pool_mu); return 0; }
    g_pool_top -= r;
    const uint64_t va = g_pool_top;
    pthread_mutex_unlock(&g_pool_mu);
    pool_report_overlap(va, r);
    return va;
}

/* Carve [va, va+len) out of the free list.  A MAP_FIXED mapping takes that
   address by force, so it must stop being available: otherwise the range stays
   in the pool, a later pool_alloc() returns it, and two mappings own the same
   memory - the new one memsets it to zero underneath the old one. */
static void pool_remove_range(uint64_t va, uint64_t len) {
    uint64_t v = va & ~UINT64_C(0xFFF);
    uint64_t l = (len + 0xFFF) & ~UINT64_C(0xFFF);
    if (!l) return;
    pthread_mutex_lock(&g_pool_mu);
    PoolFree** pp = &g_free_pool;
    while (*pp) {
        PoolFree* f = *pp;
        const uint64_t fs = f->va, fe = f->va + f->len;
        if (fe <= v || fs >= v + l) { pp = &f->next; continue; }
        if (fs < v && fe > v + l) {                 /* split in two */
            PoolFree* tail = (PoolFree*)malloc(sizeof *tail);
            if (!tail) break;
            tail->va = v + l; tail->len = fe - (v + l); tail->next = f->next;
            f->len = v - fs;
            f->next = tail;
            break;
        }
        if (fs < v) { f->len = v - fs; pp = &f->next; continue; }
        if (fe > v + l) { f->va = v + l; f->len = fe - (v + l); pp = &f->next; continue; }
        *pp = f->next; free(f);
    }
    pthread_mutex_unlock(&g_pool_mu);
}

/* Strong overrides of the shim's SysV-shm reservation hooks: borrow the same
   coalescing pool the guest mmap uses, but leave the range unmapped so shmat()
   can attach the host segment there. */
uint64_t a64port_guest_reserve(uint64_t len) {
    const uint64_t rounded = ((len + 0xFFF) & ~UINT64_C(0xFFF)) ? : 0x1000;
    return pool_alloc(rounded);
}
void a64port_guest_release(uint64_t va, uint64_t len) { pool_free_add(va, len); }

/* ── live-mapping overlap detector ─────────────────────────────────────────
   a64port_guest_mmap zeroes every new mapping (memset(P(va), 0, r)).  If the
   pool ever hands back a range that is still live - a thread stack glibc is
   running on, or a malloc arena - that memset silently zeroes it, which shows
   up much later as a thread whose saved registers come back as 0, a jump to
   pc=0, or glibc reporting corrupt heap metadata.  So track the live ranges
   and say so the moment one is handed out twice. */
#define MAPREC_MAX 16384
typedef struct { uint64_t lo, hi; int fixed; } MapRec;
static MapRec g_maprec[MAPREC_MAX];
static int g_maprec_n;
static pthread_mutex_t g_maprec_mu = PTHREAD_MUTEX_INITIALIZER;

static void maprec_add(uint64_t lo, uint64_t hi, int fixed) {
    pthread_mutex_lock(&g_maprec_mu);
    for (int i = 0; i < g_maprec_n; ++i) {
        MapRec* m = &g_maprec[i];
        if (lo < m->hi && m->lo < hi) {
            fprintf(stderr, "[a64port] MMAP OVERLAP new=[0x%llx,0x%llx)%s live=[0x%llx,0x%llx)%s\n",
                    (unsigned long long)lo, (unsigned long long)hi, fixed ? " FIXED" : "",
                    (unsigned long long)m->lo, (unsigned long long)m->hi,
                    m->fixed ? " FIXED" : "");
            if (g_maprec_n < MAPREC_MAX) g_maprec[g_maprec_n++] = *m;   /* keep both */
            break;
        }
    }
    if (g_maprec_n < MAPREC_MAX) { g_maprec[g_maprec_n].lo = lo; g_maprec[g_maprec_n].hi = hi;
                                   g_maprec[g_maprec_n].fixed = fixed; g_maprec_n++; }
    pthread_mutex_unlock(&g_maprec_mu);
}

/* What is the pool holding?  Printed once, at the first ENOMEM: live mappings
   grouped by size (largest share first) and the free list's total. */
static void pool_census(void) {
    enum { K = 64 };
    uint64_t sz[K] = {0}, tot[K] = {0}; unsigned cnt[K] = {0}, nk = 0;
    uint64_t live = 0, freeb = 0;
    pthread_mutex_lock(&g_maprec_mu);
    for (int i = 0; i < g_maprec_n; ++i) {
        const uint64_t lo = g_maprec[i].lo, hi = g_maprec[i].hi;
        if (lo < MMAP_LO || hi > MMAP_HI) continue;
        const uint64_t s = hi - lo;
        live += s;
        unsigned k = 0;
        while (k < nk && sz[k] != s) ++k;
        if (k == nk && nk < K) { sz[nk] = s; ++nk; }
        if (k < K) { cnt[k]++; tot[k] += s; }
    }
    pthread_mutex_unlock(&g_maprec_mu);
    pthread_mutex_lock(&g_pool_mu);
    for (PoolFree* f = g_free_pool; f; f = f->next) freeb += f->len;
    pthread_mutex_unlock(&g_pool_mu);
    fprintf(stderr, "[a64port] pool census: %llu MB live in %d records, %llu MB on the free list,"
                    " pool %llu MB\n", (unsigned long long)(live >> 20), g_maprec_n,
            (unsigned long long)(freeb >> 20), (unsigned long long)((MMAP_HI - MMAP_LO) >> 20));
    for (int shown = 0; shown < 10; ++shown) {
        unsigned best = K;
        for (unsigned k = 0; k < nk; ++k)
            if (tot[k] && (best == K || tot[k] > tot[best])) best = k;
        if (best == K) break;
        fprintf(stderr, "[a64port]   %5u x 0x%-9llx = %5llu MB\n", cnt[best],
                (unsigned long long)sz[best], (unsigned long long)(tot[best] >> 20));
        tot[best] = 0;
    }
}

static void pool_report_overlap(uint64_t va, uint64_t r) {
    if (!EnvOn("A64PORT_POOL_WATCH")) return;
    pthread_mutex_lock(&g_maprec_mu);
    for (int i = 0; i < g_maprec_n; ++i) {
        const MapRec* m = &g_maprec[i];
        if (va < m->hi && m->lo < va + r) {
            fprintf(stderr, "[pool] *** DOUBLE HAND-OUT [0x%llx,0x%llx) overlaps live"
                            " [0x%llx,0x%llx)%s (tid=%d)\n",
                    (unsigned long long)va, (unsigned long long)(va + r),
                    (unsigned long long)m->lo, (unsigned long long)m->hi,
                    m->fixed ? " FIXED" : "", (int)syscall(SYS_gettid));
            break;
        }
    }
    pthread_mutex_unlock(&g_maprec_mu);
}

static void maprec_del(uint64_t lo, uint64_t hi) {
    pthread_mutex_lock(&g_maprec_mu);
    for (int i = 0; i < g_maprec_n; ++i) {
        MapRec* m = &g_maprec[i];
        if (m->hi <= lo || hi <= m->lo) continue;              /* no overlap: keep */
        if (lo <= m->lo && m->hi <= hi) {                      /* fully covered: drop */
            g_maprec[i] = g_maprec[--g_maprec_n]; --i; continue;
        }
        if (lo > m->lo && hi < m->hi) {                        /* split in two */
            if (g_maprec_n < MAPREC_MAX) {
                g_maprec[g_maprec_n].lo = hi; g_maprec[g_maprec_n].hi = m->hi;
                g_maprec[g_maprec_n].fixed = m->fixed; g_maprec_n++;
            }
            m->hi = lo; continue;
        }
        if (lo <= m->lo) m->lo = hi; else m->hi = lo;           /* trim one end */
    }
    pthread_mutex_unlock(&g_maprec_mu);
}

/* Zero a page-aligned guest range.  Large ranges are handed back to the host
   kernel instead of being memset: g_mem is private anonymous memory, so after
   MADV_DONTNEED the pages read as zero, and an untouched reservation (glibc
   maps 64-128 MB per malloc arena and uses a fraction) never becomes resident
   Falls back to memset if the kernel refuses. */
/* ── guest file mappings as host file mappings ───────────────────────────────
   A guest mmap of a regular file used to be pread() into the arena: every byte
   resident, as anonymous memory, at map time.  A program that maps a 1.9 GB cache file
   then had 1.9 GB of RSS, and a
   MAP_SHARED write never reached the file.  Now the file is mmap'd MAP_FIXED
   over the arena range: pages load on touch, are evictable page cache, and
   shared writes are the file's.  The ranges are recorded because the arena's
   other paths assume anonymous memory: madvise(DONTNEED) on a file mapping
   re-reads the file instead of zeroing, so munmap and an anonymous re-map put
   a fresh anonymous mapping back first.  A64PORT_FILEMAP=0 restores pread. */
static void arena_zero_anon(uint64_t va, uint64_t r);
typedef struct FileMapRange { uint64_t lo, hi; struct FileMapRange* next; } FileMapRange;
static FileMapRange* g_filemaps;
static pthread_mutex_t g_filemap_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_filemap_on = -1;

static int filemap_enabled(void) {
    if (g_filemap_on < 0) {
        const char* e = getenv("A64PORT_FILEMAP");
        g_filemap_on = (e && *e == '0') ? 0 : 1;
    }
    return g_filemap_on;
}

/* Make [va, va+r) anonymous zero memory again wherever it is file-mapped.
   Returns 1 if any part was (the caller then has nothing left to zero there). */
static int filemap_release(uint64_t va, uint64_t r) {
    int any = 0;
    pthread_mutex_lock(&g_filemap_mu);
    for (FileMapRange** pp = &g_filemaps; *pp;) {
        FileMapRange* f = *pp;
        const uint64_t lo = va > f->lo ? va : f->lo;
        const uint64_t hi = va + r < f->hi ? va + r : f->hi;
        if (lo >= hi) { pp = &f->next; continue; }
        any = 1;
        if (mmap(P(lo), (size_t)(hi - lo), PROT_READ | PROT_WRITE,
                 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0) == MAP_FAILED)
            fprintf(stderr, "[a64port] filemap: cannot restore anonymous memory at 0x%llx: %s\n",
                    (unsigned long long)lo, strerror(errno));
        if (lo > f->lo && hi < f->hi) {              /* split */
            FileMapRange* t = (FileMapRange*)malloc(sizeof *t);
            if (t) { t->lo = hi; t->hi = f->hi; t->next = f->next; f->next = t; }
            f->hi = lo;
            pp = &f->next;
        } else if (lo > f->lo) { f->hi = lo; pp = &f->next; }
        else if (hi < f->hi)   { f->lo = hi; pp = &f->next; }
        else                   { *pp = f->next; free(f); }
    }
    pthread_mutex_unlock(&g_filemap_mu);
    return any;
}

/* Map file pages over [va, va+r).  Pages wholly past EOF stay anonymous zero
   (the kernel would SIGBUS there; the old pread path zero-filled, so keep its
   leniency).  Returns 1 on success, 0 to fall back to pread. */
static int filemap_try(uint64_t va, uint64_t r, int prot, uint64_t flags, int fd, uint64_t off) {
    if (!filemap_enabled() || (off & 0xFFF)) return 0;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) return 0;
    const uint64_t fsz = (uint64_t)st.st_size;
    if (off >= fsz) return 0;
    uint64_t flen = ((fsz - off) + 0xFFF) & ~UINT64_C(0xFFF);
    if (flen > r) flen = r;
    const int shared = (flags & 0x3) == 0x1 || (flags & 0x3) == 0x3;   /* MAP_SHARED(_VALIDATE) */
    filemap_release(va, r);                   /* replacing an older file map */
    void* want = P(va);
    void* got = MAP_FAILED;
    if (shared) {
        /* The shim ignores mprotect, so map writable when the fd allows it; a
           read-only fd gets the guest's read-only view. */
        got = mmap(want, (size_t)flen, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, fd, (off_t)off);
        if (got == MAP_FAILED && errno == EACCES && !(prot & 2))
            got = mmap(want, (size_t)flen, PROT_READ, MAP_FIXED | MAP_SHARED, fd, (off_t)off);
    } else {
        got = mmap(want, (size_t)flen, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fd, (off_t)off);
    }
    if (got == MAP_FAILED) {
        /* MAP_FIXED failures leave the old mapping in place (anonymous here). */
        static int warned;
        if (warned++ < 4)
            fprintf(stderr, "[a64port] filemap: mmap of fd %d len 0x%llx failed (%s); using pread\n",
                    fd, (unsigned long long)flen, strerror(errno));
        return 0;
    }
    FileMapRange* f = (FileMapRange*)malloc(sizeof *f);
    if (f) {
        f->lo = va; f->hi = va + flen;
        pthread_mutex_lock(&g_filemap_mu);
        f->next = g_filemaps;
        __atomic_store_n(&g_filemaps, f, __ATOMIC_RELEASE);
        pthread_mutex_unlock(&g_filemap_mu);
    }
    if (flen < r) arena_zero_anon(va + flen, r - flen);
    return 1;
}

/* A socket's mmap: the AF_PACKET RX ring libpcap asks for (PACKET_RX_RING + mmap of the
   socket fd).  The kernel shares the ring's pages, so it has to be a real MAP_SHARED
   mapping at the guest address (the arena is identity-mapped); reading the "file" as for
   a regular file fails with ESPIPE, which made pcap_activate() give up and left
   the guest's capture threads spinning on a closed handle. */
static int sockmap_try(uint64_t va, uint64_t r, int fd, uint64_t off) {
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISSOCK(st.st_mode)) return 0;
    filemap_release(va, r);
    void* got = mmap(P(va), (size_t)r, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, fd, (off_t)off);
    if (got == MAP_FAILED) {
        fprintf(stderr, "[a64port] socket mmap of fd %d len 0x%llx failed: %s\n", fd,
                (unsigned long long)r, strerror(errno));
        return -1;
    }
    FileMapRange* f = (FileMapRange*)malloc(sizeof *f);
    if (f) {
        f->lo = va; f->hi = va + r;
        pthread_mutex_lock(&g_filemap_mu);
        f->next = g_filemaps;
        __atomic_store_n(&g_filemaps, f, __ATOMIC_RELEASE);
        pthread_mutex_unlock(&g_filemap_mu);
    }
    return 1;
}

static void arena_zero(uint64_t va, uint64_t r) {
    if (__atomic_load_n(&g_filemaps, __ATOMIC_ACQUIRE)) filemap_release(va, r);
    arena_zero_anon(va, r);
}

static void arena_zero_anon(uint64_t va, uint64_t r) {
    if (r >= (UINT64_C(64) << 10) &&
        madvise(P(va), (size_t)r, MADV_DONTNEED) == 0)
        return;
    memset(P(va), 0, (size_t)r);
}

int a64port_guest_mmap(uint64_t* addr_io, uint64_t len, int prot, uint64_t flags,
                      int fd, uint64_t off) {
    const uint64_t kMapFixed = 0x10, kMapAnon = 0x20;   /* <sys/mman.h> owns these names */
    uint64_t r = (len + 0xFFF) & ~UINT64_C(0xFFF);
    if (!r) r = 0x1000;
    uint64_t va;
    if (flags & kMapFixed) {
        va = *addr_io & ~UINT64_C(0xFFF);
        if (g_hole_hi && va < g_hole_hi && va + r > g_hole_lo) { errno = ENOMEM; return -1; }   /* the host's, not the guest's */
        pool_remove_range(va, r);   /* the free list must not hand this out again */
    } else {
        va = pool_alloc(r);
        if (!va) {
            /* Pool exhaustion is silent in the guest (a C++ bad_alloc, or a
               "Cannot allocate memory" far from here) - say which request hit it. */
            static int warned;
            if (warned++ < 8)
                fprintf(stderr, "[a64port] guest mmap ENOMEM: len=0x%llx, pool floor 0x%llx "
                                "(arena top 0x%llx)\n", (unsigned long long)r,
                        (unsigned long long)g_pool_top, (unsigned long long)ARENA_TOP);
            if (warned == 1) pool_census();
            errno = ENOMEM; return -1;
        }
    }
    if (va < MMAP_LO || va + r > MMAP_HI) { errno = ENOMEM; return -1; }
    if ((flags & kMapFixed) && va < g_pool_top) {   /* keep pool below fixed maps */
        pthread_mutex_lock(&g_pool_mu);
        if (va < g_pool_top) g_pool_top = va;
        pthread_mutex_unlock(&g_pool_mu);
    }

    int sk = 0;
    if (!(flags & kMapAnon) && fd >= 0 && (sk = sockmap_try(va, r, fd, off)) != 0) {
        if (sk < 0) return -1;       /* errno from mmap */
    } else if (!(flags & kMapAnon) && fd >= 0 && !a64port_device_is_drm(fd) &&
        filemap_try(va, r, prot, flags, fd, off)) {
        /* mapped from the file; nothing to copy */
    } else if (!(flags & kMapAnon) && fd >= 0 && !a64port_device_is_drm(fd)) {
        errno = 0;
        const ssize_t got = pread(fd, P(va), (size_t)r, (off_t)off);
        if (got < 0) return -1;                       /* errno from pread */
        if ((uint64_t)got < r) memset((uint8_t*)P(va) + got, 0, (size_t)(r - got));
    } else {
        arena_zero(va, r);
    }
    *addr_io = va;
    maprec_add(va, va + r, (flags & kMapFixed) != 0);

    /* Learn a module's load address from the mapping. For an ELF this is exact:
       p_vaddr - p_offset is 0 for the first PT_LOAD of an ET_DYN, and page
       congruent for the rest, so va - (off & ~0xfff) is the base. */
    if (fd >= 0 && fd < A64PORT_MAXFD && g_fd_mod[fd] >= 0) {
        const unsigned m = (unsigned)g_fd_mod[fd];
        const uint64_t cand = va - (off & ~UINT64_C(0xFFF));
        if (!g_mod_base[m] || cand < g_mod_base[m]) {
            g_mod_base[m] = cand;
            *R_MODULES[m].basevar = cand;
            g_base_gen++;                  /* invalidate the dispatch cache */
#if defined(RECOMP_FEATURE_GUARD_GEN1)
            /* The block guard verified these words at the old base; make it
               verify again at the new one. */
            g_recomp_gg_word = ++g_gg_gen;
#endif
            fprintf(stderr, "[a64port] %-11s mapped at 0x%llx (fd %d)\n",
                    R_MODULES[m].name, (unsigned long long)cand, fd);
        }
    }
    (void)prot;
    return 1;
}

void a64port_guest_munmap(uint64_t va, uint64_t len) {
    maprec_del(va & ~UINT64_C(0xFFF), (va + len + 0xFFF) & ~UINT64_C(0xFFF));
    /* Drop the file now: the pool may hand this range out again, and a shared
       mapping must stop reaching the file the moment the guest unmaps it. */
    if (__atomic_load_n(&g_filemaps, __ATOMIC_ACQUIRE))
        filemap_release(va & ~UINT64_C(0xFFF), ((va + len + 0xFFF) & ~UINT64_C(0xFFF)) - (va & ~UINT64_C(0xFFF)));
    pool_free_add(va, len);
}

/* ── loading ─────────────────────────────────────────────────────────────── */
static int load_segments(const RModule* M, uint64_t base) {
    for (unsigned i = 0; i < M->nseg; ++i) {
        const RModSeg* s = &M->segs[i];
        char path[2048];
        /* A64PORT_SEG_ROOT replaces the build machine's ".../a64port-work/a64port"
           prefix of the compiled-in tree path (a target machine may keep the segment
           files elsewhere). */
        const char* root = getenv("A64PORT_SEG_ROOT");
        const char* tail = strstr(M->dir, "/a64port-work/a64port/");
        if (root && *root && tail)
            snprintf(path, sizeof path, "%s/%s/a64port/%s", root, tail + strlen("/a64port-work/a64port/"), s->file);
        else
            snprintf(path, sizeof path, "%s/a64port/%s", M->dir, s->file);
        FILE* f = fopen(path, "rb");
        if (!f) { fprintf(stderr, "[a64port] missing %s\n", path); return -1; }
        const uint64_t va = base + s->va;
        if (va < ARENA_BASE || va + s->size > ARENA_TOP) {
            fprintf(stderr, "[a64port] %s:%s at 0x%llx outside the arena\n",
                    M->name, s->name, (unsigned long long)va);
            fclose(f); return -1;
        }
        if (fread(P(va), 1, (size_t)s->size, f) != (size_t)s->size) {
            fprintf(stderr, "[a64port] short read on %s\n", path); fclose(f); return -1;
        }
        fclose(f);
    }
    return 0;
}

static void patch_filecache_budget(void) {}

static void patch_frame_period(void) {}
/* ── initial stack, exactly as execve builds it ───────────────────────────── */
/* the program's own arguments: host argv[2..] (argv[1] is the rootfs), e.g. myprog --verbose input.txt */
static int g_gargc;
static char** g_gargv;
static uint64_t build_stack(const char* argv0) {
    uint64_t cur = STACK_TOP;

    /* The guest's getenv() reads THIS envp, not the host's environ, so any
       host-side setting the app needs (ALSA_CONFIG_PATH, DISPLAY, ...) has to
       be copied in here. Internal/loader variables are dropped. */
    extern char** environ;
    const char* envstrs[48];
    int nenv = 0;
    for (char** e = environ; e && *e && nenv < 40; ++e) {
        const char* s = *e;
        if (!strncmp(s, "A64PORT_", 8) || !strncmp(s, "LD_", 3) ||
            !strncmp(s, "DISPLAY=", 8) || !strncmp(s, "HOME=", 5) ||
            !strncmp(s, "PWD=", 4) || !strncmp(s, "OLDPWD=", 7))
            continue;
        envstrs[nenv++] = s;
    }
    char disp[64];
    const char* dd = getenv("A64PORT_DISPLAY");
    snprintf(disp, sizeof disp, "DISPLAY=%s", dd && *dd ? dd : (getenv("DISPLAY") ? getenv("DISPLAY") : ":0"));
    static char home[512];
    { const char* h = getenv("A64PORT_GUEST_HOME"); snprintf(home, sizeof home, "HOME=%s", h && *h ? h : "/"); }
    envstrs[nenv++] = home;
    envstrs[nenv++] = "LANG=C";
    /* NOTE: MALLOC_ARENA_MAX=1 was once set to avoid a malloc
       deadlock, but that deadlock was really the global exclusive-monitor bug
       (since fixed).  Forcing a single arena now *creates* a lock-order
       inversion: a thread takes stderr's FILE lock inside fprintf, then
       blocks on the one arena lock while holding it, so every other thread
       that logs queues behind it.  Leave the arena count to glibc. */
#if A64PORT_ILP32_HOST
    /* Each extra arena reserves HEAP_MAX_SIZE (64 MB for the guest's LP64
       glibc) from the mmap pool: 32 of them would be 2 GB, more than the
       whole 32-bit pool.  Four keeps the fprintf-vs-arena inversion above
       from serialising every thread on one lock. */
    envstrs[nenv++] = "MALLOC_ARENA_MAX=4";
#else
    envstrs[nenv++] = "MALLOC_ARENA_MAX=32";
#endif
    envstrs[nenv++] = "LD_BIND_NOW=1";         /* resolve every PLT/GOT entry at
                                                 load time, before threads exist,
                                                 so runtime lazy binding cannot
                                                 deadlock ld.so's loader lock */
    envstrs[nenv++] = disp;
    if (EnvOn("A64PORT_ENV_DUMP"))
        for (int i = 0; i < nenv; ++i) fprintf(stderr, "[env] %s\n", envstrs[i]);

    uint64_t envvals[48];
    for (int i = nenv - 1; i >= 0; --i) {
        const size_t n = strlen(envstrs[i]) + 1;
        cur -= n;
        memcpy(P(cur), envstrs[i], n);
        envvals[i] = cur;
    }
    const size_t an = strlen(argv0) + 1;
    cur -= an;
    memcpy(P(cur), argv0, an);
    const uint64_t argv0_val = cur;
    uint64_t argvals[32];
    const int nargs = g_gargc < 32 ? g_gargc : 32;
    for (int i = nargs - 1; i >= 0; --i) {
        const size_t n = strlen(g_gargv[i]) + 1;
        cur -= n;
        memcpy(P(cur), g_gargv[i], n);
        argvals[i] = cur;
    }
    cur &= ~(uint64_t)7;
    cur -= 8;                        /* AT_PLATFORM */
    memcpy(P(cur), "aarch64", 8);
    const uint64_t s_platform = cur;

    cur -= 16;                       /* AT_RANDOM: 16 bytes of seed */
    const uint64_t s_rand = cur;
    for (int i = 0; i < 16; ++i) ((uint8_t*)P(s_rand))[i] = (uint8_t)(rand() >> 8);

    const uint64_t aux[][2] = {
        {3, A64PORT_PHDR},        /* AT_PHDR   - the EXECUTABLE's program headers */
        {4, A64PORT_PHENT},       /* AT_PHENT */
        {5, A64PORT_PHNUM},       /* AT_PHNUM */
        {9, A64PORT_ENTRY},       /* AT_ENTRY  - the EXECUTABLE's entry */
        {7, g_interp_base},      /* AT_BASE   - the INTERPRETER's load address */
        {6, 4096},               /* AT_PAGESZ */
        {17, 100},               /* AT_CLKTCK */
        {23, 0},                 /* AT_SECURE */
        {25, s_rand},            /* AT_RANDOM */
        {16, 3},                 /* AT_HWCAP  = FP|ASIMD (baseline only) */
        {26, 0},                 /* AT_HWCAP2 */
        {15, s_platform},        /* AT_PLATFORM */
        {11, 0}, {12, 0}, {13, 0}, {14, 0},   /* uid/euid/gid/egid */
        {31, argv0_val},         /* AT_EXECFN */
        {33, 0},                 /* AT_SYSINFO_EHDR = 0: no vDSO, so libc uses syscalls */
        {0, 0},
    };
    size_t k = 0;
    uint64_t blk[256];
    blk[k++] = 1 + (uint64_t)nargs;  /* argc */
    blk[k++] = argv0_val;            /* argv[0] */
    for (int i = 0; i < nargs; ++i) blk[k++] = argvals[i];
    blk[k++] = 0;
    for (int i = 0; i < nenv; ++i) blk[k++] = envvals[i];
    blk[k++] = 0;                    /* envp terminator */
    for (size_t i = 0; i < sizeof(aux) / sizeof(aux[0]); ++i) {
        blk[k++] = aux[i][0];
        blk[k++] = aux[i][1];
    }
    const uint64_t sp = (cur - k * 8) & ~UINT64_C(0xF);
    memcpy(P(sp), blk, k * 8);
    return sp;
}


/* ── LD1-LD4 / ST1-ST4 in one native call ──────────────────────────────────
   See runtime/neon_structs.h.  Lives here, not in the emitted tree, because
   a64recomp regenerates recomp_runtime.c on every emit. Uses only the public
   load/store API plus the guest arena pointer, so it needs nothing private. */
void recomp_ldst_struct(GuestContext* c, uint64_t addr, uint32_t rt,
                        uint32_t regs, uint32_t lanes, uint32_t esz,
                        uint32_t step, uint32_t load, uint32_t bytes)
{
    uint8_t tmp[4][16];
    const uint32_t total = lanes * regs * esz;          /* <= 64 */
    /* A64PORT_SLOT_WATCH (see recomp_runtime.c): the bulk fast paths bypass
       recomp_store*, so the slot watch must also cover a struct store whose
       byte range overlaps the watched window. */
    if (!load) {
        static uint64_t sw; static int sw_init;
        if (!sw_init) {
            sw_init = 1;
            const char* e = getenv("A64PORT_SLOT_WATCH");
            if (e && *e) sw = strtoull(e, 0, 16);
        }
        if (sw && addr < sw + 0x28 && addr + total > sw - 0x20)
            fprintf(stderr, "[slot] st-struct va=0x%llx total=%u regs=%u lanes=%u esz=%u step=%u pc=0x%llx\n",
                    (unsigned long long)addr, total, regs, lanes, esz, step,
                    (unsigned long long)c->pc);
    }
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
                /* Incremental (e,r) instead of k%regs / k/regs: regs and lanes
                   are runtime values, so the compiler cannot fold the division
                   away and doing it per byte dominated the whole helper.
                   esz is 1/2/4/8 for every structural access the guest
                   executes, so switch on it: a constant-size memcpy is
                   inlined, where a runtime-size one is a call per element
                   (one per byte for ld4 {v8-v11}.16b, a common hot
                   ldst site). */
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
    /* A struct store (ST1-ST4) is a plain store, and its fast path writes the
       host mapping directly; retire peer reservations on the range first, as
       recomp_store64 does, or a racing STXR wrongly succeeds. */
    recomp_excl_store_touch(addr, total);
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

/* Crash handler: the host glibc abort (e.g. malloc_consolidate) has no CFI, so
   gdb cannot unwind past it.  Print the aborting thread's guest block ring
   instead - that names the recompiled code that was running. */
static void crash_trace(int sig);
/* SA_SIGINFO front end: the faulting address and host pc first (a fastmem
   build has no range check, so a stray guest pointer faults right here). */
static void crash_info(int sig, siginfo_t* si, void* uc_) {
    char buf[220];
    uint64_t hpc = 0;
    const ucontext_t* uc = (const ucontext_t*)uc_;
#if defined(__x86_64__)
    hpc = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__arm__)
    hpc = (uint64_t)uc->uc_mcontext.arm_pc;
#endif
    Dl_info di;
    const char* sym = "?";
    if (hpc && dladdr((void*)(uintptr_t)hpc, &di) && di.dli_sname) sym = di.dli_sname;
    int n = snprintf(buf, sizeof buf,
                     "\n[a64port] signal %d at host pc 0x%llx (%s), fault addr 0x%llx, pid %d, guest pc 0x%llx\n",
                     sig, (unsigned long long)hpc, sym,
                     (unsigned long long)(uintptr_t)(si ? si->si_addr : 0), (int)getpid(),
                     (unsigned long long)(t_hp_ctx ? t_hp_ctx->pc : (t_uaf_ctx ? t_uaf_ctx->pc : 0)));
    if (n > 0) (void)!write(2, buf, (size_t)n);
    crash_trace(sig);
}

static void crash_trace(int sig) {
    char buf[220];
    int n = snprintf(buf, sizeof buf, "\n[a64port] signal %d; last guest blocks (newest first):\n", sig);
    if (n > 0) (void)!write(2, buf, (size_t)n);
    const unsigned total = t_tpos < TRACE_N ? t_tpos : TRACE_N;
    for (unsigned k = 0; k < total; ++k) {
        const uint64_t pc = t_trace[(t_tpos - 1 - k) & (TRACE_N - 1)];
        n = snprintf(buf, sizeof buf, "  [%2u] 0x%llx %s\n", k,
                     (unsigned long long)pc, mod_of(pc));
        if (n > 0) (void)!write(2, buf, (size_t)n);
    }
    _exit(128 + sig);
}

int main(int argc, char** argv) {
    const char* rf = getenv("A64PORT_ROOTFS");
    if (argc > 1) rf = argv[1];
    if (argc > 2) { g_gargc = argc - 2; g_gargv = argv + 2; }
    snprintf(g_rootfs, sizeof g_rootfs, "%s", rf ? rf : A64PORT_ROOTFS);
    while (strlen(g_rootfs) > 1 && g_rootfs[strlen(g_rootfs) - 1] == '/')
        g_rootfs[strlen(g_rootfs) - 1] = 0;

    /* Identity arena (A64PORT_IDENTITY, default on): map the arena AT its own
       guest address, so a guest VA is the host address (bias 0).  Every
       existing path keeps working - they all add the bias - and a build with
       -DA64PORT_FASTMEM (neon_structs.h) can then load and store through the
       guest pointer directly, with no range check.  Needs the host image and
       its libraries above ARENA_TOP: free on x86-64 (PIE at 0x55..), and on
       ARMv7 the build links the host at --image-base above the arena. */
    g_identity = 0;
    if (!getenv("A64PORT_IDENTITY") || strcmp(getenv("A64PORT_IDENTITY"), "0") != 0) {
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
        void* m = mmap((void*)(uintptr_t)ARENA_BASE, (size_t)ARENA_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
        if (m == (void*)(uintptr_t)ARENA_BASE) {
            g_mem = (uint8_t*)m;
            g_identity = 1;
            fprintf(stderr, "[a64port] identity arena: guest VA == host address (0x%llx..0x%llx)\n",
                    (unsigned long long)ARENA_BASE, (unsigned long long)ARENA_TOP);
        } else {
            if (m != MAP_FAILED) munmap(m, (size_t)ARENA_SIZE);
            /* One blocking span strictly inside the pool range: map around it. */
            uint64_t blo = ~UINT64_C(0), bhi = 0;
            FILE* mf0 = fopen("/proc/self/maps", "r");
            if (mf0) {
                char ln[512];
                while (fgets(ln, sizeof ln, mf0)) {
                    unsigned long long a = 0, b = 0;
                    if (sscanf(ln, "%llx-%llx", &a, &b) == 2 && b > ARENA_BASE && a < ARENA_TOP) {
                        if (a < blo) blo = a;
                        if (b > bhi) bhi = b;
                    }
                }
                fclose(mf0);
            }
            if (bhi && blo >= MMAP_LO && bhi <= MMAP_HI - UINT64_C(0x10000000) && bhi - blo <= UINT64_C(0x4000000)) {
                void* m1 = mmap((void*)(uintptr_t)ARENA_BASE, (size_t)(blo - ARENA_BASE), PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
                void* m2 = mmap((void*)(uintptr_t)bhi, (size_t)(ARENA_TOP - bhi), PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
                if (m1 == (void*)(uintptr_t)ARENA_BASE && m2 == (void*)(uintptr_t)bhi) {
                    g_mem = (uint8_t*)m1;
                    g_identity = 1;
                    g_hole_lo = blo; g_hole_hi = bhi;
                    fprintf(stderr, "[a64port] identity arena around a host hole 0x%llx..0x%llx (never handed to the guest)\n",
                            (unsigned long long)blo, (unsigned long long)bhi);
                } else {
                    if (m1 != MAP_FAILED) munmap(m1, (size_t)(blo - ARENA_BASE));
                    if (m2 != MAP_FAILED) munmap(m2, (size_t)(ARENA_TOP - bhi));
                }
            }
            if (!g_identity)
            fprintf(stderr, "[a64port] identity arena unavailable (%s): biased arena\n",
                    m == MAP_FAILED ? strerror(errno) : "placed elsewhere");
            /* name what is in the way (on ARMv7 it must be the host image or a
               library the loader put low) */
            FILE* mf = g_identity ? NULL : fopen("/proc/self/maps", "r");
            if (mf) {
                char ln[512];
                while (fgets(ln, sizeof ln, mf)) {
                    unsigned long long a = 0, b = 0;
                    if (sscanf(ln, "%llx-%llx", &a, &b) == 2 && b > ARENA_BASE && a < ARENA_TOP)
                        fprintf(stderr, "[a64port]   in the arena range: %s", ln);
                }
                fclose(mf);
            }
        }
    }
#ifdef A64PORT_FASTMEM
    if (!g_identity) {
        fprintf(stderr, "[a64port] this build is -DA64PORT_FASTMEM: it needs the identity arena\n");
        return 1;
    }
#endif
    if (!g_identity) {
#if A64PORT_ILP32_HOST
    {
        /* On a 32-bit board 1.6 GB may exceed RAM + swap, which heuristic
           overcommit refuses as one calloc.  MAP_NORESERVE takes only the VA;
           pages are committed when the guest touches them.  mmap also returns
           page-aligned memory, which the UAF detector's mprotects need. */
        void* m = mmap(NULL, (size_t)ARENA_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (m == MAP_FAILED) {
            fprintf(stderr, "[a64port] cannot map the %llu MB arena: %s "
                            "(rebuild with a smaller -DA64PORT_ARENA_TOP)\n",
                    (unsigned long long)(ARENA_SIZE >> 20), strerror(errno));
            return 1;
        }
        g_mem = (uint8_t*)m;
    }
#else
    {
        /* glibc serves a 16 GB calloc from one mmap'd chunk and returns the
           USER pointer - mapping base + 16 - so guest pages would start 16
           bytes into their host pages.  The UAF detector's mprotects (and any
           future page-granular host feature) need exact alignment: allocate
           two pages extra and align the base down. */
        uint8_t* raw = (uint8_t*)calloc(1, (size_t)ARENA_SIZE + 2 * 4096);
        if (!raw) { fprintf(stderr, "[a64port] cannot allocate the arena\n"); return 1; }
        g_mem = (uint8_t*)(((uintptr_t)raw + 4095) & ~(uintptr_t)4095);
    }
#endif
    }
    g_c.mem = g_mem;
    g_c.mem_size = ARENA_SIZE;
    g_c.mem_base_vaddr = ARENA_BASE;
    for (int i = 0; i < A64PORT_MAXFD; ++i) g_fd_mod[i] = -1;
    hostmem_install();
    /* Every emitted module decides "am I on a guard-v2 host?" by reading its own
       global, which a64recomp initialises to 0 and only recomp_image_guard_v2()
       ever sets - and the static multi build never calls that.  With a page table
       installed the guard would therefore abort on the first block. */
    for (unsigned gi = 0; gi < R_NGUARDS; ++gi) *R_GUARDS[gi] = 2;

    /* module 0 is the executable, module 1 is the interpreter (see gen_mods.py) */
    unsigned m_exe = 0, m_ld = 1;
    for (unsigned m = 0; m < R_NMODULES; ++m) {
        if (!strcmp(R_MODULES[m].name, R_EXE_MODULE)) m_exe = m;
        if (!strcmp(R_MODULES[m].name, "ld")) m_ld = m;
    }
    g_m_exe = m_exe;
    g_mod_base[m_exe] = R_MODULES[m_exe].base;      /* 0: link addresses */
    /* ld.so's base is ours to choose: the emitted code addresses it through
       g_mb_ld, so mods.h's link-time guess is overridden with the layout's. */
    g_mod_base[m_ld] = LD_BASE;
    g_interp_base = g_mod_base[m_ld];
    const uint64_t ld_entry = R_MODULES[m_ld].entry - R_MODULES[m_ld].base + LD_BASE;
    for (unsigned m = 0; m < R_NMODULES; ++m)       /* DSO bases: learned from mmap */
        if (m != m_exe && m != m_ld) g_mod_base[m] = 0;

    if (load_segments(&R_MODULES[m_exe], g_mod_base[m_exe]) != 0) return 1;
    patch_filecache_budget();
    patch_frame_period();
    if (load_segments(&R_MODULES[m_ld], g_mod_base[m_ld]) != 0) return 1;
    for (unsigned m = 0; m < R_NMODULES; ++m) *R_MODULES[m].basevar = g_mod_base[m];
    for (unsigned m = 0; m < R_NMODULES; ++m) R_MODULES[m].build_index();
#if defined(RECOMP_FEATURE_GUARD_GEN1)
    /* Every code image is loaded at its link address and never modified, so the
       generation guard may verify each block once rather than on every entry.
       Must follow the base writes above. */
    g_recomp_gg_word = g_gg_gen;
#endif

    fprintf(stderr,
            "[a64port] %u modules compiled in; exe @0x%llx entry=0x%llx; "
            "interp @0x%llx entry=0x%llx\n"
            "         rootfs=%s\n",
            (unsigned)R_NMODULES, (unsigned long long)g_mod_base[m_exe],
            (unsigned long long)A64PORT_ENTRY, (unsigned long long)g_mod_base[m_ld],
            (unsigned long long)ld_entry, g_rootfs);

    /* Host libs default ON: routing memcpy/memset/memmove/memcmp/
       memchr/strlen/strcmp/strncmp/strcpy/strchr through host trampolines cut
       ~30 % of total CPU in a typical run - the translated libc bodies are
       scalar per-byte loops.  A64PORT_HOSTLIBS=0 restores the translated
       bodies (A/B; the trampolines fall back byte-wise for non-arena args). */
    {
        const char* hl = getenv("A64PORT_HOSTLIBS");
        g_hostlibs = (hl && *hl && strcmp(hl, "0") == 0) ? 0 : 1;
    }
    signal(SIGUSR1, dump_backtrace);
    signal(SIGABRT, crash_trace);
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = crash_info;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGBUS, &sa, NULL);
    }
    {
        const char* e = getenv("A64PORT_WATCHDOG_BLOCKS");
        if (e && *e) g_watchdog_blocks = strtoull(e, 0, 0);
    }
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = crash_info;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, NULL);
    }
#define A64PORT_ARGV0 R_MODULES[0].file
    g_c.x[31] = build_stack(A64PORT_ARGV0);
    /* The kernel hands control to the INTERPRETER. ld.so then finds the
       executable through AT_PHDR, links everything, runs the initializers and
       branches to AT_ENTRY with x0 = _dl_fini. */
    g_c.pc = ld_entry;
    fprintf(stderr, "[a64port] -> ld.so _start  pc=0x%llx sp=0x%llx\n",
            (unsigned long long)g_c.pc, (unsigned long long)g_c.x[31]);
    fflush(stderr);
    excl_pi_init();          /* before any guest thread exists */
    prefault_start();
    pin_start();
    if (EnvOn("A64PORT_PROF")) {
        pthread_t pt;
        if (pthread_create(&pt, NULL, prof_thread, NULL) == 0) pthread_detach(pt);
    }
    if (EnvOn("A64PORT_PROF_CPU")) {
        pthread_t pt2;
        if (pthread_create(&pt2, NULL, prof_cpu_thread, NULL) == 0) pthread_detach(pt2);
    }
    if (EnvOn("A64PORT_PC_DUMP")) {
        pthread_t mon;
        if (pthread_create(&mon, NULL, pc_monitor, NULL) == 0)
            pthread_detach(mon);
    }
    guest_run(&g_c);
    if (g_hostlibs) {
        unsigned long total = 0;
        for (unsigned k = 0; k < N_N; ++k) total += g_nat_calls[k];
        fprintf(stderr, "[a64port] host libs: %lu call(s), %lu byte(s) via the fallback loop\n",
                total, g_nat_slow_bytes);
        for (unsigned k = 0; k < N_N; ++k)
            if (g_nat_calls[k])
                fprintf(stderr, "[a64port]   %-8s %lu\n", g_nat_name[k], g_nat_calls[k]);
    }
    const int code = (int)(g_c.x[0] & 0xff);
    fprintf(stderr, "[a64port] halted pc=0x%llx x0=%d after %llu blocks\n",
            (unsigned long long)g_c.pc, code, (unsigned long long)g_blocks);
    return code;
}
