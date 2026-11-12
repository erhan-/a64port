/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Hand-written leaf macros.
 *
 * A hand leaf is C written by hand that runs instead of the translated code for
 * one (module, address). It lives in this directory, is marked with one of the
 * macros below, and is copied into the emitted project's hand/ directory and
 * compiled by build-guest.sh -- so editing a leaf needs no driver rebuild, and
 * a mistake is a compile error rather than an emit-time string.
 *
 * See README.md in this directory for the workflow. Two kinds:
 *
 *   A64PORT_LEAF(mod, 0xADDR)         the block body is replaced entirely.
 *   A64PORT_LEAF_FILTER(mod, 0xADDR)  runs before the translated body; return 1
 *                                    when the case is handled and the block is
 *                                    done, 0 to run the translated body. This
 *                                    is how a leaf hands a slow path back.
 *
 * Both are entered where the guest enters the block: arguments in c->x[0..],
 * return address in c->x[30], and the context must be left as the block would
 * (result in c->x[0], c->pc = where execution continues).
 *
 * Only the runtime's memory helpers (recomp_load* / recomp_store*) may touch
 * guest memory; the module base, if needed, is `GB`.
 */
#ifndef A64PORT_HAND_H
#define A64PORT_HAND_H

#include "recomp_runtime.h"

#define A64PORT_LEAF(mod, addr) void a64port_hand_##mod##_##addr(GuestContext* c)

#define A64PORT_LEAF_FILTER(mod, addr) int a64port_hand_##mod##_##addr(GuestContext* c)

/* A64PORT_LEAF_FILTER_TO(mod, 0xADDR, 0xTARGET): a filter whose "handled" (1)
 * continues at the guest address TARGET through the emitter's own branch - a
 * goto when TARGET is in the same grouped function - instead of returning to
 * the dispatcher.  The leaf must leave the registers (and NZCV, if TARGET reads
 * them before setting them) exactly as the guest code arriving at TARGET would. */
#define A64PORT_LEAF_FILTER_TO(mod, addr, to) int a64port_hand_##mod##_##addr(GuestContext* c)

/* ── host-pointer helpers for bulk leaves ───────────────────────────────────
 * A leaf that touches many bytes should not go through recomp_load/store per
 * element.  rb_hostspan() returns a host pointer to [va, va+len) iff the whole
 * range is plain backed memory AND contiguous on the host (true for the multi
 * host's flat arena), else NULL -- the caller then returns 0 so the translated
 * body runs.  Plain host accesses bypass the exclusive-monitor bookkeeping of
 * recomp_store*, so only use them on memory no LDXR/STXR targets (pixel and
 * sample buffers).
 *
 * Two environments have to work. The multi host maps the arena through a page
 * table (`host_mem`), and the standalone differential harness owns one flat
 * buffer (`mem` + `mem_base_vaddr`, no host_mem at all). Without the flat branch
 * every bulk leaf silently declined under the differential -- and a leaf that
 * never runs is indistinguishable from a correct one, which a deliberate
 * mutation test caught: a wrong shift in one filter leaf still "passed"
 * because the filter returned 0 on every iteration. */
static inline unsigned char* rb_hostptr(GuestContext* c, uint64_t va) {
    const RecompHostMem* hm = c->host_mem;
    va &= 0xffffffffffffULL;
    if (!hm || !hm->page_entries || hm->page_bits >= 64) {
        /* Standalone / differential: one flat host allocation. The same range
           check `memptr` uses, so out-of-range never yields a pointer. */
        if (!c->mem || va < (uint64_t)c->mem_base_vaddr) return 0;
        const uint64_t off = va - c->mem_base_vaddr;
        if (off >= c->mem_size) return 0;
        return c->mem + off;
    }
    if (va < (uint64_t)c->mem_base_vaddr || va >= hm->address_space_max) return 0;
    /* Identity arena (host_loader.c): the host mapped the arena at its own
       guest addresses, so every page entry is a bias of 0 - which the table
       below would read as "unmapped". */
    if ((uintptr_t)c->mem == (uintptr_t)c->mem_base_vaddr) return (unsigned char*)(uintptr_t)va;
    uintptr_t raw = *(const uintptr_t*)((const unsigned char*)hm->page_entries +
                                        (va >> hm->page_bits) * hm->page_entry_stride);
    uintptr_t p = raw & (uintptr_t)hm->pointer_mask;
    return p ? (unsigned char*)(p + (uintptr_t)va) : 0;
}
static inline unsigned char* rb_hostspan(GuestContext* c, uint64_t va, uint64_t len) {
    if (!len) return 0;
    unsigned char* a = rb_hostptr(c, va);
    unsigned char* b = rb_hostptr(c, va + len - 1);
    if (!a || !b || (uint64_t)(b - a) != len - 1) return 0;
    return a;
}

/* rb_hostspan_id(): rb_hostspan with the identity-arena answer first (identity arena: host pointer == guest VA, so a
   range check - the same accept/decline as rb_hostspan: both ends in [mem_base_vaddr, address_space_max), no
   wrap).  For per-sample DSP leaves, which call it ~10 times per output pair (rb_hostspan was 8 % of such a
   thread in one profile).  Not forced inline (forcing rb_hostspan itself into every leaf was
   no faster).  The leafdiff hosts map it to their flat span like rb_hostspan. */
static inline unsigned char* rb_hostspan_id(GuestContext* c, uint64_t va, uint64_t len) {
    const RecompHostMem* hm = c->host_mem;
    if (len && hm && hm->page_entries && hm->page_bits < 64 && (uintptr_t)c->mem == (uintptr_t)c->mem_base_vaddr) {
        const uint64_t lo = va & 0xffffffffffffULL, hi = lo + len - 1;
        if (lo < (uint64_t)c->mem_base_vaddr || hi < lo || hi >= hm->address_space_max) return 0;
        return (unsigned char*)(uintptr_t)lo;
    }
    return rb_hostspan(c, va, len);
}

#endif /* A64PORT_HAND_H */
