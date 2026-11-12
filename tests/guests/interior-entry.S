/* SPDX-License-Identifier: GPL-2.0-or-later */
/* interior-entry.S — force a mid-block indirect entry.
 *
 * The only way recomp_lookup can return a block for an address that is not the
 * block's start is a *computed* branch whose target is an interior instruction.
 * Discovery seeds every statically visible target (direct branches, FDE/dynsym
 * roots, ADRP+ADD results), so to make the target invisible to it the address is
 * read from a .data pointer at run time.
 *
 *   entry -> first (block start)  first = [mov w4 | mid_target: mov w5 |
 *                                            mov w6 | cbz w7, do_jump]
 *   pass 1 enters at the block start, sets w7, and branches to mid_target
 *   pass 2 enters at mid_target (interior, index 1 -> _L1) and exits 42.
 *
 * If the interior-entry dispatch is wrong this halts instead of exiting 42.
 *
 *   aarch64-linux-gnu-gcc -nostdlib -static interior-entry.S -o interior-entry-a64
 */
    .section .data
ptr:
    .quad mid_target

    .text
    .global _start
_start:
    b first

first:
    mov w4, #1
mid_target:
    mov w5, #2
    mov w6, #3
    cbz w7, do_jump
    /* second pass, entered directly at mid_target: exit 42 */
    mov w8, #93
    mov w0, #42
    svc #0

do_jump:
    mov w7, #1
    adrp x1, ptr
    add  x1, x1, :lo12:ptr
    ldr  x0, [x1]
    br   x0
