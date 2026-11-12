/* SPDX-License-Identifier: GPL-2.0-or-later */
/* peephole-check.S — exercise every identity/absorbing peephole the emitter
 * added, plus the 32-bit move forms, and write the raw results so the
 * translated binary can be compared byte-for-byte with qemu-aarch64. */
    .section .bss
buf:
    .space 256
    .text
    .global _start
_start:
    /* x1 = 0x123456789abcdef0 */
    movz x1, #0xdef0
    movk x1, #0x9abc, lsl #16
    movk x1, #0x5678, lsl #32
    movk x1, #0x1234, lsl #48

    /* --- 64-bit, XZR as Rn (a_zero) --- */
    orr  x2, xzr, x1          /* MOV: result = x1 */
    eor  x3, xzr, x1          /* result = x1 */
    and  x4, xzr, x1          /* result = 0 */
    bic  x5, xzr, x1          /* result = 0 */
    orr  x6, xzr, x1, lsl #4  /* result = x1<<4 */
    orr  x7, xzr, x1, lsr #8  /* result = x1>>8 */
    orr  x8, xzr, x1, asr #4  /* result = x1>>4 arithmetic */
    orr  x9, xzr, x1, ror #8  /* result = ror(x1,8) */

    /* --- 64-bit, XZR as Rm (m_zero) --- */
    orr  x10, x1, xzr         /* result = x1 */
    eor  x11, x1, xzr         /* result = x1 */
    and  x12, x1, xzr         /* result = 0 */
    bic  x13, x1, xzr         /* result = x1 & ~0 = x1 */

    /* --- 32-bit forms (must zero the top half) --- */
    orr  w14, wzr, w1         /* result = (u32)x1 */
    eor  w15, wzr, w1
    and  w16, wzr, w1         /* 0 */
    bic  w17, wzr, w1         /* 0 */
    orr  w18, w1, wzr         /* (u32)x1 */
    and  w19, w1, wzr         /* 0 */
    bic  w20, w1, wzr         /* (u32)x1 */
    orr  w21, wzr, w1, lsl #4
    orr  w22, wzr, w1, lsr #8

    /* --- move wide, 32- and 64-bit --- */
    movz w23, #0x1234
    movz w24, #0xabcd, lsl #16
    movn w25, #0
    movn w26, #1, lsl #16
    movz x27, #0xbeef, lsl #32

    /* fold everything into a 64-bit checksum and a byte stream */
    add x2, x2, x3
    add x2, x2, x4
    add x2, x2, x5
    add x2, x2, x6
    add x2, x2, x7
    add x2, x2, x8
    add x2, x2, x9
    add x2, x2, x10
    add x2, x2, x11
    add x2, x2, x12
    add x2, x2, x13
    add x2, x2, x14
    add x2, x2, x15
    add x2, x2, x16
    add x2, x2, x17
    add x2, x2, x18
    add x2, x2, x19
    add x2, x2, x20
    add x2, x2, x21
    add x2, x2, x22
    add x2, x2, x23
    add x2, x2, x24
    add x2, x2, x25
    add x2, x2, x26
    add x2, x2, x27

    /* Also store several raw results so any single wrong lane is visible. */
    adrp x28, buf
    add  x28, x28, :lo12:buf
    stp  x2, x3, [x28]
    stp  x4, x5, [x28, #16]
    stp  x6, x7, [x28, #32]
    stp  x8, x9, [x28, #48]
    stp  x10, x13, [x28, #64]
    stp  x14, x20, [x28, #80]
    stp  x21, x24, [x28, #96]
    stp  x25, x27, [x28, #112]

    /* write(1, buf, 128) */
    mov  x0, #1
    mov  x1, x28
    mov  x2, #128
    mov  x8, #64
    svc  #0

    /* exit(0) */
    mov  x0, #0
    mov  x8, #93
    svc  #0
