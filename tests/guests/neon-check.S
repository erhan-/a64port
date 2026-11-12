/* SPDX-License-Identifier: GPL-2.0-or-later */
/* neon-check.S — exercise every vector operation the emitter's fast path
 * rewrites (SSHLL/USHLL, SSHR/USHR/SHL, integer ADD/SUB/MUL, DUP, LD1R) with
 * edge inputs, including sign boundaries and shifts, and write the raw 32
 * vector registers so the translated binary can be compared byte-for-byte
 * against qemu-aarch64.
 *
 * The inputs are chosen so that a signed/unsigned mix-up, a wrong half, a
 * wrong lane, or a lost shift changes the output: pat1 has 0x80/0xFF (sign
 * bits) and pat2 has 0x8000/0xFFFF, pat3 has 0x80000000/0xFFFFFFFF. Q=0 forms
 * are included too, because the fast path deliberately leaves them on the
 * generic body and both must agree.
 */
    .section .rodata
    .balign 16
pats:
pat0: .byte  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
pat1: .byte  0x80,0xff,0x7f,0x01,0x00,0xfe,0x02,0xaa,0x55,0x80,0xff,0x7f,0x00,0x01,0xfe,0x02
pat2: .hword 0x0000,0x0001,0x7fff,0x8000,0xffff,0x1234,0xabcd,0x0002
pat3: .word  0x00000000,0xffffffff,0x80000000,0x7fffffff
pat4: .hword 0x0002,0x0003,0x0004,0x0005,0x0006,0x0007,0x0008,0x0009
    .balign 16
scalar:
    .word  0xdeadbeef

    .section .bss
    .balign 16
buf:
    .space 512
    .text
    .global _start
_start:
    adrp x0, pats
    add  x0, x0, :lo12:pats
    ldr  q0, [x0, #0]
    ldr  q1, [x0, #16]
    ldr  q2, [x0, #32]
    ldr  q3, [x0, #48]
    ldr  q4, [x0, #64]
    adrp x1, scalar
    add  x1, x1, :lo12:scalar

    /* SSHLL / USHLL, byte -> half, low and high half, with a shift */
    ushll  v10.8h, v1.8b,  #3
    ushll2 v11.8h, v1.16b, #3
    sshll  v12.8h, v1.8b,  #2
    sshll2 v13.8h, v1.16b, #2

    /* SSHLL / USHLL, half -> word */
    ushll  v14.4s, v2.4h,  #1
    ushll2 v15.4s, v2.8h,  #1
    sshll  v16.4s, v2.4h,  #2
    sshll2 v17.4s, v2.8h,  #2

    /* shifts right/left, Q=1 and Q=0 */
    ushr   v18.4s, v3.4s, #8
    sshr   v19.4s, v3.4s, #8
    shl    v20.4s, v3.4s, #8
    ushr   v21.8h, v2.8h, #4
    sshr   v22.8h, v2.8h, #4
    shl    v23.8h, v2.8h, #4
    ushr   v5.2s,  v3.2s, #4      /* Q=0: generic path */
    shl    v6.4h,  v2.4h, #3      /* Q=0: generic path */

    /* three-register same, integer */
    add    v24.4s, v3.4s, v2.4s
    sub    v25.4s, v3.4s, v2.4s
    mul    v26.4s, v3.4s, v2.4s
    add    v27.16b, v1.16b, v2.16b
    sub    v28.16b, v1.16b, v2.16b
    mul    v29.8h, v2.8h, v4.8h
    add    v7.8h,  v2.8h, v4.8h    /* Q=1 halving: 8h is 128 bits */

    /* DUP (element) */
    dup    v30.4s, v3.s[2]
    dup    v31.8h, v2.h[5]

    /* LD1R */
    ld1r   {v8.4s},  [x1]
    ld1r   {v9.16b}, [x1]

    /* store all 32 vector registers */
    adrp x2, buf
    add  x2, x2, :lo12:buf
    str q0,  [x2, #0]
    str q1,  [x2, #16]
    str q2,  [x2, #32]
    str q3,  [x2, #48]
    str q4,  [x2, #64]
    str q5,  [x2, #80]
    str q6,  [x2, #96]
    str q7,  [x2, #112]
    str q8,  [x2, #128]
    str q9,  [x2, #144]
    str q10, [x2, #160]
    str q11, [x2, #176]
    str q12, [x2, #192]
    str q13, [x2, #208]
    str q14, [x2, #224]
    str q15, [x2, #240]
    str q16, [x2, #256]
    str q17, [x2, #272]
    str q18, [x2, #288]
    str q19, [x2, #304]
    str q20, [x2, #320]
    str q21, [x2, #336]
    str q22, [x2, #352]
    str q23, [x2, #368]
    str q24, [x2, #384]
    str q25, [x2, #400]
    str q26, [x2, #416]
    str q27, [x2, #432]
    str q28, [x2, #448]
    str q29, [x2, #464]
    str q30, [x2, #480]
    str q31, [x2, #496]

    /* write(1, buf, 512) */
    mov  x0, #1
    mov  x1, x2
    mov  x2, #512
    mov  x8, #64
    svc  #0

    /* exit(0) */
    mov  x0, #0
    mov  x8, #93
    svc  #0
