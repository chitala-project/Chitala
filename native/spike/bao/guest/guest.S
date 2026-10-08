/*
 * N1.7 (bounded Bao comparison): a minimal bare-metal guest for Bao on
 * qemu-aarch64-virt. It writes one line to the PL011 UART (0x09000000) and
 * then waits. Its only purpose is to show, when Bao reaches a guest, that a
 * static partition runs; it is not the Chitala Native image (N1.7c, which was
 * not demonstrated within the N1.7-C time-box). Position-independent: the UART
 * address is absolute and the message is addressed PC-relative, so it runs at
 * whatever base the config loads it to.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
.section ".text"
.globl _start
_start:
	movz	x1, #0x0900, lsl #16	/* x1 = 0x09000000, the PL011 data register */
	adr	x0, msg
1:	ldrb	w2, [x0], #1
	cbz	w2, 2f
	str	w2, [x1]
	b	1b
2:	wfe
	b	2b
.align 3
msg:
	.asciz "BAO-GUEST: a static partition runs (N1.7)\n"
