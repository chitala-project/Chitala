/* N1.6 (WIP): a minimal reproducer for QEMU. EL2 code: vectors, entry, and
 * the drop to an EL1 "guest" that waits in WFI (or spins). */
    .section .text.boot, "ax"
    .global _start
_start:
    ldr x0, =stack_top
    mov sp, x0
    adr x0, vectors
    msr vbar_el2, x0
    isb
    bl main
1:  wfe
    b 1b

    .global enter_guest
enter_guest:            /* x0: guest entry, x1: guest stack */
    msr elr_el2, x0
    msr sp_el1, x1
    mov x2, #0x3c5      /* EL1h, DAIF masked: physical IRQs still go to EL2 (HCR_EL2.IMO) */
    msr spsr_el2, x2
    isb
    eret

    .global guest_wfi
guest_wfi:
1:  wfi
    b 1b

    .global guest_spin
guest_spin:
1:  yield
    b 1b

.macro save_call fn
    sub sp, sp, #0xa0
    stp x0, x1, [sp, #0x00]
    stp x2, x3, [sp, #0x10]
    stp x4, x5, [sp, #0x20]
    stp x6, x7, [sp, #0x30]
    stp x8, x9, [sp, #0x40]
    stp x10, x11, [sp, #0x50]
    stp x12, x13, [sp, #0x60]
    stp x14, x15, [sp, #0x70]
    stp x16, x17, [sp, #0x80]
    stp x18, x30, [sp, #0x90]
    bl \fn
    ldp x0, x1, [sp, #0x00]
    ldp x2, x3, [sp, #0x10]
    ldp x4, x5, [sp, #0x20]
    ldp x6, x7, [sp, #0x30]
    ldp x8, x9, [sp, #0x40]
    ldp x10, x11, [sp, #0x50]
    ldp x12, x13, [sp, #0x60]
    ldp x14, x15, [sp, #0x70]
    ldp x16, x17, [sp, #0x80]
    ldp x18, x30, [sp, #0x90]
    add sp, sp, #0xa0
    eret
.endm

    .balign 0x800
vectors:
    .org vectors + 0x000
    b .
    .org vectors + 0x080
    b .
    .org vectors + 0x200
    b .
    .org vectors + 0x280        /* IRQ at EL2 */
    save_call irq
    .org vectors + 0x400
    b .
    .org vectors + 0x480        /* IRQ from EL1 (the guest) */
    save_call irq
    .org vectors + 0x800
