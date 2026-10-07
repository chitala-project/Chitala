/* N1.6 diagnosis: does QEMU wake a CPU halted in an EL1 guest's WFI when the EL2
 * physical timer (CNTHP, PPI 26: seL4's scheduler timer) fires? EL2 programs
 * CNTHP every PERIOD_US, routes physical IRQs to EL2 (HCR_EL2.IMO) without
 * trapping WFI, drops to an EL1 guest that waits in WFI (or spins), and
 * records how late each timer interrupt reaches EL2. */
#include <stdint.h>
#define UART 0x09000000UL
#define GICD 0x08000000UL
#define GICR 0x080a0000UL
#define SGI_BASE (GICR + 0x10000UL)
#define HYP_TIMER 26
#ifndef PERIOD_US
#define PERIOD_US 1000
#endif
#ifndef TICKS
#define TICKS 5000
#endif
#define W32(a, v) (*(volatile uint32_t *)(a) = (v))
#define R32(a) (*(volatile uint32_t *)(a))
#define SYSR(r) ({ uint64_t _v; __asm__ volatile("mrs %0, " #r : "=r"(_v)); _v; })
#define SYSW(r, v) __asm__ volatile("msr " #r ", %0" ::"r"((uint64_t)(v)))

extern void enter_guest(void (*entry)(void), uint64_t sp);
extern void guest_wfi(void), guest_spin(void);
static uint8_t guest_stack[4096] __attribute__((aligned(16)));

static void putc_(char c) { while (R32(UART + 0x18) & 0x20) {} W32(UART, c); }
static void puts_(const char *s) { while (*s) putc_(*s++); }
static void putu(uint64_t v) { char b[21]; int i = 20; b[i] = 0; do { b[--i] = '0' + v % 10; v /= 10; } while (v); puts_(b + i); }

static uint64_t freq, period, deadline, count, late_max, buckets[5];

static void semihost_exit(void) {
    static const uint64_t args[2] = {0x20026, 0}; /* ADP_Stopped_ApplicationExit */
    register uint64_t x0 __asm__("x0") = 0x18, x1 __asm__("x1") = (uint64_t)args;
    __asm__ volatile("hlt #0xf000" : : "r"(x0), "r"(x1) : "memory");
}

static void arm(uint64_t when) { deadline = when; SYSW(cnthp_cval_el2, when); SYSW(cnthp_ctl_el2, 1); }

void irq(void) {
    uint64_t iar = SYSR(S3_0_C12_C12_0); /* ICC_IAR1_EL1 */
    if ((iar & 0xffffff) == HYP_TIMER) {
        uint64_t now = SYSR(cntpct_el0);
        uint64_t late = now > deadline ? (now - deadline) * 1000000 / freq : 0;
        if (late > late_max) late_max = late;
        buckets[late < 100 ? 0 : late < 1000 ? 1 : late < 10000 ? 2 : late < 100000 ? 3 : 4]++;
        if (++count == TICKS) {
            puts_("ticks "); putu(count); puts_(" · late max "); putu(late_max); puts_(" us · <100us ");
            putu(buckets[0]); puts_(" <1ms "); putu(buckets[1]); puts_(" <10ms "); putu(buckets[2]);
            puts_(" <100ms "); putu(buckets[3]); puts_(" >=100ms "); putu(buckets[4]); puts_("\n");
            semihost_exit();
        }
        arm(now + period);
    }
    SYSW(S3_0_C12_C12_1, iar); /* ICC_EOIR1_EL1 */
}

void main(void) {
    freq = SYSR(cntfrq_el0);
    period = freq / 1000000 * PERIOD_US;
    /* GICv3, one security state (QEMU virt, secure=off) */
    W32(GICD, (1u << 4) | 3); /* ARE, Group 0 and 1 */
    W32(GICR + 0x14, R32(GICR + 0x14) & ~2u); /* GICR_WAKER: not asleep */
    while (R32(GICR + 0x14) & 4u) {}
    W32(SGI_BASE + 0x80, R32(SGI_BASE + 0x80) | (1u << HYP_TIMER)); /* group 1 */
    *(volatile uint8_t *)(SGI_BASE + 0x400 + HYP_TIMER) = 0x80;
    W32(SGI_BASE + 0x100, 1u << HYP_TIMER); /* enable */
    SYSW(S3_4_C12_C9_5, 0xf); /* ICC_SRE_EL2 */
    __asm__ volatile("isb");
    SYSW(S3_0_C4_C6_0, 0xff); /* ICC_PMR_EL1 */
    SYSW(S3_0_C12_C12_7, 1);  /* ICC_IGRPEN1_EL1 */
    SYSW(hcr_el2, (1UL << 31) | (1UL << 4)); /* RW, IMO; WFI not trapped (TWI clear) */
    SYSW(cnthctl_el2, 3);
    SYSW(cntvoff_el2, 0);
    __asm__ volatile("isb");
#ifdef SPIN
    puts_("guest spins; ");
#else
    puts_("guest waits in WFI; ");
#endif
    puts_("CNTHP every "); putu(PERIOD_US); puts_(" us\n");
    arm(SYSR(cntpct_el0) + period);
#ifdef SPIN
    enter_guest(guest_spin, (uint64_t)(guest_stack + sizeof guest_stack));
#else
    enter_guest(guest_wfi, (uint64_t)(guest_stack + sizeof guest_stack));
#endif
}
