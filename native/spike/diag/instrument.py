# N1.6 diagnosis: count vGIC and WFx events, and time the virtual timer's path, in a copy of libvmm (diag/run.sh and diag/core-alone.sh apply it to their own copy)
import re, sys
root = sys.argv[1]
def edit(rel, pairs):
    p = f"{root}/{rel}"; s = open(p).read()
    for old, new in pairs:
        assert s.count(old) == 1, (rel, old[:60]); s = s.replace(old, new)
    open(p, "w").write(s)
LOG2 = 'diag_{n}++; if ((diag_{n} & (diag_{n} - 1)) == 0) {{ LOG_VMM("diag {n} #%lu{extra}\\n", (unsigned long)diag_{n}{args}); }}'
def ctr(n, extra="", args=""):
    return LOG2.format(n=n, extra=extra, args=args)
edit("src/arch/aarch64/fault.c", [
    ("bool fault_handle_vcpu_exception(size_t vcpu_id)\n{",
     "unsigned long diag_wfx, diag_vppi, diag_maint;\nbool fault_handle_vcpu_exception(size_t vcpu_id)\n{"),
    ("    case HSR_WFx_EXCEPTION:\n", "    case HSR_WFx_EXCEPTION:\n        " + ctr("wfx", " hsr 0x%lx", ", (unsigned long)hsr") + "\n"),
    ("    uint64_t ppi_irq = microkit_mr_get(seL4_VPPIEvent_IRQ);\n",
     "    uint64_t ppi_irq = microkit_mr_get(seL4_VPPIEvent_IRQ);\n    " + ctr("vppi", " irq %lu", ", (unsigned long)ppi_irq") + "\n"),
    ("success = vgic_handle_fault_maintenance(vcpu_id);", ctr("maint") + " success = vgic_handle_fault_maintenance(vcpu_id);"),
])
# the virtual timer: how late its interrupt reaches the VMM after the guest's
# deadline (CNTV_CVAL + CNTVOFF, in physical counter ticks), and gaps between
# two of them longer than 100 ms
edit("src/arch/aarch64/fault.c", [
    ("unsigned long diag_wfx, diag_vppi, diag_maint;\n",
     """unsigned long diag_wfx, diag_vppi, diag_maint;
static uint64_t diag_freq, diag_last_vppi, diag_late_max;
static inline uint64_t diag_ticks(void) { uint64_t v; asm volatile("isb; mrs %0, cntpct_el0" : "=r"(v)); return v; }
static void diag_timer(size_t vcpu_id)
{
    uint64_t now = diag_ticks();
    if (!diag_freq) {
        asm volatile("mrs %0, cntfrq_el0" : "=r"(diag_freq));
        LOG_VMM("diag cntvoff %lu freq %lu\\n", (unsigned long)microkit_vcpu_arm_read_reg(vcpu_id, seL4_VCPUReg_CNTVOFF), (unsigned long)diag_freq);
    }
    if (diag_last_vppi && now - diag_last_vppi > diag_freq / 10) {
        LOG_VMM("diag vppi gap %lu ms at %lu ms\\n", (unsigned long)((now - diag_last_vppi) * 1000 / diag_freq),
                (unsigned long)(now * 1000 / diag_freq));
    }
    diag_last_vppi = now;
    uint64_t due = microkit_vcpu_arm_read_reg(vcpu_id, seL4_VCPUReg_CNTV_CVAL)
                 + microkit_vcpu_arm_read_reg(vcpu_id, seL4_VCPUReg_CNTVOFF);
    if (now > due) {
        uint64_t late = (now - due) * 1000000 / diag_freq;
        if (late > diag_late_max) {
            diag_late_max = late;
            if (late >= 1000) {
                LOG_VMM("diag vtimer late %lu us (new max) at %lu ms\\n", (unsigned long)late, (unsigned long)(now * 1000 / diag_freq));
            }
        }
    }
}
"""),
    ("    uint64_t ppi_irq = microkit_mr_get(seL4_VPPIEvent_IRQ);\n",
     "    uint64_t ppi_irq = microkit_mr_get(seL4_VPPIEvent_IRQ);\n    if (ppi_irq == 27) { diag_timer(vcpu_id); }\n"),
])
# T2..T4 of the timer's path (N1.6 B2), in the counter the guest reads
# (CNTVOFF is 0): when the VPPI reaches the VMM against the deadline the guest
# set (only with the timer enabled), when the VMM has injected it, and when the
# guest's EOI acknowledges it. A line when any segment exceeds 20 ms.
edit("src/arch/aarch64/fault.c", [
    ("static uint64_t diag_freq, diag_last_vppi, diag_late_max;\n",
     """static uint64_t diag_freq, diag_last_vppi, diag_late_max;
static uint64_t diag_due, diag_t2, diag_t3;
static unsigned long diag_seg_lines;
void diag_vppi_ack(void)
{
    uint64_t t4, lim;
    asm volatile("isb; mrs %0, cntpct_el0" : "=r"(t4));
    if (!diag_t2 || !diag_freq) { return; }
    lim = diag_freq / 50;
    if (diag_seg_lines < 300 && ((diag_due && diag_t2 > diag_due + lim) || diag_t3 > diag_t2 + lim || t4 > diag_t3 + lim)) {
        diag_seg_lines++;
        LOG_VMM("diag seg due %lu t2 %lu t3 %lu t4 %lu\\n", (unsigned long)diag_due, (unsigned long)diag_t2,
                (unsigned long)diag_t3, (unsigned long)t4);
    }
    diag_t2 = 0;
}
"""),
    ("    diag_last_vppi = now;\n",
     """    diag_last_vppi = now;
    diag_t2 = now;
    diag_due = (microkit_vcpu_arm_read_reg(vcpu_id, seL4_VCPUReg_CNTV_CTL) & 1)
               ? microkit_vcpu_arm_read_reg(vcpu_id, seL4_VCPUReg_CNTV_CVAL) : 0;
"""),
    ("    bool success = vgic_inject_irq(vcpu_id, ppi_irq);\n",
     "    bool success = vgic_inject_irq(vcpu_id, ppi_irq);\n    if (ppi_irq == 27) { asm volatile(\"isb; mrs %0, cntpct_el0\" : \"=r\"(diag_t3)); }\n"),
])
edit("src/arch/aarch64/virq.c", [
    ("static void vppi_event_ack(irq_routing_info_t irq_routing_info, void *cookie)\n{\n",
     "void diag_vppi_ack(void);\nstatic void vppi_event_ack(irq_routing_info_t irq_routing_info, void *cookie)\n{\n    diag_vppi_ack();\n"),
])
edit("src/arch/aarch64/vgic/vgic_v3_cpuif.c", [
    ("bool icc_sgi1r_el1_write(size_t vcpu_id, seL4_UserContext *regs, uint64_t data)\n{",
     "unsigned long diag_sgi;\nbool icc_sgi1r_el1_write(size_t vcpu_id, seL4_UserContext *regs, uint64_t data)\n{\n    " + ctr("sgi", " data 0x%lx", ", (unsigned long)data")),
])
edit("include/libvmm/arch/aarch64/vgic/vdist.h", [
    ("static bool vgic_dist_set_pending_irq(vgic_t *vgic, size_t vcpu_id, int irq)\n{",
     "static unsigned long diag_dedup, diag_nolr, diag_disabled;\nstatic bool vgic_dist_set_pending_irq(vgic_t *vgic, size_t vcpu_id, int irq)\n{"),
    ("        if (!is_enabled(vgic, irq, vcpu_id)) {\n",
     "        " + ctr("disabled", " irq %d", ", irq") + "\n        if (!is_enabled(vgic, irq, vcpu_id)) {\n"),
    ("        // Do nothing if it's already pending\n", "        // Do nothing if it's already pending\n        " + ctr("dedup", " irq %d", ", irq") + "\n"),
    ("        /* There were no empty list registers available, but that's not a big\n",
     "        " + ctr("nolr", " irq %d", ", irq") + "\n        /* There were no empty list registers available, but that's not a big\n"),
])
print("instrumented", root)
