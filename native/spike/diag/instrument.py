# temporary: count vGIC and WFx events in a copy of libvmm (N1.6 investigation, not committed)
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
