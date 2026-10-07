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
