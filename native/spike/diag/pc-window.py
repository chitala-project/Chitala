#!/usr/bin/env python3
"""N1.6 diagnosis: PC samples in a time window, each EL1 sample put to its guest
by the code ranges of the two images (both are loaded at 0x40600000).
Usage: pc-window.py PC_FILE CORE_ELF ADAPTER_ELF SEL4_ELF VMM_ELF FROM TO"""
import subprocess, sys
pc_file, core, adapter, sel4, vmm, lo, hi = sys.argv[1:8]
lo, hi = float(lo), float(hi)
LOAD = 0x40600000
def exec_range(elf):
    out = subprocess.run(["llvm-readelf", "-lW", elf], capture_output=True, text=True).stdout
    for l in out.splitlines():
        f = l.split()
        if f and f[0] == "LOAD" and "E" in f[6:-1]:
            return int(f[2], 16), int(f[2], 16) + int(f[5], 16)
def sym(elf, a):
    out = subprocess.run(["llvm-symbolizer", "--obj", elf, "--functions=short", hex(a)], capture_output=True, text=True).stdout
    return out.splitlines()[0][:70] if out else "?"
rc, ra = exec_range(core), exec_range(adapter)
for line in open(pc_file):
    t, el, pc = line.split(); t = float(t); pc = int(pc, 16)
    if not lo <= t <= hi:
        continue
    if el == "EL1":
        off = pc - LOAD
        who = "core" if rc[0] <= off < rc[1] else "adapter" if ra[0] <= off < ra[1] else "?"
        name = sym(core if who == "core" else adapter, off) if who != "?" else hex(pc)
        print(f"{t:8.3f} EL1 {who:7} {name}")
    else:
        print(f"{t:8.3f} {el} {'seL4' if el == 'EL2' else 'PD':7} {sym(sel4 if el == 'EL2' else vmm, pc)}")
