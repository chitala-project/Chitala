#!/usr/bin/env python3
"""N1.6 (WIP): the PC samples, with function names, as runs of the same function.
Usage: pc-symbols.py PC_FILE GUEST_ELF SEL4_ELF VMM_ELF [FROM_S TO_S]"""
import subprocess, sys
pc_file, guest, sel4, vmm = sys.argv[1:5]
lo, hi = (float(sys.argv[5]), float(sys.argv[6])) if len(sys.argv) > 6 else (0, 1e9)
LOAD = 0x40600000  # where the Hermit loader puts a guest's image (its boot log)
other = sys.argv[7] if len(sys.argv) > 7 else None  # the other guest's image, if any
rows = [l.split() for l in open(pc_file) if l.strip()]
elf = {"EL1": guest, "EL2": sel4, "EL0": vmm}
names = {}
def symbolize(path, addrs):
    out = subprocess.run(["llvm-symbolizer", "--obj", path, "--functions=short", "--no-inlines", "--demangle"]
                         + [hex(a) for a in addrs], capture_output=True, text=True).stdout.split("\n\n")
    return [(b.strip().split("\n") or ["?"])[0][:60] for b in out]
for el, path in elf.items():
    pcs = sorted({r[2] for r in rows if r[1] == el})
    if not pcs:
        continue
    if el == "EL1":
        addrs = [int(p, 16) - LOAD for p in pcs]
        a = symbolize(path, addrs)
        b = symbolize(other, addrs) if other else ["-"] * len(pcs)
        for p, x, y in zip(pcs, a, b):
            names[(el, p)] = f"core? {x} | adapter? {y}"
    else:
        for p, n in zip(pcs, symbolize(path, [int(p, 16) for p in pcs])):
            names[(el, p)] = n
runs = []
for t, el, pc in rows:
    t = float(t)
    if not lo <= t <= hi:
        continue
    name = f"{el} {names.get((el, pc), '?')}"
    if runs and runs[-1][2] == name:
        runs[-1][1] = t
    else:
        runs.append([t, t, name])
for a, b, name in runs:
    print(f"{a:8.3f} .. {b:8.3f} ({(b - a) * 1000:5.0f} ms) {name}")
