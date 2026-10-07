#!/usr/bin/env python3
"""N1.6 diagnosis: the core guest's PC samples within the slow samples' windows,
counted by function (full symbol, inlines included).
Usage: pc-profile.py RUN_DIR CORE_ELF"""
import collections, re, subprocess, sys
run, core = sys.argv[1:3]
LOAD, FREQ = 0x40600000, 62.5e6
text = open(f"{run}/boot.txt", errors="replace").read()
windows = [((int(b) / FREQ) - int(a) / 1000, int(b) / FREQ) for a, b in re.findall(r"slow: (\d+) ms, ended at virtual counter (\d+)", text)]
out = subprocess.run(["llvm-readelf", "-lW", core], capture_output=True, text=True).stdout
lo, hi = next((int(f[2], 16), int(f[2], 16) + int(f[5], 16)) for f in (l.split() for l in out.splitlines()) if f and f[0] == "LOAD" and "E" in f[6:-1])
inside, total = collections.Counter(), 0
for line in open(f"{run}/pc.txt"):
    t, el, pc = line.split(); t = float(t)
    if not any(a <= t <= b for a, b in windows):
        continue
    total += 1
    off = int(pc, 16) - LOAD
    if el == "EL1" and lo <= off < hi:
        inside[off] += 1
print(f"windows: {[(round(a,3), round(b,3)) for a, b in windows]} · samples in them: {total} · in the core guest: {sum(inside.values())}")
names = collections.Counter()
for off, n in inside.items():
    r = subprocess.run(["llvm-symbolizer", "--obj", core, "--functions=short", "--inlines", hex(off)], capture_output=True, text=True).stdout
    frames = [l for i, l in enumerate(r.strip().splitlines()) if i % 2 == 0]
    names[" < ".join(f[:45] for f in frames[:4])] += n
for name, n in names.most_common(15):
    print(f"{n:4} {name}")
