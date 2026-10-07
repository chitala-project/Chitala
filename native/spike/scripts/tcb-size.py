#!/usr/bin/env python3
"""N1.6: the size of what the core's isolation rests on, as built.

Each component of the two-guests system, its code (the text segment, from
llvm-size) and whether the core relies on it:

- the isolation TCB: what the core's isolation rests on, below it. seL4, the
  CapDL initialiser and the loader that build the system at boot, the
  Microkit's fault monitor, and the core's VMM. A fault in any of them can
  break the core's isolation;
- the core itself: the Hermit image with the Chitala node, the component
  being protected;
- outside: the relay (it can make execution fail, not happen twice or
  unsigned), the adapter's VMM and the adapter's image.

A VMM's data segment holds its guest's image, so a VMM counts by its code.
The kernel is the debug build the spike runs. Lines of C are counted for the
spike's own components (non-blank lines, comments included).

Usage: tcb-size.py --sdk-elf DIR --build DIR --images DIR --sources DIR [--out FILE]
"""
import argparse
import json
import os
import subprocess
import sys

TCB, CORE, OUTSIDE = "isolation TCB", "the core itself", "outside"
# component, file, where, role, own C sources (relative to --sources)
COMPONENTS = [
    ("seL4 kernel", "sdk:sel4.elf", TCB, "isolation, scheduling, capabilities", []),
    ("CapDL initialiser", "sdk:initialiser.elf", TCB, "builds every object and capability at boot", []),
    ("Microkit loader", "sdk:loader.elf", TCB, "loads the kernel and the system", []),
    ("Microkit monitor", "sdk:monitor.elf", TCB, "receives every protection domain's faults", []),
    ("core's VMM (libvmm)", "build:vmm_core.elf", TCB, "the core guest's faults, its virtual GIC and console", ["hermit-guest/vmm.c"]),
    ("core image (Hermit + Chitala node)", "images:chitala-native", CORE, "the Trusted Core", []),
    ("relay", "build:relay.elf", OUTSIDE, "copies bytes; can make execution fail, not happen twice or unsigned", ["two-guests/relay.c"]),
    ("adapter's VMM (libvmm)", "build:vmm_adapter.elf", OUTSIDE, "the adapter guest's faults, devices and console", ["hermit-guest/vmm.c"]),
    ("adapter image (Hermit + adapter host)", "images:chitala-native-adapter", OUTSIDE, "drives the devices", []),
]


def text_size(path):
    out = subprocess.run(["llvm-size", path], check=True, capture_output=True, text=True).stdout.splitlines()
    return int(out[1].split()[0])


def lines_of(path):
    with open(path, encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    for name in ("sdk-elf", "build", "images", "sources"):
        ap.add_argument(f"--{name}", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()
    dirs = {"sdk": args.sdk_elf, "build": args.build, "images": args.images}
    rows = []
    for name, ref, where, role, sources in COMPONENTS:
        base, file = ref.split(":")
        path = os.path.join(dirs[base], file)
        if not os.path.exists(path):
            print(f"FAIL  {name}: no {path}")
            return 1
        rows.append(
            {
                "component": name,
                "file": file,
                "where": where,
                "role": role,
                "code_bytes": text_size(path),
                "c_lines": {s: lines_of(os.path.join(args.sources, s)) for s in sources},
            }
        )
    totals = {w: sum(r["code_bytes"] for r in rows if r["where"] == w) for w in (TCB, CORE, OUTSIDE)}
    print(f"{'component':<40} {'code (KiB)':>10}  where")
    for r in rows:
        own = ", ".join(f"{os.path.basename(s)} {n} lines" for s, n in r["c_lines"].items())
        print(f"{r['component']:<40} {r['code_bytes'] / 1024:>10.1f}  {r['where']}{'  (' + own + ')' if own else ''}")
    for w, total in totals.items():
        print(f"{'total, ' + w:<40} {total / 1024:>10.1f}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"components": rows, "totals_code_bytes": totals, "kernel_config": "debug"}, f, indent=1)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
