#!/usr/bin/env python3
"""N1.5a: what the two-guests system description gives each partition.

The isolation N1.5 tests at run time starts as configuration: seL4 maps a
protection domain only what the system description gives it. This reads that
description (sel4/two-guests/two-guests.system), the one the Microkit tool
builds the image from, and checks each claim on its own:

- the two guests share no memory region;
- the adapter's guest maps its own RAM and nothing else: no device of the
  board, nothing of the core's;
- what the adapter's VMM maps of the board is read-only;
- the adapter's partition takes no interrupt of the board;
- the core's RAM is mapped only into the core's guest and its VMM;
- the relay maps no guest's memory and no device: only the channels' queues.

Usage: check-system.py SYSTEM_FILE. Exits 1 if a claim fails.
"""
import sys
import xml.etree.ElementTree as ET

CORE, ADAPTER, RELAY = "core_vmm", "adapter_vmm", "relay"


def main(path):
    root = ET.parse(path).getroot()
    regions = {mr.get("name"): mr for mr in root.iter("memory_region")}
    devices = {name for name, mr in regions.items() if mr.get("phys_addr") is not None}
    pds = {pd.get("name"): pd for pd in root.iter("protection_domain")}
    for name in (CORE, ADAPTER, RELAY):
        if name not in pds:
            print(f"FAIL  no protection domain {name} in {path}")
            return 1

    def maps(element):
        """The memory regions mapped directly into this PD or VM, with their permissions."""
        return {m.get("mr"): m.get("perms", "rw") for m in element.findall("map")}

    def vm(pd):
        return pd.find("virtual_machine")

    core_vm, adapter_vm = maps(vm(pds[CORE])), maps(vm(pds[ADAPTER]))
    adapter_vmm, relay = maps(pds[ADAPTER]), maps(pds[RELAY])

    failed = 0

    def claim(what, ok, why=""):
        nonlocal failed
        print(f"{'ok   ' if ok else 'FAIL '} {what}{'' if ok else ': ' + why}")
        failed += not ok

    shared = set(core_vm) & set(adapter_vm)
    claim("the two guests share no memory region", not shared, ", ".join(sorted(shared)))
    claim(
        "the adapter's guest maps its own RAM and nothing else",
        set(adapter_vm) == {"adapter_ram"},
        ", ".join(sorted(adapter_vm)),
    )
    writable = {mr for mr, perms in adapter_vmm.items() if mr in devices and "w" in perms}
    claim("the adapter's VMM maps no device of the board writable", not writable, ", ".join(sorted(writable)))
    irqs = [irq.get("irq") for irq in pds[ADAPTER].iter("irq")]
    claim("the adapter's partition takes no interrupt of the board", not irqs, ", ".join(irqs))
    holders = sorted(
        [name for name, pd in pds.items() if "core_ram" in maps(pd)]
        + [f"{name}'s guest" for name, pd in pds.items() if vm(pd) is not None and "core_ram" in maps(vm(pd))]
    )
    claim(
        "the core's RAM is mapped only into the core's guest and its VMM",
        holders == sorted([CORE, f"{CORE}'s guest"]),
        ", ".join(holders),
    )
    guest_memory = set().union(*(maps(vm(pd)) for pd in pds.values() if vm(pd) is not None))
    seen = sorted(set(relay) & (guest_memory | devices))
    claim("the relay maps no guest's memory and no device", relay and not seen, ", ".join(seen))
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
