#!/usr/bin/env python3
"""PlatformIsolationEvidence: what a built seL4 Microkit system gives each partition.

The isolation N1 tests at run time starts as configuration: seL4 gives a
protection domain only the capabilities and mappings its CapDL spec holds.
This reads what the Microkit tool built, not only the system description:

- the CapDL spec (microkit --capdl-json): every mapping with its rights, every
  capability with its rights, every interrupt and who receives it;
- the build report (microkit -r): the physical address of every kernel
  object, the frames of RAM included;
- the system description: which protection domains and virtual machines
  make up each partition;
- a policy (isolation-policy.json): what the partitions may share, with which
  rights, and which devices and interrupts each may have.

It compares physical ranges, not names: two regions of different names over
the same memory are seen for what they are. It writes the evidence as JSON
(--out), prints each claim, and exits 1 if one fails. --self-test then breaks
the built system in memory, one way at a time, and checks that each break
fails the claims it should.

Limits: the physical addresses are those the Microkit tool assigns and
reports; the CapDL initialiser allocates by the same spec at boot. What the
running system does is N1.5b's question.

Usage: isolation-evidence.py --system FILE --capdl FILE --report FILE
                             --policy FILE [--out FILE] [--self-test]
"""
import argparse
import copy
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from bisect import bisect_left, bisect_right

SCHEMA = "chitala.platform-isolation-evidence/0.1"
# sizes (log2 bytes) of seL4 objects whose size the spec does not state (aarch64, MCS)
OBJECT_BITS = {"PageTable": 12, "Tcb": 11, "VCpu": 12, "Endpoint": 4, "Notification": 6, "Reply": 5}
REPORT_LINE = re.compile(r"^\t(\d+) - ([^:]+): '([^']+)' @ 0x([0-9a-fA-F]+)$")
FRAME_OF_REGION = re.compile(r"^frame_mr_(.+)_\d{9}$")
FRAME_INDEX = re.compile(r"_\d+$")
# a TCB's slots that hold what the thread itself is made of: CSpace, VSpace,
# IPC buffer, scheduling context, bound notification, VCPU (the fault
# endpoint, slot 5, is someone else's)
TCB_OWN_SLOTS = {0, 1, 4, 6, 8, 9}
CLAIMS = {
    "R1": "every kernel object has a physical address, and the spec agrees with the report",
    "M1": "no two kernel objects overlap physically",
    "M2": "each partition's private RAM is reachable by that partition only",
    "S1": "memory reachable by more than one partition is only what the policy declares, with no more rights",
    "S2": "no memory shared between partitions is executable",
    "D1": "each device is reachable only by the partitions the policy names, with no more rights",
    "D2": "no DMA-capable device is given to a partition",
    "C1": "no partition holds a capability to another's objects, beyond signalling a notification "
    "and reporting faults to the monitor",
    "I1": "each interrupt has one owner, which also receives it",
    "I2": "interrupts are owned as the policy declares",
}
PROPERTIES = {
    "memory_isolation": ["R1", "M1", "M2", "S1", "S2"],
    "device_isolation": ["D1"],
    # not DMA confinement (an SMMU): only that no partition is given a
    # DMA-capable device (H0, spec 33: dma_isolation is a hardware property)
    "no_dma_device_given": ["D2"],
    "capability_isolation": ["C1"],
    "irq_isolation": ["I1", "I2"],
}


class Layout(Exception):
    """The built system is not laid out as this checker understands it: fail closed."""


def kind(obj):
    o = obj["object"]
    return next(iter(o)) if isinstance(o, dict) else o


def body(obj):
    o = obj["object"]
    return o[next(iter(o))] if isinstance(o, dict) else {}


def cap_of(slot):
    (ctype, c), = slot["cap"].items()
    return ctype, c


def rights_of(ctype, c):
    r = c.get("rights", {})
    s = ("r" if r.get("read") else "") + ("w" if r.get("write") else "")
    if ctype == "Frame" and c.get("executable"):
        s += "x"
    s += ("g" if r.get("grant") else "") + ("G" if r.get("grant_reply") else "")
    return s


def within(rights, allowed):
    return set(rights) <= set(allowed)


def hexa(n):
    return f"0x{n:x}"


def read_report(path):
    addrs = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = REPORT_LINE.match(line.rstrip("\n"))
            if m:
                addrs[m.group(3)] = int(m.group(4), 16)
    return addrs


def read_system(path):
    root = ET.parse(path).getroot()
    pds = {}
    for pd in root.iter("protection_domain"):
        vm = pd.find("virtual_machine")
        vms = []
        if vm is not None:
            vms.append((vm.get("name"), [v.get("id") for v in vm.findall("vcpu")]))
        pds[pd.get("name")] = vms
    devices = {mr.get("name") for mr in root.iter("memory_region") if mr.get("phys_addr") is not None}
    return pds, devices


def analyse(spec, addrs, pds, devices, policy):
    objs = spec["objects"]
    by_name = {o["name"]: i for i, o in enumerate(objs)}
    trusted = set(policy.get("trusted", {}))

    # partitions and their threads
    parts = {}
    for part, p in policy["partitions"].items():
        tcbs, vms = [], []
        for pd in p["protection_domains"]:
            if pd not in pds:
                raise Layout(f"no protection domain {pd} in the system")
            tcbs.append(f"tcb_{pd}")
            for vm, vcpus in pds[pd]:
                vms.append(vm)
                tcbs += [f"tcb_{vm}_{v}" for v in vcpus]
        parts[part] = {"protection_domains": p["protection_domains"], "virtual_machines": vms, "tcbs": tcbs}
    for t in trusted:
        parts[t] = {"protection_domains": [t], "virtual_machines": [], "tcbs": [f"tcb_{t}"], "trusted": True}
    for part, p in parts.items():
        for t in p["tcbs"]:
            if t not in by_name or kind(objs[by_name[t]]) != "Tcb":
                raise Layout(f"no TCB {t} for partition {part}")

    # what each partition is made of
    owner, conflicts = {}, set()

    def own(part, i):
        if owner.get(i, part) != part:
            conflicts.add(i)
        owner[i] = part

    cnodes = {part: [] for part in parts}
    vspaces = {part: [] for part in parts}
    mappings = []  # (partition, vspace, vaddr, frame index, rights)

    def walk(part, vspace, i, base):
        own(part, i)
        pt = body(objs[i])
        shift = 12 + 9 * (3 - pt["level"])
        for s in pt["slots"]:
            ctype, c = cap_of(s)
            va = base + (s["slot"] << shift)
            if ctype == "PageTable":
                walk(part, vspace, c["object"], va)
            elif ctype == "Frame":
                mappings.append((part, vspace, va, c["object"], rights_of("Frame", c)))

    def own_cnode(part, i):
        own(part, i)
        cnodes[part].append(i)
        for s in body(objs[i])["slots"]:
            ctype, c = cap_of(s)
            if ctype == "CNode" and c["object"] not in cnodes[part]:
                own_cnode(part, c["object"])
            elif ctype == "Reply":
                own(part, c["object"])

    for part, p in parts.items():
        for t in p["tcbs"]:
            ti = by_name[t]
            own(part, ti)
            for s in body(objs[ti])["slots"]:
                ctype, c = cap_of(s)
                if s["slot"] not in TCB_OWN_SLOTS:
                    continue
                if ctype == "CNode":
                    own_cnode(part, c["object"])
                elif ctype == "PageTable":
                    vspaces[part].append(t[len("tcb_"):])
                    walk(part, t[len("tcb_"):], c["object"], 0)
                elif ctype in ("SchedContext", "VCpu") or (ctype == "Notification" and "r" in rights_of(ctype, c)):
                    own(part, c["object"])
    # endpoints and notifications belong to whoever receives on them; an
    # interrupt to whoever holds its handler
    for part in parts:
        for ci in cnodes[part]:
            for s in body(objs[ci])["slots"]:
                ctype, c = cap_of(s)
                if ctype in ("Endpoint", "Notification") and "r" in rights_of(ctype, c):
                    own(part, c["object"])
                elif ctype == "ArmIrqHandler":
                    own(part, c["object"])

    # physical addresses and sizes
    failures = {k: [] for k in CLAIMS}
    phys, size = {}, {}
    for i, o in enumerate(objs):
        k, b = kind(o), body(o)
        if k == "ArmIrq":
            continue
        if o["name"] not in addrs:
            failures["R1"].append(f"{o['name']} has no physical address in the report")
            continue
        phys[i] = addrs[o["name"]]
        if k == "Frame" and b.get("paddr") is not None and b["paddr"] != phys[i]:
            failures["R1"].append(f"{o['name']}: the spec says {hexa(b['paddr'])}, the report {hexa(phys[i])}")
        if k == "Frame":
            size[i] = 1 << b["size_bits"]
        elif k == "CNode":
            size[i] = 1 << (b["size_bits"] + 5)
        elif k == "SchedContext":
            size[i] = 1 << b["size_bits"]
        elif k in OBJECT_BITS:
            size[i] = 1 << OBJECT_BITS[k]
        else:
            raise Layout(f"{o['name']}: no size known for a {k}")

    order = sorted(phys, key=lambda i: phys[i])
    overlaps = []
    reach_end, reach_obj = -1, None
    for i in order:
        if phys[i] < reach_end:
            overlaps.append({"objects": [objs[reach_obj]["name"], objs[i]["name"]], "at": hexa(phys[i])})
        if phys[i] + size[i] > reach_end:
            reach_end, reach_obj = phys[i] + size[i], i
    failures["M1"] += [f"{a['objects'][0]} and {a['objects'][1]} overlap at {a['at']}" for a in overlaps]

    def region(i):
        """A frame's memory region, or for the Microkit's own frames (code, stacks), their group."""
        m = FRAME_OF_REGION.match(objs[i]["name"])
        return m.group(1) if m else FRAME_INDEX.sub("", objs[i]["name"])

    # each partition's reach: what it maps, merged into ranges for the evidence
    intervals = [(phys[f], phys[f] + size[f], part, region(f), r, vs) for part, vs, va, f, r in mappings if f in phys]
    memory_ranges = {}
    for part in parts:
        rows = sorted(
            (region(f), vs, rgt, phys[f], size[f], va) for p, vs, va, f, rgt in mappings if p == part and f in phys
        )
        groups = {}
        for reg, vs, rgt, pa, sz, va in rows:
            g = groups.setdefault((reg, vs, rgt), [])
            if g and g[-1][1] == pa:
                g[-1][1] += sz
            else:
                g.append([pa, pa + sz])
        memory_ranges[part] = [
            {
                "region": reg,
                "mapped_in": vs,
                "rights": rgt,
                "physical": [[hexa(a), hexa(b)] for a, b in sorted(g)],
                "size": sum(b - a for a, b in g),
            }
            for (reg, vs, rgt), g in groups.items()
        ]

    # who reaches each physical segment, from every mapping, whatever its name
    points = sorted({p for a, b, *_ in intervals for p in (a, b)})
    segs = [dict() for _ in points]
    seg_regions = [set() for _ in points]
    for a, b, part, reg, rgt, vs in intervals:
        for k in range(bisect_left(points, a), bisect_left(points, b)):
            segs[k][part] = "".join(sorted(set(segs[k].get(part, "")) | set(rgt), key="rwxgG".index))
            seg_regions[k].add(reg)

    def reached(start, end):
        """Partitions reaching any byte of [start, end), with their rights."""
        who = {}
        for k in range(max(bisect_right(points, start) - 1, 0), bisect_left(points, end)):
            if points[k] < end and (k + 1 < len(points) and points[k + 1] > start):
                for part, rgt in segs[k].items():
                    who[part] = "".join(sorted(set(who.get(part, "")) | set(rgt), key="rwxgG".index))
        return who

    shared = []
    for k in range(len(points) - 1):
        if len(segs[k]) < 2:
            continue
        row = {"regions": sorted(seg_regions[k]), "rights": dict(sorted(segs[k].items()))}
        if shared and shared[-1]["_end"] == points[k] and {kk: v for kk, v in shared[-1].items() if kk[0] != "_"} == row:
            shared[-1]["_end"] = points[k + 1]
        else:
            shared.append(dict(row, _start=points[k], _end=points[k + 1]))
    declared = {s["region"]: s["rights"] for s in policy.get("shared", [])}
    declared.update({d: v["rights"] for d, v in policy.get("devices", {}).items()})
    shared_regions = []
    for s in shared:
        rng = f"[{hexa(s['_start'])}, {hexa(s['_end'])})"
        ok = len(s["regions"]) == 1 and s["regions"][0] in declared
        if ok:
            allowed = declared[s["regions"][0]]
            ok = all(p in allowed and within(r, allowed[p]) for p, r in s["rights"].items())
        if not ok:
            failures["S1"].append(f"{rng} ({', '.join(s['regions'])}) is reached by {s['rights']}, not as declared")
        for p, r in s["rights"].items():
            if "x" in r:
                failures["S2"].append(f"{rng} ({', '.join(s['regions'])}) is executable in {p}")
        shared_regions.append(
            {"regions": s["regions"], "physical": [hexa(s["_start"]), hexa(s["_end"])], "rights": s["rights"], "declared": ok}
        )

    # private RAM: reached by its partition only
    private = {}
    for part, regions in policy.get("private", {}).items():
        for reg in regions:
            frames = sorted((phys[i], size[i]) for i, o in enumerate(objs) if kind(o) == "Frame" and region(i) == reg and i in phys)
            if not frames:
                failures["M2"].append(f"no frames of {reg}")
                continue
            start, end = frames[0][0], frames[-1][0] + frames[-1][1]
            if sum(sz for _, sz in frames) != end - start:
                failures["M2"].append(f"{reg} is not one physical range")
            who = reached(start, end)
            others = sorted(p for p in who if p != part)
            if others:
                failures["M2"].append(f"{reg} [{hexa(start)}, {hexa(end)}) is reachable by {', '.join(others)}")
            private[reg] = {"partition": part, "physical": [hexa(start), hexa(end)], "size": end - start, "reachable_by": sorted(who)}

    # devices
    device_rows = []
    for dev in sorted(devices):
        frames = [i for i, o in enumerate(objs) if kind(o) == "Frame" and region(i) == dev and i in phys]
        who = {}
        for i in frames:
            for p, r in reached(phys[i], phys[i] + size[i]).items():
                who[p] = "".join(sorted(set(who.get(p, "")) | set(r), key="rwxgG".index))
        pol = policy.get("devices", {}).get(dev)
        if pol is None:
            failures["D1"].append(f"{dev} is not in the policy")
            failures["D2"].append(f"{dev}: whether it can do DMA is not declared")
        else:
            for p, r in who.items():
                if p not in pol["rights"] or not within(r, pol["rights"][p]):
                    failures["D1"].append(f"{dev} is reachable by {p} with {r!r}, the policy allows {pol['rights'].get(p, 'nothing')!r}")
            if pol.get("dma") is not False:
                failures["D2"].append(f"{dev} can do DMA, and no SMMU confines it (N1.5e)")
        device_rows.append(
            {
                "region": dev,
                "what": (pol or {}).get("what"),
                "physical": [hexa(phys[frames[0]]), hexa(phys[frames[-1]] + size[frames[-1]])] if frames else None,
                "rights": dict(sorted(who.items())),
                "dma": (pol or {}).get("dma"),
            }
        )

    # capabilities: holder, object, rights; across partitions only signals and faults
    frame_parts = {}
    for part, vs, va, f, r in mappings:
        frame_parts.setdefault(f, set()).add(part)
    caps = []

    def note(part, where, slot, ctype, c):
        target = c["object"]
        towner = owner.get(target)
        if ctype == "Frame":
            cross = part not in frame_parts.get(target, {part})
            towner = ",".join(sorted(frame_parts.get(target, []))) or None
        else:
            cross = towner is not None and towner != part
        r = rights_of(ctype, c)
        allowed = None
        if cross:
            if parts[part].get("trusted"):
                allowed = "trusted"
            elif ctype == "Notification" and r == "w":
                allowed = "signal"
            elif ctype == "Endpoint" and towner in trusted and "r" not in r:
                allowed = "fault"
            else:
                failures["C1"].append(f"{part} holds {ctype} {objs[target]['name']} of {towner} ({where} slot {slot}, rights {r!r})")
        caps.append(
            {
                "holder": part,
                "in": where,
                "slot": slot,
                "object": objs[target]["name"],
                "type": ctype,
                "owner": towner,
                "rights": r,
                "cross_partition": cross,
                **({"allowed_as": allowed} if allowed else {}),
            }
        )

    for part, p in parts.items():
        for ci in cnodes[part]:
            for s in body(objs[ci])["slots"]:
                ctype, c = cap_of(s)
                note(part, objs[ci]["name"], s["slot"], ctype, c)
        for t in p["tcbs"]:
            for s in body(objs[by_name[t]])["slots"]:
                ctype, c = cap_of(s)
                note(part, t, s["slot"], ctype, c)
    for i in sorted(conflicts):
        failures["C1"].append(f"{objs[i]['name']} belongs to more than one partition")

    # interrupts
    holders = {}
    for c in caps:
        if c["type"] == "ArmIrqHandler":
            holders.setdefault(c["object"], set()).add(c["holder"])
    irq_rows, owned_irqs = [], {}
    for irq in spec.get("irqs", []):
        h = objs[irq["handler"]]
        held = sorted(holders.get(h["name"], []))
        targets = [cap_of(s)[1]["object"] for s in body(h)["slots"] if cap_of(s)[0] == "Notification"]
        receivers = sorted({owner.get(t) for t in targets if owner.get(t)})
        if len(held) != 1 or receivers != held:
            failures["I1"].append(f"IRQ {irq['irq']}: handler held by {held or 'nobody'}, received by {receivers or 'nobody'}")
        for p in held:
            owned_irqs.setdefault(p, []).append(irq["irq"])
        irq_rows.append({"irq": irq["irq"], "handler_held_by": held, "received_by": receivers, "notification": [objs[t]["name"] for t in targets]})
    want = {p: sorted(v) for p, v in policy.get("interrupts", {}).items()}
    have = {p: sorted(v) for p, v in owned_irqs.items()}
    if want != have:
        failures["I2"].append(f"interrupts owned {have}, the policy declares {want}")

    claims = [{"id": k, "statement": s, "verdict": "FAIL" if failures[k] else "PASS", "detail": failures[k]} for k, s in CLAIMS.items()]
    verdict = {c["id"]: c["verdict"] for c in claims}
    return {
        "schema": SCHEMA,
        "partitions": parts,
        "memory_ranges": memory_ranges,
        "private_memory": private,
        "kernel_object_overlaps": overlaps,
        "shared_regions": shared_regions,
        "devices": device_rows,
        "capabilities": caps,
        "interrupts": irq_rows,
        "dma": {"devices": [d["region"] for d in device_rows if d["dma"]], "smmu": "not configured (N1.5e)"},
        "claims": claims,
        "properties": {
            prop: "verified" if all(verdict[c] == "PASS" for c in ids) else "violated" for prop, ids in PROPERTIES.items()
        },
        "verdict": "PASS" if all(v == "PASS" for v in verdict.values()) else "FAIL",
        "limits": [
            "physical addresses are those the Microkit tool assigns and reports; the CapDL initialiser allocates by the same spec at boot",
            "what the running system does is tested at run time (N1.5b onwards)",
        ],
    }


def failed(evidence):
    return {c["id"] for c in evidence["claims"] if c["verdict"] == "FAIL"}


def self_test(spec, addrs, pds, devices, policy):
    """Breaks the built system in memory, one way at a time; each break must fail its claims."""
    by_name = {o["name"]: i for i, o in enumerate(spec["objects"])}

    def slots(s, name):
        return body(s["objects"][by_name[name]])["slots"]

    def first(prefix):
        return min(i for n, i in by_name.items() if n.startswith(prefix))

    def frame_cap(i, write=True, x=False):
        rights = {"read": True, "write": write, "grant": False, "grant_reply": False}
        return {"Frame": {"object": i, "rights": rights, "cached": True, "executable": x}}

    def guest_table(s):
        return slots(s, "pd_adapter_vaddr_0x40000000")

    def m_core_ram_in_adapter(s, a):
        guest_table(s).append({"slot": 300, "cap": frame_cap(first("frame_mr_core_ram_"))})

    def m_alias(s, a):
        core = first("frame_mr_core_ram_")
        s["objects"].append({"name": "frame_mr_alias_000000000", "object": {"Frame": {"size_bits": 21, "paddr": None, "init": {"entries": []}}}})
        a["frame_mr_alias_000000000"] = a[s["objects"][core]["name"]]
        guest_table(s).append({"slot": 300, "cap": frame_cap(len(s["objects"]) - 1)})

    def m_core_tcb(s, a):
        slots(s, "cnode_adapter_vmm").append({"slot": 400, "cap": {"Tcb": {"object": by_name["tcb_core_0"]}}})

    def m_irq(s, a):
        core, adapter = slots(s, "cnode_core_vmm"), slots(s, "cnode_adapter_vmm")
        handler = next(x for x in core if "ArmIrqHandler" in x["cap"])
        core.remove(handler)
        adapter.append(handler)

    def m_rtc_writable(s, a):
        for x in slots(s, "pt_adapter_vmm_vaddr_0x21000000"):
            x["cap"]["Frame"]["rights"]["write"] = True

    def m_queue_executable(s, a):
        slots(s, "pt_relay_vaddr_0x30000000")[0]["cap"]["Frame"]["executable"] = True

    def m_read_core_notification(s, a):
        rights = {"read": True, "write": False, "grant": False, "grant_reply": False}
        slots(s, "cnode_adapter_vmm").append({"slot": 401, "cap": {"Notification": {"object": by_name["ntfn_core_vmm"], "badge": 0, "rights": rights}}})

    def m_core_code_in_relay(s, a):
        slots(s, "pt_relay_vaddr_0x30000000").append({"slot": 500, "cap": frame_cap(first("frame_elf_core_vmm"), write=False)})

    breaks = [
        ("the core's RAM mapped into the adapter's guest", m_core_ram_in_adapter, {"M2", "S1"}),
        ("an alias of the core's RAM, under another name, in the adapter's guest", m_alias, {"M1", "M2", "S1"}),
        ("a capability to the core's vCPU thread for the adapter's VMM", m_core_tcb, {"C1"}),
        ("the core's interrupt handed to the adapter's VMM", m_irq, {"I1", "I2"}),
        ("the RTC writable for the adapter's VMM", m_rtc_writable, {"D1", "S1"}),
        ("a channel queue executable in the relay", m_queue_executable, {"S2"}),
        ("a right to receive on the core's notification for the adapter's VMM", m_read_core_notification, {"C1"}),
        ("a frame of the core VMM's code mapped into the relay", m_core_code_in_relay, {"S1"}),
    ]
    # a break needs what it breaks: a system whose core receives no interrupt
    # (H0.2's ZynqMP build) has no handler to hand over
    has_irq = any("ArmIrqHandler" in x["cap"] for x in slots(spec, "cnode_core_vmm"))
    if not has_irq:
        print("--    not applicable: the core's interrupt handed to the adapter's VMM (the core receives none here)")
        breaks = [b for b in breaks if b[1] is not m_irq]
    caught = 0
    for what, mutate, expected in breaks:
        s, a = copy.deepcopy(spec), dict(addrs)
        mutate(s, a)
        got = failed(analyse(s, a, pds, devices, policy))
        if expected <= got:
            caught += 1
            print(f"ok    caught: {what} → fails {', '.join(sorted(expected))}")
        else:
            print(f"FAIL  missed: {what}: fails {sorted(got) or 'nothing'}, expected {sorted(expected)}")
    print(f"self-test: {caught} of {len(breaks)} breaks caught")
    return caught == len(breaks)


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    for name in ("system", "capdl", "report", "policy"):
        ap.add_argument(f"--{name}", required=True)
    ap.add_argument("--out")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    with open(args.capdl, encoding="utf-8") as f:
        spec = json.load(f)
    with open(args.policy, encoding="utf-8") as f:
        policy = json.load(f)
    addrs = read_report(args.report)
    pds, devices = read_system(args.system)
    try:
        evidence = analyse(spec, addrs, pds, devices, policy)
    except Layout as e:
        print(f"FAIL  the built system is not laid out as expected: {e}")
        return 1
    evidence["inputs"] = {name: {"path": getattr(args, name), "sha256": sha256(getattr(args, name))} for name in ("system", "capdl", "report", "policy")}
    for c in evidence["claims"]:
        print(f"{'ok   ' if c['verdict'] == 'PASS' else 'FAIL '} {c['id']} {c['statement']}")
        for d in c["detail"][:5]:
            print(f"        {d}")
    for reg, p in evidence["private_memory"].items():
        print(f"      {reg}: physical [{p['physical'][0]}, {p['physical'][1]}), reachable by {', '.join(p['reachable_by'])}")
    print("      properties: " + ", ".join(f"{k} {v}" for k, v in evidence["properties"].items()))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=1)
            f.write("\n")
    ok = evidence["verdict"] == "PASS"
    if args.self_test:
        ok = self_test(spec, addrs, pds, devices, policy) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
