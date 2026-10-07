# Direction: Chitala as a Physical Trust Fabric

The Project Lead's direction of 2026-10-07, after N1.3. It does not change the architecture. It says what the architecture is for, what it protects, and in what order it grows. The plan of record is still [`ROADMAP.md`](../../ROADMAP.md); this page is the reasoning behind it.

## What Chitala is

The name stays **Chitala OS**. Architecturally, though, Chitala is a **Physical Trust Fabric**: an authority and safety fabric. Its core is a specification:
- Authority, Safety and Evidence;
- Execution, Outcome and Audit.

That specification has several deployments, all with the same semantics:

```text
                 Chitala specification
          Authority · Safety · Evidence
          Execution · Outcome · Audit
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
 Chitala Hosted    Chitala Edge     Chitala Native
 Linux, macOS      an appliance     seL4: robots, vehicles,
                   in the home      high consequence
```

**No TV or fridge runs Chitala Native.** A home has a Chitala Edge server that governs what it reaches through adapters:
- Matter;
- Home Assistant;
- BACnet;
- Modbus;
- ONVIF;
- vendor APIs.

A robot or a vehicle runs Chitala Native on seL4.

> Cosmos proposes, ROS plans, AUTOSAR controls, Matter communicates — **Chitala governs.**

## The backbone, which does not change

```text
Principal → Identity → Intent → Authority → Safety → Approval
  → Trusted Execution Boundary → ExecOrder → Adapter → physical world
  → Evidence / Outcome → Recovery / Audit
```

Five decisions are protected for the long term:
1. **An AI sends intents, never commands.**
2. **Safety only narrows.** It never creates authority.
3. **Adapters stay outside the Trusted Core.**
4. **A command is not an outcome.**
5. **A new kind of device comes as a profile and an adapter, never as a change to the core.**

## The order

1. **Now: finish Native N1.**
   - N1.4 ✅: two guests and the relay;
   - N1.5: memory, crashes, DMA, and a hostile relay;
   - N1.6: latency and time isolation;
   - N1.7: the comparison with Bao;
   - N1.8: ADR 0002.

   N1 answers the question everything else rests on: if an adapter is compromised, can Chitala's authority and safety still be trusted? No new home, TV, fridge or kitchen work starts before it.

   N1.5 goes in this order (Project Lead, 2026-10-07):
   - a: the adapter's guest loses the UART and the RTC it shares with the core's. A shared UART lets it forge the core's log, and a shared RTC lets it move the core's wall clock: a trust boundary crossed, not only a test contaminated;
   - b: memory read and write attacks;
   - c: an adapter's crash and reboot;
   - d: a hostile relay that drops, duplicates, reorders, flips or truncates;
   - e: DMA through the SMMUv3.
2. **Native Hardware Gate H0,** right after N1.8. The Native architecture runs on real silicon as early as possible, to catch the assumptions QEMU can hide:
   - the GIC, virtualization and the timer;
   - entropy;
   - the SMMU or IOMMU, where the board has one;
   - boot reliability;
   - basic latency.

   It is not a robot or a smart home. If the architecture has a problem on silicon, it is found before more is built on it.
3. **Typed Evidence.** Safety receives evidence with a source, a time, a validity, a scope, a quality and a provenance, for example an `ObstacleEvidence` or a `LocalizationEvidence`. Never a bare `safe = true`. Safety decides whether the evidence is enough. This comes before any new Safety rule.
4. **Safety Contract v0.1.** A capability declares:
   - the evidence it requires;
   - its envelope;
   - when it is denied;
   - its outcome;
   - its safe state;
   - its minimum assurance.

   The device-specific knowledge that is still in the core moves out into contracts: `SAFE-4-PHYSICAL`'s door rule, and `SAFE-9-MOTION`'s robot state keys. The core understands contracts, not kitchens, pumps or robots.
5. **Loadable, signed profiles.** Profiles are packages, outside the binary:
   - signed, versioned and schema-checked;
   - bounded;
   - each declaring outcomes, required evidence, risk, recovery and minimum assurance;
   - with vendor namespaces (`x-<vendor>.*`).

   A new machine needs no Chitala release.
6. **Assurance levels: A0 to A3, the official scale** (Project Lead, 2026-10-07). `A` stands for assurance, and is not confused with the levels of other standards.

   | Level | Means | For example | Requires |
   |---|---|---|---|
   | A0 | basic governed execution | lights, media | Hosted is enough |
   | A1 | verified execution and outcome | HVAC, a fridge | signed orders, verified outcomes |
   | A2 | high consequence | a door, a pump, a robot | isolated execution, a watchdog |
   | A3 | safety-critical, high assurance | a vehicle, a medical device | hardware roots, diverse evidence, independent safety |

   What matters more than the number of levels is that each level's requirements are **machine-checkable**. A deployment reports its properties, and the node compares them with what a capability requires:

   ```text
   capability requires A2
   deployment reports: isolation = true, watchdog = true, hardware_key = false
   → A2 met

   capability requires A2, on a deployment that only offers A0
   → DENY
   ```

   No A4 is added for more tiers' sake. The specification grows only when a real use case needs more than A3.
7. **The history evaluator in its own Native domain, and the robot deadman.**
8. **Domain hardware validation:**
   - a real robot;
   - real Matter devices;
   - a real pump or HVAC;
   - a real deadman and watchdog.

   It comes after Typed Evidence, Safety Contracts and assurance levels, so that it tests the final abstractions. Validation on real hardware is two milestones, H0 and this one, not one line.
9. **Home Profile v0.2:** climate, media, camera, pump.
10. **Kitchen, water and appliance profiles.**
11. **Robots, industry, vehicles.**

**Later:**
- hardware-backed keys;
- secure and measured boot;
- updates and rollback;
- federation across households and organisations.

## Information authority

Chitala governs AI → actuator today. The same identities, delegation and capabilities also govern **AI → sensitive information**:
- `camera.view`, `camera.record`, `camera.export_clip`;
- `microphone.listen`;
- `health.read`, `sleep.read`, `location.read`;
- `computer.read_file`.

An AI allowed to switch the lights is not thereby allowed to look through a camera. A health assistant may read heart rate, blood pressure and weight, and still may not export a clip or read a bank account. This extends the resource and capability model; it needs no new core. `device.read_history` (spec 29) is the first such capability already.

## Resources, not devices

Chitala reasons about **resources, capabilities, evidence and contracts**. Many future resources are not devices:
- a room or a building;
- a house's energy system (`house.energy` → `enter_island_mode`);
- a robot fleet;
- an AI service;
- a water or medical system.

`kitchen → emergency.shutdown` may act on several devices. The resource model already allows this, and code should not drift back to being device-centric.

## What Chitala does not build

- No Chitala AI model, LLM, SLAM, vision, media player, browser or robot planner.
- No replacement for Linux, QNX, ROS, AUTOSAR, Home Assistant, Cosmos or Isaac.

## Open design questions for the post-N1 work

These are recorded now so that the designs answer them:

- **Contracts only add.** A contract adds requirements on top of the core's minimums:
  - a stop always wins;
  - state that is unknown or stale fails safe for actions of medium risk or more;
  - nothing runs without an authorised, cleared, single-use order.

  A vendor's profile can never loosen these, and an owner's or installer's envelope can only tighten a vendor's.
- **Moving rules out of the core keeps their proof.** `SAFE-4` and `SAFE-9` move into contracts with equivalence tests, and the `safety-rules` mutation set stays green across the move.
- **A signature is not the truth.** Signed evidence proves its source, not what the source says. Evidence sources need identities. Device attestation (gap G-4) and diverse evidence matter from A2 and A3.
- **Loading a profile is governed.** It is an operation of an owner or an explicitly allowed admin, never of an AI, like history rules (spec 32). It is audited and protected against rollback, and changing a profile is a safety-affecting change.
- **The node enforces assurance.** An action whose contract needs A2 is refused on a deployment that only offers A0.
- **A platform's assurance properties are established, not claimed.** In the N1 spike, the execution host that reaches the adapter's guest reports `isolated() = true` because of the topology. N1.5 is what shows it. After N1, a property such as isolation must come from the platform's configuration, validated, or from attestation: never from a hard-coded claim.
- **Information authority controls release, not use.** Once data is released, Chitala cannot govern what is done with it. A read states its purpose and retention, and reads are audited.
- **Composite capabilities fail partway.** A resource capability that acts on several devices needs the Plan Engine's semantics for partial failure and recovery (spec 23).
