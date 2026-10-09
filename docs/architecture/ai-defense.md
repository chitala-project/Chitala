# Comprehensive defense against AI (target)

**Status:** a target. The project owner set it on 2026-10-09, and it awaits the Project Lead's review. Nothing in it is built unless its row says so. It sets where the [software track](../../ROADMAP.md#the-software-track-while-h0-waits-for-hardware) is going and adds items to it. It changes no decision already taken: P0 stays first, and the track's order stands.

## Where Chitala stands

Chitala is a useful layer of defense today. On Chitala's path, it limits what an AI may do: its authority, the safety conditions that are defined, the approvals a person gives, and a record of all of it.

It is not yet a comprehensive defense against AI:
- the defects of P0 are not all fixed;
- Safety does not decide on typed evidence, and there are no Safety Contracts yet;
- nothing enforces Chitala's decision at the device;
- the whole protective path has not been verified under load and faults;
- the node has no hardened substrate in use;
- no AI has yet been set to attack Chitala itself.

## The goal

A comprehensive defense against AI, stated so that it can be checked:

1. **Complete mediation.** Every way an AI can act on a device, on a person's data or through a service passes a point that Chitala controls: on the node, at the device, and at the way out of the AI's runtime.
2. **Each layer fails closed.** When a layer fails or is unsure, it refuses, or brings things to a safe state. No layer's failure opens another.
3. **Defense in depth against AI as an attacker.** The node is built so that a capable AI attacker who finds a bug gains as little as possible.
4. **Evidence for every claim.** Each claim has a test that anyone can run again: under load, under faults, and against an attacking AI, with its environment and commit stated. An assurance case names what remains.

Chitala never claims that it stops every attack by an AI. A protection that claims that makes a promise; Chitala makes claims it can show. That is how it intends to be the stronger defense:
- **wider:** both directions of threat below, not one;
- **deeper:** enforcement down to the device, not only on the node;
- **shown:** tests, an open challenge on a published configuration, and an assurance case.

## Two directions of threat

| | AI attacks the system | AI acts through what it was given |
|---|---|---|
| What happens | an AI finds and exploits a bug, in Chitala, its host, a device or a service | an AI with real tokens and tools is steered, deceives, splits a goal, or goes around a check |
| Examples | a memory-safety bug in a parser; a kernel exploit; a flood that denies the owner control | an instruction hidden in a web page; an approver tired by questions; a door opened in small steps; a platform token used directly |
| What answers it | a small trusted base, memory safety, isolation by a verified kernel, signed boot and updates, fuzzing and proofs | authority, safety on evidence, approval bound to its context, containment of the runtime, enforcement at the device |

A protection built on a certified kernel alone answers the first direction. Chitala must answer both.

## Threats from AI

| | Threat | Layers | Status today |
|---|---|---|---|
| T1 | Acting beyond its authority | L1 | implemented: Authority, delegation limits, revocation |
| T2 | Being steered by content: a web page, a message, a document, a device's name | L1, L2 | partly: content grants nothing; approvals. The runtime is not contained (L2) |
| T3 | Deceiving or tiring the person who approves | L1 | partly: P1a. Context bound to the approval (P1b) and what people understand (G-9) remain |
| T4 | Splitting a harmful goal into small permitted steps | L1 | partly: checked history constraints (`SAFE-10`). P5 and D2 remain |
| T5 | Lying about the world: spoofed or stale evidence | L1, L3 | partly: P2 (types). P3 and attestation (D3, gap G-4) remain |
| T6 | Going around Chitala: a platform's token, a direct network path, another control path | L2, L3 | design: P8, credential custody ([apps and services](apps-and-services.md)); gap G-8 |
| T7 | Taking data out | L1, L2 | design: information authority (P7), labels and the broker |
| T8 | Denying the owner control: floods, replays, full queues | L1 | in progress: P0 |
| T9 | Changing its own rules: policy, profiles, its permissions, Chitala's software | L1, L4 | partly: loosening needs an owner and is audited. P7 and D4 remain |
| T10 | Many agents together: collusion, chains of delegation | L1 | partly: delegation limits. D2 remains |
| T11 | Exploiting a bug in Chitala or its host | L4, L5 | partly: Rust, fuzzing, mutation runs. Native on seL4 (N1, H0), D1 and D5 remain |
| T12 | Exploiting a device or its firmware, below Chitala | L3 | out of Chitala's reach, except enforcement at the device (P8) and attestation (D3). Device-local safety stays required |

## Five layers

| Layer | What it holds | Items | Done when |
|---|---|---|---|
| **L1 Mediation** | Every action of an AI is decided: authority, safety on typed evidence and contracts, approval bound to its context, limits over sequences and across resources | P0, P1b, P3a, P3b, P5, P7, D2 | T1–T5, T8–T10 of D1's catalogue are refused, under load and faults |
| **L2 Containment of the runtime** | An AI's runtime reaches only Chitala's broker: no network of its own, no credentials of its own. Chitala holds the credentials and checks what leaves | the sandbox interface and its backends ([evaluation](positioning-and-comparison.md)); the broker; egress | an agent in its sandbox reaches nothing but the broker, and D1's escape attempts fail |
| **L3 No way around at the device** | A device refuses a command not signed by Chitala for its session; Chitala knows what the device is | P8, D3 | the conformance suite passes, stated as simulated until a device shows it |
| **L4 A hardened node** | A small trusted base, isolated by a verified kernel; signed and measured boot; signed updates that never roll back; proofs for selected pieces | N1, H0, D4, D5 | H0 reports PASS for the properties claimed, on a board; the proofs are checked in CI |
| **L5 Shown** | An attacking AI, load and faults, deterministic simulation, comparison with other systems, an assurance case, a path to standards | D1, D6, D7, D8; the [comparison suite](positioning-and-comparison.md) | each claim of L1–L4 has its evidence, and the residual risks are written down |

## New items

| Item | Layer | What | Done when | Status |
|---|---|---|---|---|
| **D1** | L5 | **An AI red team.** Attacker agents set against a node in simulation, with a catalogue of strategies, one or more per threat. Deterministic attackers run in CI. Attackers driven by a model run in the lab; their transcripts are kept and replayed as regression tests | every strategy is refused or contained. An escape becomes a hazard with a test. Each report states its environment, commit and model, and counts the valid actions refused too | design |
| **D2** | L1 | **Limits over sequences.** Per agent, and across the agents that act for one principal: the physical effect in a window, the risk taken in total, refusals that repeat. Exceeding one leads to containment | D1's T4 and T10 strategies are refused. It only narrows: it never allows what another check refused | design |
| **D3** | L3 | **Device attestation** (gap G-4). What a device is, and what it runs, is shown before Chitala relies on its evidence or its enforcement | a device that cannot show it is treated as unattested, and gains nothing from evidence it signs | design |
| **D4** | L4 | **Measured and secure boot; signed updates** for the node and the adapter hosts, with anti-rollback | an image or update not signed, or older than the one installed, is refused | design |
| **D5** | L4 | **Proofs for selected pieces,** first the replay cache's invariant and "only narrows" in the decision. Each proof covers the property and the code it names, nothing more | the proofs run in CI and fail when the code breaks them | design |
| **D6** | L5 | **An assurance case per deployment profile:** the claims, their evidence, and the residual risks | each profile that claims an assurance level has one | design |
| **D7** | L5 | **A path to standards:** IEC 62443-4-1 (the development process) and -4-2 (a component), ETSI EN 303 645 (consumer IoT). A gap analysis first | the gaps are listed, each with an item or a reason | design |
| **D8** | L5 | **An open challenge** on a published configuration, once L1–L3 are implemented. Its rules, its scope and what counts as a break are published first | a break is a hazard with a test, and the result is published whatever it is | design |

## Order

- **P0 stays first,** as decided. The software track's order stands: P3a, P1b, P4, P3b, P5, P6, P7, P8.
- **D1 starts beside P0,** as test code. It adds no path to ALLOW. Its catalogue gives each later step a test it must pass, and shows today's gaps.
- **D2** follows P5.
- **D3 and D4** come with P8 and H0.
- **D5** starts with the replay cache and the decision function.
- **D6 to D8** come last. D8 only once L1 to L3 are implemented.

## The first code: D1

Prepared, and to be built once this target is reviewed:
- **Where.** A test harness outside the Trusted Core, `crates/chitala-redteam`, a development tool that is never shipped in a node. It drives a real node in-process, over the simulators Chitala already has: the fake Home Assistant and the robot simulator.
- **An attacker.** It sees what an agent of a given principal can see: its tools, the devices' state, the content it reads. It proposes requests, content to plant and the order to try them in, within a budget of attempts.
- **The catalogue, first version.** Each entry names its threat (T1–T12) and its expected outcome:
  - T1: a capability outside the agent's rights;
  - T2: an instruction planted in a device's name, a web page or a message;
  - T3: a flood of questions to an approver; words that pass for Chitala's;
  - T4: a door opened in small steps;
  - T5: stale evidence; evidence from a source that is not the device;
  - T8: replays and floods against the owner's stop;
  - T9: a request to change policy, or to delegate to itself;
  - T10: two agents of one principal splitting a goal.
- **What it measures.**
  - **Escapes:** actions that reached an adapter beyond what policy and safety allow. They must be zero.
  - **The cost:** valid actions refused, and latency.
  - **For each refusal:** which layer refused it.
- **Attackers driven by a model.** An attacker that asks a model for its next move. It runs only in the lab, with a key. Its transcripts are saved and replayed without the model, so that a strategy found once is tested forever.
- **The report.** It follows the comparison suite's form: the environment, the commit, the configuration, the model, and what was not measured.

## What this does not claim

- That any layer is built before its row says so.
- That Chitala stops every attack by an AI.
- That a result in simulation holds on hardware.
- That seL4's proofs cover Chitala's configuration: they cover the configurations they name.
- That a device below Chitala is safe: device-local safety (a watchdog or deadman, an emergency stop) stays required.
