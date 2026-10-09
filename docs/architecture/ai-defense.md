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

## Every direction of attack

An AI may attack from any direction, and several at once. The threats above say *what* it tries. This section checks that no *position* is left without an answer, and no *asset* without a guarantee.

The catalogue never ends. It grows from four sources, and each entry carries its status:
- this review, done again for each release;
- what D1's red team finds;
- incidents;
- other people's reports ([SECURITY.md](../../SECURITY.md)).

### Where the AI sits

| | Position | What it can do | What answers it | Status |
|---|---|---|---|---|
| A1 | **An agent Chitala serves** | use its grants; ask; split a goal; flood | L1: authority, safety, approval, budgets, D2 | partly |
| A2 | **Content an agent reads:** pages, mail, messages, documents, images, audio, device and room names, calendars | steer the agent | content grants nothing; approvals show the requester's words, labelled; L2 limits where a steered agent can reach | partly |
| A3 | **The people who own or approve:** phishing, cloned voices and faces, pressure of time, fatigue | obtain an approval, a key, a change of policy | approvals only by an enrolled key, never by a message or a voice; the budget of questions; the context bound to the approval (P1b); D9 | partly |
| A4 | **The local network:** a compromised laptop, camera or IoT device | reach the node, a device or a gateway directly; flood | the node listens only on local IPC, with the peer's identity (spec 11); P0's intake; a device reachable around Chitala (G-8): P8, and segmentation as a deployment requirement (D10) | partly |
| A5 | **A device, an adapter host, a gateway or a hub:** Home Assistant, a Matter controller, a sidecar | lie about state; act without Chitala; use credentials it holds | typed evidence and contracts (P2, P3); adapter hosts isolated (spec 19); P8; D3; gap G-8 | partly |
| A6 | **A third-party app or service on Chitala** | take data out; act beyond its manifest | the least of three, the broker, labels ([apps and services](apps-and-services.md)) | design |
| A7 | **Radio and the physical world:** jamming, replayed radio, sensors fooled by light, sound or magnets, tampering | make evidence wrong or stale; deny control | freshness, conflicts kept, unknown as a value (P2); device-local safety; D3; D10 | partly |
| A8 | **The internet,** the services an agent uses, **the model provider itself** | a poisoned or backdoored model behind an agent; poisoned answers | no agent is trusted, whatever its model: Chitala decides on authority and evidence, never on an agent's reasoning; services reached through the broker | partly |
| A9 | **The supply chain:** dependencies, the build, updates, profiles, adapters | ship a backdoor | dependency review (`cargo deny`, `cargo audit`), pinned versions; signed profiles (P7); signed updates and measured boot (D4); D11 | partly |
| A10 | **Chitala itself:** a bug in the node, its host or its kernel | get past every check at once | Rust, no `unsafe` in the core, fuzzing, mutation runs; Native on seL4 (L4); D5; D1 aimed at the node itself | partly |
| A11 | **An AI that Chitala hosts,** later | act as an insider | it is a principal like any other, with no path around the decision (D13) | design |
| A12 | **Many AIs at once,** in several positions | combine them: one plants content, one floods, one asks | each layer holds on its own; D2 across agents; D1's combined strategies | design |

### What it goes after

| Asset | The guarantee sought | Where |
|---|---|---|
| Actuation: what devices do | nothing happens that authority, safety and approval did not decide, and the device itself checks it | L1, L3 |
| Authority: keys, tokens, policy, delegations, approvals | only narrows on its own. Loosening needs an owner, is audited, and is never taken from content | L1, L4 |
| Evidence | its source, freshness and scope are known; a conflict and an unknown are kept | L1, L3 |
| The owner's control: the stop | available under load, within a published bound | L1 (P0) |
| Data | nothing leaves except through the broker, by its labels | L2 |
| Records: audit, history | tamper-evident, anchored, durable before an order leaves | L1, L4 |
| Time | never goes back; a start never precedes the last audited event | implemented |
| Identity and enrolment | a principal is enrolled by an owner, never by a request | L1 |
| Chitala's software and configuration | signed, measured, never rolled back | L4 |
| What people understand | what they approve is what happens | L1 (P1a, P1b, D9) |

### Techniques, phase by phase

| Phase | Technique | What answers it | Status |
|---|---|---|---|
| Reconnaissance | probing the policy through refusals, explanations and the time a decision takes | refusal reasons limited for whom they serve; explanation needs its own right and redacts (decided); D12 | partly |
| Evasion | staying under every threshold, low and slow; a check made long before its use; races | the fence right before the send (spec 19; P0 moves it after the wait); D2 over long windows; D1's low-and-slow strategies | partly |
| Persistence | a delegation, a lease, a plan; an automation planted inside a platform | delegations and leases expire and can be revoked; an automation inside Home Assistant is outside Chitala (G-8): P8 | partly |
| Abuse of protection | stopping a pump that cools; unlocking "for a fire"; forcing recovery | a capability is `halts` only if it truly only stops (decided); each profile's protective actions and their limits in contracts (P3); D14 | partly |
| Poisoning | of history, telemetry and baselines | history constraints only narrow (`SAFE-10`). Poisoning can still make Chitala refuse: D15 bounds that harm | partly |
| Exhaustion | CPU on signatures, the disk, the queues, an approver's attention | P0's bounds; the budget of questions | in progress |
| Time | NTP or the real-time clock set back | the trusted clock never goes back; a start's floor comes from the audit | implemented |
| Confusion | names that look alike; words that pass for Chitala's | P1a escapes and labels the requester's words; D9 | partly |

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
| **D9** | L1 | **The human channel.** Approvals only by an enrolled key on the person's own device. A published list of what Chitala never asks for by message, voice or call. Names normalized, and look-alikes flagged. Tests of what people understand (G-9) | D1's A3 strategies fail: a cloned voice or a message obtains nothing | design |
| **D10** | L2, L3 | **Network and radio.** The node's listening surface stated and tested. Segmentation as a deployment requirement, checked by a probe. Jamming and replayed radio as D1 strategies | the probe finds nothing reachable around Chitala in a conforming deployment | design |
| **D11** | L4 | **The supply chain.** Reproducible builds, an SBOM, signed releases. Dependency review stays | a release can be rebuilt bit for bit, and its signature checked | design |
| **D12** | L1 | **Oracles and side channels.** What a refusal, an explanation and a decision's timing reveal, and to whom | a review, and a test for each finding | design |
| **D13** | L1 | **An AI that Chitala hosts.** No privileged path: the same decision as any principal | tests that it gets nothing another principal would not | design |
| **D14** | L1 | **Protective actions that harm.** Each profile declares its protective actions and their own limits, in contracts | D1's abuse strategies fail: a stop never stops what keeps a device safe | design |
| **D15** | L1 | **Poisoned history and baselines.** What poisoned history can make Chitala refuse, and the bound on that harm | the harm is bounded, and it is reported | design |
| **D8** | L5 | **An open challenge** on a published configuration, once L1–L3 are implemented. Its rules, its scope and what counts as a break are published first | a break is a hazard with a test, and the result is published whatever it is | design |

## Order

- **P0 stays first,** as decided. The software track's order stands: P3a, P1b, P4, P3b, P5, P6, P7, P8.
- **D1 starts beside P0,** as test code. It adds no path to ALLOW. Its catalogue gives each later step a test it must pass, and shows today's gaps.
- **D2** follows P5.
- **D3 and D4** come with P8 and H0.
- **D5** starts with the replay cache and the decision function.
- **D9** with P1b. **D10 and D11** beside P8 and H0. **D12, D13 and D15** with P3 and the explanation. **D14** with P3a's contracts.
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
  - T10: two agents of one principal splitting a goal;
  - and, as they come within reach, one or more strategies for each position A1–A12, alone and combined.
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
