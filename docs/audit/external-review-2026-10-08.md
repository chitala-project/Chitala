# External architecture review, 2026-10-08

**Scope.** An external review of `main` at `134b61c` (2026-10-08). It checked the documents against the code of Authority, Safety and the Execution Boundary, and against their tests. Its question: can Chitala become the layer that keeps people safe among many AIs and devices?

**Its conclusion.** The architecture fits that role. The current version proves part of the protection, but not yet enough to make it responsible for safety in a complex real environment.

This page maps each of its points to where the repository records it. Most of the gaps it names were recorded on 2026-10-08, after `134b61c`, in #87 and the ROADMAP. They are designs, not implementations. One point was new, and is answered here: an AI that persuades a person to approve a harmful action.

## Point by point

| The review's point | Where the repository records it | State |
|---|---|---|
| AI proposes, Chitala decides; Safety apart from Authority; an owner's approval does not override Safety | specs 15–17; Constitution C4 | built, tested: the [traceability matrix](../safety/traceability.md) |
| The mechanisms already in code: identities, narrowing delegation, approvals bound to one request, two keys, busy and rate rules, the authority fence, outcomes without resends, recovery, a stop always wins | specs 16, 17, 19, 21, 22, 30 | built, tested: the matrix, rows H-GEN-001 to H-GEN-016 and H-ROB-* |
| Refusing a request does not protect a device that another path still controls; a compromised Matter sidecar holds the fabric's keys | hazard H-GEN-017, gap G-8; [device-side enforcement](../architecture/device-side-enforcement.md) (#87) | a design. The implementation follows H0's platform evidence |
| Several valid actions together can be dangerous: a burner without ventilation, a door against an escape route, two robots in one passage, a shared electrical limit | ROADMAP step 6: cross-resource constraints and capacity reservation | to design |
| A plan that stops partway does not undo its steps | ROADMAP step 6: Plan Engine v0.2, recovery obligations | to design |
| A signature proves who sent data, not that it is true; robot safety arrives as flags; no device attestation | gaps G-4, G-5, G-6; ROADMAP step 5 (Typed Evidence); [direction](../architecture/direction.md) | to build |
| Distribution and scale; federation | ROADMAP step 12; spec 13, R11 | later, by design |
| Privacy: viewing, recording and exporting kept apart | [direction](../architecture/direction.md), information authority | to design |
| Human control: an interface people understand, fast revocation, alerts in proportion | [spec 34](../../specs/34-trusted-approval.md), beside ROADMAP step 6 | a design (this change) |
| An AI can still persuade a person to approve a harmful action | hazard H-GEN-018, gap G-9, spec 34 | a design (this change); a residual risk remains |

## Where we read it the same way

- **Recovery when a plan partly succeeds.** The review does not ask for a default undo, and neither does the repository. Both call for conditional recovery: safe points, acceptable states, recovery actions on evidence, and a hand-over to a person. A physical action may not be reversible, and reversing it may be worse.
- **Paths outside Chitala.** Some paths cannot be closed. Home Assistant's own users and automations are peers to Chitala, so a deployment that uses Home Assistant declares them and accepts a lower assurance. Local physical controls are kept, such as a stop button or an escape route. Every physical control path is still classified in the deployment's assessment.
- **A stop in software is not a stop in the world.** That a stop was accepted does not show that the machine stopped in time. That evidence comes from the device: a watchdog or deadman (gap G-5) and the profile's contract.

## Revocation, stated precisely

Discussing the review brought out that spec 05 said "revocation is immediate everywhere". That was too strong. Specs 05 and 19 now say what a revocation reaches:
- **It stops** everything that still needs its authority checked: new requests, an approval being decided, a lease's next use, a plan's next step, an order decided but not yet sent.
- **The order's lifetime** bounds only how long the adapter host's gate still accepts it.
- **Neither** cancels an order the gate has accepted, nor anything queued beyond the adapter host. Neither stops a motion already running.

Tests:
- before the fence, and after the action: `a_domain_wide_revocation_before_the_fence_and_after_the_action`;
- past the fence, before the device acts: `a_revocation_after_the_fence_does_not_reach_an_order_on_its_way` (it models a hostile or slow channel; it is no evidence of how the production transport classifies such an order);
- a motion already running: `a_revocation_does_not_stop_a_motion_already_running`.
