# Positioning, and a suite of comparisons (proposal)

**Status:** a proposal. The project owner put the direction forward on 2026-10-09, and the Project Lead agreed with it on conditions, which are written here. Nothing in it is built. The platforms named below are standards to build on or to measure against, never dependencies that have been chosen. Chitala keeps its own goal: Chitala Native.

## Where Chitala stands

Chitala is the layer of **authority and safety across people, AIs and the actions of devices**:
- who may do what, for whom, and for how long;
- what is safe to do now, and on what evidence;
- what a person must approve, and what they must be shown;
- whether an action took effect, and what happens when it did not;
- a record of all of it.

It does not replace the platforms beneath and beside it ([direction](direction.md), [ADR 0002](../adr/0002-production-native-architecture.md)). Using them as backends, or measuring against them, strengthens that goal. It does not turn Chitala into a gateway.

## Standards to build on, or to measure against

| Area | Standard | Its status for Chitala |
|---|---|---|
| Sandboxing apps and agents (Hosted) | NVIDIA OpenShell | **Being evaluated**, as an optional backend for Hosted |
| Isolation (Native) | seL4 + Microkit | Chosen, on conditions (ADR 0002). DMA isolation, and every property of hardware, wait for H0 |
| Evidence and the handling of faults | QNX; safety PLCs (IEC 61508, ISO 13849) | A yardstick of rigour, and the device-local layer beneath Chitala. Never something Chitala replaces |
| Connecting devices | Home Assistant, ROS 2, Matter | Adapters: Home Assistant and Matter today, ROS 2 later |

### OpenShell, being evaluated

OpenShell is NVIDIA's open-source runtime for running agents in sandboxes. Its policies cover the file system, the network, processes and inference. The network is denied by default. The policy is enforced outside the agent's process. The agent never sees a real credential: OpenShell adds credentials only to requests bound for endpoints a policy allows. The official repository has released `v0.1.2` (2026-09-28, not a prerelease). Its `0.1.x` line runs on Docker, Podman or host virtualization ([releases](https://github.com/NVIDIA/OpenShell/releases), [README](https://github.com/NVIDIA/OpenShell)).

None of that shows that it is safe enough for Chitala. Each version and configuration that is chosen is assessed on its own. The conditions, from the Project Lead:
1. **Least of three.** A manifest declares what an app wants. The policy enforced is the intersection of the manifest, the rights an owner granted, and the deployment's own limits.
2. **One way out.** An app reaches only the broker Chitala names. It never uses OpenShell's credential provider to go around Chitala's checks on what leaves ([apps and services](apps-and-services.md)).
3. **Nothing widens on its own.** A change of policy, a restart of the sandbox or an update of a package never widens what an app may do.
4. **Measured before it is called fit.** CPU, memory, the time to start, and how it fails are measured on a home server before it is called suitable there.
5. **Chitala's own abstraction.** Chitala's sandbox interface stays independent of OpenShell. Native needs it, and so would any other backend.

## A suite of comparisons

The aim is to show, with tests anyone can run again, what Chitala adds, and what it costs. It never asks which system is "safer" overall: these systems do different jobs. Each comparison is about one property, on a stack configured as a careful operator would configure it.

### What is compared, with what

| Against | What is compared |
|---|---|
| Home Assistant | who may call an action; human approval; whether the outcome is checked; what happens when the outcome is unknown |
| OpenShell | isolation of files, network and credentials; the ways data can still leave around the isolation |
| ROS 2 with SROS2 | who may talk on which topic; stale evidence; a lost link; control of a robot |
| QNX, safety PLCs | real-time behaviour and safety functions, in their assessed configuration and scope only |

### Fairness

- **A careful baseline.** Each baseline gets a reasonable protective configuration: scoped tokens where it has them, SROS2's access control, OpenShell's default-deny policy. It is never set up to fail.
- **The same conditions.** The same devices or simulator, the same load, the same faults, on both sides.
- **The costs are measured too**, not only the harm prevented:
  - dangerous actions that went through;
  - valid actions refused;
  - latency;
  - resources (CPU, memory);
  - recovery after faults.
- **Milestones are kept apart.** A first milestone never stands in for a last one:

| Measure | Its milestones, each timed |
|---|---|
| Revocation | received → blocked at the gate → an effect already under way handled |
| Stop | received by the node → received by the controller → the device in a safe state |

- **Where others are better, it says so:** a real-time kernel's determinism, a certified controller's reaction time, an ecosystem's reach.
- **Each report states** the environment, the commit, the configuration of each side, and what was not measured.

### First scenarios, to refine

| Scenario | Property |
|---|---|
| An AI holding a Home Assistant token for a lock is told by a web page to open it | approval; content grants nothing |
| An answer from a device is lost after the command was sent | an action done twice, or not at all |
| A lock reports "locked" while its last report is stale | stale evidence |
| An agent in a sandbox may reach Home Assistant's API, and reads a camera, then sends a clip out | export paths around the isolation |
| A ROS 2 node with publish rights sends a motion while localization is lost | stale evidence; motion safety |
| A right is revoked while an order is on its way | revocation, at each milestone |
| A stop is sent while the node is under load | stop, at each milestone |

## Phases (proposed)

| Phase | What |
|---|---|
| C0 | This proposal |
| C1 | A harness on the simulators Chitala already has (the fake Home Assistant, the robot simulator), with Home Assistant alone as the first baseline |
| C2 | OpenShell's evaluation: the five conditions, and its costs measured on a home server |
| C3 | ROS 2 with SROS2 as a baseline, once a ROS 2 adapter exists |
| C4 | Comparison with QNX or safety PLCs: a documented reference within their assessed scope, not a race |

Each phase reports in the form above, with its status: design, implemented, simulation-validated, hardware-pending.

## What this does not claim

- That Chitala is safer than any of these platforms overall.
- That OpenShell, seL4 or any other standard here is safe for Chitala in a given configuration before that configuration is assessed.
- That a result on a simulator holds on hardware.
