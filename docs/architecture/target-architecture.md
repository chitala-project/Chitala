# Chitala target architecture

![Chitala target architecture](../assets/chitala-architecture-overview.png)

This is Chitala's **target** architecture: where the design is going, not what the code does today. In the diagram, parts marked *future* are not implemented, parts marked *in progress* are under development, and parts marked *software complete* still need validation on physical devices. This page gives the status of every part of the diagram. The [roadmap](../../ROADMAP.md) has the plan.

What does not change from one release to the next is the invariant:

> **AI produces Intent. Chitala produces Authority. Only the Trusted Execution Boundary produces physical Commands.**

## Status of each part

| Layer | Part | Status | Where |
|---|---|---|---|
| 1 People and AI | homeowner, administrator, guest | implemented: principals with roles; delegation to a guest's AI | [02](../../specs/02-identity.md), [05](../../specs/05-capability-token.md) |
| | local and cloud AI agents | implemented: any AI that speaks MCP (Claude, ChatGPT, local models) | [12](../../specs/12-ai-broker-mcp.md) |
| 2 Interface and intent | app, dashboard, voice | **future**: today people use the `chitala` command line | — |
| | MCP, agent-to-agent, API | implemented: the MCP broker, agent hand-off, the node's signed IPC | [11](../../specs/11-node-ipc.md), [12](../../specs/12-ai-broker-mcp.md) |
| | signed intent | implemented | [15](../../specs/15-intent.md) |
| 3 Chitala core | identity, capability registry | implemented | [02](../../specs/02-identity.md), [04](../../specs/04-capability-registry.md) |
| | authority, safety | implemented: the Authority Engine; Safety rules `SAFE-1` to `SAFE-10`, history-derived Safety included; a safety case with its hazards traced to tests and mutation runs ([`docs/safety/`](../safety/README.md)) | [16](../../specs/16-authority-engine.md), [17](../../specs/17-safety.md), [32](../../specs/32-checked-history-constraints.md) |
| | human approval, two-key | implemented | [14](../../specs/14-resource-model.md), [16](../../specs/16-authority-engine.md) |
| | plan engine, execution lease | implemented | [23](../../specs/23-plan-engine.md), [21](../../specs/21-execution-lease.md) |
| | trusted execution boundary | implemented | [19](../../specs/19-execution-boundary.md) |
| | policy, audit log | implemented | [06](../../specs/06-policy.md), [09](../../specs/09-audit.md) |
| | observability | **first form**: the audit log, security events, the reference monitor, device twins, and a local history of device state, outside the Trusted Core, that people and AIs read through the node as `device.read_history`. No performance metrics yet | [08](../../specs/08-reference-monitor.md), [10](../../specs/10-twin-and-events.md), [29](../../specs/29-telemetry-history.md) |
| | outcome verification, recovery | implemented | [22](../../specs/22-outcome-recovery.md) |
| 4 Runtime and adapters | adapter host | implemented: one separate process per adapter type, supervised by the node | [19](../../specs/19-execution-boundary.md) |
| | Home Assistant adapter | implemented, checked against a real Home Assistant | [25](../../specs/25-home-assistant-adapter.md) |
| | direct Matter adapter | **software complete, physical validation pending**: on Chitala's own fabric through a matter.js sidecar. It passes the conformance suite and drove the Matter SDK's lock through the whole chain in the lab | [26](../../specs/26-adapter-conformance.md), [27](../../specs/27-direct-matter-adapter.md) |
| | Chitala Device Runtime | **future**: a device runtime outside the Trusted Core. Its first piece exists: the local history of device state | [29](../../specs/29-telemetry-history.md), [roadmap](../../ROADMAP.md) |
| | robot and vehicle adapters | **in progress**: the Robot Profile v0.1 for a differential-drive ground robot, with its Safety rule and a simulator (`robot-sim`); and its adversarial suite. Physical robots and vehicles are future | [30](../../specs/30-robot-profile.md), [31](../../specs/31-robot-adversarial-suite.md) |
| | cloud storage and reporting | **future** | — |
| 5 Devices | door lock, light, plug | implemented in the Home profile; tested with virtual devices, a real Home Assistant and Matter SDK devices. Physical devices are step ③B | [24](../../specs/24-home-profile.md) |
| | air conditioner, sensors, camera, humanoid robot, EV, edge node | **future**: not in the Home profile v0.1 (the mock has a virtual thermostat) | — |
| 6 Feedback and governance | human notifications | **future**: recovery and approvals are visible through the command line, events and the audit log | [22](../../specs/22-outcome-recovery.md) |
| | status reporting, safety alerts | **first form**: device state, outcomes, security events and recovery records | [09](../../specs/09-audit.md), [22](../../specs/22-outcome-recovery.md) |
| | human decisions | implemented: approve, deny, hold, revoke | [16](../../specs/16-authority-engine.md) |

## About the diagram

The diagram started as an illustration. Its title, and the *future*, *in progress* and *software complete* labels, were added so that it does not claim what the code does not do. When a part changes status, update its label and this table together.
