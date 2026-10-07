# OpenRAL and Chitala: a comparison

Checked on 2026-10-07 against the public repository [`OpenRAL/openral`](https://github.com/OpenRAL/openral) (created 2026-07-09; last push 2026-10-06). Written for the Project Lead, to see what Chitala should learn from OpenRAL and where the two might overlap. Facts about OpenRAL come from its README, its `CLAUDE.md`, its safety READMEs, its roadmap and a search of its code. Where the repository says nothing, the table says "not found", which is not the same as "absent".

## What OpenRAL is

The repository describes OpenRAL as an *Open-source Robot Agentic Layer*: an operating layer for embodied AI, built on ROS 2 (Jazzy), MoveIt 2, Nav2 and `ros2_control`. It is Apache-2.0 in its public repo. A private "OpenRAL Pro" holds fleet and cloud dispatch and other commercial parts.

```text
L4 Reasoner (LLM)  ── typed tool calls from a closed palette built from installed skills
L3 rSkills (VLA)   ── visuomotor policies at 30–200 Hz
L5 Safety          ── a C++ kernel in its own process: "Python proposes, C++ disposes"
L0 HAL             ── 15+ robots, real and simulated
L6 Observability   ── OpenTelemetry, a dataset flywheel
```

## The comparison

| # | Criterion | OpenRAL | Chitala |
|---|---|---|---|
| 1 | **Purpose** | a robot AI stack: perception, VLA policies, an LLM planner, a safety kernel, many robots | an authority and safety layer between AIs, people and physical devices, across domains (home, robot, later vehicle) |
| 2 | **Who may command** (identity, roles) | not found: no user, operator or AI identity model | signed identities for people, AIs, services and devices; roles; agency ("on behalf of") |
| 3 | **Delegation and revocation** | not found | capability tokens (Biscuit), attenuated, revocable by id or in cascade, time-bound |
| 4 | **Human approval** | a "human-handoff" step at the end of the replanning ladder; operator prompts can preempt the planner | high-risk intents need an owner's signed approval; two-key resources; approvals bound to the request and its context |
| 5 | **How AI output becomes action** | typed `ReasonerToolCall`s from a closed palette generated from the installed rSkill registry | signed intents, judged by Identity → Authority → Safety → approval → the trusted boundary, which alone mints a single-use order |
| 6 | **The safety boundary** | a deny-by-default C++ kernel: joint, torque, workspace and speed envelopes; self, world and voxel collision, with predictive checks; NaN and dimension gates; a stale state is dropped (fail closed) | Safety rules SAFE-1 to SAFE-10 over a governed resource: holds, state freshness, physics, envelopes, rate, busy, recovery, motion (geofence, obstacle, e-stop, stale pose), history; a stop always wins |
| 7 | **Geometry and collision** | **much richer**: exact hulls, swept volumes, occupancy grids, a hazard-driven design | a convex geofence and an obstacle flag (Robot Profile v0.1) |
| 8 | **Isolation of the boundary** | a separate process on the ROS 2 graph; no SROS2 or DDS-Security found, so the topics carry no authentication | the trusted boundary signs every order; adapter hosts verify it (session-bound, single-use); a partitioning spike next (N1) |
| 9 | **Independent watchdog** | **yes**: a deadman process E-stops when safe actions stop during an execution window; a hardware E-stop bridge | Chitala's stop always wins, and a robot is required to carry its own watchdog and hardware E-stop (spec 30); Chitala itself has no deadman |
| 10 | **Outcome verification** | learned progress and success monitors (a reward model, a scene VLM) gate the mission | a declared, checkable outcome per action: the device's observed state (or pose within a tolerance), from evidence confirmed current; diverged or unconfirmed leads to recovery |
| 11 | **Recovery** | a bounded replanning ladder (retry, parameter tweak, substitute skill, replan, hand off to a human); a latched E-stop with a cooldown-gated reset | recovery with a declared safe state on evidence only, with a per-capability retry policy; only a person ends a recovery |
| 12 | **Audit** | OpenTelemetry spans, metrics and logs; structured logs of planner decisions | a hash-chained, signed audit log with checkpoints and anti-rollback; every decision and outcome on record before it acts |
| 13 | **History-based safety** | not found | SAFE-10: signed, short-lived constraints from a separate evaluator; deny only; unknown time counts against the rule; the history chain anchored in the audit log |
| 14 | **Skill and code provenance** | rSkill packages are reproducible, but signing (sigstore) is not done yet: a fail-closed gate requires signed skills | not applicable (Chitala does not load models); signed releases and SBOMs for its own code |
| 15 | **Robots and devices supported** | **15+** (SO-100, Franka, UR5e, ALOHA, Unitree G1/H1, …), real and simulated, with 10+ simulators | Home: lights, plugs, locks through Home Assistant and Matter (lab-validated); robots: one simulated differential-drive base |
| 16 | **Ecosystem** | ROS 2 native, MoveIt 2, Nav2, `ros2_control`, LeRobot, Hugging Face Hub | Matter, Home Assistant, MCP; ROS 2 not yet |
| 17 | **Safety process** | changes to the safety code need a safety working-group reviewer, a hazard-log update (private) and tests showing the change is at least as conservative; "never add a flag that disables safety", "never a debug mode that bypasses E-stop" | specs per step with threat sections, mutation testing of every guarantee, adversarial suites, a core freeze with Lead-approved exceptions; no hazard log in the safety-engineering sense yet |
| 18 | **Assurance** | tests on real schemas and simulators; formal certification is "remaining work" (v1.0: "a certifiable build") | mutation testing, fuzzing of every trust boundary, a threat model, ThreadSanitizer runs; the formal path through seL4 is still to be proven (N1) |
| 19 | **Language and runtime** | Python 3.12 + C++ safety kernel, on ROS 2 / Linux | Rust; hosted on Linux/macOS, and as a Hermit unikernel (Native lab) |
| 20 | **Licence and model** | Apache-2.0 public; a private commercial tier (fleet, cloud dispatch) | Apache-2.0 |

## What Chitala should learn from OpenRAL

1. **An independent deadman watchdog.** OpenRAL's watchdog is a separate process that E-stops a robot whose safe action stream stops during an execution window. It survives a crash of the planner and of the kernel. Chitala relies on the robot's own watchdog (spec 30). A Chitala-side deadman for the robot path, a heartbeat the adapter must keep while a motion runs, would be cheap defence in depth.
2. **"Unknown, not safe" for status.** OpenRAL's latched safety status is re-stamped every second, and a consumer treats a stale status as unknown. Chitala does the same for device state (F6, F12); its own safety status (holds, recovery) could be published the same way for dashboards and AIs.
3. **A hazard log, and a safety review rule.** Chitala's specs carry threat sections and its guarantees are mutation-tested. What it lacks is a hazard log in the safety-engineering sense (ISO 12100 / IEC 61508 style) and a written rule that changes to Safety need a second reviewer and tests at least as conservative. Both are prerequisites for any certification.
4. **Richer motion safety for robots.** OpenRAL's predictive, geometry-aware collision checks are far ahead of Chitala's geofence and obstacle flag. Chitala should not rebuild them, by its positioning: it should consume a robot stack's own safety verdict as evidence, and keep its own refusals.
5. **Provenance of what runs.** OpenRAL plans signed skills, and fails closed without them. For Chitala, the analogue is signed adapter and evaluator binaries.

## Where they overlap, and where they do not

The overlap is narrow: both put a deny-by-default boundary between an AI's proposal and a robot's actuators.

The difference is in what each is built around:
- **OpenRAL** is built around **making robots capable**: perception, learned policies, planning, many embodiments.
- **Chitala** is built around **who may make a physical system do what**: identity, delegation, approval, revocation, one verified order, outcome, recovery, audit. And it does so across domains.

So OpenRAL is not a competitor to Chitala's core; it is a candidate **system for Chitala to govern**, as Matter and Home Assistant are for the home:

```text
            Chitala (authority, approval, audit, outcome)
   ┌───────────┼──────────────────────┐
 Matter      ROS 2 / OpenRAL        AUTOSAR
Smart Home   Robot                  Vehicle
```

A Chitala adapter for ROS 2 could:
- grant or refuse *which rSkill, on which robot, for whom*;
- pass its order to OpenRAL's runner;
- read the outcome back as evidence.

OpenRAL's safety kernel would stay the robot's own protection beneath Chitala's refusals, as a robot's own watchdog does today (spec 30).

**Risk of collision of directions:** if OpenRAL adds identity, authorization and approval (its private Pro tier mentions fleet and cloud dispatch), the authority layer for robots could come from the robot stack itself. Chitala's answer is depth and breadth: the same authority model across home, robot and vehicle, with an isolation foundation (Native, seL4) that a Python/ROS 2 stack does not aim for.

## Sources

- Repository and README: <https://github.com/OpenRAL/openral>
- The safety kernel: `cpp/openral_safety_kernel/README.md`; the watchdog: `packages/openral_safety_watchdog/README.md`; `CLAUDE.md` §§1–4; `docs/roadmap/index.md`
- Introduction on Open Robotics Discourse (July 2026): <https://discourse.openrobotics.org/t/openral-the-agentic-harness-for-physical-ai-ros-2-native/56352>
- Robots: <https://github.com/OpenRAL/openral/blob/master/docs/reference/robots.md>
