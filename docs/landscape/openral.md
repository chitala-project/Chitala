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
| 2 | **Who may command** (identity, roles) | not found in the public repository: no identity model for users, operators or AIs | signed identities for people, AIs, services and devices; roles; agency ("on behalf of") |
| 3 | **Delegation and revocation** | not found | capability tokens (Biscuit), attenuated, revocable by id or in cascade, time-bound |
| 4 | **Human approval** | a "human-handoff" step at the end of the replanning ladder; operator prompts can preempt the planner | high-risk intents need an owner's signed approval; two-key resources; approvals bound to the request and its context |
| 5 | **How AI output becomes action** | typed `ReasonerToolCall`s from a closed palette generated from the installed rSkill registry | signed intents, judged by Identity → Authority → Safety → approval → the trusted boundary, which alone mints a single-use order |
| 6 | **The safety boundary** | a deny-by-default C++ kernel: joint, torque, workspace and speed envelopes; self, world and voxel collision, with predictive checks; NaN and dimension gates; a stale state is dropped (fail closed) | Safety rules SAFE-1 to SAFE-10 over a governed resource: holds, state freshness, physics, envelopes, rate, busy, recovery, motion (geofence, obstacle, e-stop, stale pose), history; a stop always wins |
| 7 | **Geometry and collision** | **much richer**: exact hulls, swept volumes, occupancy grids, a hazard-driven design | a convex geofence and an obstacle flag (Robot Profile v0.1) |
| 8 | **Isolation of the boundary** | a separate process on the ROS 2 graph. No SROS2 or DDS-Security configuration found in the public repository: `/openral/safe_action` should not be taken as an authenticated trust boundary unless a deployment adds security outside it | the trusted boundary signs every order; adapter hosts verify it (session-bound, single-use); a partitioning spike next (N1) |
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

Reviewed by the Project Lead on 2026-10-07; the decisions are given with each item.

1. **An independent deadman, as defence in depth.**
   - OpenRAL's watchdog is a separate process. It E-stops a robot whose stream of safe actions stops during an execution window, and it survives a crash of the planner and of the kernel.
   - For Chitala, a deadman is the **fourth** layer, never the only one. A robot keeps, beneath it: a hardware E-stop, a local motor watchdog, and its controller's watchdog (spec 30).
   - A heartbeat carried over a network fails exactly when the link does, so it must never be the mechanism that stops a robot.
   - *Decision:* write a spec, after the Native evaluator domain; not in the Trusted Core.
2. **"Unknown, not safe" for Chitala's own status.**
   - OpenRAL re-stamps its latched safety status every second, and a consumer treats a stale status as unknown.
   - Chitala does the same for device state (F6, F12). Its own safety status (holds, recovery) could be published the same way, for dashboards, AIs, remote supervisors and later integrations: `recovery = false` stamped at 10:02:01, with no heartbeat by 10:02:20, means *unknown*, not *safe*.
   - These are the semantics of a published status, not a new source of authority. A status reports; it never grants.
3. **A hazard log, a traceability matrix and a safety review rule.**
   - OpenRAL requires a safety working-group reviewer, a hazard-log update and tests at least as conservative for any change to its safety code.
   - Chitala has the parts (SAFE rules, threats, specs, tests, mutation runs), but their links are scattered.
   - A hazard log, a matrix from hazard to requirement, control, test and evidence, and a rule for safety-affecting changes would make them a structured safety case. They have value even without any certification.
   - *Decision:* do it now.
4. **Typed evidence from a robot stack, not a verdict.**
   - OpenRAL's predictive, geometry-aware collision checks are far ahead of Chitala's geofence and obstacle flag.
   - Chitala should not rebuild them. Voxel maps, SLAM, collision geometry, trajectory planning and VLA models stay out of the Trusted Core.
   - Nor should Chitala trust a bare `safe = true`. A robot stack provides **typed, current evidence**, for example an `ObstacleEvidence` with its source, measurement time, validity, clearance, quality, region and provenance; or a `LocalizationEvidence`, `CollisionFreeEvidence` or `MotionEnvelopeEvidence`. SAFE-9 decides by policy what it accepts.
   - The external system provides evidence; Chitala makes the authority and safety decision.
5. **Admission of executable components.**
   - An adapter or an evaluator binary would carry a hash, a signature and a manifest, and be admitted before it may start, failing closed otherwise.
   - This follows OpenRAL's direction (its skill signing is not implemented yet) and Chitala's own signed releases.
   - *Decision:* production hardening, N2/N3; it does not block N1.

## Where they overlap, and where they do not

The overlap is narrow: both put a deny-by-default boundary between an AI's proposal and a robot's actuators.

The difference is in what each is built around:
- **OpenRAL** is built around **making robots capable**: perception, learned policies, planning, many embodiments.
- **Chitala** is built around **who may make a physical system do what**: identity, delegation, approval, revocation, one verified order, outcome, recovery, audit. And it does so across domains.

So OpenRAL is not a competitor to Chitala's core. It is a robot stack that can sit **beneath** Chitala's authority, as Matter and Home Assistant do for the home:

```text
AI / planner / VLA
        ↓
     OpenRAL
        ↓
proposed robot action
        ↓
     Chitala         Authority + Safety
        ↓
    ExecOrder
        ↓
ROS 2 / controller
        ↓
      Robot          its own safety kernel, watchdogs, hardware E-stop
```

OpenRAL can be far better than Chitala at perception, collision geometry, VLA, MoveIt, Nav2 and robot hardware without threatening what Chitala is for.

**A potential overlap, not a confirmed one:** if OpenRAL Pro later adds principal identity, authorization, delegation and governed execution, the architectural overlap with Chitala would grow. Nothing in the public repository says it will, and it is no reason for Chitala to change direction now.

**Not now** (Project Lead, 2026-10-07): an OpenRAL integration or a full ROS 2 adapter.

## Reusing OpenRAL's work

- **Architecture and algorithms first.** Code is copied only where it clearly pays. OpenRAL is Python and C++ and Chitala is Rust, so most of it would be written again in any case.
- **Code that is reused follows Apache-2.0:**
  - its licence and copyright notices are kept;
  - its `NOTICE` is carried over;
  - the changes are marked.
- **Copyright is not the whole question.** Patents and trademarks can apply as well.
- **Nothing comes from OpenRAL's private repositories.** That includes its hazard log and its Pro tier.

## Sources

- Repository and README: <https://github.com/OpenRAL/openral>
- The safety kernel: `cpp/openral_safety_kernel/README.md`; the watchdog: `packages/openral_safety_watchdog/README.md`; `CLAUDE.md` §§1–4; `docs/roadmap/index.md`
- Introduction on Open Robotics Discourse (July 2026): <https://discourse.openrobotics.org/t/openral-the-agentic-harness-for-physical-ai-ros-2-native/56352>
- Robots: <https://github.com/OpenRAL/openral/blob/master/docs/reference/robots.md>
