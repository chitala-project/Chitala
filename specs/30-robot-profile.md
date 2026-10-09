# 30 — Robot Profile v0.1: a differential-drive ground robot

**Status:** v0.4 step 2 (Project Lead, 2026-10-06). It covers the profile, the registry entries, Safety, outcome verification and a simulator. Its adversarial suite is [spec 31](31-robot-adversarial-suite.md); history-derived Safety comes next.

A robot moves through space where people are. Chitala governs it like any other device: an AI sends an intent, Authority decides, Safety checks, the trusted boundary mints the order, and the outcome is verified. The Project Lead decided four things for this step (2026-10-06):

1. **Robot Safety lives in the core**, as one refuse-only rule, `SAFE-9-MOTION`, driven by limits declared on the resource. This is an additive v0.4 change to the core.
2. **A stop always wins**, in Safety and in Authority.
3. **A motion's outcome is a pose within a tolerance**, computed from where the robot started.
4. **Every motion is medium risk.** A stop is low risk.

## The profile

`specs/profiles/robot-v0.1.json` has one class, `mobile_base`, a differential-drive ground robot. It is bound to resources of kind `robot`.

- **Required:** `device.read_state`, `robot.stop`, `robot.move_linear`, `robot.rotate`.
- **Optional:** `robot.goto_pose`, `device.read_history`.

### Capabilities (registry 0.1.4, additive)

| Capability | Risk | Parameters | Outcome |
|---|---|---|---|
| `robot.stop` | low | none | at rest within 2 s: `motion_state` one of `idle`, `stopped`, `estopped` (`any_of`, registry 0.1.5) |
| `robot.move_linear` | medium | `distance_mm` (±10 m; negative goes backwards), `speed_mm_s` (50–2000) | `motion_state` = `idle`; the pose is the start pose moved `distance_mm` along its heading, within 50 mm and 3° |
| `robot.rotate` | medium | `angle_mdeg` (±720°; positive is counter-clockwise), `speed_mdeg_s` (5–360 °/s) | `motion_state` = `idle`; the heading is the start heading turned by `angle_mdeg`, within 3°, and the position has not moved more than 30 mm |
| `robot.goto_pose` | medium | `x_mm`, `y_mm`, `theta_mdeg`, `speed_mm_s` | `motion_state` = `idle`; the pose is the target, within 100 mm and 5° |

The registry gives the outer bounds. A resource sets its own limits inside them.

### State

Every value is an integer, a boolean or text. Positions are in millimetres and angles in millidegrees, in the map frame.

| Key | Meaning |
|---|---|
| `pose_x_mm`, `pose_y_mm`, `pose_theta_mdeg` | the localised pose; the heading is counter-clockwise from the map's x axis |
| `localized_at_ms` | when that pose was fixed, by the robot's clock |
| `linear_velocity_mm_s`, `angular_velocity_mdeg_s` | measured |
| `motion_state` | `idle` (the last motion ended), `moving`, `stopped` (halted by `robot.stop`, or by a protective stop before its motion ended), `estopped` (the emergency stop is pressed) |
| `obstacle_detected` | something is in the robot's protective field |
| `emergency_stop` | the hardware emergency stop is pressed |

**What cannot be known is left out.** A robot that is not localised reports no pose and no `localized_at_ms`. It never reports a guessed pose.

## Limits on the resource

A resource that binds a motion must declare where and how fast the robot may move. Otherwise the configuration is refused.

```json
"envelope": [
  { "capability": "robot.move_linear", "param": "speed_mm_s", "min": 50, "max": 800 },
  { "capability": "robot.goto_pose", "param": "speed_mm_s", "min": 50, "max": 800 },
  { "capability": "robot.rotate", "param": "speed_mdeg_s", "min": 5000, "max": 90000 }
],
"motion": {
  "geofence": [[-1000, -1000], [4000, -1000], [4000, 3000], [-1000, 3000]],
  "max_localization_age_ms": 1000
},
"safe_state": { "capability": "robot.stop" }
```

- **Speed:** every motion's speed parameter needs an envelope bound. `SAFE-5-ENVELOPE` enforces it, as it does any envelope.
- **Geofence:** a convex polygon of 3 to 64 corners, in mm. Convex, because a straight path between two points inside a convex region stays inside it.
- **`max_localization_age_ms`:** from 50 to 10 000 ms.
- **Safe state:** an action that halts (`robot.stop`), required, so that recovery stops the robot.

## Safety

### `SAFE-9-MOTION`

A motion is refused:

- while the emergency stop is pressed (`emergency_stop`, or `motion_state` = `estopped`);
- while an obstacle is detected;
- while the robot is still moving: one motion at a time, so stop it first. A robot whose motion state is unknown is refused too;
- when the robot is not localised;
- when its pose is too old. The age is `|now − localized_at_ms|` (a pose stamped in the future counts as that old, finding F13 of spec 31), and never less than the observation's own age. A robot clock that is off cannot make a stale pose look fresh;
- when the path leaves the geofence. The end pose is computed from the observed start pose and the command. The start and the end must both be inside, so the straight path between them is too.

`SAFE-3-STATE` applies as usual: a motion is medium risk, so it needs the robot's state, recently observed.

### A stop always wins

- **Safety never refuses a capability that only halts** (`"halts": true` in the registry, `robot.stop`). That covers a hold (`SAFE-1`), recovery (`SAFE-8`), busy (`SAFE-7`), rate (`SAFE-6`), unknown state (`SAFE-3`) and a contained device (`SAFE-2`). Stopping is never less safe than not stopping.
- **A stop is not counted against the rate**, so nobody can use stops to hold motions back.
- **The check right before an order is sent** (spec 19) does not keep a stop back for a hold or a recovery either. Its tokens and principals are still checked.
- **`robot.stop` is the robot's safe state** (spec 22). After a broken motion, recovery runs it unless the robot is at rest already. If the stop cannot reach it, a new stop is decided only when the robot is seen again still moving (SAFE-8, spec 22).
- **Authority:** a token right to any motion on a robot resource also grants `robot.stop` there. An AI with such a right also gets the MCP tool `robot_stop`. By the default policy, a stop is low risk, so a guest or a child may stop the robot but not move it. That is the policy of this profile (Robot Profile v0.1), not a default for every profile (Project Lead, 2026-10-09). A capability is marked `halts` only if it truly only stops.

A capability may declare `halts` only if it is a device action without parameters. Nothing that takes a parameter can be trusted to only stop.

**A software stop is no emergency stop.** Chitala's stop is an order over a link. When the link is lost while the robot moves, Chitala cannot make it stop. A physical robot governed by this profile must have its own safety layer, independent of Chitala:
- a hardware emergency stop;
- a watchdog that brings it to a safe state by itself when its controller's heartbeat or its link is lost.

Chitala decides what may be done. It does not replace the robot's own protection (Project Lead, 2026-10-07).

## Outcome verification

An outcome may now declare a `pose` (additive):

```json
"outcome": {
  "state": { "motion_state": "idle" },
  "pose": {
    "motion": { "linear": { "distance": "distance_mm", "speed": "speed_mm_s" } },
    "tolerance_mm": 50,
    "tolerance_mdeg": 3000
  },
  "within_ms": 3000
}
```

- **The expected pose:** when the order is minted, the node takes the robot's last observed pose as the start, and computes the end from it with the command (`linear`, `rotate` or `goto`).
- **The deadline:** `within_ms` plus the motion's own time (distance or angle divided by speed). A `goto`'s turns are covered by its `within_ms`.
- **Verified** when the robot reports the expected state and a pose within the tolerance (headings compared the short way round).
- **Unknown start:** if the start pose was unknown, nothing can confirm the motion, and its outcome ends `diverged` or `unconfirmed`. Safety refuses such a motion anyway.
- **Pose in the record:** the outcome records carry `expected_pose` and `observed_pose`.
- **Broken promises:** wheel slip ends the motion short, and a stall never arrives. Either way the outcome is `diverged`, the robot enters recovery, and recovery stops it.
- **Superseded:** a motion interrupted by a later `robot.stop` is `superseded`, not failed.

## The simulator (`robot-sim`)

`chitala_adapters::robot_sim` is a differential-drive robot simulated on the adapter host's clock. It starts at the map's origin.

- **Motion takes time.** An order is accepted at once and the robot moves. Each observation reports where it is now, and its pose is fixed at every observation.
- **Its own invariants**, like a real robot's:
  - it refuses to move while its emergency stop is pressed or something is in its way;
  - it halts by itself when either happens during a motion (a protective stop);
  - a new motion replaces one under way.
- **Faults**, for the adversarial suite:
  - an obstacle;
  - the emergency stop;
  - localisation lost, or stale;
  - wheel slip, so it ends short;
  - a stall, so it never arrives;
  - an answer lost on its way back, with or without effect, or with the robot going offline;
  - offline.

## Tests

| Test | What it shows |
|---|---|
| `chitala-model`: `motion` (4) | headings wrap; linear motions, turns and goals end where expected, at their own speed; a geofence is convex and holds straight paths |
| `chitala-adapters`: `robot_sim` (7) | motion over time, turns and goals, stop, obstacle and emergency stop, localisation lost or stale, slip and stall, lost answers and offline; every state conforms to the profile |
| `chitala-node/tests/robot.rs` (8) | an AI moves the robot with a token, and its pose is verified, from where it was, after a motion longer than the outcome's own time; SAFE-5 and SAFE-9 keep it within its limits, and nothing refused reaches it; a stop always wins (a hold, the emergency stop, no pose, a guest); stops do not count against the rate; a robot without limits, a speed bound or a stop as its safe state is refused; a motion right includes the stop; slip and stall end `diverged` and recovery stops the robot; a stop supersedes the motion it interrupts |
| `chitala-mcp/tests/broker.rs`: `a_motion_right_brings_the_stop_tool` | an AI holding `robot.goto_pose` gets the tool `robot_stop`, and its stop is verified; a right on a light brings none |

**Mutations: 17 of 17 caught.**
- In Safety:
  - a stop refused like any action;
  - stops counted against the rate;
  - the emergency stop or an obstacle ignored (2);
  - a stale pose taken for fresh;
  - no geofence;
  - a second motion while moving.
- At the fence: a hold keeps a stop back.
- In Authority and the broker: a motion right without the stop (2).
- In outcomes:
  - the pose left out;
  - the start pose ignored;
  - the motion's own time not added to the deadline.
- In the resource checks: a robot without motion limits, a speed bound, or a stop as its safe state, accepted (3).
- In the registry: motion as low risk.
