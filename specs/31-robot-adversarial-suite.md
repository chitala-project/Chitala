# 31 — Robot adversarial suite

**Status:** v0.4 step 3 (Project Lead, 2026-10-06). The robot of spec 30, put through what the world does to a moving machine, with the simulator's faults and through the whole chain. It found **F13**, fixed here.

Spec 28 did this for the home: backends that crash, devices that drop off, reports that come late. A robot adds motion. A fault can happen while it moves, and a motion that goes wrong goes wrong somewhere in the room. Whatever happens, these invariants hold:

- **It never moves on its own.** After a fault, nothing resumes a motion. Only a new order, cleared by Authority and Safety, moves it.
- **A broken promise stops it.** A motion that did not end where it should is `diverged` or `unconfirmed`. The robot enters recovery, and recovery stops it when it can be reached. Only a person ends the recovery.
- **A stop always gets through**: to an owner, to a guest, under a hold, in recovery.
- **Nothing made up.** A pose that cannot be trusted is no pose:
  - lost;
  - stuck on an old fix;
  - stamped by a clock that is off;
  - malformed.

  It neither starts a motion nor verifies one.

## Fault classes

| Fault | What must happen | Test |
|---|---|---|
| Something gets in its way mid-motion | the robot halts by itself (a protective stop); the motion is `diverged`; recovery; it stays where it halted, the obstacle long gone, until a person releases it | `an_obstacle_mid_motion_halts_it_and_nothing_resumes_it` |
| The emergency stop is pressed mid-motion | `diverged`; held by its emergency stop, the robot is at rest: no stop is needed, and none is sent; a guest's stop is verified; no motion until it is released and a person ends the recovery | `the_emergency_stop_mid_motion` |
| Localisation lost, or stuck on an old pose, mid-motion | the robot arrived, and nobody can tell: `diverged`, recovery, a stop; no motion starts from a pose it does not have | `localisation_lost_or_stale_mid_motion_is_no_evidence` |
| The answer to a motion is lost | if it moved, its pose shows it: `applied`. If it did not, its settled state shows that: `not_applied`, no recovery. If it did not and then lost where it is: `unconfirmed`, recovery. If it also went silent: `unconfirmed`, recovery, and no stop sent into the silence | `an_answer_lost_on_the_way_back` |
| It drops off the network mid-motion | last seen moving: `diverged`; recovery's stop cannot reach it, and is never resent. Back, it is observed first: at rest, nothing is sent; still moving, a new stop is decided and sent once (SAFE-8, spec 22). Coming back ends nothing: a person releases it | `the_robot_drops_off_mid_motion`, `a_stop_lost_to_a_dropped_link_is_decided_anew_on_reconnect` |
| The link flaps, to a robot that ignores stops | one attempt per newer observation that still shows it moving, one at a time, three per episode; then a person is told, once | `a_flapping_link_never_spams_stops`, `one_safe_state_attempt_at_a_time` |
| Chitala restarts mid-motion | the promise, with its expected pose, survives the restart (persisted as JSON) and is kept: verified, or broken and the robot stopped; nothing is sent twice | `a_restart_mid_motion_keeps_its_promise` |
| Two AIs want it at once | one motion at a time; the other AI may stop it (its motion right includes the stop), and the stopped motion is `superseded`, not failed | `two_ais_at_once` |
| Its clock is off (F13) | a pose stamped in the future counts as that old; a little skew is tolerated, more is refused, ahead or behind | `a_robot_clock_off_cannot_make_a_stale_pose_fresh` |
| Its state is malformed or forged | a pose that is not integers is no pose; an unknown motion state is not `idle`; a robot that claims to be elsewhere than its goal is `diverged` | `a_malformed_state_is_no_evidence` |
| The geofence's edge | a goal on the edge is inside, a millimetre beyond is not; backwards out of it is refused like forwards; at the corner, facing out, it cannot move out | `the_geofence_at_its_edge` |

## Finding F13: a robot clock ahead made a stale pose look fresh

**Problem.** `SAFE-9` measured a pose's age as `now − localized_at_ms`, on the robot's clock, and never less than the observation's age. A robot whose clock runs ahead stamps its fixes in the future. If its localisation then stalls on an old fix, the fix stays "fresh" for as long as the clock is ahead. A robot 5 s ahead, with a limit of 1 s, could start a motion from a pose up to 5 s old.

**Fix.** A pose stamped in the future counts as that old: the age is `|now − localized_at_ms|`.
- **Small skew:** a skew below the resource's limit still passes, with less margin.
- **Larger skew:** refused, with the reason "its clock is ahead". A misconfigured clock shows up instead of being trusted.

## Decided: a stop lost to a dropped link

**The question:** should a recovery's stop be retried? A robot that drops off mid-motion cannot be reached by the recovery's stop.

**The Project Lead's decision (2026-10-06): never resend it, decide anew on new evidence.** Back, the robot is observed first:
- at rest: nothing is sent;
- still moving: a new stop is minted and sent once;
- not observable yet: nothing blind.

The rule is general SAFE-8 semantics (spec 22), for any resource with a safe state: one attempt per confirmed unsafe observation, never one per timeout.

## Tests and mutations

`chitala-node/tests/robot_adversarial.rs` holds 10 tests on the shared robot harness (`tests/common/robot.rs`). The harness's restart goes through JSON, as the node's state file does.

The simulator gained two faults for it: a skewed clock (`clock_skew`) and forged or malformed values (`forge`).

**Mutations: 4 of 4 caught.**
- F13 undone.
- A motion's expected pose not persisted.
- `not_applied` judged without a pose.
- The simulator without its protective stop.

The suite would notice the last one: an obstacle must halt a robot that is under way.
