# Hazard log

What can go physically wrong through Chitala, what Chitala does about it, and what it relies on outside itself. Each hazard's requirements, tests and evidence are in [the traceability matrix](traceability.md). How this log is kept is in [the README](README.md).

Each hazard has:
- **Causes**: how it can arise, by fault, misuse or attack;
- **Harm**: what it can lead to, at worst;
- **Controls**: what Chitala does about it;
- **Relies on**: what Chitala needs from outside itself for those controls to hold;
- **Status**: one of
  - *controlled*: every control is in place and tested;
  - *controlled, with assumptions*: the controls hold only if what the hazard relies on holds;
  - *partly controlled*: a gap is open, and named.

No hazard here carries a risk estimate. How likely a harm is, and how much risk is acceptable, depend on the deployment: its equipment, its site and its people.

## General: any actuator

### H-GEN-001: An action nobody with authority asked for
- **Causes:**
  - an AI acting beyond its rights, or after a prompt injection;
  - a forged or replayed request;
  - a stolen, expired or revoked token;
  - an AI laundering authority through another AI.
- **Harm:** anything the device can do: a door opened to an intruder, an appliance started.
- **Controls:** signed identities; the reference monitor; Authority (tokens, delegation, revocation, approvals); one path from a decision to an actuator, through the trusted execution boundary (specs 02, 08, 16, 19).
- **Relies on:** keys kept secret (spec 13, R1).
- **Status:** controlled, with assumptions. Each attack spec 13 blocks has a test.

### H-GEN-002: One action executed twice
- **Causes:** a resend after a lost answer; a replayed order; two executors; a restart mid-order.
- **Harm:** a door unlocked again after it was locked; a motor started twice.
- **Controls:**
  - every order is single-use, bound to one executor session, and expires (spec 19);
  - a command whose answer was lost is never sent again; its fate is settled from evidence (specs 22, 26).
- **Relies on:** adapters that pass the conformance suite, which forbids their own retries (spec 26).
- **Status:** controlled, with assumptions.

### H-GEN-003: An action on unknown or stale state
- **Causes:**
  - a device that cannot be observed;
  - an old cached reading, or a reading folded in late;
  - a subscription gone quiet;
  - a clock set back.
- **Harm:** acting on a belief, not a fact: heating what is already hot, locking a door that is open.
- **Controls:**
  - `SAFE-3-STATE` refuses actions of medium risk or more on state that is unknown or older than its maximum age;
  - only state confirmed current is evidence (specs 10, 22; F12).
- **Relies on:** devices that report their state truthfully. By default the witness of an action is the device itself (spec 13, R14).
- **Status:** controlled, with assumptions.

### H-GEN-004: An action that contradicts the physical state
- **Causes:** an authorized request made without knowing the state, for example locking a door that stands open.
- **Harm:** a bolt thrown into the frame; a door that will not close; damage.
- **Controls:**
  - `SAFE-4-PHYSICAL`;
  - the device's own invariants: the layer after the command, independent of Chitala (Constitution C5).
- **Relies on:** devices that keep their own invariants.
- **Status:** partly controlled. `SAFE-4` knows one contradiction (v0.1: `lock.lock` while the door is open); a profile that needs others needs a rule for each (gap G-3).

### H-GEN-005: Parameters outside safe limits
- **Causes:** an AI or a person asking for too much: a setpoint too high, a speed too fast.
- **Harm:** overheating, overspeed, damage, injury.
- **Controls:** `SAFE-5-ENVELOPE`: each resource's own envelope, tighter than the registry's limits.
- **Relies on:** an installer who sets the envelope right for the real equipment.
- **Status:** controlled, with assumptions.

### H-GEN-006: Actuation repeated too often
- **Causes:** an agent caught in a loop; two agents fighting; oscillation.
- **Harm:** wear; overheated motors and relays; flicker.
- **Controls:** `SAFE-6-RATE`.
- **Status:** controlled.

### H-GEN-007: Conflicting orders that interleave
- **Causes:** two clients, two controllers or two agents acting on one resource at once.
- **Harm:** contradictory commands to one mechanism: a door driven both ways, two motions at once.
- **Controls:** `SAFE-7-BUSY`: one action at a time per device and per resource, across devices.
- **Status:** controlled.

### H-GEN-008: An action during a safety hold
- **Causes:** a request, or an order already in flight, while a person keeps a resource still, for maintenance or because someone is in danger.
- **Harm:** a machine that starts while someone works on it.
- **Controls:**
  - `SAFE-1-HOLD` covers the resource and everything below it, and stops orders already in flight;
  - holds survive a restart, and a rollback past one is refused;
  - only owners and admins place or lift a hold, never an AI (C11).
- **Relies on:** a person who places the hold.
- **Status:** controlled, with assumptions.

### H-GEN-009: A failed action that goes unnoticed
- **Causes:** a jammed lock; a device that drops off; a command lost on the way.
- **Harm:** a system believed safe that is not: a door believed locked that is open.
- **Controls:**
  - every action declares a checkable outcome, verified from evidence confirmed current (spec 22);
  - an action of medium risk or more that missed its outcome puts the resource in recovery (`SAFE-8-RECOVERY`), and only a person ends it.
- **Status:** controlled.

### H-GEN-010: A recovery that makes things worse
- **Causes:** a safe state sent blind, again and again; a flapping link; stale evidence taken for danger.
- **Harm:** repeated actuation; wear; a mechanism cycled on a false alarm.
- **Controls:** `SAFE-8-RECOVERY`:
  - one new order per confirmed unsafe observation, never a resend;
  - at most as many attempts as the safe state's retry policy allows (spec 22).
- **Status:** controlled.

### H-GEN-011: Actuation through a compromised device
- **Causes:** a device that is quarantined, in recovery or due for re-attestation, or that was never trusted.
- **Harm:** commands that a compromised device misuses or reports falsely.
- **Controls:** `SAFE-2-DEVICE`:
  - nothing through a contained device;
  - no action of high risk or more through a device that is not trusted.
- **Relies on:** detecting that a device is compromised. There is no device attestation yet (spec 13, R5).
- **Status:** partly controlled (gap G-4).

### H-GEN-012: An approval of an action that became unsafe meanwhile
- **Causes:** the state changes while a person decides; an approval arrives late.
- **Harm:** an action carried out in a situation nobody approved.
- **Controls:**
  - Safety runs again when the person answers, and again right before the boundary mints an order;
  - a clearance covers exactly one action of one request, at one time (specs 17, 19).
- **Status:** controlled.

### H-GEN-013: A protective action that Chitala blocks
- **Causes:** a stop refused by a rule, a hold, a recovery, a rate limit or a history rule; a stop the requester has no right to send.
- **Harm:** a machine that cannot be stopped through Chitala.
- **Controls:**
  - a stop always wins: a capability that only halts passes Safety and the in-flight checks, and does not count against the rate (specs 17, 30);
  - a right to move includes the right to stop;
  - no history rule can govern a stop or a safe state (spec 32).
- **Relies on:** the machine's own hardware E-stop and watchdogs, which never depend on Chitala (spec 30).
- **Status:** controlled, with assumptions.

### H-GEN-014: Safety state lost or rolled back
- **Causes:** a crash; an old state file restored; the audit log truncated.
- **Harm:** a hold or a recovery that disappears, so actions resume.
- **Controls:**
  - holds and recoveries are persisted, and each change moves the authority epoch;
  - a state behind the audit log is refused at start-up;
  - every action is on record before it is carried out (specs 09, 17).
- **Relies on:** one disk cannot show that the state *and* the audit log were rolled back together. That needs an anchor outside it, such as a hardware monotonic counter or checkpoints held elsewhere (spec 13, R2, planned for v0.5).
- **Status:** controlled, with assumptions.

### H-GEN-015: Time manipulated
- **Causes:**
  - a clock set back, to revive expired tokens, approvals or questions;
  - a device clock ahead, making old data look fresh.
- **Harm:** an action allowed on authority or evidence that has expired.
- **Controls:**
  - the platform clock never goes back, and the node refuses to start behind its audit log (spec 18; spec 13, R3);
  - a pose's age is measured both ways from now (F13).
- **Status:** controlled.

### H-GEN-016: Chitala fails in the middle of an action
- **Causes:** a crash, a hang or a power loss of the node or of an adapter host.
- **Harm:** an action half done, its fate unknown.
- **Controls:**
  - an order expires and dies with the node that minted it;
  - an unknown execution survives a restart and is settled from evidence, never by a resend;
  - a hung adapter host does not stall the node (specs 19, 22);
  - an adapter host that does not come up at start leaves the node running, degraded: its devices refuse orders (not sent), and it is started again only on demand, in a new session (spec 11).
- **Relies on:** devices that behave safely when their controller goes silent (Constitution C5; spec 30, the robot's watchdog).
- **Status:** controlled, with assumptions.

## Home

### H-HOME-001: A door opened for someone who should not enter
- **Causes:** a child's or a guest's AI; an AI asked by a stranger; one person acting as both keys.
- **Harm:** intrusion; a child leaving alone.
- **Controls:**
  - unlocking is high risk, and an AI's request needs an owner's approval of that exact intent;
  - a two-key door needs two different people (specs 14, 16).
- **Status:** controlled.

### H-HOME-002: A door believed locked that is not
- **Causes:** a jammed bolt; a lock that Home Assistant reports unavailable; a dead Matter lock whose cached state looks new.
- **Harm:** intrusion.
- **Controls:**
  - a lock nobody can observe is not known to be locked;
  - a failed lock puts the door in recovery, with a single safe-state attempt (spec 22; adapters, specs 25 and 27).
- **Status:** controlled. Validated in the lab against real Home Assistant and Matter devices (v0.3).

## Robot

Robots are validated on a simulator only (spec 30). The robot's own protections stay primary: Chitala is the layer before the command, never the only way to stop a machine.

### H-ROB-001: Motion that does not stop when it should
- **Causes:** a stop lost to a dropped link; a stop refused; a robot that drops off mid-motion; the node down.
- **Harm:** collision; injury.
- **Controls:**
  - a stop always wins (H-GEN-013), and a stop supersedes the motion it interrupts;
  - a lost stop is decided anew on reconnect, on new evidence, up to `robot.stop`'s retry policy (spec 22).
- **Relies on:** the robot's hardware E-stop, its local motor watchdog and its controller's watchdog, which are the primary protection (spec 30). A Chitala deadman is planned as a fourth layer (roadmap; gap G-5).
- **Status:** controlled, with assumptions.

### H-ROB-002: Motion into an obstacle or a person
- **Causes:** an obstacle in the path; an E-stop pressed; a motion started regardless.
- **Harm:** collision; injury.
- **Controls:** `SAFE-9-MOTION` refuses a motion with an obstacle detected or the E-stop pressed, and nothing resumes a halted motion by itself.
- **Relies on:** the robot's own obstacle sensing and collision avoidance. Chitala sees a flag, not geometry.
- **Status:** partly controlled. Typed, current evidence from the robot stack is planned (gap G-6).

### H-ROB-003: Motion from a wrong pose
- **Causes:** localisation lost or stale; a robot clock that is off; a malformed state.
- **Harm:** a motion planned from the wrong place, ending somewhere unintended.
- **Controls:** `SAFE-9-MOTION` refuses a motion without a pose, or from a pose fixed longer ago than the resource allows, measured both ways from now (F13).
- **Status:** controlled.

### H-ROB-004: Motion that leaves its permitted area
- **Causes:** a goal or a path outside the area the robot may use.
- **Harm:** a robot where people are, or near a stair or a road.
- **Controls:** `SAFE-9-MOTION` checks the straight path against the resource's convex geofence.
- **Relies on:** an accurate pose, and a robot that moves straight between poses.
- **Status:** controlled, with assumptions.

### H-ROB-005: Motion too fast
- **Causes:** a speed parameter above what the place allows.
- **Harm:** collision energy; loss of control.
- **Controls:**
  - `SAFE-5-ENVELOPE` bounds every motion's speed;
  - a robot without declared motion limits is refused (spec 30).
- **Status:** controlled.

### H-ROB-006: Motion that silently goes wrong
- **Causes:** wheel slip; a stall; a restart mid-motion.
- **Harm:** a robot believed elsewhere, and later motions planned from the wrong place.
- **Controls:** the pose outcome, within its tolerance, is verified; a broken promise puts the robot in recovery, and its safe state is a stop (specs 22, 30).
- **Status:** controlled.

### H-ROB-007: Two commanders, one robot
- **Causes:** two AIs, or an AI and a person, moving one robot at once.
- **Harm:** contradictory motions.
- **Controls:** `SAFE-7-BUSY`, and a stop supersedes the motion it interrupts.
- **Status:** controlled.

### H-ROB-008: A storm of stops on a flapping link
- **Causes:** a link that drops and comes back over and over.
- **Harm:** a robot and its controller flooded with stop orders; real faults hidden in the noise.
- **Controls:** `SAFE-8-RECOVERY`: one attempt at a time, one per confirmed observation, within the retry policy.
- **Status:** controlled.

## History

### H-HIST-001: Cumulative over-use
- **Causes:** a pump, heater or motor run longer, or more often, than it may: each action alone looks harmless.
- **Harm:** overheating; wear; flooding; fire.
- **Controls:** `SAFE-10-HISTORY`: a history rule, checked by the history evaluator, denies an action that would break its limit (spec 32).
- **Relies on:** an owner who declares the rule.
- **Status:** controlled, with assumptions.

### H-HIST-002: A false history verdict
- **Causes:** a forged, stale or replayed record; one from another evaluator; a history log edited or cut back.
- **Harm:** an action allowed past its limit.
- **Controls:** `SAFE-10-HISTORY`:
  - a record must come from the authorized evaluator, be bound to the request's evaluation context and the rule's version, and be fresh;
  - the history log is hash-chained, and its head is anchored in the audit log (spec 32).
- **Status:** controlled.

### H-HIST-003: Unknown time counted as safe
- **Causes:** gaps in the history: the device unobservable, the recorder restarted, events dropped.
- **Harm:** an action allowed past its limit, because the time nobody saw was taken as off.
- **Controls:** `SAFE-10-HISTORY`:
  - the evaluator takes the worst case;
  - a rule that cannot be decided is `INSUFFICIENT_HISTORY`, and fails closed for the governed action.
- **Status:** controlled.

### H-HIST-004: A history rule weakened or removed by an AI
- **Causes:** an AI with domain rights; a prompt-injected agent.
- **Harm:** a protective limit removed without a person deciding it.
- **Controls:** only owners, and admins explicitly allowed, set or remove rules (C11); every change is a new, audited version (spec 32).
- **Status:** controlled.
