//! The robot adversarial suite (spec 31): what the world does to a moving
//! robot, through the whole chain. Something gets in its way, its emergency
//! stop is pressed, it loses where it is, its answers are lost, it drops
//! off, Chitala restarts while it moves, two AIs want it at once, its clock
//! is off, its state is malformed.
//!
//! Whatever happens:
//! - **it never moves on its own:** after a fault, nothing resumes a motion;
//!   only a new, cleared order moves it;
//! - **a broken promise stops it:** a motion that did not end where it
//!   should is `diverged` or `unconfirmed`, the robot enters recovery, and
//!   is stopped when it can be observed;
//! - **a stop always gets through;**
//! - **nothing made up:** a pose that cannot be trusted is no pose.

mod common;

use chitala_adapters::mock::Lost;
use chitala_adapters::robot_sim::Localization;
use chitala_model::{ExecCode, ParamValue, Payload, Pose};
use common::robot::*;
use serde_json::Value;

fn drive(h: &mut Home, distance_mm: i64) -> chitala_node::Response {
    h.owner("robot.move_linear", &[("distance_mm", distance_mm), ("speed_mm_s", 500)])
}

/// The last verdict on a capability's order.
fn verdict(h: &Home, capability: &str) -> Value {
    h.outcomes().into_iter().rfind(|o| o["capability"] == capability).unwrap_or(Value::Null)
}

fn robot() -> chitala_model::EntityId {
    id(ROBOT)
}

/// Something gets in the robot's way mid-motion: it halts by itself (a
/// protective stop), the motion is broken, and nothing moves it again until
/// a person releases it, the obstacle long gone.
#[test]
fn an_obstacle_mid_motion_halts_it_and_nothing_resumes_it() {
    let mut h = home();
    assert!(drive(&mut h, 2_000).is_ok());
    h.pass(1_000);
    h.sim.obstacle(&robot(), true);
    h.settle();
    assert_eq!(verdict(&h, "robot.move_linear")["status"], "diverged");
    assert!(h.in_recovery());
    let halted = h.sim.pose(&robot()).unwrap();
    assert!(halted.x_mm < 2_000, "{halted:?}");
    h.sim.obstacle(&robot(), false);
    h.pass(5_000);
    assert_eq!(h.sim.pose(&robot()), Some(halted), "it never moves on its own");
    assert!(refused_by(&drive(&mut h, 500), "SAFE-8-RECOVERY"), "in recovery until a person releases it");
    assert!(h.owner("robot.stop", &[]).is_ok(), "a stop gets through");
    assert!(h.release().is_ok());
    h.pass(500);
    assert!(drive(&mut h, 500).is_ok());
}

/// The emergency stop is pressed mid-motion. The motion is broken; recovery
/// sends a stop once, which the robot takes but cannot confirm while
/// pressed, and never sends another. Nothing moves until it is released and
/// a person ends the recovery.
#[test]
fn the_emergency_stop_mid_motion() {
    let mut h = home();
    assert!(drive(&mut h, 2_000).is_ok());
    h.pass(500);
    h.sim.emergency_stop(&robot(), true);
    h.settle();
    assert_eq!(verdict(&h, "robot.move_linear")["status"], "diverged");
    assert!(h.in_recovery());
    h.settle();
    h.pass(10_000);
    assert_eq!(h.sim.commands(&robot()), 2, "the motion, and the recovery's one stop: no loop");
    assert!(h.req("person:guest", ROBOT, "robot.stop", Payload::new()).is_ok(), "a guest still stops it");
    assert!(refused_by(&drive(&mut h, 300), "SAFE-8-RECOVERY"));
    h.sim.emergency_stop(&robot(), false);
    assert!(h.release().is_ok());
    h.pass(500);
    assert!(drive(&mut h, 300).is_ok());
}

/// Localisation lost, or stuck on an old pose, mid-motion: the robot moved,
/// but its pose cannot show where to. No evidence: the motion is broken, the
/// robot stopped, and no motion starts from a pose it does not have.
#[test]
fn localisation_lost_or_stale_mid_motion_is_no_evidence() {
    for fault in [Localization::Lost, Localization::Stale] {
        let mut h = home();
        assert!(drive(&mut h, 2_000).is_ok());
        h.pass(500);
        h.sim.localization(&robot(), fault);
        h.settle();
        let o = verdict(&h, "robot.move_linear");
        assert_eq!(o["status"], "diverged", "{fault:?}: {o}");
        assert!(h.in_recovery(), "{fault:?}");
        assert_eq!(h.sim.pose(&robot()).unwrap().x_mm, 2_000, "{fault:?}: it did arrive; nobody can tell");
        assert!(h.release().is_ok());
        h.pass(2_000);
        let r = drive(&mut h, 300);
        assert!(refused_by(&r, "SAFE-9-MOTION"), "{fault:?}: {}", r.summary());
    }
}

/// The answer to a motion is lost on its way back. If it moved, its pose
/// shows it: `applied`. If it did not, its settled state shows that:
/// `not_applied`, and no recovery. If it went silent too, nobody can tell:
/// `unconfirmed`, recovery, and no stop sent into the silence.
#[test]
fn an_answer_lost_on_the_way_back() {
    let mut h = home();
    h.sim.lose_next(&robot(), Lost::AfterEffect);
    let r = drive(&mut h, 1_000);
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    h.settle();
    assert_eq!(verdict(&h, "robot.move_linear")["status"], "applied");

    h.sim.lose_next(&robot(), Lost::WithoutEffect);
    assert!(!drive(&mut h, 1_000).is_ok());
    h.settle();
    assert_eq!(verdict(&h, "robot.move_linear")["status"], "not_applied");
    assert!(!h.in_recovery(), "it did not move: a known state");

    // the same, but it loses where it is right after: it did not move, and
    // cannot show it. Not `not_applied`: nobody knows
    h.sim.lose_next(&robot(), Lost::WithoutEffect);
    assert!(!drive(&mut h, -500).is_ok());
    h.sim.localization(&robot(), Localization::Lost);
    h.settle();
    assert_eq!(verdict(&h, "robot.move_linear")["status"], "unconfirmed");
    assert!(h.in_recovery());
    h.sim.localization(&robot(), Localization::Live);
    assert!(h.release().is_ok());
    h.pass(1_000);

    h.sim.lose_next(&robot(), Lost::AndOffline);
    assert!(!drive(&mut h, 1_000).is_ok());
    h.settle();
    assert_eq!(verdict(&h, "robot.move_linear")["status"], "unconfirmed");
    assert!(h.in_recovery());
    assert_eq!(h.sim.commands(&robot()), 4, "no stop sent into the silence");
    h.sim.offline(&robot(), false);
    h.pass(1_000);
    assert!(refused_by(&drive(&mut h, 300), "SAFE-8-RECOVERY"), "back, and still in recovery");
    assert!(h.owner("robot.stop", &[]).is_ok());
}

/// The robot drops off the network mid-motion, and comes back. It was last
/// seen still moving: the motion is broken (`diverged`), it is in recovery,
/// and the recovery's one stop cannot reach it. Coming back ends nothing: a
/// person stops it or releases it.
#[test]
fn the_robot_drops_off_mid_motion() {
    let mut h = home();
    assert!(drive(&mut h, 2_000).is_ok());
    h.pass(500);
    h.sim.offline(&robot(), true);
    h.settle();
    assert_eq!(verdict(&h, "robot.move_linear")["status"], "diverged", "last seen moving");
    assert!(h.in_recovery());
    h.settle();
    assert_eq!(h.sim.commands(&robot()), 1, "nothing reached it while it was off");
    h.sim.offline(&robot(), false);
    h.pass(2_000);
    assert!(h.in_recovery(), "coming back ends nothing");
    assert!(refused_by(&drive(&mut h, 300), "SAFE-8-RECOVERY"));
    assert!(h.owner("robot.stop", &[]).is_ok(), "a person stops it");
}

/// Chitala restarts while the robot moves. The promise was persisted with
/// its expected pose: after the restart it is kept, and verified, or broken
/// and the robot stopped. Nothing is sent twice.
#[test]
fn a_restart_mid_motion_keeps_its_promise() {
    let mut h = home();
    assert!(drive(&mut h, 2_000).is_ok());
    h.pass(1_000);
    let mut h = restart(h);
    h.settle();
    let o = verdict(&h, "robot.move_linear");
    assert_eq!(
        (o["status"].as_str(), o["expected_pose"]["pose"]["x_mm"].as_i64()),
        (Some("verified"), Some(2_000)),
        "{o}"
    );
    assert_eq!(h.sim.commands(&robot()), 1);

    h.sim.slip(&robot(), 0.5);
    assert!(drive(&mut h, 1_000).is_ok());
    h.pass(500);
    let mut h = restart(h);
    h.settle();
    assert_eq!(verdict(&h, "robot.move_linear")["status"], "diverged");
    assert!(h.in_recovery());
    h.settle();
    assert_eq!(h.sim.commands(&robot()), 3, "two motions, one stop");
}

/// Two AIs want the robot at once: one motion at a time. The other may stop
/// it (its motion right includes the stop), and the stopped motion is
/// superseded, not failed.
#[test]
fn two_ais_at_once() {
    let mut h = home();
    let a = h.delegate("ai:assistant", ROBOT_R, "robot.move_linear");
    let b = h.delegate("ai:other", ROBOT_R, "robot.rotate");
    let r = h.ai("ai:assistant", "robot.move_linear", &[("distance_mm", 2_000), ("speed_mm_s", 400)], Some(&a));
    assert!(r.is_ok(), "{}", r.summary());
    h.pass(500);
    let r = h.ai("ai:other", "robot.rotate", &[("angle_mdeg", 90_000), ("speed_mdeg_s", 45_000)], Some(&b));
    assert!(refused_by(&r, "still moving"), "{}", r.summary());
    assert!(h.ai("ai:other", "robot.stop", &[], Some(&b)).is_ok());
    h.settle();
    assert_eq!(verdict(&h, "robot.move_linear")["status"], "superseded");
    assert!(!h.in_recovery());
    h.pass(500);
    let r = h.ai("ai:other", "robot.rotate", &[("angle_mdeg", 90_000), ("speed_mdeg_s", 45_000)], Some(&b));
    assert!(r.is_ok(), "{}", r.summary());
}

/// The robot's clock is off (finding F13). Ahead, its pose would look
/// fresher than it is: a pose stamped in the future counts as that old. A
/// little skew is tolerated; more is refused, whichever way.
#[test]
fn a_robot_clock_off_cannot_make_a_stale_pose_fresh() {
    let mut h = home();
    h.sim.clock_skew(&robot(), 300);
    h.pass(500);
    assert!(drive(&mut h, 200).is_ok(), "300 ms ahead: within the 1 s allowed");
    h.settle();
    // observed again only after half the state's 2 s
    h.sim.clock_skew(&robot(), 5_000);
    h.sim.localization(&robot(), Localization::Stale);
    h.pass(1_500);
    let r = drive(&mut h, 200);
    assert!(refused_by(&r, "in the future"), "{}", r.summary());
    h.sim.localization(&robot(), Localization::Live);
    h.sim.clock_skew(&robot(), -5_000);
    h.pass(1_500);
    assert!(refused_by(&drive(&mut h, 200), "SAFE-9-MOTION"), "behind: as stale as it says");
}

/// A malformed or forged state: a pose that is not one is no pose; a
/// motion state nobody knows is not idle.
#[test]
fn a_malformed_state_is_no_evidence() {
    let mut h = home();
    h.sim.forge(&robot(), "pose_x_mm", ParamValue::from("12.5"));
    h.pass(1_000);
    assert!(refused_by(&drive(&mut h, 200), "not localised"));
    let mut h = home();
    h.sim.forge(&robot(), "motion_state", ParamValue::from("hovering"));
    h.pass(1_000);
    assert!(refused_by(&drive(&mut h, 200), "is unknown"));
    // a robot that claims to have arrived somewhere else is not believed
    let mut h = home();
    assert!(drive(&mut h, 1_000).is_ok());
    h.sim.forge(&robot(), "pose_x_mm", ParamValue::Int(3_000));
    h.settle();
    assert_eq!(verdict(&h, "robot.move_linear")["status"], "diverged");
}

/// The geofence, at its edge: a goal on the edge is inside; a millimetre
/// beyond is not; backwards out of it is refused like forwards.
#[test]
fn the_geofence_at_its_edge() {
    let mut h = home();
    let goto = |h: &mut Home, x: i64, y: i64| {
        h.owner("robot.goto_pose", &[("x_mm", x), ("y_mm", y), ("theta_mdeg", 0), ("speed_mm_s", 800)])
    };
    assert!(refused_by(&goto(&mut h, 4_001, 3_000), "geofence"));
    assert!(refused_by(&drive(&mut h, -1_001), "geofence"), "backwards");
    let r = goto(&mut h, 4_000, 3_000);
    assert!(r.is_ok(), "{}", r.summary());
    h.settle();
    assert!(h.sim.pose(&robot()).unwrap().within(&Pose::new(4_000, 3_000, 0), 1, 1));
    assert!(refused_by(&drive(&mut h, 1), "geofence"), "at the corner, facing out");
}
