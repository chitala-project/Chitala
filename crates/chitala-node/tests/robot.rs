//! A ground robot through the whole chain (Robot Profile v0.1, spec 30): an
//! AI moves it with a token, Safety keeps it inside its limits (SAFE-5,
//! SAFE-9), a stop always wins, and its outcome is a pose within a tolerance.

mod common;

use chitala_adapters::robot_sim::Localization;
use chitala_model::{payload, Geofence, ParamValue, Payload, Pose};
use chitala_resource::Resource;
use common::robot::*;
use serde_json::Value;

/// An AI moves the robot with its token; the outcome is the pose the motion
/// leads to, from where the robot was, within the tolerance.
#[test]
fn an_ai_moves_the_robot_and_its_pose_is_verified() {
    let mut h = home();
    let r = h.ai("ai:assistant", "robot.move_linear", &[("distance_mm", 1_000), ("speed_mm_s", 500)], None);
    assert!(!r.is_ok(), "no token, no motion: {}", r.summary());
    let token = h.delegate("ai:assistant", ROBOT_R, "robot.move_linear");
    // 5 s of motion: longer than the outcome's own 3 s, which it is added to
    let r = h.ai("ai:assistant", "robot.move_linear", &[("distance_mm", 2_000), ("speed_mm_s", 400)], Some(&token));
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(h.node.pending_outcomes().len(), 1, "under way");
    h.settle();
    let o = h.last_outcome();
    assert_eq!(o["status"], "verified", "{o}");
    assert_eq!(o["expected_pose"]["pose"]["x_mm"], 2_000, "{o}");
    assert_eq!(o["observed_pose"]["x_mm"], 2_000, "{o}");
    // from where it is now, not from where it began
    let r = h.ai("ai:assistant", "robot.move_linear", &[("distance_mm", -500), ("speed_mm_s", 500)], Some(&token));
    assert!(r.is_ok(), "{}", r.summary());
    h.settle();
    let o = h.last_outcome();
    assert_eq!(
        (o["status"].as_str(), o["expected_pose"]["pose"]["x_mm"].as_i64()),
        (Some("verified"), Some(1_500)),
        "{o}"
    );
    assert_eq!(h.sim.pose(&id(ROBOT)), Some(Pose::new(1_500, 0, 0)));
    // the same token does not turn it
    let r = h.ai("ai:assistant", "robot.rotate", &[("angle_mdeg", 90_000), ("speed_mdeg_s", 45_000)], Some(&token));
    assert!(!r.is_ok(), "{}", r.summary());
}

/// SAFE-5 and SAFE-9: the robot moves only within its limits, from a known
/// recent pose, with nothing in its way and its emergency stop released.
#[test]
fn safety_keeps_the_robot_within_its_limits() {
    let mut h = home();
    let robot = id(ROBOT);
    let go = |h: &mut Home, d: i64, v: i64| h.owner("robot.move_linear", &[("distance_mm", d), ("speed_mm_s", v)]);
    assert!(refused_by(&go(&mut h, 500, 900), "SAFE-5-ENVELOPE"), "faster than the resource allows");
    assert!(refused_by(&go(&mut h, 4_500, 500), "SAFE-9-MOTION"), "out of the geofence");
    let r = h.owner("robot.goto_pose", &[("x_mm", 3_000), ("y_mm", 3_500), ("theta_mdeg", 0), ("speed_mm_s", 500)]);
    assert!(refused_by(&r, "geofence"), "{}", r.summary());

    h.sim.obstacle(&robot, true);
    h.pass(1_000);
    assert!(refused_by(&go(&mut h, 500, 500), "obstacle"));
    h.sim.obstacle(&robot, false);
    h.sim.emergency_stop(&robot, true);
    h.pass(1_000);
    assert!(refused_by(&go(&mut h, 500, 500), "emergency stop"));
    h.sim.emergency_stop(&robot, false);
    h.sim.localization(&robot, Localization::Lost);
    h.pass(1_000);
    assert!(refused_by(&go(&mut h, 500, 500), "not localised"));
    h.sim.localization(&robot, Localization::Stale);
    h.pass(1_500);
    assert!(refused_by(&go(&mut h, 500, 500), "fixed"), "a pose fixed 1.5 s ago");
    h.sim.localization(&robot, Localization::Live);
    h.pass(1_000);

    // one motion at a time
    assert!(go(&mut h, 2_000, 500).is_ok());
    h.pass(1_000);
    assert!(refused_by(&go(&mut h, 500, 500), "still moving"));
    assert_eq!(h.sim.commands(&robot), 1, "nothing refused reached the robot");
}

/// A stop always wins: under a safety hold, with the emergency stop pressed,
/// with its pose unknown, from a guest. Nobody but its owner moves it.
#[test]
fn a_stop_always_wins() {
    let mut h = home();
    let robot = id(ROBOT);
    let hold = payload([("resource", ParamValue::from(ROBOT_R))]);
    assert!(h.req("person:alice", "domain:home", "domain.safety_hold", hold).is_ok());
    let r = h.owner("robot.move_linear", &[("distance_mm", 500), ("speed_mm_s", 500)]);
    assert!(refused_by(&r, "SAFE-1-HOLD"), "{}", r.summary());
    let r = h.owner("robot.stop", &[]);
    assert!(r.is_ok(), "under a hold: {}", r.summary());

    h.sim.emergency_stop(&robot, true);
    h.sim.localization(&robot, Localization::Lost);
    h.pass(500);
    assert!(h.owner("robot.stop", &[]).is_ok(), "pressed and lost");
    // a guest stops it, and does not move it
    assert!(h.req("person:guest", ROBOT, "robot.stop", Payload::new()).is_ok());
    let r = h.req("person:guest", ROBOT, "robot.move_linear", ints(&[("distance_mm", 100), ("speed_mm_s", 100)]));
    assert!(!r.is_ok(), "{}", r.summary());
    // stops are no actuations to hold motions back
    for _ in 0..10 {
        assert!(h.owner("robot.stop", &[]).is_ok());
    }
}

/// Stops are no actuations: however many, they never hold a motion back
/// under the rate (SAFE-6).
#[test]
fn stops_do_not_count_against_the_rate() {
    let mut h = home();
    for _ in 0..10 {
        assert!(h.owner("robot.stop", &[]).is_ok());
    }
    h.pass(500);
    let r = h.owner("robot.move_linear", &[("distance_mm", 300), ("speed_mm_s", 300)]);
    assert!(r.is_ok(), "{}", r.summary());
}

/// A robot is governed only within limits: a resource that binds a motion
/// without a geofence, or without a bound on its speed, is refused.
#[test]
fn a_robot_without_limits_is_refused() {
    let registry = chitala_model::CapabilityRegistry::core_v0_1();
    let check = |r: Resource| chitala_resource::ResourceGraph::new(vec![r], &registry).map(|_| ());
    let mut r = robot();
    r.parent = None;
    r.owners = vec![id("person:alice")];
    assert_eq!(check(r.clone()).map_err(|e| e.to_string()), Ok(()));
    let mut no_fence = r.clone();
    no_fence.motion = None;
    assert!(check(no_fence).unwrap_err().to_string().contains("no motion limits"));
    let mut fast = r.clone();
    fast.envelope.retain(|l| l.capability.as_str() != "robot.rotate");
    assert!(check(fast).unwrap_err().to_string().contains("speed_mdeg_s"));
    let mut concave = r.clone();
    concave.motion.as_mut().unwrap().geofence =
        Geofence(vec![[0, 0], [4_000, 0], [4_000, 1_000], [1_000, 1_000], [1_000, 3_000], [0, 3_000]]);
    assert!(check(concave).unwrap_err().to_string().contains("convex"));
    let mut no_stop = r.clone();
    no_stop.safe_state = None;
    assert!(check(no_stop).unwrap_err().to_string().contains("safe state is its stop"));
    let mut still = r;
    still.bindings.retain(|b| !b.capability.as_str().starts_with("robot."));
    still.safe_state = None;
    still.envelope.clear();
    assert!(check(still).unwrap_err().to_string().contains("binds no motion"), "limits with nothing to limit");
}

/// A right to move a robot includes the right to stop it; nothing else does.
#[test]
fn a_motion_right_includes_the_stop() {
    let mut h = home();
    let moves = h.delegate("ai:assistant", ROBOT_R, "robot.goto_pose");
    let lights = h.delegate("ai:other", "resource:living-room-light", "light.turn_on");
    assert!(h.ai("ai:assistant", "robot.stop", &[], Some(&moves)).is_ok());
    assert!(!h.ai("ai:other", "robot.stop", &[], Some(&lights)).is_ok());
    assert!(!h.ai("ai:other", "robot.stop", &[], None).is_ok());
}

/// Wheel slip ends the motion short: diverged, and the robot is in
/// recovery. It is at rest already (`idle`): no stop is sent. A stall never
/// arrives: diverged at the deadline, the robot still moving, and the stop
/// is sent.
#[test]
fn slip_and_stalls_break_the_promise_and_recovery_stops_the_robot() {
    let mut h = home();
    let robot = id(ROBOT);
    h.sim.slip(&robot, 0.9);
    assert!(h.owner("robot.move_linear", &[("distance_mm", 2_000), ("speed_mm_s", 500)]).is_ok());
    h.settle();
    let moved = h.outcomes().into_iter().find(|o| o["capability"] == "robot.move_linear").unwrap();
    assert_eq!(moved["status"], "diverged", "1800 mm of 2000: {moved}");
    assert!(h.in_recovery());
    h.pass(5_000);
    assert_eq!(h.sim.commands(&robot), 1, "at rest: no stop needed");
    assert!(h.release().is_ok());

    h.sim.slip(&robot, 1.0);
    h.sim.stall(&robot, true);
    assert!(h.owner("robot.rotate", &[("angle_mdeg", 90_000), ("speed_mdeg_s", 90_000)]).is_ok());
    h.settle();
    let stop = h.outcomes().into_iter().find(|o| o["capability"] == "robot.stop").expect("the safe state ran");
    assert_eq!(stop["status"], "verified", "{stop}");
    assert_eq!(h.sim.commands(&robot), 3, "the motion, the stalled turn, its stop");
    assert!(!h.sim.moving(&robot), "the stall's motion was stopped");
}

/// A motion interrupted by a stop is superseded, not failed.
#[test]
fn a_stop_supersedes_the_motion_it_interrupts() {
    let mut h = home();
    assert!(h.owner("robot.move_linear", &[("distance_mm", 3_000), ("speed_mm_s", 500)]).is_ok());
    h.pass(1_000);
    assert!(h.owner("robot.stop", &[]).is_ok());
    h.settle();
    let outcomes = h.outcomes();
    let status = |c: &str| outcomes.iter().find(|o| o["capability"] == c).map(|o| o["status"].clone());
    assert_eq!(status("robot.move_linear"), Some(Value::from("superseded")));
    assert_eq!(status("robot.stop"), Some(Value::from("verified")));
    assert!(!h.in_recovery());
}
