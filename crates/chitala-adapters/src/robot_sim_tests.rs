use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

use super::*;
use crate::testkit::*;

const ROBOT_PROFILE: &str = include_str!("../../../specs/profiles/robot-v0.1.json");

fn id() -> EntityId {
    EntityId::parse("device:robot").unwrap()
}

fn sim() -> (RobotSim, Arc<AtomicU64>) {
    let (clock, t) = fixed_clock(NOW);
    let sim = RobotSim::new(clock);
    sim.add(id(), Pose::new(0, 0, 0));
    (sim, t)
}

fn int(s: &Payload, k: &str) -> i64 {
    s.get(k).and_then(ParamValue::as_int).unwrap_or_else(|| panic!("{k} in {s:?}"))
}

fn text<'a>(s: &'a Payload, k: &str) -> &'a str {
    match s.get(k) {
        Some(ParamValue::Text(t)) => t,
        other => panic!("{k}: {other:?}"),
    }
}

fn go(sim: &mut RobotSim, capability: &str, params: &[(&str, i64)]) -> Result<Payload, AdapterError> {
    let p: Payload = params.iter().map(|(k, v)| (k.to_string(), ParamValue::Int(*v))).collect();
    sim.execute(authorize(&id(), capability, p))
}

fn at(sim: &mut RobotSim, t: &AtomicU64, ms: u64) -> Payload {
    t.store(NOW + ms, Ordering::SeqCst);
    sim.observe(&id()).unwrap().state
}

/// Every state the robot reports is one the Robot Profile v0.1 allows: only
/// its keys, the required ones always, the motion states it names.
fn conforms(s: &Payload) {
    let profile: Value = serde_json::from_str(ROBOT_PROFILE).unwrap();
    let keys = profile["classes"][0]["state"].as_object().unwrap();
    for (k, def) in keys {
        if def["required"] == true {
            assert!(s.contains_key(k), "{k} is required: {s:?}");
        }
    }
    for k in s.keys() {
        assert!(keys.contains_key(k), "{k} is not in the profile");
    }
    let states: Vec<&str> =
        keys["motion_state"]["one_of"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert!(states.contains(&text(s, "motion_state")), "{s:?}");
    let pose = ["pose_x_mm", "pose_y_mm", "pose_theta_mdeg", "localized_at_ms"];
    assert!(
        pose.iter().all(|k| s.contains_key(*k)) || pose.iter().all(|k| !s.contains_key(*k)),
        "a whole pose or none"
    );
}

/// A motion takes its time: accepted at once, under way, then done where it
/// was meant to end.
#[test]
fn a_linear_motion_takes_its_time() {
    let (mut sim, t) = sim();
    let s = go(&mut sim, "robot.move_linear", &[("distance_mm", 1_000), ("speed_mm_s", 250)]).unwrap();
    assert_eq!((text(&s, "motion_state"), int(&s, "linear_velocity_mm_s")), ("moving", 250));
    conforms(&s);
    let s = at(&mut sim, &t, 2_000);
    assert_eq!((int(&s, "pose_x_mm"), text(&s, "motion_state")), (500, "moving"));
    let s = at(&mut sim, &t, 4_500);
    assert_eq!((int(&s, "pose_x_mm"), int(&s, "pose_y_mm")), (1_000, 0));
    assert_eq!((text(&s, "motion_state"), int(&s, "linear_velocity_mm_s")), ("idle", 0));
    assert_eq!(int(&s, "localized_at_ms"), i64::try_from(NOW + 4_500).unwrap());
    conforms(&s);
    // backwards
    go(&mut sim, "robot.move_linear", &[("distance_mm", -400), ("speed_mm_s", 400)]).unwrap();
    let s = at(&mut sim, &t, 6_000);
    assert_eq!(int(&s, "pose_x_mm"), 600);
}

#[test]
fn turns_and_goals() {
    let (mut sim, t) = sim();
    go(&mut sim, "robot.rotate", &[("angle_mdeg", 90_000), ("speed_mdeg_s", 45_000)]).unwrap();
    let s = at(&mut sim, &t, 1_000);
    assert_eq!((int(&s, "pose_theta_mdeg"), int(&s, "angular_velocity_mdeg_s")), (45_000, 45_000));
    let s = at(&mut sim, &t, 2_000);
    assert_eq!((int(&s, "pose_theta_mdeg"), text(&s, "motion_state")), (90_000, "idle"));
    // to (1000, 1000) facing west: turn 45° right, drive 1414 mm, turn 135° left
    go(&mut sim, "robot.goto_pose", &[("x_mm", 1_000), ("y_mm", 1_000), ("theta_mdeg", 180_000), ("speed_mm_s", 500)])
        .unwrap();
    let s = at(&mut sim, &t, 2_000 + 500 + 2_829 + 1_500 + 10);
    assert_eq!(text(&s, "motion_state"), "idle", "{s:?}");
    let end = Pose::of(&s).unwrap();
    assert!(end.within(&Pose::new(1_000, 1_000, 180_000), 1, 1), "{end:?}");
    conforms(&s);
}

/// A stop halts a motion where the robot is.
#[test]
fn a_stop_halts_where_it_is() {
    let (mut sim, t) = sim();
    go(&mut sim, "robot.move_linear", &[("distance_mm", 2_000), ("speed_mm_s", 500)]).unwrap();
    at(&mut sim, &t, 1_000);
    let s = go(&mut sim, "robot.stop", &[]).unwrap();
    assert_eq!((text(&s, "motion_state"), int(&s, "linear_velocity_mm_s")), ("stopped", 0));
    let s = at(&mut sim, &t, 5_000);
    assert_eq!((int(&s, "pose_x_mm"), text(&s, "motion_state")), (500, "stopped"));
    // a stop at rest changes nothing
    let s = go(&mut sim, "robot.stop", &[]).unwrap();
    assert_eq!(text(&s, "motion_state"), "stopped");
}

/// The robot's own invariants: an obstacle or the emergency stop halts a
/// motion and refuses the next one; a stop is always taken.
#[test]
fn obstacles_and_the_emergency_stop_halt_it() {
    let (mut sim, t) = sim();
    go(&mut sim, "robot.move_linear", &[("distance_mm", 2_000), ("speed_mm_s", 500)]).unwrap();
    at(&mut sim, &t, 1_000);
    sim.obstacle(&id(), true);
    let s = at(&mut sim, &t, 2_000);
    assert_eq!((int(&s, "pose_x_mm"), text(&s, "motion_state")), (500, "stopped"));
    assert_eq!(s.get("obstacle_detected"), Some(&ParamValue::Bool(true)));
    let r = go(&mut sim, "robot.move_linear", &[("distance_mm", 100), ("speed_mm_s", 100)]);
    assert!(matches!(r, Err(AdapterError::Refused(_))), "{r:?}");
    assert!(go(&mut sim, "robot.stop", &[]).is_ok());
    sim.obstacle(&id(), false);

    go(&mut sim, "robot.rotate", &[("angle_mdeg", 90_000), ("speed_mdeg_s", 90_000)]).unwrap();
    sim.emergency_stop(&id(), true);
    let s = at(&mut sim, &t, 3_000);
    assert_eq!((text(&s, "motion_state"), s.get("emergency_stop")), ("estopped", Some(&ParamValue::Bool(true))));
    assert_eq!(int(&s, "pose_theta_mdeg"), 0, "halted before it turned");
    assert!(matches!(
        go(&mut sim, "robot.rotate", &[("angle_mdeg", 1_000), ("speed_mdeg_s", 5_000)]),
        Err(AdapterError::Refused(_))
    ));
    assert!(go(&mut sim, "robot.stop", &[]).is_ok());
    sim.emergency_stop(&id(), false);
    let s = at(&mut sim, &t, 3_100);
    assert_eq!(text(&s, "motion_state"), "stopped");
    conforms(&s);
}

/// What it cannot know, it leaves out: no pose when lost; a stale pose says
/// when it was fixed.
#[test]
fn localisation_lost_or_stale() {
    let (mut sim, t) = sim();
    sim.localization(&id(), Localization::Lost);
    let s = at(&mut sim, &t, 100);
    assert!(Pose::of(&s).is_none() && !s.contains_key("localized_at_ms"), "{s:?}");
    conforms(&s);
    sim.localization(&id(), Localization::Live);
    at(&mut sim, &t, 200);
    sim.localization(&id(), Localization::Stale);
    go(&mut sim, "robot.move_linear", &[("distance_mm", 1_000), ("speed_mm_s", 1_000)]).unwrap();
    let s = at(&mut sim, &t, 1_500);
    assert_eq!((int(&s, "pose_x_mm"), int(&s, "localized_at_ms")), (0, i64::try_from(NOW + 200).unwrap()));
    assert_eq!(sim.pose(&id()).unwrap().x_mm, 1_000, "it moved all the same");
}

/// Slip ends short; a stall never arrives.
#[test]
fn slip_and_stalls() {
    let (mut sim, t) = sim();
    sim.slip(&id(), 0.8);
    go(&mut sim, "robot.move_linear", &[("distance_mm", 1_000), ("speed_mm_s", 500)]).unwrap();
    let s = at(&mut sim, &t, 3_000);
    assert_eq!((int(&s, "pose_x_mm"), text(&s, "motion_state")), (800, "idle"));
    sim.slip(&id(), 1.0);
    sim.stall(&id(), true);
    go(&mut sim, "robot.move_linear", &[("distance_mm", 1_000), ("speed_mm_s", 500)]).unwrap();
    let s = at(&mut sim, &t, 20_000);
    assert_eq!((int(&s, "pose_x_mm"), text(&s, "motion_state"), int(&s, "linear_velocity_mm_s")), (800, "moving", 0));
}

/// An answer lost on its way back: the robot moved, or did not; it cannot be
/// told from the answer. Offline is unavailable.
#[test]
fn lost_answers_and_offline() {
    let (mut sim, t) = sim();
    sim.lose_next(&id(), Lost::AfterEffect);
    let r = go(&mut sim, "robot.move_linear", &[("distance_mm", 500), ("speed_mm_s", 500)]);
    assert!(matches!(r, Err(AdapterError::Indeterminate(_))), "{r:?}");
    assert_eq!(int(&at(&mut sim, &t, 2_000), "pose_x_mm"), 500);
    sim.lose_next(&id(), Lost::WithoutEffect);
    assert!(go(&mut sim, "robot.move_linear", &[("distance_mm", 500), ("speed_mm_s", 500)]).is_err());
    assert_eq!(int(&at(&mut sim, &t, 4_000), "pose_x_mm"), 500);
    sim.offline(&id(), true);
    t.store(NOW + 5_000, Ordering::SeqCst);
    assert!(matches!(sim.observe(&id()), Err(AdapterError::Unavailable(_))));
    assert_eq!(sim.commands(&id()), 2);
}
