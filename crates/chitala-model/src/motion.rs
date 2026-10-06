//! Motion of a ground robot (spec 30): its pose, where a motion takes it,
//! and how long that takes. Plain arithmetic, shared by the registry's
//! outcomes, Safety's geofence and outcome verification.
//!
//! Units are integers, as everywhere in payloads: millimetres, millidegrees,
//! milliseconds. Headings are counter-clockwise from the map's x axis.

use serde::{Deserialize, Serialize};

use crate::value::{ParamValue, Payload};

/// The state keys of a robot's pose (Robot Profile v0.1).
pub const POSE_X: &str = "pose_x_mm";
pub const POSE_Y: &str = "pose_y_mm";
pub const POSE_THETA: &str = "pose_theta_mdeg";

const FULL_TURN: i64 = 360_000;

/// Where a robot is, in the map frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Pose {
    pub x_mm: i64,
    pub y_mm: i64,
    /// Normalised to (−180°, 180°].
    pub theta_mdeg: i64,
}

impl Pose {
    pub fn new(x_mm: i64, y_mm: i64, theta_mdeg: i64) -> Self {
        Self { x_mm, y_mm, theta_mdeg: wrap(theta_mdeg) }
    }

    /// The pose a state reports; `None` if any of it is missing, as for a
    /// robot that has lost its localisation.
    pub fn of(state: &Payload) -> Option<Self> {
        let int = |k| state.get(k).and_then(ParamValue::as_int);
        Some(Self::new(int(POSE_X)?, int(POSE_Y)?, int(POSE_THETA)?))
    }

    /// The distance between two positions, in mm.
    pub fn distance_mm(&self, other: &Pose) -> u64 {
        let (dx, dy) = ((self.x_mm - other.x_mm) as f64, (self.y_mm - other.y_mm) as f64);
        dx.hypot(dy).round() as u64
    }

    /// Whether `other` is within `mm` of this position and `mdeg` of this heading.
    pub fn within(&self, other: &Pose, mm: u64, mdeg: u64) -> bool {
        self.distance_mm(other) <= mm && turn(self.theta_mdeg, other.theta_mdeg).unsigned_abs() <= mdeg
    }
}

/// `a` in (−180°, 180°].
pub fn wrap(a: i64) -> i64 {
    let r = a.rem_euclid(FULL_TURN);
    if r > FULL_TURN / 2 {
        r - FULL_TURN
    } else {
        r
    }
}

/// The shortest turn from heading `from` to heading `to`.
pub fn turn(from: i64, to: i64) -> i64 {
    wrap(to - from)
}

/// What a motion's outcome promises (spec 30): the pose it must end at,
/// within a tolerance, computed from the pose observed when it was cleared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoseOutcome {
    pub motion: Motion,
    pub tolerance_mm: u64,
    pub tolerance_mdeg: u64,
}

/// A motion, by the names of the parameters that carry it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Motion {
    /// Straight along the heading, backwards if negative.
    Linear { distance: String, speed: String },
    /// On the spot, counter-clockwise if positive.
    Rotate { angle: String, speed: String },
    /// To a pose: turn towards it, drive straight, turn to its heading.
    Goto { x: String, y: String, theta: String, speed: String },
}

impl Motion {
    /// The parameters it reads.
    pub fn params(&self) -> Vec<&str> {
        match self {
            Motion::Linear { distance, speed } => vec![distance, speed],
            Motion::Rotate { angle, speed } => vec![angle, speed],
            Motion::Goto { x, y, theta, speed } => vec![x, y, theta, speed],
        }
    }

    /// The parameter that carries its speed.
    pub fn speed(&self) -> &str {
        match self {
            Motion::Linear { speed, .. } | Motion::Rotate { speed, .. } | Motion::Goto { speed, .. } => speed,
        }
    }

    /// Where a motion with `params` takes a robot at `start`, and how long
    /// the motion itself takes at its speed, in ms (turning on the way to a
    /// goal is not counted: the outcome's own time covers it). `None` if a
    /// parameter is missing or the speed is not positive.
    pub fn plan(&self, params: &Payload, start: Pose) -> Option<(Pose, u64)> {
        let int = |k: &String| params.get(k).and_then(ParamValue::as_int);
        let duration = |amount: i64, speed: i64| -> Option<u64> {
            (speed > 0).then(|| (amount.unsigned_abs().saturating_mul(1_000)).div_ceil(speed.unsigned_abs()))
        };
        match self {
            Motion::Linear { distance, speed } => {
                let d = int(distance)?;
                let heading = (start.theta_mdeg as f64 / 1_000.0).to_radians();
                let end = Pose::new(
                    start.x_mm + (d as f64 * heading.cos()).round() as i64,
                    start.y_mm + (d as f64 * heading.sin()).round() as i64,
                    start.theta_mdeg,
                );
                Some((end, duration(d, int(speed)?)?))
            }
            Motion::Rotate { angle, speed } => {
                let a = int(angle)?;
                Some((Pose::new(start.x_mm, start.y_mm, start.theta_mdeg + a), duration(a, int(speed)?)?))
            }
            Motion::Goto { x, y, theta, speed } => {
                let end = Pose::new(int(x)?, int(y)?, int(theta)?);
                let d = i64::try_from(start.distance_mm(&end)).ok()?;
                Some((end, duration(d, int(speed)?)?))
            }
        }
    }
}

/// A convex region of the map, as a polygon in mm (spec 30): a robot's
/// geofence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Geofence(pub Vec<[i64; 2]>);

impl Geofence {
    /// At least three corners, in order, enclosing a convex region.
    pub fn check(&self) -> Result<(), String> {
        let n = self.0.len();
        if !(3..=64).contains(&n) {
            return Err(format!("a geofence has 3 to 64 corners, not {n}"));
        }
        let mut sign = 0i128;
        for i in 0..n {
            let c = cross(self.0[i], self.0[(i + 1) % n], self.0[(i + 2) % n]);
            if c != 0 {
                if sign != 0 && c.signum() != sign {
                    return Err("a geofence must be convex".into());
                }
                sign = c.signum();
            }
        }
        if sign == 0 {
            return Err("a geofence must enclose an area".into());
        }
        Ok(())
    }

    /// Whether a point is inside or on the edge.
    pub fn contains(&self, x_mm: i64, y_mm: i64) -> bool {
        let n = self.0.len();
        let (mut pos, mut neg) = (false, false);
        for i in 0..n {
            let c = cross(self.0[i], self.0[(i + 1) % n], [x_mm, y_mm]);
            pos |= c > 0;
            neg |= c < 0;
        }
        !(pos && neg)
    }

    /// Whether the straight path between two positions stays inside: in a
    /// convex region, it does when both ends do.
    pub fn holds(&self, from: &Pose, to: &Pose) -> bool {
        self.contains(from.x_mm, from.y_mm) && self.contains(to.x_mm, to.y_mm)
    }
}

/// The cross product of (b − a) and (c − a).
fn cross(a: [i64; 2], b: [i64; 2], c: [i64; 2]) -> i128 {
    let (abx, aby) = (i128::from(b[0] - a[0]), i128::from(b[1] - a[1]));
    let (acx, acy) = (i128::from(c[0] - a[0]), i128::from(c[1] - a[1]));
    abx * acy - aby * acx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::payload;

    fn linear() -> Motion {
        Motion::Linear { distance: "distance_mm".into(), speed: "speed_mm_s".into() }
    }

    #[test]
    fn headings_wrap() {
        assert_eq!(wrap(190_000), -170_000);
        assert_eq!(wrap(-180_000), 180_000);
        assert_eq!(wrap(720_000), 0);
        assert_eq!(turn(170_000, -170_000), 20_000, "the short way round");
        assert!(Pose::new(0, 0, 179_000).within(&Pose::new(0, 0, -179_000), 0, 2_000));
    }

    #[test]
    fn a_linear_motion_follows_the_heading() {
        let p = payload([("distance_mm", ParamValue::Int(1_000)), ("speed_mm_s", ParamValue::Int(250))]);
        let (end, ms) = linear().plan(&p, Pose::new(100, 200, 90_000)).unwrap();
        assert_eq!((end, ms), (Pose::new(100, 1_200, 90_000), 4_000));
        let back = payload([("distance_mm", ParamValue::Int(-500)), ("speed_mm_s", ParamValue::Int(250))]);
        assert_eq!(linear().plan(&back, Pose::new(0, 0, 0)).unwrap(), (Pose::new(-500, 0, 0), 2_000));
        let still = payload([("distance_mm", ParamValue::Int(500)), ("speed_mm_s", ParamValue::Int(0))]);
        assert_eq!(linear().plan(&still, Pose::new(0, 0, 0)), None, "no speed, no motion");
    }

    #[test]
    fn rotations_and_goals() {
        let r = Motion::Rotate { angle: "angle_mdeg".into(), speed: "speed_mdeg_s".into() };
        let p = payload([("angle_mdeg", ParamValue::Int(-270_000)), ("speed_mdeg_s", ParamValue::Int(90_000))]);
        assert_eq!(r.plan(&p, Pose::new(5, 5, 0)).unwrap(), (Pose::new(5, 5, 90_000), 3_000));
        let g =
            Motion::Goto { x: "x_mm".into(), y: "y_mm".into(), theta: "theta_mdeg".into(), speed: "speed_mm_s".into() };
        let p = payload([
            ("x_mm", ParamValue::Int(3_000)),
            ("y_mm", ParamValue::Int(4_000)),
            ("theta_mdeg", ParamValue::Int(45_000)),
            ("speed_mm_s", ParamValue::Int(500)),
        ]);
        assert_eq!(g.plan(&p, Pose::new(0, 0, 0)).unwrap(), (Pose::new(3_000, 4_000, 45_000), 10_000));
    }

    #[test]
    fn a_geofence_is_convex_and_holds_straight_paths() {
        let room = Geofence(vec![[0, 0], [4_000, 0], [4_000, 3_000], [0, 3_000]]);
        assert!(room.check().is_ok());
        assert!(room.contains(4_000, 1_500), "the edge is inside");
        assert!(!room.contains(4_001, 1_500));
        assert!(room.holds(&Pose::new(100, 100, 0), &Pose::new(3_900, 2_900, 0)));
        assert!(!room.holds(&Pose::new(100, 100, 0), &Pose::new(5_000, 100, 0)));
        let l_shape = Geofence(vec![[0, 0], [4_000, 0], [4_000, 1_000], [1_000, 1_000], [1_000, 3_000], [0, 3_000]]);
        assert!(l_shape.check().is_err(), "not convex: a straight path could leave it");
        assert!(Geofence(vec![[0, 0], [1, 1], [2, 2]]).check().is_err(), "no area");
        assert!(Geofence(vec![[0, 0], [1, 1]]).check().is_err());
    }
}
