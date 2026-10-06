//! A simulated differential-drive ground robot (Robot Profile v0.1, spec
//! 30), the adapter `robot-sim`.
//!
//! A motion takes time on the host's clock. An order is accepted at once,
//! the robot moves, and each observation reports where it is now. The robot
//! keeps its own invariants: it refuses to move while its emergency stop is
//! pressed or something is in its way, and it halts by itself when either
//! happens during a motion (a protective stop).
//!
//! Faults, for the adversarial suite (spec 30):
//! - an obstacle;
//! - the emergency stop;
//! - localisation lost, or stale;
//! - wheel slip, so the robot ends short;
//! - a stall, so it never arrives;
//! - an answer lost on its way back;
//! - offline.
//!
//! What the robot cannot know is left out: a robot that is not localised
//! reports no pose.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use chitala_model::{payload, CapabilityId, EntityId, ParamValue, Payload, Pose};

use crate::mock::Lost;
use crate::{AdapterError, Clock, DeviceAdapter, Observed, VerifiedOrder};

/// The adapter's name in device descriptors.
pub const ADAPTER: &str = "robot-sim";

/// How fast a `robot.goto_pose` turns, in mdeg/s.
pub const GOTO_TURN_RATE_MDEG_S: i64 = 90_000;

/// The capabilities of a simulated robot.
pub fn capabilities() -> Vec<CapabilityId> {
    ["device.read_state", "robot.stop", "robot.move_linear", "robot.rotate", "robot.goto_pose"]
        .iter()
        .map(|c| CapabilityId::parse(c).expect("static capability ids are valid"))
        .collect()
}

/// Where the robot's localisation stands.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Localization {
    /// Fixed at every observation.
    Live,
    /// Lost: no pose is reported.
    Lost,
    /// Stuck on the pose it had when it went stale, and that time.
    Stale,
}

/// One part of a motion: turn on the spot, or drive straight.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Step {
    /// Millidegrees left, at a signed rate in mdeg/s.
    Turn { left: f64, rate: f64 },
    /// Millimetres left, at a signed speed in mm/s.
    Drive { left: f64, speed: f64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Halt {
    /// The last motion ended.
    Idle,
    /// Halted before its motion ended: `robot.stop`, or a protective stop.
    Stopped,
}

#[derive(Debug, Clone)]
struct Robot {
    /// The true pose, in mm and mdeg.
    x: f64,
    y: f64,
    theta: f64,
    steps: VecDeque<Step>,
    halt: Halt,
    /// Until when the motion was simulated.
    at: u64,
    obstacle: bool,
    estop: bool,
    localization: Localization,
    /// The pose localisation went stale on, and when.
    stale: Option<(Pose, u64)>,
    /// The share of each commanded distance the wheels actually cover.
    slip: f64,
    stalled: bool,
    offline: bool,
    lose_next: Option<Lost>,
    commands: usize,
    /// How far the robot's clock is off the host's, in ms.
    skew_ms: i64,
    /// Values reported in place of the real ones: a malformed or forged state.
    forged: Payload,
    /// Takes every command and does nothing: a broken robot.
    deaf: bool,
}

impl Robot {
    fn new(at: Pose, now: u64) -> Self {
        Self {
            x: at.x_mm as f64,
            y: at.y_mm as f64,
            theta: at.theta_mdeg as f64,
            steps: VecDeque::new(),
            halt: Halt::Idle,
            at: now,
            obstacle: false,
            estop: false,
            localization: Localization::Live,
            stale: None,
            slip: 1.0,
            stalled: false,
            offline: false,
            lose_next: None,
            commands: 0,
            skew_ms: 0,
            forged: Payload::new(),
            deaf: false,
        }
    }

    fn pose(&self) -> Pose {
        Pose::new(self.x.round() as i64, self.y.round() as i64, self.theta.round() as i64)
    }

    /// Move on to `now`.
    fn advance(&mut self, now: u64) {
        let mut dt = now.saturating_sub(self.at) as f64 / 1_000.0;
        self.at = self.at.max(now);
        if self.stalled {
            return;
        }
        while dt > 0.0 {
            let Some(step) = self.steps.front_mut() else { break };
            let (left, rate) = match step {
                Step::Turn { left, rate } | Step::Drive { left, speed: rate } => (left, *rate),
            };
            let need = *left / rate.abs();
            let t = need.min(dt);
            let done = rate.abs() * t;
            *left -= done;
            dt -= t;
            match *step {
                Step::Turn { rate, .. } => self.theta += done * rate.signum(),
                Step::Drive { speed, .. } => {
                    let heading = (self.theta / 1_000.0).to_radians();
                    let d = done * speed.signum() * self.slip;
                    self.x += d * heading.cos();
                    self.y += d * heading.sin();
                }
            }
            if t >= need {
                self.steps.pop_front();
                if self.steps.is_empty() {
                    self.halt = Halt::Idle;
                }
            }
        }
    }

    /// Halt, before the motion ended.
    fn halt(&mut self) {
        if !self.steps.is_empty() {
            self.steps.clear();
            self.halt = Halt::Stopped;
        }
    }

    fn state(&self, now: u64) -> Payload {
        let (v, w) = match (self.stalled, self.steps.front()) {
            (false, Some(Step::Drive { speed, .. })) => ((speed * self.slip).round() as i64, 0),
            (false, Some(Step::Turn { rate, .. })) => (0, rate.round() as i64),
            _ => (0, 0),
        };
        let motion_state = match (self.estop, self.steps.is_empty(), self.halt) {
            (true, _, _) => "estopped",
            (false, false, _) => "moving",
            (false, true, Halt::Idle) => "idle",
            (false, true, Halt::Stopped) => "stopped",
        };
        let mut s = payload([
            ("motion_state", ParamValue::from(motion_state)),
            ("linear_velocity_mm_s", ParamValue::Int(v)),
            ("angular_velocity_mdeg_s", ParamValue::Int(w)),
            ("obstacle_detected", ParamValue::Bool(self.obstacle)),
            ("emergency_stop", ParamValue::Bool(self.estop)),
        ]);
        let fix = match self.localization {
            Localization::Live => Some((self.pose(), now)),
            Localization::Stale => self.stale,
            Localization::Lost => None,
        };
        if let Some((p, at)) = fix {
            s.insert("pose_x_mm".into(), ParamValue::Int(p.x_mm));
            s.insert("pose_y_mm".into(), ParamValue::Int(p.y_mm));
            s.insert("pose_theta_mdeg".into(), ParamValue::Int(p.theta_mdeg));
            let at = i64::try_from(at).unwrap_or(i64::MAX).saturating_add(self.skew_ms);
            s.insert("localized_at_ms".into(), ParamValue::Int(at));
        }
        s.extend(self.forged.clone());
        s
    }

    /// What the robot does with an order that reached it.
    fn apply(&mut self, capability: &str, p: &Payload, now: u64) -> Result<Payload, AdapterError> {
        let int = |k: &str| {
            p.get(k)
                .and_then(ParamValue::as_int)
                .ok_or_else(|| AdapterError::Refused(format!("{capability}: {k} missing")))
        };
        if self.deaf {
            return Ok(self.state(now));
        }
        if capability == "robot.stop" {
            // stopped, whether it was moving or not
            self.steps.clear();
            self.halt = Halt::Stopped;
            return Ok(self.state(now));
        }
        // the robot's own invariants, whatever the order says
        if self.estop {
            return Err(AdapterError::Refused("the emergency stop is pressed".into()));
        }
        if self.obstacle {
            return Err(AdapterError::Refused("something is in the way".into()));
        }
        let steps = match capability {
            "robot.move_linear" => {
                vec![Step::Drive {
                    left: int("distance_mm")?.abs() as f64,
                    speed: signed(int("speed_mm_s")?, int("distance_mm")?),
                }]
            }
            "robot.rotate" => {
                vec![Step::Turn {
                    left: int("angle_mdeg")?.abs() as f64,
                    rate: signed(int("speed_mdeg_s")?, int("angle_mdeg")?),
                }]
            }
            "robot.goto_pose" => {
                let (x, y, theta) = (int("x_mm")? as f64, int("y_mm")? as f64, int("theta_mdeg")?);
                let (dx, dy) = (x - self.x, y - self.y);
                let distance = dx.hypot(dy);
                let mut steps = Vec::new();
                let mut heading = self.theta.round() as i64;
                if distance >= 1.0 {
                    let towards = (dy.atan2(dx).to_degrees() * 1_000.0).round() as i64;
                    steps.push(turn(heading, towards));
                    heading = towards;
                    steps.push(Step::Drive { left: distance, speed: int("speed_mm_s")?.abs() as f64 });
                }
                steps.push(turn(heading, theta));
                steps.into_iter().filter(|s| !matches!(s, Step::Turn { left, .. } if *left == 0.0)).collect()
            }
            other => return Err(AdapterError::Refused(format!("a robot does not {other}"))),
        };
        // a new motion replaces one still under way
        self.steps = steps.into();
        self.halt = if self.steps.is_empty() { Halt::Idle } else { self.halt };
        Ok(self.state(now))
    }
}

/// `speed` with the sign of `amount`.
fn signed(speed: i64, amount: i64) -> f64 {
    speed.abs() as f64 * if amount < 0 { -1.0 } else { 1.0 }
}

/// The shortest turn from one heading to another, at the goto's rate.
fn turn(from: i64, to: i64) -> Step {
    let by = chitala_model::motion::turn(from, to);
    Step::Turn { left: by.abs() as f64, rate: signed(GOTO_TURN_RATE_MDEG_S, by) }
}

/// Simulated robots. A clone is another handle on the same robots: one
/// serves a node as its adapter while another plays the physical world.
#[derive(Clone)]
pub struct RobotSim {
    robots: Arc<Mutex<BTreeMap<EntityId, Robot>>>,
    clock: Clock,
}

impl RobotSim {
    pub fn new(clock: Clock) -> Self {
        Self { robots: Arc::default(), clock }
    }

    fn robots(&self) -> MutexGuard<'_, BTreeMap<EntityId, Robot>> {
        // a panic while holding the lock leaves plain data: carry on with it
        self.robots.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Change a robot, moved on to now first.
    fn with<T>(&self, id: &EntityId, f: impl FnOnce(&mut Robot) -> T) -> Option<T> {
        let now = (self.clock)();
        self.robots().get_mut(id).map(|r| {
            r.advance(now);
            f(r)
        })
    }

    /// A robot at `at`, at rest and localised.
    pub fn add(&self, id: EntityId, at: Pose) {
        let now = (self.clock)();
        self.robots().insert(id, Robot::new(at, now));
    }

    /// Where the robot really is.
    pub fn pose(&self, id: &EntityId) -> Option<Pose> {
        self.with(id, |r| r.pose())
    }

    /// Whether it is moving.
    pub fn moving(&self, id: &EntityId) -> bool {
        self.with(id, |r| !r.steps.is_empty()).unwrap_or(false)
    }

    /// Something in the robot's protective field: it halts.
    pub fn obstacle(&self, id: &EntityId, there: bool) {
        self.with(id, |r| {
            r.obstacle = there;
            if there {
                r.halt();
            }
        });
    }

    /// The emergency stop, pressed or released.
    pub fn emergency_stop(&self, id: &EntityId, pressed: bool) {
        self.with(id, |r| {
            if pressed {
                r.halt();
                r.halt = Halt::Stopped;
            }
            r.estop = pressed;
        });
    }

    pub fn localization(&self, id: &EntityId, l: Localization) {
        let now = (self.clock)();
        self.with(id, |r| {
            r.stale = (l == Localization::Stale).then(|| (r.pose(), now));
            r.localization = l;
        });
    }

    /// The share of each commanded distance the wheels cover (1.0: no slip).
    pub fn slip(&self, id: &EntityId, share: f64) {
        self.with(id, |r| r.slip = share);
    }

    /// The motors turn no more: a motion under way never ends.
    pub fn stall(&self, id: &EntityId, stalled: bool) {
        self.with(id, |r| r.stalled = stalled);
    }

    pub fn offline(&self, id: &EntityId, off: bool) {
        self.with(id, |r| r.offline = off);
    }

    /// The answer to the next command is lost on its way back.
    pub fn lose_next(&self, id: &EntityId, how: Lost) {
        self.with(id, |r| r.lose_next = Some(how));
    }

    /// The robot's clock runs `ms` ahead of the host's (behind if negative).
    pub fn clock_skew(&self, id: &EntityId, ms: i64) {
        self.with(id, |r| r.skew_ms = ms);
    }

    /// Report `value` for `key` from now on, whatever the truth: a malformed
    /// or forged state.
    pub fn forge(&self, id: &EntityId, key: &str, value: ParamValue) {
        self.with(id, |r| {
            r.forged.insert(key.into(), value);
        });
    }

    /// The robot takes every command, answers, and does nothing.
    pub fn deaf(&self, id: &EntityId, deaf: bool) {
        self.with(id, |r| r.deaf = deaf);
    }

    /// Commands that reached the robot.
    pub fn commands(&self, id: &EntityId) -> usize {
        self.with(id, |r| r.commands).unwrap_or(0)
    }
}

impl std::fmt::Debug for RobotSim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RobotSim").field("robots", &self.robots().keys().collect::<Vec<_>>()).finish()
    }
}

fn reachable<'a>(robots: &'a mut BTreeMap<EntityId, Robot>, id: &EntityId) -> Result<&'a mut Robot, AdapterError> {
    let r = robots.get_mut(id).ok_or_else(|| AdapterError::Failed(format!("{id} is not a simulated robot")))?;
    if r.offline {
        return Err(AdapterError::Unavailable(format!("{id} does not answer")));
    }
    Ok(r)
}

impl DeviceAdapter for RobotSim {
    fn name(&self) -> &str {
        ADAPTER
    }

    fn manages(&self, device: &EntityId) -> bool {
        self.robots().contains_key(device)
    }

    fn observe(&mut self, device: &EntityId) -> Result<Observed, AdapterError> {
        let now = (self.clock)();
        let mut robots = self.robots();
        let r = reachable(&mut robots, device)?;
        r.advance(now);
        Ok(Observed::live(r.state(now)))
    }

    fn execute(&mut self, order: VerifiedOrder) -> Result<Payload, AdapterError> {
        let now = (self.clock)();
        let mut robots = self.robots();
        let r = reachable(&mut robots, order.target())?;
        r.advance(now);
        r.commands += 1;
        let (capability, params) = (order.capability().as_str(), order.payload());
        let lost = || AdapterError::Indeterminate("the answer was lost on its way back".into());
        match r.lose_next.take() {
            None => r.apply(capability, params, now),
            Some(Lost::WithoutEffect) => Err(lost()),
            Some(Lost::AfterEffect) => r.apply(capability, params, now).and_then(|_| Err(lost())),
            Some(Lost::AndOffline) => {
                let done = r.apply(capability, params, now);
                r.offline = true;
                done.and_then(|_| Err(lost()))
            }
        }
    }
}

#[cfg(test)]
#[path = "robot_sim_tests.rs"]
mod tests;
