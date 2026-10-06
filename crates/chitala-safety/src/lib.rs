//! Safety invariants (spec `specs/17-safety.md`).
//!
//! Policy answers *who may do what*; owners and administrators change it. Safety
//! answers *what must never physically happen, whoever asks*. The two are kept
//! apart on purpose:
//!
//! - this crate does not depend on the policy engine, tokens or identities;
//! - it is consulted **after** Authority and **again** right before the trusted
//!   boundary mints a command (state may change while a human is deciding);
//! - it can only refuse. There is no rule, setting or call that turns a denial
//!   from Authority into an allow, and no policy can switch a rule off.
//!
//! | rule | id | refuses |
//! |------|----|---------|
//! | hold | `SAFE-1-HOLD` | any action on a resource, or below a resource, under a safety hold |
//! | device | `SAFE-2-DEVICE` | any action through a contained device; high risk through a device that is not TRUSTED |
//! | state | `SAFE-3-STATE` | medium+ risk actions when the resource's state is unknown or older than its state reference allows |
//! | physical | `SAFE-4-PHYSICAL` | actions that contradict the reported physical state (bolting an open door) |
//! | envelope | `SAFE-5-ENVELOPE` | parameters outside the resource's own envelope |
//! | rate | `SAFE-6-RATE` | more actuations of one resource per window than it tolerates (oscillation, looping agents) |
//! | busy | `SAFE-7-BUSY` | an action through a device that is still executing another order (two actions cleared on the same state must not interleave) |
//! | recovery | `SAFE-8-RECOVERY` | any action on a resource in recovery after a failed outcome, or below it, except that resource's own safe-state action |
//!
//! A successful check yields a [`Clearance`] for exactly one action. Like the
//! Authority grant it has no public constructor; the trusted boundary requires
//! both before it produces a physical command.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, VecDeque};

use chitala_model::{CapabilityDef, CapabilityKind, EntityId, ParamValue, Payload, RiskClass, SecurityState};
use chitala_resource::{ResourceGraph, ResourceId, ResourceKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyConfig {
    pub window_ms: u64,
    /// Actuations of one resource per window.
    pub max_actuations: u32,
    /// Actuations per window when the action is high or critical risk.
    pub max_high_risk_actuations: u32,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self { window_ms: 60_000, max_actuations: 6, max_high_risk_actuations: 3 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    Hold,
    Device,
    State,
    Physical,
    Envelope,
    Rate,
    Busy,
    Recovery,
}

impl Rule {
    pub fn id(self) -> &'static str {
        match self {
            Rule::Hold => "SAFE-1-HOLD",
            Rule::Device => "SAFE-2-DEVICE",
            Rule::State => "SAFE-3-STATE",
            Rule::Physical => "SAFE-4-PHYSICAL",
            Rule::Envelope => "SAFE-5-ENVELOPE",
            Rule::Rate => "SAFE-6-RATE",
            Rule::Busy => "SAFE-7-BUSY",
            Rule::Recovery => "SAFE-8-RECOVERY",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}: {reason}", rule.id())]
pub struct Violation {
    pub rule: Rule,
    pub reason: String,
}

/// The last reported state of the resource's state reference.
#[derive(Debug, Clone, Copy)]
pub struct Observation<'a> {
    pub age_ms: u64,
    pub state: &'a Payload,
}

/// One physical action, as Authority resolved it.
#[derive(Debug, Clone, Copy)]
pub struct Proposed<'a> {
    /// Id of the intent or request this action belongs to. The clearance is
    /// bound to it: a clearance for one intent never clears another.
    pub subject: &'a [u8; 16],
    pub resource: &'a ResourceId,
    pub capability: &'a CapabilityDef,
    pub params: &'a Payload,
    pub risk: RiskClass,
    /// The device the resource binds the capability to.
    pub device: &'a EntityId,
    pub device_state: SecurityState,
    /// `None` when nothing has been observed yet.
    pub observation: Option<Observation<'a>>,
    /// The device is still executing another order (the node knows).
    pub device_busy: bool,
    /// The resource is still being acted on by another order, possibly through
    /// another device (the node knows).
    pub resource_busy: bool,
}

/// Proof that safety checked exactly one action of one intent or request.
/// Neither `Clone` nor constructible outside this crate.
#[derive(Debug)]
pub struct Clearance {
    subject: [u8; 16],
    resource: ResourceId,
    capability: chitala_model::CapabilityId,
    device: EntityId,
    params: Payload,
    checked_at_ms: u64,
}

impl Clearance {
    pub fn subject(&self) -> &[u8; 16] {
        &self.subject
    }
    pub fn resource(&self) -> &ResourceId {
        &self.resource
    }
    pub fn capability(&self) -> &chitala_model::CapabilityId {
        &self.capability
    }
    pub fn device(&self) -> &EntityId {
        &self.device
    }
    pub fn params(&self) -> &Payload {
        &self.params
    }
    pub fn checked_at_ms(&self) -> u64 {
        self.checked_at_ms
    }
}

/// The safety layer of one domain: rules, holds and recent actuations.
#[derive(Debug, Default)]
pub struct Safety {
    cfg: SafetyConfig,
    holds: BTreeMap<ResourceId, String>,
    /// Resources in recovery after a failed outcome, with why (spec 22).
    recovering: BTreeMap<ResourceId, String>,
    history: HashMap<ResourceId, VecDeque<u64>>,
}

fn violation(rule: Rule, reason: impl Into<String>) -> Result<(), Violation> {
    Err(Violation { rule, reason: reason.into() })
}

/// Physical invariants by resource kind: the action must not contradict what
/// the resource reports.
fn physical(kind: &ResourceKind, capability: &str, state: &Payload) -> Option<&'static str> {
    let open = matches!(state.get("door_open"), Some(ParamValue::Bool(true)));
    match (kind, capability) {
        (ResourceKind::Door | ResourceKind::Gate | ResourceKind::Lock, "lock.lock") if open => {
            Some("the door is reported open; throwing the bolt would jam it and leave it unsecured")
        }
        _ => None,
    }
}

impl Safety {
    pub fn new(cfg: SafetyConfig) -> Self {
        Self { cfg, holds: BTreeMap::new(), recovering: BTreeMap::new(), history: HashMap::new() }
    }

    pub fn config(&self) -> &SafetyConfig {
        &self.cfg
    }

    /// Put a resource (and everything below it) under a safety hold. Releasing
    /// a hold is a human, out-of-band decision.
    pub fn hold(&mut self, id: ResourceId, reason: impl Into<String>) {
        self.holds.insert(id, reason.into());
    }

    pub fn release(&mut self, id: &ResourceId) -> bool {
        self.holds.remove(id).is_some()
    }

    pub fn holds(&self) -> impl Iterator<Item = (&ResourceId, &str)> {
        self.holds.iter().map(|(k, v)| (k, v.as_str()))
    }

    /// Put a resource (and everything below it) in recovery after an action's
    /// outcome failed: only its safe-state action may run there until a human
    /// ends the recovery (spec 22).
    pub fn recover(&mut self, id: ResourceId, reason: impl Into<String>) {
        self.recovering.insert(id, reason.into());
    }

    pub fn end_recovery(&mut self, id: &ResourceId) -> bool {
        self.recovering.remove(id).is_some()
    }

    pub fn recovering(&self) -> impl Iterator<Item = (&ResourceId, &str)> {
        self.recovering.iter().map(|(k, v)| (k, v.as_str()))
    }

    fn recent(&self, id: &ResourceId, now: u64) -> usize {
        let window = self.cfg.window_ms;
        self.history.get(id).map_or(0, |h| h.iter().filter(|t| now < **t + window).count())
    }

    /// Evaluate every rule without side effects (used before asking a human:
    /// nobody is asked to approve what safety would refuse anyway).
    pub fn check(&self, graph: &ResourceGraph, p: &Proposed<'_>, now: u64) -> Result<(), Violation> {
        if p.capability.kind == CapabilityKind::Query {
            return Ok(());
        }
        let Some(resource) = graph.get(p.resource) else {
            return violation(Rule::Hold, format!("{} is not a governed resource", p.resource));
        };

        // SAFE-1: holds apply to the resource and everything below the held one
        if let Some((held, why)) = graph.lineage(p.resource).iter().find_map(|r| self.holds.get_key_value(&r.id)) {
            return violation(Rule::Hold, format!("{held} is under a safety hold: {why}"));
        }

        // SAFE-8: after a failed outcome, a resource takes nothing but the
        // action that brings it back to its safe state, until a human ends
        // the recovery
        let safe_state =
            resource.safe_state.as_ref().is_some_and(|s| s.capability == p.capability.id && &s.params == p.params);
        for (r, why) in graph.lineage(p.resource).iter().filter_map(|r| self.recovering.get_key_value(&r.id)) {
            if !(r == p.resource && safe_state) {
                return violation(
                    Rule::Recovery,
                    format!(
                        "{r} is in recovery ({why}); only its safe-state action may run until a person releases it"
                    ),
                );
            }
        }

        // SAFE-7: one action at a time per device — a second action cleared on
        // the same state as one still executing could interleave with it
        if p.device_busy {
            return violation(Rule::Busy, format!("{} is still executing another action", p.device));
        }
        // the same one thing, reached through another device, is just as busy
        if p.resource_busy {
            return violation(Rule::Busy, format!("{} is still being acted on by another order", p.resource));
        }

        // SAFE-2: the executing device
        if !p.device_state.may_act() {
            return violation(Rule::Device, format!("{} is {}", p.device, p.device_state));
        }
        if p.risk >= RiskClass::High && p.device_state != SecurityState::Trusted {
            return violation(
                Rule::Device,
                format!("{} is {}; {} actions need a TRUSTED device", p.device, p.device_state, p.risk),
            );
        }

        // SAFE-3: known, fresh state before anything that matters
        if p.risk >= RiskClass::Medium {
            if let Some(sref) = &resource.state {
                match p.observation {
                    None => return violation(Rule::State, format!("the state of {} is unknown", p.resource)),
                    Some(o) if o.age_ms > sref.max_age_ms => {
                        return violation(
                            Rule::State,
                            format!(
                                "the state of {} is {} s old (at most {} s for this action)",
                                p.resource,
                                o.age_ms / 1000,
                                sref.max_age_ms / 1000
                            ),
                        )
                    }
                    Some(_) => {}
                }
            }
        }

        // SAFE-4: physics
        if let Some(o) = p.observation {
            if let Some(why) = physical(&resource.kind, p.capability.id.as_str(), o.state) {
                return violation(Rule::Physical, why);
            }
        }

        // SAFE-5: the resource's own envelope
        for l in resource.limits(&p.capability.id) {
            if let Some(ParamValue::Int(v)) = p.params.get(&l.param) {
                if *v < l.min || *v > l.max {
                    return violation(
                        Rule::Envelope,
                        format!("{} = {v} is outside [{}, {}] at {}", l.param, l.min, l.max, p.resource),
                    );
                }
            }
        }

        // SAFE-6: actuation rate
        let limit = if p.risk >= RiskClass::High { self.cfg.max_high_risk_actuations } else { self.cfg.max_actuations }
            as usize;
        if self.recent(p.resource, now) >= limit {
            return violation(
                Rule::Rate,
                format!("{} was actuated {limit} times in the last {} s", p.resource, self.cfg.window_ms / 1000),
            );
        }
        Ok(())
    }

    /// Check, then record the actuation and hand out the clearance the trusted
    /// boundary needs. Call right before minting the command.
    pub fn clear(&mut self, graph: &ResourceGraph, p: &Proposed<'_>, now: u64) -> Result<Clearance, Violation> {
        self.check(graph, p, now)?;
        if p.capability.kind == CapabilityKind::Action {
            let window = self.cfg.window_ms;
            let h = self.history.entry(p.resource.clone()).or_default();
            while matches!(h.front(), Some(t) if now >= *t + window) {
                h.pop_front();
            }
            h.push_back(now);
        }
        Ok(Clearance {
            subject: *p.subject,
            resource: p.resource.clone(),
            capability: p.capability.id.clone(),
            device: p.device.clone(),
            params: p.params.clone(),
            checked_at_ms: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chitala_model::{payload, CapabilityId, CapabilityRegistry};
    use chitala_resource::{Boundary, CapabilityBinding, ParamLimit, Resource, SafeState, StateRef};

    fn rid(s: &str) -> ResourceId {
        ResourceId::new(s).unwrap()
    }
    fn eid(s: &str) -> EntityId {
        EntityId::parse(s).unwrap()
    }
    fn cap(s: &str) -> CapabilityId {
        CapabilityId::parse(s).unwrap()
    }

    fn graph() -> (ResourceGraph, CapabilityRegistry) {
        let reg = CapabilityRegistry::core_v0_1();
        let base = |id: &str, kind, parent: Option<&str>| Resource {
            id: rid(id),
            kind,
            name: id.into(),
            parent: parent.map(rid),
            owners: vec![],
            boundary: Boundary::Interior,
            zone: None,
            bindings: vec![],
            state: None,
            envelope: vec![],
            two_key: false,
            safe_state: None,
            motion: None,
        };
        let mut home = base("home", ResourceKind::Site, None);
        home.owners = vec![eid("person:alice")];
        let mut door = base("front-door", ResourceKind::Door, Some("entrance"));
        door.bindings = ["lock.lock", "lock.unlock"]
            .iter()
            .map(|c| CapabilityBinding { capability: cap(c), device: eid("device:front-door"), risk_floor: None })
            .collect();
        door.state = Some(StateRef { device: eid("device:front-door"), max_age_ms: 30_000 });
        door.safe_state = Some(SafeState { capability: cap("lock.lock"), params: Payload::new() });
        let mut light = base("light", ResourceKind::Light, Some("home"));
        light.bindings = vec![CapabilityBinding {
            capability: cap("light.set_brightness"),
            device: eid("device:light"),
            risk_floor: None,
        }];
        light.state = Some(StateRef { device: eid("device:light"), max_age_ms: 30_000 });
        light.envelope = vec![ParamLimit {
            capability: cap("light.set_brightness"),
            param: "brightness_pct".into(),
            min: 0,
            max: 60,
        }];
        let g = ResourceGraph::new(vec![home, base("entrance", ResourceKind::Space, Some("home")), door, light], &reg)
            .unwrap();
        (g, reg)
    }

    struct Case<'a> {
        reg: &'a CapabilityRegistry,
        resource: ResourceId,
        cap: &'static str,
        params: Payload,
        device_state: SecurityState,
        state: Option<(u64, Payload)>,
        busy: bool,
    }

    impl<'a> Case<'a> {
        fn door(reg: &'a CapabilityRegistry, cap: &'static str) -> Self {
            Case {
                reg,
                resource: rid("front-door"),
                cap,
                params: Payload::new(),
                device_state: SecurityState::Trusted,
                state: Some((1_000, payload([("locked", true), ("door_open", false)]))),
                busy: false,
            }
        }
        fn run(&self, s: &mut Safety, g: &ResourceGraph, now: u64) -> Result<Clearance, Violation> {
            let def = self.reg.get(&cap(self.cap)).unwrap();
            let device = g.get(&self.resource).unwrap().binding(&def.id).unwrap().device.clone();
            s.clear(
                g,
                &Proposed {
                    subject: &[1; 16],
                    resource: &self.resource,
                    capability: def,
                    params: &self.params,
                    risk: def.risk,
                    device: &device,
                    device_state: self.device_state,
                    observation: self.state.as_ref().map(|(age, st)| Observation { age_ms: *age, state: st }),
                    device_busy: self.busy,
                    resource_busy: false,
                },
                now,
            )
        }
    }

    fn rule(r: Result<Clearance, Violation>) -> Rule {
        r.unwrap_err().rule
    }

    #[test]
    fn clean_actions_are_cleared_for_exactly_themselves() {
        let (g, reg) = graph();
        let mut s = Safety::default();
        let c = Case::door(&reg, "lock.unlock").run(&mut s, &g, 0).unwrap();
        assert_eq!(c.resource(), &rid("front-door"));
        assert_eq!(c.capability().as_str(), "lock.unlock");
        assert_eq!(c.device(), &eid("device:front-door"));
    }

    #[test]
    fn holds_cover_everything_below() {
        let (g, reg) = graph();
        let mut s = Safety::default();
        s.hold(rid("entrance"), "fire alarm test");
        let v = Case::door(&reg, "lock.unlock").run(&mut s, &g, 0).unwrap_err();
        assert_eq!(v.rule, Rule::Hold);
        assert!(v.reason.contains("fire alarm test"));
        assert!(s.release(&rid("entrance")));
        assert!(Case::door(&reg, "lock.unlock").run(&mut s, &g, 0).is_ok());
    }

    #[test]
    fn recovery_lets_only_the_safe_state_through() {
        let (g, reg) = graph();
        let mut s = Safety::default();
        s.recover(rid("front-door"), "lock.lock was not confirmed");
        let v = Case::door(&reg, "lock.unlock").run(&mut s, &g, 0).unwrap_err();
        assert_eq!(v.rule, Rule::Recovery);
        assert!(v.reason.contains("lock.lock was not confirmed"));
        // the safe state itself, exactly as declared, is cleared (by every other rule too)
        assert!(Case::door(&reg, "lock.lock").run(&mut s, &g, 0).is_ok());
        let mut c = Case::door(&reg, "lock.lock");
        c.state = Some((1_000, payload([("locked", false), ("door_open", true)])));
        assert_eq!(rule(c.run(&mut s, &g, 0)), Rule::Physical);
        // a container in recovery has no safe state of its own: nothing below it runs
        s.recover(rid("entrance"), "test");
        assert_eq!(rule(Case::door(&reg, "lock.lock").run(&mut s, &g, 0)), Rule::Recovery);
        assert!(s.end_recovery(&rid("entrance")) && s.end_recovery(&rid("front-door")));
        assert!(!s.end_recovery(&rid("front-door")));
        assert!(Case::door(&reg, "lock.unlock").run(&mut s, &g, 0).is_ok());
        // a resource without a safe state takes nothing at all
        s.recover(rid("light"), "test");
        let c = Case {
            resource: rid("light"),
            cap: "light.set_brightness",
            params: payload([("brightness_pct", 10i64)]),
            ..Case::door(&reg, "lock.lock")
        };
        assert_eq!(rule(c.run(&mut s, &g, 0)), Rule::Recovery);
    }

    #[test]
    fn contained_devices_do_not_actuate() {
        let (g, reg) = graph();
        let mut s = Safety::default();
        let mut c = Case::door(&reg, "lock.unlock");
        c.device_state = SecurityState::Suspicious;
        assert_eq!(rule(c.run(&mut s, &g, 0)), Rule::Device);
        c.cap = "lock.lock"; // medium risk through a SUSPICIOUS device is fine
        assert!(c.run(&mut s, &g, 0).is_ok());
        c.device_state = SecurityState::Quarantined;
        assert_eq!(rule(c.run(&mut s, &g, 0)), Rule::Device);
    }

    #[test]
    fn unknown_or_stale_state_fails_safe() {
        let (g, reg) = graph();
        let mut s = Safety::default();
        let mut c = Case::door(&reg, "lock.unlock");
        c.state = None;
        assert_eq!(rule(c.run(&mut s, &g, 0)), Rule::State);
        c.state = Some((30_001, Payload::new()));
        assert_eq!(rule(c.run(&mut s, &g, 0)), Rule::State);
        c.state = Some((30_000, Payload::new()));
        assert!(c.run(&mut s, &g, 0).is_ok());
    }

    #[test]
    fn physics_beats_permission() {
        let (g, reg) = graph();
        let mut s = Safety::default();
        let mut c = Case::door(&reg, "lock.lock");
        c.state = Some((1_000, payload([("locked", false), ("door_open", true)])));
        assert_eq!(rule(c.run(&mut s, &g, 0)), Rule::Physical);
        c.cap = "lock.unlock";
        assert!(c.run(&mut s, &g, 0).is_ok());
    }

    #[test]
    fn resource_envelope_is_stricter_than_the_registry() {
        let (g, reg) = graph();
        let mut s = Safety::default();
        let mut c = Case::door(&reg, "light.set_brightness");
        c.resource = rid("light");
        c.params = payload([("brightness_pct", 90i64)]);
        assert_eq!(rule(c.run(&mut s, &g, 0)), Rule::Envelope);
        c.params = payload([("brightness_pct", 60i64)]);
        assert!(c.run(&mut s, &g, 0).is_ok());
    }

    #[test]
    fn rate_limits_actuation_and_recovers() {
        let (g, reg) = graph();
        let mut s = Safety::default();
        let c = Case::door(&reg, "lock.unlock");
        for t in 0..3 {
            c.run(&mut s, &g, t).unwrap();
        }
        assert_eq!(rule(c.run(&mut s, &g, 10)), Rule::Rate);
        // a dry run neither counts nor clears
        let def = reg.get(&cap("lock.unlock")).unwrap();
        let p = Proposed {
            subject: &[1; 16],
            resource: &c.resource,
            capability: def,
            params: &c.params,
            risk: def.risk,
            device: &eid("device:front-door"),
            device_state: SecurityState::Trusted,
            observation: None,
            device_busy: false,
            resource_busy: false,
        };
        assert_eq!(s.check(&g, &p, 10).unwrap_err().rule, Rule::State);
        // after the window it works again
        assert!(c.run(&mut s, &g, 60_000).is_ok());
        assert_eq!(c.run(&mut s, &g, 60_001).unwrap().subject(), &[1; 16], "bound to its intent");
        // medium-risk actions have a higher budget, counted per resource
        let lock = Case::door(&reg, "lock.lock");
        let mut s = Safety::default();
        for t in 0..6 {
            lock.run(&mut s, &g, t).unwrap();
        }
        assert_eq!(rule(lock.run(&mut s, &g, 7)), Rule::Rate);
    }

    #[test]
    fn one_action_at_a_time_per_device() {
        let (g, reg) = graph();
        let mut s = Safety::default();
        let mut c = Case::door(&reg, "lock.unlock");
        c.busy = true;
        assert_eq!(rule(c.run(&mut s, &g, 0)), Rule::Busy);
        c.busy = false;
        assert!(c.run(&mut s, &g, 0).is_ok());
    }
}
