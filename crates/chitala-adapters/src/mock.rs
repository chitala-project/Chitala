//! Virtual devices for mock-first development (Blueprint v17 §7).
//!
//! Each device keeps the state a real one would report and enforces a local
//! invariant where it makes sense: a virtual lock refuses to lock while the door is
//! open — a perfectly authorized, correctly signed command can still be refused by
//! the device (Security Constitution C5). Fault injection covers offline devices
//! and one-shot failures.

use std::collections::BTreeMap;

use chitala_model::{payload, CapabilityId, EntityId, ParamValue, Payload};

use crate::{AdapterError, DeviceAdapter, Simulation, VerifiedOrder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtualKind {
    Light,
    Switch,
    Thermostat,
    Lock,
}

impl VirtualKind {
    /// Infer the device type from the capabilities it declares.
    pub fn from_capabilities<'a>(caps: impl IntoIterator<Item = &'a CapabilityId>) -> Option<Self> {
        caps.into_iter().find_map(|c| match c.as_str().split('.').next() {
            Some("light") => Some(VirtualKind::Light),
            Some("switch") => Some(VirtualKind::Switch),
            Some("climate") => Some(VirtualKind::Thermostat),
            Some("lock") => Some(VirtualKind::Lock),
            _ => None,
        })
    }

    /// The canonical capabilities such a device offers.
    pub fn capabilities(self) -> Vec<CapabilityId> {
        let ids: &[&str] = match self {
            VirtualKind::Light => &["device.read_state", "light.turn_on", "light.turn_off", "light.set_brightness"],
            VirtualKind::Switch => &["device.read_state", "switch.turn_on", "switch.turn_off"],
            VirtualKind::Thermostat => &["device.read_state", "climate.set_target_temperature"],
            VirtualKind::Lock => &["device.read_state", "lock.lock", "lock.unlock"],
        };
        ids.iter().map(|c| CapabilityId::parse(c).expect("static capability ids are valid")).collect()
    }

    fn initial_state(self) -> Payload {
        match self {
            VirtualKind::Light => payload([("on", ParamValue::Bool(false)), ("brightness_pct", ParamValue::Int(100))]),
            VirtualKind::Switch => payload([("on", false)]),
            VirtualKind::Thermostat => {
                payload([("target_celsius", ParamValue::Int(24)), ("current_celsius", ParamValue::Int(27))])
            }
            VirtualKind::Lock => payload([("locked", true), ("door_open", false)]),
        }
    }
}

#[derive(Debug, Clone)]
struct VirtualDevice {
    kind: VirtualKind,
    state: Payload,
    offline: bool,
    fail_next: Option<AdapterError>,
}

#[derive(Debug, Default)]
pub struct MockAdapter {
    devices: BTreeMap<EntityId, VirtualDevice>,
}

impl MockAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, id: EntityId, kind: VirtualKind) {
        self.devices.insert(id, VirtualDevice { kind, state: kind.initial_state(), offline: false, fail_next: None });
    }

    pub fn kind(&self, id: &EntityId) -> Option<VirtualKind> {
        self.devices.get(id).map(|d| d.kind)
    }

    pub fn set_offline(&mut self, id: &EntityId, offline: bool) {
        if let Some(d) = self.devices.get_mut(id) {
            d.offline = offline;
        }
    }

    /// Make the next `execute` on `id` fail with `err`.
    pub fn fail_next(&mut self, id: &EntityId, err: AdapterError) {
        if let Some(d) = self.devices.get_mut(id) {
            d.fail_next = Some(err);
        }
    }

    /// Physical world change outside Chitala (someone opens the door).
    pub fn set_door_open(&mut self, id: &EntityId, open: bool) {
        if let Some(d) = self.devices.get_mut(id).filter(|d| d.kind == VirtualKind::Lock) {
            d.state.insert("door_open".into(), ParamValue::Bool(open));
        }
    }

    fn device(&mut self, id: &EntityId) -> Result<&mut VirtualDevice, AdapterError> {
        let d =
            self.devices.get_mut(id).ok_or_else(|| AdapterError::Failed(format!("{id} is not a virtual device")))?;
        if d.offline {
            return Err(AdapterError::Unavailable(format!("{id} is offline")));
        }
        Ok(d)
    }
}

fn int(p: &Payload, k: &str) -> Result<i64, AdapterError> {
    p.get(k).and_then(ParamValue::as_int).ok_or_else(|| AdapterError::Failed(format!("missing {k}")))
}

impl DeviceAdapter for MockAdapter {
    fn name(&self) -> &str {
        "mock"
    }

    fn manages(&self, device: &EntityId) -> bool {
        self.devices.contains_key(device)
    }

    fn observe(&mut self, device: &EntityId) -> Result<Payload, AdapterError> {
        Ok(self.device(device)?.state.clone())
    }

    fn execute(&mut self, action: VerifiedOrder) -> Result<Payload, AdapterError> {
        let d = self.device(action.target())?;
        if let Some(err) = d.fail_next.take() {
            return Err(err);
        }
        let p = action.payload();
        let s = &mut d.state;
        match (d.kind, action.capability().as_str()) {
            (VirtualKind::Light, "light.turn_on") => {
                s.insert("on".into(), true.into());
                if s.get("brightness_pct").and_then(ParamValue::as_int) == Some(0) {
                    s.insert("brightness_pct".into(), 100i64.into());
                }
            }
            (VirtualKind::Light, "light.turn_off") => {
                s.insert("on".into(), false.into());
            }
            (VirtualKind::Light, "light.set_brightness") => {
                let b = int(p, "brightness_pct")?;
                s.insert("brightness_pct".into(), b.into());
                s.insert("on".into(), (b > 0).into());
            }
            (VirtualKind::Switch, "switch.turn_on") => {
                s.insert("on".into(), true.into());
            }
            (VirtualKind::Switch, "switch.turn_off") => {
                s.insert("on".into(), false.into());
            }
            (VirtualKind::Thermostat, "climate.set_target_temperature") => {
                s.insert("target_celsius".into(), int(p, "celsius")?.into());
            }
            (VirtualKind::Lock, "lock.lock") => {
                if s.get("door_open").and_then(ParamValue::as_bool) == Some(true) {
                    return Err(AdapterError::Refused("cannot lock while the door is open".into()));
                }
                s.insert("locked".into(), true.into());
            }
            (VirtualKind::Lock, "lock.unlock") => {
                s.insert("locked".into(), false.into());
            }
            (kind, cap) => return Err(AdapterError::Failed(format!("{kind:?} does not implement {cap}"))),
        }
        Ok(s.clone())
    }

    fn simulate(&mut self, device: &EntityId, change: &Simulation) -> Result<(), AdapterError> {
        let kind =
            self.kind(device).ok_or_else(|| AdapterError::Failed(format!("{device} is not a virtual device")))?;
        match change {
            Simulation::Offline(off) => self.set_offline(device, *off),
            Simulation::DoorOpen(open) if kind == VirtualKind::Lock => self.set_door_open(device, *open),
            Simulation::DoorOpen(_) => return Err(AdapterError::Failed(format!("{device} has no door"))),
            Simulation::FailNext(err) => self.fail_next(device, err.clone()),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::authorize;

    fn setup(kind: VirtualKind) -> (MockAdapter, EntityId) {
        let id = EntityId::parse("device:virtual-1").unwrap();
        let mut a = MockAdapter::new();
        a.add(id.clone(), kind);
        (a, id)
    }

    #[test]
    fn light() {
        let (mut a, id) = setup(VirtualKind::Light);
        let s = a.execute(authorize(&id, "light.turn_on", Payload::new())).unwrap();
        assert_eq!(s.get("on"), Some(&ParamValue::Bool(true)));
        let s = a.execute(authorize(&id, "light.set_brightness", payload([("brightness_pct", 0i64)]))).unwrap();
        assert_eq!(s.get("on"), Some(&ParamValue::Bool(false)));
        let s = a.execute(authorize(&id, "light.turn_on", Payload::new())).unwrap();
        assert_eq!(s.get("brightness_pct"), Some(&ParamValue::Int(100)));
        assert_eq!(a.observe(&id).unwrap(), s);
    }

    #[test]
    fn lock_invariant_refuses_authorized_command() {
        let (mut a, id) = setup(VirtualKind::Lock);
        a.execute(authorize(&id, "lock.unlock", Payload::new())).unwrap();
        a.set_door_open(&id, true);
        let err = a.execute(authorize(&id, "lock.lock", Payload::new())).unwrap_err();
        assert_eq!(err.code(), chitala_model::ExecCode::DeviceRefused);
        a.set_door_open(&id, false);
        let s = a.execute(authorize(&id, "lock.lock", Payload::new())).unwrap();
        assert_eq!(s.get("locked"), Some(&ParamValue::Bool(true)));
    }

    #[test]
    fn faults() {
        let (mut a, id) = setup(VirtualKind::Switch);
        a.set_offline(&id, true);
        assert!(matches!(a.observe(&id), Err(AdapterError::Unavailable(_))));
        assert!(matches!(
            a.execute(authorize(&id, "switch.turn_on", Payload::new())),
            Err(AdapterError::Unavailable(_))
        ));
        a.set_offline(&id, false);
        a.fail_next(&id, AdapterError::Failed("relay stuck".into()));
        assert!(a.execute(authorize(&id, "switch.turn_on", Payload::new())).is_err());
        assert!(a.execute(authorize(&id, "switch.turn_on", Payload::new())).is_ok());
    }

    #[test]
    fn kind_inference() {
        let caps = VirtualKind::Thermostat.capabilities();
        assert_eq!(VirtualKind::from_capabilities(&caps), Some(VirtualKind::Thermostat));
        let only_read = [CapabilityId::parse("device.read_state").unwrap()];
        assert_eq!(VirtualKind::from_capabilities(&only_read), None);
    }
}
