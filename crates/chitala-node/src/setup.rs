//! `chitala init`: create a sample domain with virtual devices.
//!
//! For a single-machine trial all private keys end up in one key store. In a
//! real deployment each person's key stays on their own device and only the
//! public key is enrolled; the authority key belongs on the node (ideally in a
//! TPM/secure element — v5 §8).

use chitala_adapters::mock::VirtualKind;
use chitala_model::{CapabilityId, DeviceDescriptor, EntityId, Geofence, Payload, SecurityClass};
use chitala_platform::{KeyRef, PlatformError, SecureKeyStore, Storage, StoragePath, Visibility};
use chitala_resource::{
    Boundary, CapabilityBinding, MotionLimits, ParamLimit, Resource, ResourceId, ResourceKind, SafeState, StateRef,
    DEFAULT_MAX_STATE_AGE_MS,
};

use crate::config::{key_ref, ContainmentConfig, HomeAssistantConfig, NodeConfig, PrincipalConfig, AUTHORITY_KEY};
use crate::NodeError;

pub const CONFIG_FILE: &str = "chitala.json";
/// Where the CLI keeps the tokens each holder was given (private).
pub const TOKENS_DIR: &str = "tokens";

pub struct InitSummary {
    /// The config object in the platform's storage.
    pub config: StoragePath,
    pub principals: Vec<(EntityId, Vec<String>)>,
    pub devices: Vec<EntityId>,
}

fn id(s: &str) -> EntityId {
    EntityId::parse(s).expect("static ids are valid")
}

fn device(id_: &str, name: &str, kind: VirtualKind, sc: SecurityClass, room: &str) -> DeviceDescriptor {
    DeviceDescriptor {
        id: id(id_),
        name: name.into(),
        adapter: "mock".into(),
        capabilities: kind.capabilities(),
        security_class: sc,
        room: Some(room.into()),
    }
}

/// Sample principals: an owner, an adult, a guest, a child, and an AI
/// assistant for the owner, the guest and the child — none of the AIs holds any
/// right until a human delegates one.
pub fn sample_principals() -> Vec<(EntityId, Vec<String>)> {
    vec![
        (id("person:alice"), vec!["owner".into()]),
        (id("person:bob"), vec!["adult".into()]),
        (id("person:guest"), vec!["guest".into()]),
        (id("person:child"), vec!["child".into()]),
        (id("ai:assistant"), vec![]),
        (id("ai:guest-assistant"), vec![]),
        (id("ai:kid-assistant"), vec![]),
    ]
}

/// Which person each sample AI acts for.
pub fn sample_agency() -> Vec<(EntityId, Vec<EntityId>)> {
    vec![
        (id("ai:assistant"), vec![id("person:alice")]),
        (id("ai:guest-assistant"), vec![id("person:guest")]),
        (id("ai:kid-assistant"), vec![id("person:child")]),
    ]
}

fn resource(
    local: &str,
    kind: ResourceKind,
    name: &str,
    parent: Option<&str>,
    device: Option<(&str, &[&str])>,
) -> Resource {
    let rid = |s: &str| ResourceId::new(s).expect("static ids are valid");
    Resource {
        id: rid(local),
        kind,
        name: name.into(),
        parent: parent.map(rid),
        owners: vec![],
        boundary: Boundary::Interior,
        zone: None,
        bindings: device
            .map(|(d, caps)| {
                caps.iter()
                    .map(|c| CapabilityBinding {
                        capability: CapabilityId::parse(c).expect("static ids are valid"),
                        device: id(d),
                        risk_floor: None,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        state: device.map(|(d, _)| StateRef { device: id(d), max_age_ms: DEFAULT_MAX_STATE_AGE_MS }),
        envelope: vec![],
        two_key: false,
        safe_state: None,
        motion: None,
    }
}

/// The sample home as governed resources: what an AI names in an intent.
/// Every device's history is offered (spec 29); who may read it is policy's
/// and the tokens' to say.
pub fn sample_resources() -> Vec<Resource> {
    let mut home = resource("home", ResourceKind::Site, "Home", None, None);
    home.owners = vec![id("person:alice")];
    let mut entrance = resource("entrance", ResourceKind::Space, "Entrance", Some("home"), None);
    entrance.zone = Some("entrance".into());
    let mut door = resource(
        "front-door",
        ResourceKind::Door,
        "Front door",
        Some("entrance"),
        Some(("device:front-door", &["device.read_state", "device.read_history", "lock.lock", "lock.unlock"])),
    );
    door.boundary = Boundary::Perimeter;
    // after a failed outcome the door goes back to locked (spec 22)
    door.safe_state =
        Some(SafeState { capability: CapabilityId::parse("lock.lock").expect("static id"), params: Payload::new() });
    let mut thermostat = resource(
        "thermostat",
        ResourceKind::Climate,
        "Air conditioner",
        Some("living-room"),
        Some(("device:thermostat", &["device.read_state", "device.read_history", "climate.set_target_temperature"])),
    );
    thermostat.envelope = vec![ParamLimit {
        capability: CapabilityId::parse("climate.set_target_temperature").expect("static id"),
        param: "celsius".into(),
        min: 18,
        max: 28,
    }];
    vec![
        home,
        resource("living-room", ResourceKind::Space, "Living room", Some("home"), None),
        resource("bedroom", ResourceKind::Space, "Bedroom", Some("home"), None),
        entrance,
        resource(
            "living-room-light",
            ResourceKind::Light,
            "Living room light",
            Some("living-room"),
            Some((
                "device:living-room-light",
                &[
                    "device.read_state",
                    "device.read_history",
                    "light.turn_on",
                    "light.turn_off",
                    "light.set_brightness",
                ],
            )),
        ),
        resource(
            "fan",
            ResourceKind::Switch,
            "Fan",
            Some("bedroom"),
            Some((
                "device:fan-plug",
                &["device.read_state", "device.read_history", "switch.turn_on", "switch.turn_off"],
            )),
        ),
        thermostat,
        door,
    ]
}

/// A simulated ground robot in the sample home's living room (spec 30), on
/// the `robot-sim` adapter: a 5 m × 4 m geofence, at most 800 mm/s and
/// 90°/s, a pose at most 1 s old, and a stop as its safe state.
pub fn sample_robot() -> (DeviceDescriptor, Resource) {
    let device = id("device:robot");
    let capabilities = chitala_adapters::robot_sim::capabilities();
    let limit = |c: &str, param: &str, min, max| ParamLimit {
        capability: CapabilityId::parse(c).expect("static id"),
        param: param.into(),
        min,
        max,
    };
    let resource = Resource {
        id: ResourceId::parse("resource:robot").expect("static id"),
        kind: ResourceKind::Robot,
        name: "Robot".into(),
        parent: Some(ResourceId::parse("resource:living-room").expect("static id")),
        owners: vec![],
        boundary: Boundary::default(),
        zone: None,
        bindings: capabilities
            .iter()
            .map(|c| CapabilityBinding { capability: c.clone(), device: device.clone(), risk_floor: None })
            .collect(),
        state: Some(StateRef { device: device.clone(), max_age_ms: 2_000 }),
        envelope: vec![
            limit("robot.move_linear", "speed_mm_s", 50, 800),
            limit("robot.goto_pose", "speed_mm_s", 50, 800),
            limit("robot.rotate", "speed_mdeg_s", 5_000, 90_000),
        ],
        two_key: false,
        safe_state: Some(SafeState {
            capability: CapabilityId::parse("robot.stop").expect("static id"),
            params: Payload::new(),
        }),
        motion: Some(MotionLimits {
            geofence: Geofence(vec![[-1_000, -1_000], [4_000, -1_000], [4_000, 3_000], [-1_000, 3_000]]),
            max_localization_age_ms: 1_000,
        }),
    };
    let descriptor = DeviceDescriptor {
        id: device,
        name: "Robot".into(),
        adapter: chitala_adapters::robot_sim::ADAPTER.into(),
        capabilities,
        security_class: SecurityClass::Sc2,
        room: Some("living-room".into()),
    };
    (descriptor, resource)
}

/// Sample virtual home.
pub fn sample_devices() -> Vec<DeviceDescriptor> {
    vec![
        device("device:living-room-light", "Living room light", VirtualKind::Light, SecurityClass::Sc2, "living-room"),
        device("device:fan-plug", "Fan plug", VirtualKind::Switch, SecurityClass::Sc1, "bedroom"),
        device("device:thermostat", "Air conditioner", VirtualKind::Thermostat, SecurityClass::Sc2, "living-room"),
        device("device:front-door", "Front door lock", VirtualKind::Lock, SecurityClass::Sc3, "entrance"),
    ]
}

/// Create the sample domain in a platform: keys in its key store, the config
/// (public keys only) as [`CONFIG_FILE`] in its storage, and a private `tokens`
/// area. Never overwrites: an existing config or key is an error.
pub fn init_domain(storage: &dyn Storage, keys: &dyn SecureKeyStore) -> Result<InitSummary, NodeError> {
    let platform = |e: PlatformError| NodeError::Platform(e.to_string());
    let config_path = StoragePath::new(CONFIG_FILE).map_err(platform)?;
    if storage.exists(&config_path).map_err(platform)? {
        return Err(NodeError::Config(format!("{CONFIG_FILE} already exists")));
    }
    storage.ensure_dir(&StoragePath::new(TOKENS_DIR).map_err(platform)?, Visibility::Private).map_err(platform)?;

    let generate = |key: KeyRef| -> Result<String, NodeError> {
        let pk = keys.generate(&key).map_err(|e| NodeError::Key(format!("{key}: {e}")))?;
        Ok(hex::encode(pk))
    };
    let authority_public_key = generate(KeyRef::new(AUTHORITY_KEY).map_err(platform)?)?;
    let node_id = id("service:node");
    let node_public_key = generate(key_ref(&node_id)?)?;

    let mut principals = Vec::new();
    for (pid, roles) in sample_principals() {
        let public_key = generate(key_ref(&pid)?)?;
        let serves = sample_agency().into_iter().find(|(a, _)| a == &pid).map(|(_, s)| s).unwrap_or_default();
        principals.push(PrincipalConfig { id: pid, public_key, roles, serves });
    }

    let devices = sample_devices();
    let config = NodeConfig {
        domain: id("domain:home"),
        node_id,
        authority_public_key,
        node_public_key,
        keys_dir: "keys".into(),
        socket: "chitala.sock".into(),
        audit_log: "audit.audit.jsonl".into(),
        state_file: "domain-state.json".into(),
        policy_file: None,
        principals: principals.clone(),
        devices: devices.clone(),
        resources: sample_resources(),
        home_assistant: None::<HomeAssistantConfig>,
        matter: None,
        history: Default::default(),
        adapter_host: None,
        containment: ContainmentConfig::default(),
    };
    let text = serde_json::to_string_pretty(&config).expect("config serializes");
    storage.create_new(&config_path, format!("{text}\n").as_bytes(), Visibility::Shared).map_err(platform)?;
    Ok(InitSummary {
        config: config_path,
        principals: principals.into_iter().map(|p| (p.id, p.roles)).collect(),
        devices: devices.into_iter().map(|d| d.id).collect(),
    })
}
