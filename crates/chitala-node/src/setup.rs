//! `chitala init`: create a sample domain with virtual devices.
//!
//! For a single-machine trial all private keys end up in one `keys/` directory.
//! In a real deployment each person's key stays on their own device and only the
//! public key is enrolled; the authority key belongs on the node (ideally in a
//! TPM/secure element — v5 §8).

use std::path::Path;

use chitala_adapters::mock::VirtualKind;
use chitala_identity::Keypair;
use chitala_model::{CapabilityId, DeviceDescriptor, EntityId, SecurityClass};
use chitala_resource::{
    Boundary, CapabilityBinding, ParamLimit, Resource, ResourceId, ResourceKind, StateRef, DEFAULT_MAX_STATE_AGE_MS,
};

use crate::config::{
    key_file_name, write_key, ContainmentConfig, HomeAssistantConfig, NodeConfig, PrincipalConfig, AUTHORITY_KEY_FILE,
};
use crate::NodeError;

pub const CONFIG_FILE: &str = "chitala.json";

pub struct InitSummary {
    pub config_path: std::path::PathBuf,
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
    }
}

/// The sample home as governed resources: what an AI names in an intent.
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
        Some(("device:front-door", &["device.read_state", "lock.lock", "lock.unlock"])),
    );
    door.boundary = Boundary::Perimeter;
    let mut thermostat = resource(
        "thermostat",
        ResourceKind::Climate,
        "Air conditioner",
        Some("living-room"),
        Some(("device:thermostat", &["device.read_state", "climate.set_target_temperature"])),
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
                &["device.read_state", "light.turn_on", "light.turn_off", "light.set_brightness"],
            )),
        ),
        resource(
            "fan",
            ResourceKind::Switch,
            "Fan",
            Some("bedroom"),
            Some(("device:fan-plug", &["device.read_state", "switch.turn_on", "switch.turn_off"])),
        ),
        thermostat,
        door,
    ]
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

pub fn init_domain(dir: &Path) -> Result<InitSummary, NodeError> {
    let config_path = dir.join(CONFIG_FILE);
    if config_path.exists() {
        return Err(NodeError::Config(format!("{} already exists", config_path.display())));
    }
    for sub in ["keys", "tokens"] {
        let d = dir.join(sub);
        std::fs::create_dir_all(&d)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    let authority = Keypair::generate(&chitala_platform_host::OsEntropy);
    write_key(&dir.join("keys").join(AUTHORITY_KEY_FILE), &authority)?;
    let node_id = id("service:node");
    let node_key = Keypair::generate(&chitala_platform_host::OsEntropy);
    write_key(&dir.join("keys").join(key_file_name(&node_id)), &node_key)?;

    let mut principals = Vec::new();
    for (pid, roles) in sample_principals() {
        let k = Keypair::generate(&chitala_platform_host::OsEntropy);
        write_key(&dir.join("keys").join(key_file_name(&pid)), &k)?;
        let serves = sample_agency().into_iter().find(|(a, _)| a == &pid).map(|(_, s)| s).unwrap_or_default();
        principals.push(PrincipalConfig { id: pid, public_key: hex::encode(k.public_key()), roles, serves });
    }

    let devices = sample_devices();
    let config = NodeConfig {
        domain: id("domain:home"),
        node_id,
        authority_public_key: hex::encode(authority.public_key()),
        node_public_key: hex::encode(node_key.public_key()),
        keys_dir: "keys".into(),
        socket: "chitala.sock".into(),
        audit_log: "audit.audit.jsonl".into(),
        state_file: "domain-state.json".into(),
        policy_file: None,
        principals: principals.clone(),
        devices: devices.clone(),
        resources: sample_resources(),
        home_assistant: None::<HomeAssistantConfig>,
        adapter_host: None,
        containment: ContainmentConfig::default(),
    };
    let text = serde_json::to_string_pretty(&config).expect("config serializes");
    std::fs::write(&config_path, format!("{text}\n"))?;
    Ok(InitSummary {
        config_path,
        principals: principals.into_iter().map(|p| (p.id, p.roles)).collect(),
        devices: devices.into_iter().map(|d| d.id).collect(),
    })
}
