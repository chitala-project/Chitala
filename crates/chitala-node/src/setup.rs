//! `chitala init`: create a sample domain with virtual devices.
//!
//! For a single-machine trial all private keys end up in one `keys/` directory.
//! In a real deployment each person's key stays on their own device and only the
//! public key is enrolled; the authority key belongs on the node (ideally in a
//! TPM/secure element — v5 §8).

use std::path::Path;

use chitala_adapters::mock::VirtualKind;
use chitala_identity::Keypair;
use chitala_model::{DeviceDescriptor, EntityId, SecurityClass};

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

/// Sample principals: an owner, an adult, an AI assistant without any rights.
pub fn sample_principals() -> Vec<(EntityId, Vec<String>)> {
    vec![
        (id("person:alice"), vec!["owner".into()]),
        (id("person:bob"), vec!["adult".into()]),
        (id("ai:assistant"), vec![]),
    ]
}

/// Sample virtual home.
pub fn sample_devices() -> Vec<DeviceDescriptor> {
    vec![
        device("device:living-room-light", "Đèn phòng khách", VirtualKind::Light, SecurityClass::Sc2, "living-room"),
        device("device:fan-plug", "Ổ cắm quạt", VirtualKind::Switch, SecurityClass::Sc1, "bedroom"),
        device("device:thermostat", "Điều hòa", VirtualKind::Thermostat, SecurityClass::Sc2, "living-room"),
        device("device:front-door", "Khóa cửa chính", VirtualKind::Lock, SecurityClass::Sc3, "entrance"),
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

    let authority = Keypair::generate();
    write_key(&dir.join("keys").join(AUTHORITY_KEY_FILE), &authority)?;
    let node_id = id("service:node");
    let node_key = Keypair::generate();
    write_key(&dir.join("keys").join(key_file_name(&node_id)), &node_key)?;

    let mut principals = Vec::new();
    for (pid, roles) in sample_principals() {
        let k = Keypair::generate();
        write_key(&dir.join("keys").join(key_file_name(&pid)), &k)?;
        principals.push(PrincipalConfig { id: pid, public_key: hex::encode(k.public_key()), roles });
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
