//! Fuzz harnesses for Chitala's trust boundaries (specs/13-threat-model.md, R8).
//!
//! Each harness feeds attacker-controlled bytes to the exact function that sees
//! them in production and checks invariants beyond "does not panic":
//!
//! | target          | boundary                                   | invariant |
//! |-----------------|--------------------------------------------|-----------|
//! | `csme_envelope` | COSE from an unauthenticated peer          | parse/verify never panic |
//! | `csme_payload`  | CBOR body after signature verification      | decode ∘ encode = id |
//! | `token`         | capability tokens (Biscuit)                 | only domain-signed tokens verify |
//! | `node_request`  | the whole Reference Monitor pipeline        | never ALLOW without a valid signature of an enrolled principal; every reply signed and bound |
//! | `ipc`           | IPC request line (server), reply line (client) | an unsigned/forged reply never authenticates |
//! | `ha_state`      | JSON from Home Assistant                    | bounded canonical state |
//! | `audit_log`     | audit file read during start-up/recovery    | verify never panics |
//! | `exec_order`    | orders entering the adapter host            | only node-signed, fresh, single-use orders execute |
//! | `host_line`     | host request lines / node-side host replies | admitted replies are bounded and typed |
//!
//! Seeds ([`seeds`]) are generated deterministically from test keys so the fuzzer
//! starts from valid, signed inputs and explores just past the signature checks.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use chitala_adapters::home_assistant::state_to_payload;
use chitala_adapters::host::{parse_reply as parse_host_reply, AdapterHost};
use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_audit::{verify_lines, AuditLog, Signer};
use chitala_csme::{Csme, SignedEnvelope};
use chitala_identity::{test_seed, Keypair, PublicKey};
use chitala_model::{payload, CapabilityId, CapabilityRegistry, EntityId, ParamValue, Payload};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::ipc::{parse_reply, parse_request, request_digest, sign_reply, verify_reply};
use chitala_node::setup::sample_devices;
use chitala_node::{DomainState, Node, NodeParts, PolicySource, Requester};
use chitala_policy::PolicyEngine;
use chitala_token::{bytes_from_base64, Grant, RevocationList, Right, TokenAuthority, TokenVerifier};

/// Fixed node clock: seeds are valid at this instant.
pub const T0: u64 = 1_790_000_000_000;

pub const TARGETS: [&str; 9] = [
    "csme_envelope",
    "csme_payload",
    "token",
    "node_request",
    "ipc",
    "ha_state",
    "audit_log",
    "exec_order",
    "host_line",
];

const PRINCIPALS: [(&str, &[&str]); 4] =
    [("person:alice", &["owner"]), ("person:bob", &["adult"]), ("ai:assistant", &[]), ("ai:helper", &[])];

fn id(s: &str) -> EntityId {
    EntityId::parse(s).expect("static id")
}
fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).expect("static capability")
}
fn key(label: &str) -> Keypair {
    Keypair::from_seed(&test_seed(label))
}
fn authority() -> TokenAuthority {
    TokenAuthority::new(&key("domain:home/authority"))
}
fn node_key() -> Keypair {
    key("service:node")
}

/// The default policy, validated once (Cedar parsing dominates node start-up).
fn policy_engine() -> Arc<PolicyEngine> {
    static ENGINE: OnceLock<Arc<PolicyEngine>> = OnceLock::new();
    ENGINE
        .get_or_init(|| {
            Arc::new(PolicyEngine::with_default_policies(&CapabilityRegistry::core_v0_1()).expect("default policy"))
        })
        .clone()
}

/// A fresh in-memory node with the sample home, clock fixed at [`T0`].
pub fn fresh_node() -> Node {
    let mut mock = MockAdapter::new();
    let devices = sample_devices();
    for d in &devices {
        mock.add(d.id.clone(), VirtualKind::from_capabilities(&d.capabilities).expect("sample device"));
    }
    let time = Arc::new(AtomicU64::new(T0));
    let clock: chitala_node::Clock = Arc::new(move || time.load(Ordering::SeqCst));
    Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: node_key(),
        authority_key: key("domain:home/authority"),
        principals: PRINCIPALS
            .iter()
            .map(|(p, roles)| (id(p), key(p).public_key(), roles.iter().map(|r| r.to_string()).collect()))
            .collect(),
        devices,
        executor: chitala_node::executor::in_process(&node_key().public_key(), vec![Box::new(mock)], clock.clone()),
        policy: PolicySource::Engine(policy_engine()),
        audit: AuditLog::in_memory(Some(Signer { id: id("service:node"), key: node_key() })),
        state: DomainState::default(),
        state_path: None,
        containment: ContainmentConfig::default(),
        monitor: MonitorConfig::default(),
        clock,
    })
    .expect("fuzz node")
}

// ───────────────────────────── harnesses ─────────────────────────────

pub fn csme_envelope(data: &[u8]) {
    if let Ok(env) = SignedEnvelope::parse(data) {
        let _ = env.key_id();
        let _ = env.verify(&key("person:alice").public_key());
        let _ = env.payload().len();
    }
}

pub fn csme_payload(data: &[u8]) {
    if let Ok(m) = Csme::from_cbor(data) {
        let again = Csme::from_cbor(&m.to_cbor()).expect("a decoded message re-encodes to a decodable message");
        assert_eq!(again, m, "decode ∘ encode must be the identity");
    }
}

pub fn token(data: &[u8]) {
    let verifier = TokenVerifier::new(&authority().public_key());
    if let Ok(t) = verifier.verify(data) {
        let holder = t.holder.clone();
        for r in t.rights.clone() {
            let _ = t.authorize(&holder, &r.target, &r.capability, T0);
        }
        let _ = t.authorize(&id("ai:intruder"), &id("device:front-door"), &cap("lock.unlock"), T0);
        let _ = RevocationList::new().is_revoked(&t);
        let _ = t.print();
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = bytes_from_base64(text);
    }
}

pub fn node_request(data: &[u8]) {
    let mut node = fresh_node();
    let reply = node.handle_signed(data);
    verify_reply(&reply, &node.node_public_key(), Some(&request_digest(data)))
        .expect("every node reply is signed and bound to its request");
    if reply.get("decision").and_then(|d| d.as_str()) == Some("allow") {
        let authentic = PRINCIPALS.iter().any(|(p, _)| chitala_csme::open(data, &key(p).public_key()).is_ok());
        assert!(authentic, "ALLOW for a request that no enrolled principal signed");
    }
    if reply.get("authenticated") == Some(&serde_json::Value::Bool(false)) {
        assert!(reply.get("reason").is_none(), "unauthenticated callers must not get details");
    }
}

pub fn ipc(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let _ = parse_request(&text);
    let pk: PublicKey = node_key().public_key();
    if let Ok(v) = parse_reply(&text, &pk, None) {
        verify_reply(&v, &pk, None).expect("parse_reply only returns authenticated replies");
    }
}

pub fn ha_state(data: &[u8]) {
    let (entity, json) = match data.iter().position(|b| *b == b'\n') {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &b""[..]),
    };
    let entity = String::from_utf8_lossy(entity);
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(json) {
        let p = state_to_payload(&entity, &v);
        assert!(p.len() <= 3, "bounded state");
        for value in p.values() {
            if let ParamValue::Text(t) = value {
                assert!(t.chars().count() <= 64, "bounded text");
            }
        }
    }
}

pub fn audit_log(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let k = node_key();
        let trusted = HashMap::from([(k.key_id(), k.public_key())]);
        let _ = verify_lines(text.lines(), &trusted);
    }
}

fn host() -> AdapterHost {
    let mut mock = MockAdapter::new();
    for d in sample_devices() {
        mock.add(d.id.clone(), VirtualKind::from_capabilities(&d.capabilities).expect("sample device"));
    }
    AdapterHost::new(node_key().public_key(), vec![Box::new(mock)], Arc::new(|| T0))
}

pub fn exec_order(data: &[u8]) {
    let mut h = host();
    let device = id("device:living-room-light");
    if h.execute(&device, data).is_ok() {
        let order = chitala_csme::order::ExecOrder::open(data, &node_key().public_key())
            .expect("only orders signed by the node key execute");
        assert_eq!(order.target, device, "an order executes only on its own device");
        assert!(h.execute(&device, data).is_err(), "orders are single use");
    }
}

pub fn host_line(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let _ = host().handle_line(&text);
    if let Ok(Ok(Some(state))) = parse_host_reply(&text) {
        assert!(state.len() <= chitala_adapters::host::MAX_STATE_ENTRIES);
        for (k, v) in &state {
            assert!(k.chars().count() <= chitala_adapters::host::MAX_STATE_KEY);
            if let ParamValue::Text(t) = v {
                assert!(t.chars().count() <= chitala_adapters::host::MAX_STATE_TEXT);
            }
        }
    }
}

/// Dispatch by target name.
pub fn run(target: &str, data: &[u8]) {
    match target {
        "csme_envelope" => csme_envelope(data),
        "csme_payload" => csme_payload(data),
        "token" => token(data),
        "node_request" => node_request(data),
        "ipc" => ipc(data),
        "ha_state" => ha_state(data),
        "audit_log" => audit_log(data),
        "exec_order" => exec_order(data),
        "host_line" => host_line(data),
        other => panic!("unknown fuzz target {other}"),
    }
}

// ───────────────────────────── seeds ─────────────────────────────

fn token_for(holder: &str, rights: &[(&str, &str)]) -> Vec<u8> {
    authority()
        .issue(
            &Grant {
                holder: id(holder),
                issuer: id("person:alice"),
                rights: rights.iter().map(|(t, c)| Right::new(id(t), cap(c))).collect(),
                not_after_ms: T0 + 600_000,
            },
            T0,
        )
        .expect("seed token")
        .bytes
}

fn request(n: u8, who: &str, target: &str, capability: &str, pl: Payload, token: Option<Vec<u8>>) -> Csme {
    let registry = CapabilityRegistry::core_v0_1();
    let r = Requester::new(id(who), key(who), id("service:fuzz")).with_token(token);
    let mut m = r.envelope(&registry, &id(target), &cap(capability), pl, T0);
    m.message_id = [n; 16];
    m
}

fn requests() -> Vec<(String, Csme)> {
    let ai_token = token_for("ai:assistant", &[("device:living-room-light", "light.set_brightness")]);
    vec![
        (
            "person:alice".into(),
            request(1, "person:alice", "device:living-room-light", "light.turn_on", Payload::new(), None),
        ),
        (
            "ai:assistant".into(),
            request(
                2,
                "ai:assistant",
                "device:living-room-light",
                "light.set_brightness",
                payload([("brightness_pct", 30i64)]),
                Some(ai_token),
            ),
        ),
        ("person:bob".into(), request(3, "person:bob", "device:front-door", "lock.unlock", Payload::new(), None)),
        (
            "person:alice".into(),
            request(
                4,
                "person:alice",
                "domain:home",
                "domain.delegate",
                payload([
                    ("holder", ParamValue::from("ai:assistant")),
                    ("target", ParamValue::from("device:thermostat")),
                    ("capability", ParamValue::from("climate.set_target_temperature")),
                    ("ttl_s", ParamValue::Int(600)),
                ]),
                None,
            ),
        ),
        (
            "person:alice".into(),
            request(5, "person:alice", "device:front-door", "device.read_state", Payload::new(), None),
        ),
    ]
}

fn signed_requests() -> Vec<Vec<u8>> {
    requests().into_iter().map(|(who, m)| m.sign(&key(&who))).collect()
}

/// Deterministic seed inputs for a target.
pub fn seeds(target: &str) -> Vec<Vec<u8>> {
    match target {
        "csme_envelope" | "node_request" => signed_requests(),
        "csme_payload" => requests().into_iter().map(|(_, m)| m.to_cbor()).collect(),
        "token" => {
            let parent =
                token_for("person:bob", &[("device:front-door", "lock.unlock"), ("device:fan-plug", "switch.turn_on")]);
            let verified = authority().verifier().verify(&parent).expect("seed parent");
            let child = authority()
                .delegate(
                    &verified,
                    &id("person:bob"),
                    &Grant {
                        holder: id("ai:helper"),
                        issuer: id("person:bob"),
                        rights: vec![Right::new(id("device:fan-plug"), cap("switch.turn_on"))],
                        not_after_ms: T0 + 60_000,
                    },
                    T0,
                )
                .expect("seed child")
                .bytes;
            let attenuated = chitala_token::attenuate(
                &parent,
                &authority().public_key(),
                &chitala_token::Restriction { not_after_ms: Some(T0 + 1_000), ..Default::default() },
            )
            .expect("seed attenuation");
            vec![parent, child, attenuated]
        }
        "ipc" => {
            let req = signed_requests().remove(0);
            let mut reply = serde_json::json!({"decision": "allow", "mid": "01", "request": request_digest(&req)});
            sign_reply(&mut reply, &id("service:node"), &node_key());
            vec![
                br#"{"op":"hello"}"#.to_vec(),
                format!(r#"{{"op":"submit","csme":"{}"}}"#, hex::encode(&req)).into_bytes(),
                reply.to_string().into_bytes(),
                br#"{"error":"node is busy"}"#.to_vec(),
            ]
        }
        "ha_state" => vec![
            b"light.living_room\n{\"state\":\"on\",\"attributes\":{\"brightness\":128}}".to_vec(),
            b"climate.x\n{\"state\":\"cool\",\"attributes\":{\"temperature\":23.5,\"current_temperature\":27}}"
                .to_vec(),
            b"lock.front\n{\"state\":\"locked\"}".to_vec(),
            b"sensor.y\n{\"state\":\"unavailable\"}".to_vec(),
        ],
        "audit_log" => {
            let mut node = fresh_node();
            for r in signed_requests() {
                node.handle(&r);
            }
            node.checkpoint().expect("checkpoint");
            vec![node.audit().lines().join("\n").into_bytes()]
        }
        "exec_order" => {
            let light = id("device:living-room-light");
            let order = |n: u8, c: &str, pl: Payload| chitala_csme::order::ExecOrder {
                id: [n; 16],
                actor: id("person:alice"),
                target: light.clone(),
                capability: cap(c),
                capability_version: 1,
                decided_at_ms: T0,
                expires_at_ms: T0 + 10_000,
                payload: pl,
            };
            vec![
                order(1, "light.turn_on", Payload::new()).sign(&node_key()),
                order(2, "light.set_brightness", payload([("brightness_pct", 30i64)])).sign(&node_key()),
                // signed by a principal, not the node: must never execute
                order(3, "light.turn_on", Payload::new()).sign(&key("person:alice")),
            ]
        }
        "host_line" => {
            let o = chitala_csme::order::ExecOrder {
                id: [9; 16],
                actor: id("person:alice"),
                target: id("device:front-door"),
                capability: cap("lock.unlock"),
                capability_version: 1,
                decided_at_ms: T0,
                expires_at_ms: T0 + 10_000,
                payload: Payload::new(),
            };
            vec![
                format!(
                    r#"{{"op":"execute","device":"device:front-door","order":"{}"}}"#,
                    hex::encode(o.sign(&node_key()))
                )
                .into_bytes(),
                br#"{"op":"observe","device":"device:thermostat"}"#.to_vec(),
                br#"{"op":"simulate","device":"device:front-door","change":{"door_open":true}}"#.to_vec(),
                br#"{"ok":true,"state":{"on":true,"brightness_pct":40,"mode":"cool"}}"#.to_vec(),
                br#"{"ok":false,"code":"X_DEVICE_REFUSED","message":"door open"}"#.to_vec(),
            ]
        }
        other => panic!("unknown fuzz target {other}"),
    }
}

/// Cheap deterministic mutations used by the stable smoke test.
pub fn mutations(seed: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![seed.to_vec(), Vec::new()];
    let step = (seed.len() / 24).max(1);
    for i in (0..seed.len()).step_by(step) {
        out.push(seed[..i].to_vec());
        let mut flipped = seed.to_vec();
        flipped[i] ^= 0x01 << (i % 8);
        out.push(flipped);
        let mut extended = seed.to_vec();
        extended.insert(i, 0xff);
        out.push(extended);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs on stable: every harness over every seed and a set of mutations.
    #[test]
    fn harnesses_hold_on_seeds_and_mutations() {
        for target in TARGETS {
            let seeds = seeds(target);
            assert!(!seeds.is_empty(), "{target} has no seeds");
            for seed in &seeds {
                for input in mutations(seed) {
                    run(target, &input);
                }
            }
        }
    }

    /// The seeds really pass the signature layer (otherwise fuzzing would stall there).
    #[test]
    fn seeds_are_authentic() {
        let mut node = fresh_node();
        let allowed = signed_requests().iter().filter(|r| node.handle(r).is_allow()).count();
        assert!(allowed >= 3, "only {allowed} seed requests were allowed");
        let verifier = authority().verifier();
        assert!(seeds("token").iter().all(|t| verifier.verify(t).is_ok()));
    }
}
