//! End-to-end tests of the node: milestone 0.0.1 and 0.0.2 (Blueprint v17 §4, §18),
//! containment (v8 §9), device-side invariants (C5), persistence and IPC.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_adapters::Simulation;
use chitala_audit::{verify_lines, AuditLog, Signer};
use chitala_boundary::TrustedExecutionBoundary;
use chitala_bus::Filter;
use chitala_identity::{test_seed, Keypair};
use chitala_intent::Intent;
use chitala_model::{
    payload, CapabilityId, DenyCode, EntityId, EventKind, ExecCode, ParamValue, Payload, SecurityState,
};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::hosted::now_ms;
use chitala_node::setup::{sample_devices, sample_resources, CONFIG_FILE};
use chitala_node::{node_from_config, LoadedConfig, Node, NodeParts, Requester, Response, Submit};
use chitala_platform::{Endpoint, IpcTransport};
use chitala_resource::ResourceId;
use chitala_token::bytes_from_base64;

const T0: u64 = 1_790_000_000_000;

fn id(s: &str) -> EntityId {
    EntityId::parse(s).unwrap()
}

struct Home {
    node: Node,
    keys: HashMap<String, Keypair>,
    clock: Arc<AtomicU64>,
    /// The node's adapters, reachable behind its back: the physical world can
    /// change without the node seeing it.
    devices: Arc<dyn chitala_node::executor::Executor>,
}

fn home() -> Home {
    let people = [
        ("person:alice", vec!["owner"]),
        ("person:bob", vec!["adult"]),
        ("person:carol", vec!["guest"]),
        ("person:dan", vec!["child"]),
        ("ai:assistant", vec![]),
        ("ai:helper", vec![]),
    ];
    let mut keys = HashMap::new();
    let mut principals = Vec::new();
    for (who, roles) in people {
        let k = Keypair::from_seed(&test_seed(who));
        principals.push((id(who), k.public_key(), roles.into_iter().map(String::from).collect()));
        keys.insert(who.to_string(), k);
    }
    let mut mock = MockAdapter::new();
    let devices = sample_devices();
    for d in &devices {
        mock.add(d.id.clone(), VirtualKind::from_capabilities(&d.capabilities).unwrap());
    }
    let clock = Arc::new(AtomicU64::new(T0));
    let c = Arc::clone(&clock);
    let node_clock: chitala_node::Clock = Arc::new(move || c.load(Ordering::SeqCst));
    let boundary = TrustedExecutionBoundary::new(test_entropy());
    let executor = chitala_node::executor::in_process(&boundary, vec![Box::new(mock)], node_clock.clone());
    let node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: Keypair::from_seed(&test_seed("service:node")),
        authority_key: Keypair::from_seed(&test_seed("domain:home/authority")),
        principals,
        devices,
        agency: vec![(id("ai:assistant"), vec![id("person:alice")]), (id("ai:helper"), vec![id("person:alice")])],
        resources: sample_resources(),
        safety: Default::default(),
        executor: Arc::clone(&executor),
        policy: chitala_node::PolicySource::Default,
        audit: AuditLog::in_memory(Some(Signer {
            id: id("service:node"),
            key: Keypair::from_seed(&test_seed("service:node")),
        })),
        state: chitala_node::DomainState::default(),
        state_file: None,
        containment: ContainmentConfig::default(),
        monitor: MonitorConfig::default(),
        entropy: std::sync::Arc::new(chitala_platform::memory::test_entropy()),
        clock: node_clock,
        clock_watch: None,
        boundary,
    })
    .unwrap();
    Home { node, keys, clock, devices: executor }
}

impl Home {
    fn tick(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    fn req(&mut self, who: &str, target: &str, cap: &str, pl: Payload, token: Option<&[u8]>) -> Response {
        let r = Requester::new(
            id(who),
            self.keys[who].clone(),
            id("service:test"),
            std::sync::Arc::new(chitala_platform::memory::test_entropy()),
        )
        .with_token(token.map(<[u8]>::to_vec));
        let now = self.node.now();
        let bytes = r.sign(self.node.registry(), &id(target), &CapabilityId::parse(cap).unwrap(), pl, now);
        self.tick(1);
        self.node.handle(&bytes)
    }

    /// An AI (or a person) asks for an outcome on a resource.
    fn intent(&mut self, who: &str, for_: &str, resource: &str, cap: &str, token: Option<&[u8]>) -> Response {
        let now = self.node.now();
        let mut i = Intent::new(
            chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
            id(who),
            id(for_),
            CapabilityId::parse(cap).unwrap(),
            ResourceId::parse(resource).unwrap(),
            now,
            60_000,
        );
        i.authority = token.map(<[u8]>::to_vec);
        let bytes = i.sign(&self.keys[who]);
        self.tick(1);
        self.node.handle(&bytes)
    }

    fn delegate(
        &mut self,
        who: &str,
        holder: &str,
        target: &str,
        cap: &str,
        ttl_s: i64,
        parent: Option<&str>,
    ) -> Response {
        let mut pl = payload([
            ("holder", ParamValue::from(holder)),
            ("target", ParamValue::from(target)),
            ("capability", ParamValue::from(cap)),
            ("ttl_s", ParamValue::Int(ttl_s)),
        ]);
        if let Some(p) = parent {
            pl.insert("parent_token".into(), ParamValue::from(p));
        }
        self.req(who, "domain:home", "domain.delegate", pl, None)
    }

    /// [`Home::delegate`] that lets the holder hand the right on `hops` more times.
    fn delegate_transferable(
        &mut self,
        who: &str,
        holder: &str,
        target: &str,
        cap: &str,
        ttl_s: i64,
        hops: i64,
    ) -> Response {
        let pl = payload([
            ("holder", ParamValue::from(holder)),
            ("target", ParamValue::from(target)),
            ("capability", ParamValue::from(cap)),
            ("ttl_s", ParamValue::Int(ttl_s)),
            ("redelegate", ParamValue::Int(hops)),
        ]);
        self.req(who, "domain:home", "domain.delegate", pl, None)
    }

    fn state_of(&self, who: &str) -> SecurityState {
        self.node.identities().get(&id(who)).unwrap().state
    }

    fn audit_ok(&self) {
        let lines = self.node.audit().lines();
        verify_lines(lines.iter().map(String::as_str), &HashMap::new()).expect("audit chain verifies");
    }
}

fn token_of(r: &Response) -> (String, Vec<u8>, String) {
    assert!(r.is_ok(), "delegation failed: {}", r.summary());
    let res = r.result.as_ref().unwrap();
    let b64 = res["token"].as_str().unwrap().to_string();
    let bytes = bytes_from_base64(&b64).unwrap();
    (b64, bytes, res["revocation_id"].as_str().unwrap().to_string())
}

fn deny_code(r: &Response) -> DenyCode {
    assert!(!r.is_allow(), "expected deny, got {}", r.summary());
    r.code.unwrap()
}

const LIGHT: &str = "device:living-room-light";
const DOOR: &str = "device:front-door";
const LIGHT_R: &str = "resource:living-room-light";
const DOOR_R: &str = "resource:front-door";

// ───────────────────────── milestone 0.0.1 ─────────────────────────

#[test]
fn milestone_0_0_1_authorized_light_on_and_unauthorized_ai_denied() {
    let mut h = home();
    let events = h.node.subscribe(Filter::All);

    // User → Identity → Capability → Authority → Virtual Light → ON → Event → State → Audit
    let r = h.req("person:alice", LIGHT, "light.turn_on", Payload::new(), None);
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(r.result.as_ref().unwrap()["reported"]["on"], true);
    let twin = h.node.twins().get(&id(LIGHT)).unwrap();
    assert_eq!(twin.reported.get("on"), Some(&ParamValue::Bool(true)));
    let ev = events.drain();
    assert!(ev.iter().any(|e| e.kind == EventKind::StateChanged && e.source == id(LIGHT) && e.caused_by == r.mid));

    // Unauthorized AI → intent: turn_off(light) → DENIED → Security Event → Audit Log
    let r = h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_off", None);
    assert_eq!(deny_code(&r), DenyCode::TokenMissing);
    assert_eq!(r.step.as_deref(), Some("delegation"));
    // …and it cannot fall back to sending a command
    let r = h.req("ai:assistant", LIGHT, "light.turn_off", Payload::new(), None);
    assert_eq!(deny_code(&r), DenyCode::IntentRequired);
    let ev = events.drain();
    assert!(ev.iter().any(|e| e.kind == EventKind::SecurityDenied && e.source == id("ai:assistant")));
    assert_eq!(h.node.twins().get(&id(LIGHT)).unwrap().reported.get("on"), Some(&ParamValue::Bool(true)));

    let lines = h.node.audit().lines();
    let last: serde_json::Value = serde_json::from_str(&lines[lines.len() - 2]).unwrap();
    assert_eq!(last["kind"], "decision");
    assert_eq!(last["decision"], "deny");
    assert_eq!(last["path"], "intent");
    assert_eq!(last["code"], "E_TOKEN_MISSING");
    assert_eq!(last["actor"], "ai:assistant");
    assert_eq!(last["on_behalf_of"], "person:alice");
    assert_eq!(last["trace"].as_array().unwrap().last().unwrap()["step"], "delegation");
    h.audit_ok();
}

#[test]
fn queries_and_inventory() {
    let mut h = home();
    let r = h.req("person:bob", LIGHT, "device.read_state", Payload::new(), None);
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(r.result.as_ref().unwrap()["freshness"], "fresh");
    let r = h.req("person:bob", "domain:home", "domain.list_devices", Payload::new(), None);
    assert_eq!(r.result.unwrap()["devices"].as_array().unwrap().len(), 4);
    // a guest may not list the inventory, an AI without a token sees nothing
    assert_eq!(
        deny_code(&h.req("person:carol", "domain:home", "domain.list_devices", Payload::new(), None)),
        DenyCode::PolicyDenied
    );
    assert_eq!(
        deny_code(&h.req("ai:assistant", "domain:home", "domain.list_devices", Payload::new(), None)),
        DenyCode::TokenMissing
    );
}

// ───────────────────────── milestone 0.0.2 ─────────────────────────

#[test]
fn milestone_0_0_2_delegation_and_revocation() {
    let mut h = home();
    let r = h.delegate("person:alice", "ai:assistant", LIGHT_R, "light.turn_on", 600, None);
    let (_, ai_token, rid) = token_of(&r);

    let r = h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(&ai_token));
    assert!(r.is_ok(), "{}", r.summary());
    // scope: other capability, other resource
    assert_eq!(
        deny_code(&h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_off", Some(&ai_token))),
        DenyCode::TokenDenied
    );
    assert_eq!(
        deny_code(&h.intent("ai:assistant", "person:alice", DOOR_R, "lock.unlock", Some(&ai_token))),
        DenyCode::TokenDenied
    );
    // holder-bound: another AI cannot use a stolen token
    assert_eq!(
        deny_code(&h.intent("ai:helper", "person:alice", LIGHT_R, "light.turn_on", Some(&ai_token))),
        DenyCode::TokenDenied
    );

    // revoke → denied immediately
    let r =
        h.req("person:alice", "domain:home", "domain.revoke_token", payload([("revocation_id", rid.as_str())]), None);
    assert!(r.is_ok(), "{}", r.summary());
    assert_eq!(
        deny_code(&h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(&ai_token))),
        DenyCode::TokenRevoked
    );
    assert!(h.node.domain_state().revocations.contains(&rid));

    // expiry
    let r = h.delegate("person:alice", "ai:assistant", LIGHT_R, "light.turn_off", 2, None);
    let (_, short, _) = token_of(&r);
    h.tick(3_000);
    assert_eq!(
        deny_code(&h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_off", Some(&short))),
        DenyCode::TokenDenied
    );

    // a right on a room covers what is in it; a right on a room without the
    // capability is refused at delegation time
    let (_, room, _) =
        token_of(&h.delegate("person:alice", "ai:assistant", "resource:living-room", "light.turn_off", 600, None));
    assert!(h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_off", Some(&room)).is_ok());
    let r = h.delegate("person:alice", "ai:assistant", "resource:bedroom", "lock.unlock", 600, None);
    assert_eq!(r.error.unwrap().code, ExecCode::InvalidArgument);
    h.audit_ok();
}

#[test]
fn delegation_cannot_amplify() {
    let mut h = home();
    // bob (adult) does not hold lock.unlock and cannot invent it
    let r = h.delegate("person:bob", "person:carol", DOOR, "lock.unlock", 600, None);
    assert_eq!(r.error.as_ref().unwrap().code, ExecCode::DelegationDenied);

    // a right is non-transferable unless the grantor says otherwise
    let (plain_b64, _, _) = token_of(&h.delegate("person:alice", "person:bob", DOOR, "lock.unlock", 1800, None));
    let r = h.delegate("person:bob", "person:carol", DOOR, "lock.unlock", 600, Some(&plain_b64));
    assert_eq!(r.error.as_ref().unwrap().code, ExecCode::DelegationDenied);
    assert!(r.error.unwrap().message.contains("non-transferable"));

    // alice gives bob unlock for 30 minutes (v12 §18), and lets him pass it on once
    let (bob_b64, bob_token, bob_rid) =
        token_of(&h.delegate_transferable("person:alice", "person:bob", DOOR, "lock.unlock", 1800, 1));
    assert!(h.req("person:bob", DOOR, "lock.unlock", Payload::new(), Some(&bob_token)).is_ok());

    // bob re-delegates to carol (guest): depth 2, expiry ≤ parent
    let r = h.delegate("person:bob", "person:carol", DOOR, "lock.unlock", 86_400, Some(&bob_b64));
    let (_, carol_token, _) = token_of(&r);
    let res = r.result.unwrap();
    assert_eq!(res["depth"], 2);
    let v = h.node.verifier().verify(&bob_token).unwrap();
    assert!(res["expires_at_ms"].as_u64().unwrap() <= v.expires_at_ms);
    assert!(h.req("person:carol", DOOR, "lock.unlock", Payload::new(), Some(&carol_token)).is_ok());

    // bob cannot widen the right while re-delegating
    let r = h.delegate("person:bob", "person:carol", LIGHT, "light.turn_on", 60, Some(&bob_b64));
    assert_eq!(r.error.as_ref().unwrap().code, ExecCode::DelegationDenied);
    // nobody can hand an AI or a child a right the constitution forbids them to use
    let r = h.delegate("person:alice", "ai:assistant", DOOR, "lock.unlock", 60, None);
    assert_eq!(r.error.as_ref().unwrap().code, ExecCode::DelegationDenied);
    assert!(r.error.unwrap().message.contains("C11-ai-no-high-risk"));
    let r = h.delegate("person:alice", "person:dan", DOOR, "lock.unlock", 60, None);
    assert_eq!(r.error.as_ref().unwrap().code, ExecCode::DelegationDenied);
    // …but on the door *resource* the AI may hold it: every use is escalated to a human
    assert!(h.delegate("person:alice", "ai:assistant", DOOR_R, "lock.unlock", 60, None).is_ok());
    let r = h.delegate("person:alice", "person:dan", DOOR_R, "lock.unlock", 60, None);
    assert_eq!(r.error.as_ref().unwrap().code, ExecCode::DelegationDenied);
    // AI may never delegate: it sends no commands at all
    let r = h.delegate("ai:assistant", "ai:helper", LIGHT, "light.turn_on", 60, None);
    assert_eq!(deny_code(&r), DenyCode::IntentRequired);

    // carol may not revoke bob's token; alice revokes it and carol's child dies with it
    let r = h.req(
        "person:carol",
        "domain:home",
        "domain.revoke_token",
        payload([("revocation_id", bob_rid.as_str())]),
        None,
    );
    assert_eq!(deny_code(&r), DenyCode::PolicyDenied);
    let r = h.req(
        "person:alice",
        "domain:home",
        "domain.revoke_token",
        payload([("revocation_id", bob_rid.as_str())]),
        None,
    );
    assert!(r.is_ok());
    assert_eq!(
        deny_code(&h.req("person:carol", DOOR, "lock.unlock", Payload::new(), Some(&carol_token))),
        DenyCode::TokenRevoked
    );
    h.audit_ok();

    // the parent token never appears in the audit log
    let all = h.node.audit().lines().join("\n");
    assert!(!all.contains(&bob_b64));
    assert!(all.contains("[REDACTED]"));
}

// ───────────────────────── containment ─────────────────────────

#[test]
fn probing_ai_is_contained_and_only_a_human_restores_it() {
    let mut h = home();
    let (_, token, _) = token_of(&h.delegate("person:alice", "ai:assistant", LIGHT_R, "light.turn_on", 3600, None));
    let cfg = ContainmentConfig::default();

    for i in 1..=cfg.quarantine_after {
        let r = h.intent("ai:assistant", "person:alice", DOOR_R, "lock.unlock", Some(&token));
        assert!(!r.is_allow());
        let expected = if i >= cfg.quarantine_after {
            SecurityState::Quarantined
        } else if i >= cfg.restricted_after {
            SecurityState::Restricted
        } else if i >= cfg.suspicious_after {
            SecurityState::Suspicious
        } else {
            SecurityState::Trusted
        };
        assert_eq!(h.state_of("ai:assistant"), expected, "after {i} denials");
    }
    // quarantined: even its legitimate right is gone
    assert_eq!(
        deny_code(&h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(&token))),
        DenyCode::PrincipalState
    );
    // forged traffic in someone's name never counts against them
    assert_eq!(h.state_of("ai:helper"), SecurityState::Trusted);

    // no shortcut back to TRUSTED; the recovery path is RECOVERY → RE_ATTEST → TRUSTED
    let set = |h: &mut Home, who: &str, state: &str| {
        h.req(
            who,
            "domain:home",
            "domain.set_principal_state",
            payload([("principal", "ai:assistant"), ("state", state)]),
            None,
        )
    };
    let r = set(&mut h, "person:alice", "TRUSTED");
    assert_eq!(r.error.unwrap().code, ExecCode::InvalidArgument);
    // an adult may not change security states
    assert_eq!(deny_code(&set(&mut h, "person:bob", "RECOVERY")), DenyCode::PolicyDenied);
    for s in ["RECOVERY", "RE_ATTEST", "TRUSTED"] {
        assert!(set(&mut h, "person:alice", s).is_ok());
    }
    assert!(h.intent("ai:assistant", "person:alice", LIGHT_R, "light.turn_on", Some(&token)).is_ok());
    // nobody changes their own state
    let r = h.req(
        "person:alice",
        "domain:home",
        "domain.set_principal_state",
        payload([("principal", "person:alice"), ("state", "SUSPICIOUS")]),
        None,
    );
    assert_eq!(r.error.unwrap().code, ExecCode::NotPermitted);
    h.audit_ok();
}

#[test]
fn humans_are_rate_limited_not_quarantined() {
    let mut h = home();
    for _ in 0..25 {
        let _ = h.req("person:bob", DOOR, "lock.unlock", Payload::new(), None);
    }
    assert_eq!(h.state_of("person:bob"), SecurityState::Trusted);
    for _ in 0..10 {
        let _ = h.req("person:bob", LIGHT, "light.turn_on", Payload::new(), None);
    }
    assert_eq!(deny_code(&h.req("person:bob", LIGHT, "light.turn_on", Payload::new(), None)), DenyCode::RateLimited);
}

// ───────────────────────── device-side invariant ─────────────────────────

#[test]
fn safety_and_the_device_both_refuse_unsafe_commands() {
    let mut h = home();
    assert!(h.req("person:alice", DOOR, "lock.unlock", Payload::new(), None).is_ok());
    // the node sees the door open: Safety refuses bolting it, even for the owner
    h.node.simulate(&id(DOOR), Simulation::DoorOpen(true)).unwrap();
    let r = h.req("person:alice", DOOR, "lock.lock", Payload::new(), None);
    assert_eq!(deny_code(&r), DenyCode::Safety);
    assert!(r.reason.as_deref().unwrap_or_default().contains("SAFE-4-PHYSICAL"), "{:?}", r.reason);
    // the door closes, then opens again without the node seeing it: Safety
    // clears on stale knowledge, and the device's own invariant (C5) refuses
    h.node.simulate(&id(DOOR), Simulation::DoorOpen(false)).unwrap();
    h.devices.simulate(&id(DOOR), &Simulation::DoorOpen(true)).unwrap();
    let r = h.req("person:alice", DOOR, "lock.lock", Payload::new(), None);
    assert!(r.is_allow());
    assert_eq!(r.error.as_ref().unwrap().code, ExecCode::DeviceRefused);
    // desired says locked, the device says unlocked: visible drift, no lie in the twin
    let r = h.req("person:alice", DOOR, "device.read_state", Payload::new(), None);
    let view = r.result.unwrap();
    assert_eq!(view["reported"]["locked"], false);
    assert_eq!(view["drift"]["locked"], true);

    h.node.simulate(&id(LIGHT), Simulation::Offline(true)).unwrap();
    let r = h.req("person:alice", LIGHT, "light.turn_on", Payload::new(), None);
    assert_eq!(r.error.unwrap().code, ExecCode::DeviceUnavailable);
    h.audit_ok();
}

// ───────────────────────── persistence + IPC (hosted platform) ─────────────────────────

/// Load a domain config; adapters run in the real `chitala-adapter-host` process.
fn load_config(dir: &std::path::Path) -> LoadedConfig {
    let mut loaded = LoadedConfig::load(dir.join(CONFIG_FILE)).unwrap();
    loaded.config.adapter_host = Some(env!("CARGO_BIN_EXE_chitala-adapter-host").into());
    loaded
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("chitala-{tag}-{}-{}", std::process::id(), now_ms()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn test_entropy() -> Arc<dyn chitala_platform::Entropy> {
    Arc::new(chitala_platform::memory::test_entropy())
}

#[test]
fn config_node_persists_revocations_and_audit() {
    let dir = temp_dir("persist");
    chitala_node::hosted::init_domain(&dir).unwrap();
    assert!(chitala_node::hosted::init_domain(&dir).is_err(), "init must not overwrite a domain");
    let loaded = load_config(&dir);
    let alice = loaded.keypair(&id("person:alice")).unwrap();
    let ai = loaded.keypair(&id("ai:assistant")).unwrap();

    let (token, rid) = {
        let mut node = node_from_config(&loaded).unwrap();
        let req = Requester::new(id("person:alice"), alice.clone(), id("service:test"), test_entropy());
        let pl = payload([
            ("holder", ParamValue::from("ai:assistant")),
            ("target", ParamValue::from(LIGHT_R)),
            ("capability", ParamValue::from("light.turn_on")),
            ("ttl_s", ParamValue::Int(600)),
        ]);
        let r = node.handle(&req.sign(
            node.registry(),
            &id("domain:home"),
            &CapabilityId::parse("domain.delegate").unwrap(),
            pl,
            now_ms(),
        ));
        let (_, token, rid) = token_of(&r);
        let r = node.handle(&req.sign(
            node.registry(),
            &id("domain:home"),
            &CapabilityId::parse("domain.revoke_token").unwrap(),
            payload([("revocation_id", rid.as_str())]),
            now_ms(),
        ));
        assert!(r.is_ok());
        node.checkpoint().unwrap();
        (token, rid)
    };

    // restart: revocation and audit chain survive
    let mut node = node_from_config(&loaded).unwrap();
    assert!(node.domain_state().revocations.contains(&rid));
    let mut i = Intent::new(
        chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
        id("ai:assistant"),
        id("person:alice"),
        CapabilityId::parse("light.turn_on").unwrap(),
        ResourceId::parse(LIGHT_R).unwrap(),
        node.now(),
        60_000,
    );
    i.authority = Some(token);
    let r = node.handle(&i.sign(&ai));
    assert_eq!(deny_code(&r), DenyCode::TokenRevoked);
    drop(node);
    let node_key = loaded.keypair(&id("service:node")).unwrap();
    let trusted = HashMap::from([(node_key.key_id(), node_key.public_key())]);
    let report = chitala_node::hosted::verify_audit_file(&dir.join("audit.audit.jsonl"), &trusted).unwrap();
    assert!(report.last_signed_seq.is_some());
    assert!(report.records >= 6);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The node serves any IPC transport of the PAL, and the client is the same code.
fn round_trip_over(ipc: Arc<dyn IpcTransport>, endpoint: &str) {
    let h = home();
    let alice = h.keys["person:alice"].clone();
    let registry = h.node.registry().clone();
    let node_pk = h.node.node_public_key();
    let node = Arc::new(Mutex::new(h.node));
    let endpoint = Endpoint::new(endpoint).unwrap();
    let (ipc2, ep2, n2) = (Arc::clone(&ipc), endpoint.clone(), Arc::clone(&node));
    std::thread::spawn(move || chitala_node::ipc::serve(n2, ipc2.as_ref(), &ep2).unwrap());
    let mut client = chitala_node::NodeClient::new(ipc, endpoint, node_pk);
    let mut hello = None;
    for _ in 0..100 {
        if let Ok(v) = client.hello() {
            hello = Some(v);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(hello.unwrap()["domain"], "domain:home");
    let req = Requester::new(id("person:alice"), alice, id("service:cli"), test_entropy());
    let now = T0;
    let r = client
        .submit(&req.sign(&registry, &id(LIGHT), &CapabilityId::parse("light.turn_on").unwrap(), Payload::new(), now))
        .unwrap();
    assert!(r.is_ok(), "{}", r.summary());
    let r = client.submit(b"garbage").unwrap();
    assert_eq!(r.code, Some(DenyCode::Decode));
    assert!(r.reason.is_none(), "unauthenticated callers get no details");
}

#[test]
fn ipc_round_trip_over_a_unix_socket() {
    let dir = temp_dir("ipc");
    round_trip_over(Arc::new(chitala_platform_host::UnixIpc::new(&dir).unwrap()), "n.sock");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn ipc_round_trip_over_the_memory_transport() {
    round_trip_over(Arc::new(chitala_platform::memory::MemoryIpc::new()), "node");
}

// ───────────────────────── attacks on the node itself ─────────────────────────

fn sign_as(loaded: &LoadedConfig, who: &str, target: &str, cap: &str, pl: Payload) -> Vec<u8> {
    let key = loaded.keypair(&id(who)).unwrap();
    Requester::new(id(who), key, id("service:test"), test_entropy()).sign(
        &chitala_model::CapabilityRegistry::core_v0_1(),
        &id(target),
        &CapabilityId::parse(cap).unwrap(),
        pl,
        now_ms(),
    )
}

fn delegate_pl(holder: &str, target: &str, cap: &str) -> Payload {
    payload([
        ("holder", ParamValue::from(holder)),
        ("target", ParamValue::from(target)),
        ("capability", ParamValue::from(cap)),
        ("ttl_s", ParamValue::Int(600)),
    ])
}

/// v10 §2: a client never trusts a reply that the pinned node key did not sign
/// for exactly its request.
#[test]
fn forged_or_misbound_replies_are_rejected() {
    use chitala_node::ipc::{request_digest, sign_reply, verify_reply};
    let node_key = Keypair::from_seed(&test_seed("service:node"));
    let evil = Keypair::from_seed(&test_seed("service:evil"));
    let req = b"some request";
    let mut v = serde_json::json!({"decision": "allow", "request": request_digest(req), "result": {"token": "x"}});
    let mut forged = v.clone();
    sign_reply(&mut forged, &id("service:node"), &evil);
    assert!(verify_reply(&forged, &node_key.public_key(), Some(&request_digest(req))).is_err());

    sign_reply(&mut v, &id("service:node"), &node_key);
    assert!(verify_reply(&v, &node_key.public_key(), Some(&request_digest(req))).is_ok());
    // a genuine reply to *another* request cannot be passed off for this one
    assert!(verify_reply(&v, &node_key.public_key(), Some(&request_digest(b"other"))).is_err());
    // any edit breaks the signature
    let mut edited = v.clone();
    edited["decision"] = "deny".into();
    assert!(verify_reply(&edited, &node_key.public_key(), Some(&request_digest(req))).is_err());
    let mut stripped = v.clone();
    stripped.as_object_mut().unwrap().remove("sig");
    assert!(verify_reply(&stripped, &node_key.public_key(), None).is_err());
}

#[test]
fn client_refuses_an_impostor_node() {
    use std::io::{BufRead, BufReader, Write};
    let dir = temp_dir("impostor");
    let ipc: Arc<dyn IpcTransport> = Arc::new(chitala_platform_host::UnixIpc::new(&dir).unwrap());
    let endpoint = Endpoint::new("fake.sock").unwrap();
    let listener = ipc.listen(&endpoint).unwrap();
    // the impostor answers "allow" to everything, signed with its own key
    std::thread::spawn(move || {
        while let Ok(stream) = listener.accept() {
            let mut w = stream.try_clone().unwrap();
            let mut line = String::new();
            BufReader::new(stream).read_line(&mut line).unwrap();
            let csme =
                serde_json::from_str::<serde_json::Value>(&line).unwrap()["csme"].as_str().unwrap_or("").to_string();
            let digest = chitala_node::ipc::request_digest(&hex::decode(csme).unwrap_or_default());
            let mut v = serde_json::json!({"decision": "allow", "request": digest});
            chitala_node::ipc::sign_reply(&mut v, &id("service:node"), &Keypair::from_seed(&test_seed("impostor")));
            writeln!(w, "{v}").unwrap();
        }
    });
    let real_node = Keypair::from_seed(&test_seed("service:node")).public_key();
    let mut client = chitala_node::NodeClient::new(ipc, endpoint, real_node);
    let alice = Keypair::from_seed(&test_seed("person:alice"));
    let bytes = Requester::new(id("person:alice"), alice, id("service:cli"), test_entropy()).sign(
        &chitala_model::CapabilityRegistry::core_v0_1(),
        &id(DOOR),
        &CapabilityId::parse("lock.unlock").unwrap(),
        Payload::new(),
        T0,
    );
    let err = client.submit(&bytes).unwrap_err();
    assert!(err.contains("not authenticated"), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// v13 §7: rolling back the state file must not un-revoke a token, and deleting
/// or truncating the audit log must not give the node a clean slate.
#[test]
fn rollback_truncation_and_deletion_refuse_to_start() {
    let dir = temp_dir("rollback");
    chitala_node::hosted::init_domain(&dir).unwrap();
    let loaded = load_config(&dir);
    let state = dir.join("domain-state.json");
    let audit = dir.join("audit.audit.jsonl");
    let old_state = dir.join("old-state.json");
    {
        let mut node = node_from_config(&loaded).unwrap();
        let r = node.handle(&sign_as(
            &loaded,
            "person:alice",
            "domain:home",
            "domain.delegate",
            delegate_pl("ai:assistant", LIGHT, "light.turn_on"),
        ));
        let (_, _, rid) = token_of(&r);
        std::fs::copy(&state, &old_state).unwrap();
        let r = node.handle(&sign_as(
            &loaded,
            "person:alice",
            "domain:home",
            "domain.revoke_token",
            payload([("revocation_id", rid.as_str())]),
        ));
        assert!(r.is_ok());
    }
    assert!(node_from_config(&loaded).is_ok(), "an intact domain starts");

    // 1. state rolled back to before the revocation
    let good_state = std::fs::read(&state).unwrap();
    std::fs::copy(&old_state, &state).unwrap();
    let err = node_from_config(&loaded).err().expect("rolled-back state must be refused").to_string();
    assert!(err.contains("rolled back"), "{err}");
    // 2. state deleted
    std::fs::remove_file(&state).unwrap();
    assert!(node_from_config(&loaded).is_err());
    std::fs::write(&state, &good_state).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // 3. audit truncated before the anchored head
    let good_audit = std::fs::read_to_string(&audit).unwrap();
    let lines: Vec<&str> = good_audit.lines().collect();
    std::fs::write(&audit, format!("{}\n", lines[..2].join("\n"))).unwrap();
    let err = node_from_config(&loaded).err().expect("truncated audit must be refused").to_string();
    assert!(err.contains("integrity"), "{err}");
    // 4. audit deleted
    std::fs::remove_file(&audit).unwrap();
    assert!(node_from_config(&loaded).is_err());
    std::fs::write(&audit, &good_audit).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(node_from_config(&loaded).is_ok());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The replay cache lives in memory; a request signed before a restart is refused.
#[test]
fn replay_after_restart_is_refused() {
    let dir = temp_dir("restart");
    chitala_node::hosted::init_domain(&dir).unwrap();
    let loaded = load_config(&dir);
    let bytes = {
        let mut node = node_from_config(&loaded).unwrap();
        let bytes = sign_as(&loaded, "person:alice", DOOR, "lock.unlock", Payload::new());
        assert!(node.handle(&bytes).is_ok());
        bytes
    };
    std::thread::sleep(std::time::Duration::from_millis(5));
    let mut node = node_from_config(&loaded).unwrap();
    assert_eq!(deny_code(&node.handle(&bytes)), DenyCode::Replay);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn private_files_and_sockets() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("perms");
    chitala_node::hosted::init_domain(&dir).unwrap();
    let loaded = load_config(&dir);
    let key = dir.join("keys").join("person-alice.key");
    assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    for d in ["keys", "tokens"] {
        assert_eq!(std::fs::metadata(dir.join(d)).unwrap().permissions().mode() & 0o777, 0o700, "{d}");
    }
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = loaded.keypair(&id("person:alice")).unwrap_err().to_string();
    assert!(err.contains("chmod 600"), "{err}");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();

    {
        let mut node = node_from_config(&loaded).unwrap();
        let r = node.handle(&sign_as(
            &loaded,
            "person:alice",
            "domain:home",
            "domain.delegate",
            delegate_pl("ai:assistant", LIGHT, "light.turn_on"),
        ));
        assert!(r.is_ok());
    }
    for f in ["audit.audit.jsonl", "domain-state.json"] {
        let mode = std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{f}");
    }
    // state that others can read is refused, not used
    let state = dir.join("domain-state.json");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = node_from_config(&loaded).err().expect("weak state must be refused").to_string();
    assert!(err.contains("domain-state.json"), "{err}");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();

    // a socket path too long for SUN_LEN moves into a private 0700 directory
    let deep = dir.join("a".repeat(60)).join("b".repeat(60));
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::copy(dir.join(CONFIG_FILE), deep.join(CONFIG_FILE)).unwrap();
    let deep_domain = load_config(&deep).domain().unwrap();
    let sock = deep_domain.platform.ipc.describe(&deep_domain.endpoint);
    assert!(sock.len() < 100, "{sock}");
    let parent = std::path::Path::new(&sock).parent().unwrap();
    assert_eq!(std::fs::metadata(parent).unwrap().permissions().mode() & 0o777, 0o700);
    std::fs::remove_dir_all(&dir).unwrap();
}

// ───────────────────────── adapter isolation (threat model R4) ─────────────────────────

#[cfg(unix)]
mod isolation {
    use super::*;
    use chitala_adapters::AdapterError;
    use chitala_node::executor::{ComponentHost, Executor, HostSpec, MIN_RESPAWN_INTERVAL};
    use chitala_platform::ComponentSpec;
    use chitala_platform_host::{ProcessHost, SystemTimeSource};
    use std::time::{Duration, Instant};

    /// An adapter host process on the hosted platform, accepting `boundary`'s orders.
    fn process_host(
        program: &std::path::Path,
        env: Vec<(String, String)>,
        boundary: &TrustedExecutionBoundary,
        timeout: Duration,
    ) -> Result<ComponentHost, AdapterError> {
        ComponentHost::start(
            Arc::new(ProcessHost),
            Arc::new(SystemTimeSource::new()),
            test_entropy(),
            HostSpec {
                component: ComponentSpec { program: program.display().to_string(), env },
                devices: sample_devices(),
                home_assistant: None,
                order_key: boundary.order_key(),
                timeout,
            },
        )
    }

    /// A node on the real clock whose adapters run in `executor`.
    fn node_with(boundary: TrustedExecutionBoundary, executor: Arc<dyn Executor>, node_key: &Keypair) -> Node {
        let mut keys = Vec::new();
        for (who, roles) in [("person:alice", vec!["owner".to_string()]), ("ai:assistant", vec![])] {
            keys.push((id(who), Keypair::from_seed(&test_seed(who)).public_key(), roles));
        }
        Node::new(NodeParts {
            domain: id("domain:home"),
            node_id: id("service:node"),
            node_key: node_key.clone(),
            authority_key: Keypair::from_seed(&test_seed("domain:home/authority")),
            principals: keys,
            devices: sample_devices(),
            agency: vec![],
            resources: sample_resources(),
            safety: Default::default(),
            executor,
            policy: chitala_node::PolicySource::Default,
            audit: AuditLog::in_memory(None),
            state: chitala_node::DomainState::default(),
            state_file: None,
            containment: ContainmentConfig::default(),
            monitor: MonitorConfig::default(),
            entropy: std::sync::Arc::new(chitala_platform::memory::test_entropy()),
            clock: Arc::new(now_ms),
            clock_watch: None,
            boundary,
        })
        .unwrap()
    }

    fn sign(node: &Node, who: &str, target: &str, cap: &str) -> Vec<u8> {
        Requester::new(id(who), Keypair::from_seed(&test_seed(who)), id("service:test"), test_entropy()).sign(
            node.registry(),
            &id(target),
            &CapabilityId::parse(cap).unwrap(),
            Payload::new(),
            node.now(),
        )
    }

    /// A fake adapter host (shell script) for failure injection.
    fn script(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        p
    }

    #[test]
    fn crashed_adapter_host_never_reaches_the_monitor() {
        let node_key = Keypair::from_seed(&test_seed("service:node"));
        let program = std::path::Path::new(env!("CARGO_BIN_EXE_chitala-adapter-host"));
        let boundary = TrustedExecutionBoundary::new(test_entropy());
        let host = Arc::new(process_host(program, Vec::new(), &boundary, Duration::from_secs(5)).unwrap());
        assert!(host.isolated());
        let mut node = node_with(boundary, host.clone(), &node_key);
        assert!(node.handle(&sign(&node, "person:alice", LIGHT, "light.turn_on")).is_ok());

        // the adapter host dies (crash, OOM kill, exploit …)
        let pid = host.component_id().unwrap();
        assert!(std::process::Command::new("kill").args(["-9", &pid.to_string()]).status().unwrap().success());
        std::thread::sleep(Duration::from_millis(100));

        let r = node.handle(&sign(&node, "person:alice", LIGHT, "light.turn_off"));
        assert!(r.is_allow());
        assert_eq!(r.error.unwrap().code, ExecCode::DeviceUnavailable);
        // the Reference Monitor is untouched
        assert_eq!(
            deny_code(&node.handle(&sign(&node, "ai:assistant", LIGHT, "light.turn_off"))),
            DenyCode::IntentRequired
        );
        verify_lines(node.audit().lines().iter().map(String::as_str), &HashMap::new()).unwrap();

        // and the host comes back, rate-limited
        std::thread::sleep(MIN_RESPAWN_INTERVAL + Duration::from_millis(100));
        assert!(node.handle(&sign(&node, "person:alice", LIGHT, "light.turn_on")).is_ok());
        assert_eq!(host.restarts(), 1);
        assert_ne!(host.component_id(), Some(pid));
    }

    #[test]
    fn hung_adapter_host_does_not_stall_the_node() {
        let dir = temp_dir("hung-host");
        let program = script(
            &dir,
            "hang.sh",
            r#"read init
echo '{"ok":true}'
while read line; do
  case "$line" in
    *'"op":"observe"'*) echo '{"ok":true,"state":{"on":false}}' ;;
    *) exec /bin/sleep 30 ;;
  esac
done"#,
        );
        let node_key = Keypair::from_seed(&test_seed("service:node"));
        let boundary = TrustedExecutionBoundary::new(test_entropy());
        let host = process_host(&program, Vec::new(), &boundary, Duration::from_millis(800)).unwrap();
        let node = Arc::new(Mutex::new(node_with(boundary, Arc::new(host), &node_key)));

        let slow = sign(&node.lock().unwrap(), "person:alice", LIGHT, "light.turn_on");
        let n2 = Arc::clone(&node);
        let started = Instant::now();
        let waiting = std::thread::spawn(move || {
            let v = chitala_node::ipc::submit_shared(&n2, &slow).unwrap();
            (serde_json::from_value::<Response>(v).unwrap(), started.elapsed(), Instant::now())
        });
        std::thread::sleep(Duration::from_millis(300));
        // while the device call hangs, the node keeps judging other requests
        let quick = sign(&node.lock().unwrap(), "ai:assistant", LIGHT, "light.turn_off");
        let v = chitala_node::ipc::submit_shared(&node, &quick).unwrap();
        let quick_done = Instant::now();
        assert_eq!(v["code"], "E_INTENT_REQUIRED");

        let (r, took, slow_done) = waiting.join().unwrap();
        assert_eq!(r.error.unwrap().code, ExecCode::DeviceUnavailable);
        assert!(took >= Duration::from_millis(800));
        // had the node lock been held during the device call, the quick request
        // could only have finished after the hung one
        assert!(quick_done < slow_done, "node lock held during the device call");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn garbage_from_an_adapter_host_is_contained() {
        let dir = temp_dir("garbage-host");
        let program = script(
            &dir,
            "garbage.sh",
            r#"read init
echo '{"ok":true}'
while read line; do echo '{"ok":true,"state":{"on":1.5,"admin":{"root":true}}}'; done"#,
        );
        let node_key = Keypair::from_seed(&test_seed("service:node"));
        let boundary = TrustedExecutionBoundary::new(test_entropy());
        let host = process_host(&program, Vec::new(), &boundary, Duration::from_secs(2)).unwrap();
        let mut node = node_with(boundary, Arc::new(host), &node_key);
        let r = node.handle(&sign(&node, "person:alice", LIGHT, "light.turn_on"));
        assert_eq!(r.error.unwrap().code, ExecCode::DeviceUnavailable);
        // nothing the broken host said reached the twin
        assert!(node.twins().get(&id(LIGHT)).map(|t| t.reported.is_empty()).unwrap_or(true));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn adapter_host_gets_an_empty_environment() {
        let dir = temp_dir("env-host");
        let program = script(
            &dir,
            "env.sh",
            r#"read init
echo '{"ok":true}'
while read line; do echo "{\"ok\":true,\"state\":{\"leak\":\"${HOME}${USER}${CHITALA_LEAK_TEST}\"}}"; done"#,
        );
        std::env::set_var("CHITALA_LEAK_TEST", "secret-from-the-node");
        let boundary = TrustedExecutionBoundary::new(test_entropy());
        let host = process_host(&program, Vec::new(), &boundary, Duration::from_secs(2)).unwrap();
        let state = host.observe(&id(LIGHT)).unwrap();
        assert_eq!(state.get("leak"), Some(&ParamValue::Text(String::new())));
        // only explicitly granted variables reach the host (e.g. the HA token)
        let granted = vec![("CHITALA_LEAK_TEST".into(), "granted".into())];
        let host = process_host(&program, granted, &boundary, Duration::from_secs(2)).unwrap();
        assert_eq!(host.observe(&id(LIGHT)).unwrap().get("leak"), Some(&ParamValue::Text("granted".into())));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

// ───────────────────────── the node on a platform without an OS (spec 18) ─────────────────────────

mod memory_platform {
    use super::*;
    use chitala_node::executor::{ComponentHost, Executor, MIN_RESPAWN_INTERVAL};
    use chitala_node::{Domain, NodeConfig, NodeEnv, StoredObject};
    use chitala_platform::memory::{self, MemoryControls, Program};
    use chitala_platform::{ComponentSpec, Platform, StoragePath, TimeSource, TrustedClock, Visibility};
    use std::io::{BufRead, BufReader, Write};
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    /// The real adapter host protocol loop as an in-memory component.
    fn adapter_host_program(time: Arc<dyn TimeSource>) -> Program {
        Arc::new(move |input, mut output, _env| {
            let clock = Arc::new(TrustedClock::new(Arc::clone(&time), 0)).as_clock();
            chitala_adapters::host::run(&mut BufReader::new(input), &mut output, clock);
        })
    }

    fn stored(p: &Platform, path: &str) -> StoredObject {
        StoredObject::new(Arc::clone(&p.storage), StoragePath::new(path).unwrap())
    }

    /// `chitala init` + the node's environment, all inside the memory platform.
    fn memory_domain(seed: &str) -> (Domain, NodeEnv, MemoryControls) {
        let (platform, ctl) = memory::platform(seed, T0);
        ctl.exec.register("adapter-host", adapter_host_program(Arc::clone(&platform.time)));
        let summary = chitala_node::setup::init_domain(platform.storage.as_ref(), platform.keys.as_ref()).unwrap();
        let text = platform.storage.read(&summary.config, Visibility::Shared).unwrap().unwrap();
        let config: NodeConfig = serde_json::from_slice(&text).unwrap();
        let env = NodeEnv {
            audit_log: stored(&platform, &config.audit_log),
            state_file: stored(&platform, &config.state_file),
            policy_file: None,
            adapter_host: "adapter-host".into(),
            home_assistant_env: Vec::new(),
        };
        let domain = Domain { config, platform, endpoint: Endpoint::new("node").unwrap() };
        (domain, env, ctl)
    }

    /// v0.2 Step 2 pass criterion: the whole node — keys, state, audit, IPC,
    /// adapter hosts, time — runs on a platform that has no files, sockets,
    /// processes or pipes at all.
    #[test]
    fn node_runs_end_to_end_on_the_memory_platform() {
        let (domain, env, ctl) = memory_domain("node-e2e");
        let node = chitala_node::start_node(&domain, &env).unwrap();
        let node = Arc::new(Mutex::new(node));
        let (n2, d2) = (Arc::clone(&node), domain.clone());
        std::thread::spawn(move || chitala_node::ipc::serve(n2, d2.platform.ipc.as_ref(), &d2.endpoint).unwrap());

        let mut client = domain.client().unwrap();
        let mut hello = None;
        for _ in 0..100 {
            if let Ok(v) = client.hello() {
                hello = Some(v);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(hello.unwrap()["domain"], "domain:home");

        let registry = chitala_model::CapabilityRegistry::core_v0_1();
        let alice = Requester::new(
            id("person:alice"),
            domain.keypair(&id("person:alice")).unwrap(),
            id("service:cli"),
            Arc::clone(&domain.platform.entropy),
        );
        let now = |d: &Domain| {
            ctl.time.advance(10);
            d.platform.time.wall_ms()
        };
        // the owner opens the door: the order reaches the adapter host component
        let r = client
            .submit(&alice.sign(
                &registry,
                &id(DOOR),
                &CapabilityId::parse("lock.unlock").unwrap(),
                Payload::new(),
                now(&domain),
            ))
            .unwrap();
        assert!(r.is_ok(), "{}", r.summary());
        assert_eq!(r.result.as_ref().unwrap()["reported"]["locked"], false);

        // the owner delegates the light to her AI; the AI's intent is allowed
        let r = client
            .submit(&alice.sign(
                &registry,
                &id("domain:home"),
                &CapabilityId::parse("domain.delegate").unwrap(),
                delegate_pl("ai:assistant", LIGHT_R, "light.turn_on"),
                now(&domain),
            ))
            .unwrap();
        let (_, token, _) = token_of(&r);
        let mut i = Intent::new(
            chitala_intent::new_intent_id(domain.platform.entropy.as_ref()),
            id("ai:assistant"),
            id("person:alice"),
            CapabilityId::parse("light.turn_on").unwrap(),
            ResourceId::parse(LIGHT_R).unwrap(),
            now(&domain),
            60_000,
        );
        i.authority = Some(token);
        let r = client.submit(&i.sign(&domain.keypair(&id("ai:assistant")).unwrap())).unwrap();
        assert!(r.is_ok(), "{}", r.summary());

        // state and a verifiable audit log are in the platform's storage
        node.lock().unwrap().checkpoint().unwrap();
        assert!(domain.platform.storage.exists(&env.state_file.path).unwrap());
        let node_pk = domain.node_public_key().unwrap();
        let trusted = HashMap::from([(chitala_identity::key_id_of(&node_pk), node_pk)]);
        let report = chitala_node::verify_audit(&env.audit_log, &trusted).unwrap();
        assert!(report.records >= 5 && report.last_signed_seq.is_some());
    }

    /// Threat model N8: a safety hold survives a restart (a crash or a power cut
    /// must not lift a protection nobody decided to lift), and a state file
    /// rolled back to before the hold is refused rather than obeyed.
    #[test]
    fn safety_holds_survive_a_restart_and_a_rollback_is_refused() {
        let (domain, env, ctl) = memory_domain("holds");
        let registry = chitala_model::CapabilityRegistry::core_v0_1();
        let person = |who: &str| {
            Requester::new(
                id(who),
                domain.keypair(&id(who)).unwrap(),
                id("service:cli"),
                Arc::clone(&domain.platform.entropy),
            )
        };
        let (alice, bob) = (person("person:alice"), person("person:bob"));
        let send = |node: &mut chitala_node::Node, who: &Requester, target: &str, c: &str, pl: Payload| {
            let bytes = who.sign(&registry, &id(target), &CapabilityId::parse(c).unwrap(), pl, node.now());
            node.handle(&bytes)
        };
        let hold =
            payload([("resource", ParamValue::from(DOOR_R)), ("reason", ParamValue::from("electrician at work"))]);

        let before_hold = {
            let mut node = chitala_node::start_node(&domain, &env).unwrap();
            let r = send(
                &mut node,
                &alice,
                "domain:home",
                "domain.delegate",
                delegate_pl("ai:assistant", LIGHT_R, "light.turn_on"),
            );
            assert!(r.is_ok(), "{}", r.summary());
            let snapshot = env.state_file.read(Visibility::Private).unwrap().unwrap();
            let r = send(&mut node, &alice, "domain:home", "domain.safety_hold", hold.clone());
            assert!(r.is_ok(), "{}", r.summary());
            snapshot
        };

        // the node restarts: the hold is still there, with its reason
        {
            let mut node = chitala_node::start_node(&domain, &env).unwrap();
            let r = send(&mut node, &bob, DOOR, "lock.lock", Payload::new());
            assert_eq!(deny_code(&r), DenyCode::Safety, "{}", r.summary());
            assert!(r.reason.as_deref().unwrap_or_default().contains("electrician at work"), "{:?}", r.reason);
        }

        // a state file from before the hold is a rollback: the node refuses to start
        let current = env.state_file.read(Visibility::Private).unwrap().unwrap();
        ctl.storage.tamper(&env.state_file.path, before_hold);
        let err =
            chitala_node::start_node(&domain, &env).err().expect("a rolled-back hold must be refused").to_string();
        assert!(err.contains("rolled back"), "{err}");
        ctl.storage.tamper(&env.state_file.path, current);

        // lifted by an owner, it stays lifted after the next restart
        {
            let mut node = chitala_node::start_node(&domain, &env).unwrap();
            let r = send(&mut node, &alice, "domain:home", "domain.safety_release", payload([("resource", DOOR_R)]));
            assert!(r.is_ok(), "{}", r.summary());
        }
        let mut node = chitala_node::start_node(&domain, &env).unwrap();
        let r = send(&mut node, &bob, DOOR, "lock.lock", Payload::new());
        assert!(r.is_ok(), "{}", r.summary());
    }

    /// Spec 22: a resource in recovery after a failed outcome stays in
    /// recovery across a restart (only a person ends it), a state file rolled
    /// back to before it is refused, and the adapter host — a component on
    /// this platform — carries the faults and the safe state like any order.
    #[test]
    fn a_recovery_survives_a_restart_and_a_rollback_is_refused() {
        let (domain, env, ctl) = memory_domain("recovery");
        let registry = chitala_model::CapabilityRegistry::core_v0_1();
        let alice = Requester::new(
            id("person:alice"),
            domain.keypair(&id("person:alice")).unwrap(),
            id("service:cli"),
            Arc::clone(&domain.platform.entropy),
        );
        let send = |node: &mut chitala_node::Node, target: &str, c: &str, pl: Payload| {
            ctl.time.advance(10);
            let bytes = alice.sign(&registry, &id(target), &CapabilityId::parse(c).unwrap(), pl, node.now());
            node.handle(&bytes)
        };
        let recovery = |env: &NodeEnv| {
            let bytes = env.state_file.read(Visibility::Private).unwrap().unwrap();
            serde_json::from_slice::<chitala_node::DomainState>(&bytes).unwrap().recovery
        };

        let before = {
            let mut node = chitala_node::start_node(&domain, &env).unwrap();
            assert!(send(&mut node, DOOR, "lock.unlock", Payload::new()).is_ok());
            node.simulate(&id(DOOR), Simulation::Stuck(true)).unwrap();
            // something to persist before the recovery
            let r = send(
                &mut node,
                "domain:home",
                "domain.delegate",
                delegate_pl("ai:assistant", LIGHT_R, "light.turn_on"),
            );
            assert!(r.is_ok(), "{}", r.summary());
            let snapshot = env.state_file.read(Visibility::Private).unwrap().unwrap();
            let r = send(&mut node, DOOR, "lock.lock", Payload::new());
            assert_eq!(r.outcome.as_ref().unwrap()["status"], "pending", "{}", r.summary());
            ctl.time.advance(6_000);
            node.tick();
            assert!(node.domain_state().recovery.contains_key(&ResourceId::parse(DOOR_R).unwrap()));
            snapshot
        };
        assert!(recovery(&env).contains_key(&ResourceId::parse(DOOR_R).unwrap()), "persisted");

        // the node restarts: the door is still in recovery
        {
            let mut node = chitala_node::start_node(&domain, &env).unwrap();
            let r = send(&mut node, DOOR, "lock.unlock", Payload::new());
            assert_eq!(deny_code(&r), DenyCode::Safety, "{}", r.summary());
            assert!(r.reason.as_deref().unwrap_or_default().contains("SAFE-8-RECOVERY"), "{:?}", r.reason);
        }

        // a state file from before the recovery is a rollback: refused
        let current = env.state_file.read(Visibility::Private).unwrap().unwrap();
        ctl.storage.tamper(&env.state_file.path, before);
        let err = chitala_node::start_node(&domain, &env).err().expect("a rolled-back recovery is refused").to_string();
        assert!(err.contains("rolled back"), "{err}");
        ctl.storage.tamper(&env.state_file.path, current);

        // released by the owner, it stays released
        {
            let mut node = chitala_node::start_node(&domain, &env).unwrap();
            let r = send(&mut node, "domain:home", "domain.safety_release", payload([("resource", DOOR_R)]));
            assert!(r.is_ok(), "{}", r.summary());
        }
        assert!(recovery(&env).is_empty());
        let mut node = chitala_node::start_node(&domain, &env).unwrap();
        ctl.time.advance(61_000);
        node.tick();
        let r = send(&mut node, DOOR, "lock.unlock", Payload::new());
        assert!(r.is_ok(), "{}", r.summary());
    }

    /// Audit (v0.2 RC, H1b): the record of an action must be durable before its
    /// order can leave the node. If the state file cannot be written, nothing
    /// executes ("no evidence, no action" for the write-ahead record too).
    #[test]
    fn an_action_whose_record_cannot_be_written_never_executes() {
        let (domain, env, ctl) = memory_domain("wal-fail");
        let registry = chitala_model::CapabilityRegistry::core_v0_1();
        let alice = Requester::new(
            id("person:alice"),
            domain.keypair(&id("person:alice")).unwrap(),
            id("service:cli"),
            Arc::clone(&domain.platform.entropy),
        );
        let send = |node: &mut chitala_node::Node, target: &str, c: &str| {
            ctl.time.advance(10);
            let bytes =
                alice.sign(&registry, &id(target), &CapabilityId::parse(c).unwrap(), Payload::new(), node.now());
            node.handle(&bytes)
        };
        let mut node = chitala_node::start_node(&domain, &env).unwrap();
        ctl.storage.fail_writes(&env.state_file.path, true);
        let r = send(&mut node, DOOR, "lock.unlock");
        assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::Internal), "{}", r.summary());
        assert!(r.error.as_ref().unwrap().message.contains("not executed"), "{}", r.summary());
        // the door never moved: a fresh observation still says locked
        let seen = send(&mut node, DOOR, "device.read_state");
        assert_eq!(seen.result.as_ref().unwrap()["reported"]["locked"], true, "{}", seen.summary());
        // the record is written but the order's identity cannot be: the order
        // is minted, then dropped unsent
        ctl.storage.fail_writes_after(&env.state_file.path, 1);
        let r = send(&mut node, DOOR, "lock.unlock");
        assert_eq!(r.error.as_ref().map(|e| e.code), Some(ExecCode::Internal), "{}", r.summary());
        assert!(r.error.as_ref().unwrap().message.contains("not sent"), "{}", r.summary());
        ctl.storage.fail_writes(&env.state_file.path, false);
        let seen = send(&mut node, DOOR, "device.read_state");
        assert_eq!(seen.result.as_ref().unwrap()["reported"]["locked"], true, "{}", seen.summary());
        // WAL crash points A and B: the state file still holds that reservation,
        // without an order. A restart drops it: nothing was sent
        let on_disk: chitala_node::DomainState =
            serde_json::from_slice(&env.state_file.read(Visibility::Private).unwrap().unwrap()).unwrap();
        assert_eq!(on_disk.inflight.len(), 1, "the reservation reached the disk");
        assert!(on_disk.inflight.values().all(|e| !e.minted()), "its order did not");
        drop(node);
        let mut node = chitala_node::start_node(&domain, &env).unwrap();
        assert!(node.pending_outcomes().is_empty(), "never minted, never watched");
        assert!(node.domain_state().inflight.is_empty());
        // once the state can be written, the same request goes through
        let r = send(&mut node, DOOR, "lock.unlock");
        assert!(r.is_ok(), "{}", r.summary());
        assert!(node.domain_state().inflight.is_empty());
    }

    /// Audit (v0.2 RC): an action that may change the world is on record in
    /// the state file before it can; a state file rolled back past it (to forget
    /// that a command may have run) is refused at start-up, and a restart
    /// watches it again.
    #[test]
    fn an_action_on_record_survives_a_restart_and_a_rollback_past_it_is_refused() {
        let (domain, env, ctl) = memory_domain("in-flight");
        let registry = chitala_model::CapabilityRegistry::core_v0_1();
        let alice = Requester::new(
            id("person:alice"),
            domain.keypair(&id("person:alice")).unwrap(),
            id("service:cli"),
            Arc::clone(&domain.platform.entropy),
        );
        let send = |node: &mut chitala_node::Node, target: &str, c: &str, pl: Payload| {
            ctl.time.advance(10);
            let bytes = alice.sign(&registry, &id(target), &CapabilityId::parse(c).unwrap(), pl, node.now());
            node.handle(&bytes)
        };
        let before = {
            let mut node = chitala_node::start_node(&domain, &env).unwrap();
            let r = send(
                &mut node,
                "domain:home",
                "domain.delegate",
                delegate_pl("ai:assistant", LIGHT_R, "light.turn_on"),
            );
            assert!(r.is_ok(), "{}", r.summary());
            let snapshot = env.state_file.read(Visibility::Private).unwrap().unwrap();
            // a slow lock: the outcome is still pending when the node goes down
            node.simulate(&id(DOOR), Simulation::Lag(5)).unwrap();
            let r = send(&mut node, DOOR, "lock.unlock", Payload::new());
            assert_eq!(r.outcome.as_ref().unwrap()["status"], "pending", "{}", r.summary());
            snapshot
        };
        let state = env.state_file.read(Visibility::Private).unwrap().unwrap();
        let persisted: chitala_node::DomainState = serde_json::from_slice(&state).unwrap();
        assert_eq!(persisted.inflight.len(), 1, "on record");
        // a state file from before it: refused
        ctl.storage.tamper(&env.state_file.path, before);
        let err =
            chitala_node::start_node(&domain, &env).err().expect("a rollback past an action is refused").to_string();
        assert!(err.contains("rolled back"), "{err}");
        ctl.storage.tamper(&env.state_file.path, state);
        // the real one: the node watches the action again
        let node = chitala_node::start_node(&domain, &env).unwrap();
        assert_eq!(node.pending_outcomes().len(), 1, "watched again after the restart");
        assert_eq!(node.domain_state().inflight.len(), 1);
    }

    /// Spec 21: a lease's uses survive a restart, and a state file rolled back
    /// to fewer uses is refused rather than handing out a use twice.
    #[test]
    fn lease_uses_survive_a_restart_and_a_rollback_is_refused() {
        use chitala_intent::{LeaseClause, LeaseTerms};
        let (domain, env, ctl) = memory_domain("leases");
        let registry = chitala_model::CapabilityRegistry::core_v0_1();
        let alice = Requester::new(
            id("person:alice"),
            domain.keypair(&id("person:alice")).unwrap(),
            id("service:cli"),
            Arc::clone(&domain.platform.entropy),
        );
        let ai = domain.keypair(&id("ai:assistant")).unwrap();
        let thermostat = "resource:thermostat";
        let set = "climate.set_target_temperature";
        let intent = |node: &chitala_node::Node, token: &[u8], lease: LeaseClause, params: Payload| {
            let mut i = Intent::new(
                chitala_intent::new_intent_id(domain.platform.entropy.as_ref()),
                id("ai:assistant"),
                id("person:alice"),
                CapabilityId::parse(set).unwrap(),
                ResourceId::parse(thermostat).unwrap(),
                node.now(),
                60_000,
            );
            i.authority = Some(token.to_vec());
            i.params = params;
            i.lease = Some(lease);
            i.sign(&ai)
        };
        let celsius = |c: i64| payload([("celsius", ParamValue::Int(c))]);

        let (token, lease, after_one) = {
            let mut node = chitala_node::start_node(&domain, &env).unwrap();
            let pl = delegate_pl("ai:assistant", thermostat, set);
            let bytes = alice.sign(
                &registry,
                &id("domain:home"),
                &CapabilityId::parse("domain.delegate").unwrap(),
                pl,
                node.now(),
            );
            let (_, token, _) = token_of(&node.handle(&bytes));
            let terms = LeaseTerms {
                max_uses: 2,
                duration_ms: 3_600_000,
                envelope: [("celsius".to_string(), (20, 24))].into(),
            };
            let r = node.handle(&intent(&node, &token, LeaseClause::Request(terms), Payload::new()));
            assert!(r.is_ok(), "{}", r.summary());
            let id_hex = r.result.unwrap()["lease"]["id"].as_str().unwrap().to_string();
            let lease: [u8; 16] = hex::decode(&id_hex).unwrap().try_into().unwrap();
            ctl.time.advance(10);
            assert!(node.handle(&intent(&node, &token, LeaseClause::Use(lease), celsius(21))).is_ok());
            (token, lease, env.state_file.read(Visibility::Private).unwrap().unwrap())
        };
        // after a restart, one use is left
        {
            let mut node = chitala_node::start_node(&domain, &env).unwrap();
            ctl.time.advance(10);
            assert!(node.handle(&intent(&node, &token, LeaseClause::Use(lease), celsius(22))).is_ok());
            ctl.time.advance(10);
            let r = node.handle(&intent(&node, &token, LeaseClause::Use(lease), celsius(23)));
            assert_eq!(deny_code(&r), DenyCode::LeaseExhausted, "{}", r.summary());
        }
        // a state file from before the second use is a rollback: refused
        ctl.storage.tamper(&env.state_file.path, after_one);
        let err =
            chitala_node::start_node(&domain, &env).err().expect("a rolled-back lease must be refused").to_string();
        assert!(err.contains("rolled back"), "{err}");
    }

    /// Private data that others could reach is refused through the PAL, on any
    /// backend — the node never looks at permission bits itself.
    #[test]
    fn weakened_state_or_keys_are_refused() {
        let (domain, env, ctl) = memory_domain("weak");
        {
            // an authority change persists the domain state
            let mut node = chitala_node::start_node(&domain, &env).unwrap();
            let alice = Requester::new(
                id("person:alice"),
                domain.keypair(&id("person:alice")).unwrap(),
                id("service:cli"),
                Arc::clone(&domain.platform.entropy),
            );
            let bytes = alice.sign(
                node.registry(),
                &id("domain:home"),
                &CapabilityId::parse("domain.delegate").unwrap(),
                delegate_pl("ai:assistant", LIGHT_R, "light.turn_on"),
                node.now(),
            );
            assert!(node.handle(&bytes).is_ok());
        }
        assert!(chitala_node::start_node(&domain, &env).is_ok());
        ctl.storage.weaken(&env.state_file.path);
        let err = chitala_node::start_node(&domain, &env).err().expect("weak state must be refused").to_string();
        assert!(err.contains("insecure"), "{err}");

        let (domain, env, ctl) = memory_domain("weak-key");
        let _ = env;
        // the memory key store holds keys in RAM; the software store over memory storage can be weakened
        let keys = chitala_platform::SoftwareKeyStore::new(
            Arc::clone(&domain.platform.storage) as Arc<dyn chitala_platform::Storage>,
            Arc::clone(&domain.platform.entropy),
            StoragePath::new("keys").unwrap(),
        )
        .unwrap();
        let alice = chitala_platform::KeyRef::new("person-alice").unwrap();
        chitala_platform::SecureKeyStore::generate(&keys, &alice).unwrap();
        ctl.storage.weaken(&StoragePath::new("keys/person-alice.key").unwrap());
        let mut weak = domain.clone();
        weak.platform.keys = Arc::new(keys);
        let err = weak.keypair(&id("person:alice")).unwrap_err().to_string();
        assert!(err.contains("insecure"), "{err}");
    }

    /// The restart rate limit runs on the platform's monotonic clock: no
    /// sleeping, and a wall-clock jump cannot bypass it.
    #[test]
    fn adapter_host_restarts_follow_the_platform_clock() {
        let (platform, ctl) = memory::platform("respawn", T0);
        let starts = Arc::new(AtomicUsize::new(0));
        let real = adapter_host_program(Arc::clone(&platform.time));
        let s2 = Arc::clone(&starts);
        // the first instance answers init and then crashes
        ctl.exec.register(
            "flaky",
            Arc::new(move |input, mut output, env| {
                if s2.fetch_add(1, Ordering::SeqCst) == 0 {
                    let mut line = String::new();
                    let _ = BufReader::new(input).read_line(&mut line);
                    let _ = writeln!(output, "{{\"ok\":true}}");
                    return;
                }
                real(input, output, env)
            }),
        );
        let boundary = TrustedExecutionBoundary::new(Arc::clone(&platform.entropy));
        let host = ComponentHost::start(
            Arc::clone(&platform.exec),
            Arc::clone(&platform.time),
            Arc::clone(&platform.entropy),
            chitala_node::executor::HostSpec {
                component: ComponentSpec { program: "flaky".into(), env: vec![] },
                devices: sample_devices(),
                home_assistant: None,
                order_key: boundary.order_key(),
                timeout: Duration::from_secs(2),
            },
        )
        .unwrap();
        assert!(!host.isolated(), "the memory backend must not claim isolation");
        assert!(host.observe(&id(LIGHT)).is_err(), "the host crashed");
        // the wall clock jumps an hour: still restarting
        ctl.time.set_wall(T0 + 3_600_000);
        let err = host.observe(&id(LIGHT)).unwrap_err().to_string();
        assert!(err.contains("restarting"), "{err}");
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        // a second of monotonic time later it comes back
        ctl.time.advance_monotonic(MIN_RESPAWN_INTERVAL.as_millis() as u64);
        assert!(host.observe(&id(LIGHT)).is_ok());
        assert_eq!(host.restarts(), 1);
        assert_eq!(starts.load(Ordering::SeqCst), 2);
    }
}

// ───────────────────────── trusted time (threat model R3) ─────────────────────────

mod time {
    use super::*;
    use chitala_platform::memory::MemoryTime;
    use chitala_platform::{TimeSource, TrustedClock};

    /// A wall clock the test sets (monotonic time stands still unless advanced).
    fn controllable(start: u64) -> Arc<MemoryTime> {
        Arc::new(MemoryTime::new(start))
    }

    #[test]
    fn clock_rollback_cannot_revive_an_expired_token() {
        let t = controllable(T0);
        let trusted = Arc::new(TrustedClock::new(t.clone() as Arc<dyn TimeSource>, 0));
        let clock = trusted.as_clock();
        let node_key = Keypair::from_seed(&test_seed("service:node"));
        let mut mock = MockAdapter::new();
        for d in sample_devices() {
            mock.add(d.id.clone(), VirtualKind::from_capabilities(&d.capabilities).unwrap());
        }
        let keys: HashMap<&str, Keypair> =
            ["person:alice", "ai:assistant"].into_iter().map(|w| (w, Keypair::from_seed(&test_seed(w)))).collect();
        let boundary = TrustedExecutionBoundary::new(test_entropy());
        let mut node = Node::new(NodeParts {
            domain: id("domain:home"),
            node_id: id("service:node"),
            node_key: node_key.clone(),
            authority_key: Keypair::from_seed(&test_seed("domain:home/authority")),
            principals: vec![
                (id("person:alice"), keys["person:alice"].public_key(), vec!["owner".into()]),
                (id("ai:assistant"), keys["ai:assistant"].public_key(), vec![]),
            ],
            devices: sample_devices(),
            agency: vec![(id("ai:assistant"), vec![id("person:alice")])],
            resources: sample_resources(),
            safety: Default::default(),
            executor: chitala_node::executor::in_process(&boundary, vec![Box::new(mock)], clock.clone()),
            policy: chitala_node::PolicySource::Default,
            audit: AuditLog::in_memory(None),
            state: chitala_node::DomainState::default(),
            state_file: None,
            containment: ContainmentConfig::default(),
            monitor: MonitorConfig::default(),
            entropy: std::sync::Arc::new(chitala_platform::memory::test_entropy()),
            clock,
            clock_watch: Some(trusted),
            boundary,
        })
        .unwrap();
        let req = |node: &mut Node, who: &str, target: &str, cap: &str, pl: Payload, token: Option<&[u8]>| {
            let r = Requester::new(
                id(who),
                keys[who].clone(),
                id("service:test"),
                std::sync::Arc::new(chitala_platform::memory::test_entropy()),
            )
            .with_token(token.map(<[u8]>::to_vec));
            let bytes = r.sign(node.registry(), &id(target), &CapabilityId::parse(cap).unwrap(), pl, node.now());
            node.handle(&bytes)
        };
        let pl = payload([
            ("holder", ParamValue::from("ai:assistant")),
            ("target", ParamValue::from(LIGHT_R)),
            ("capability", ParamValue::from("light.turn_on")),
            ("ttl_s", ParamValue::Int(2)),
        ]);
        let (_, token, _) = token_of(&req(&mut node, "person:alice", "domain:home", "domain.delegate", pl, None));
        let intent = |node: &mut Node, token: &[u8]| {
            let mut i = Intent::new(
                chitala_intent::new_intent_id(chitala_platform::memory::test_entropy()),
                id("ai:assistant"),
                id("person:alice"),
                CapabilityId::parse("light.turn_on").unwrap(),
                ResourceId::parse(LIGHT_R).unwrap(),
                node.now(),
                60_000,
            );
            i.authority = Some(token.to_vec());
            node.handle(&i.sign(&keys["ai:assistant"]))
        };
        assert!(intent(&mut node, &token).is_ok());

        t.set_wall(T0 + 3_000); // the token expires
        let r = intent(&mut node, &token);
        assert_eq!(deny_code(&r), DenyCode::TokenDenied);

        t.set_wall(T0); // an attacker sets the clock back
        let r = intent(&mut node, &token);
        assert_eq!(deny_code(&r), DenyCode::TokenDenied, "a rolled-back clock revived an expired token");
        assert!(node.now() >= T0 + 3_000);
        // and the attempt is on the record
        let clock_records: Vec<serde_json::Value> = node
            .audit()
            .lines()
            .iter()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|v| v["kind"] == "clock")
            .collect();
        assert_eq!(clock_records.len(), 1);
        assert!(clock_records[0]["behind_ms"].as_u64().unwrap() >= 3_000);
    }

    #[test]
    fn startup_refuses_a_clock_behind_the_audit() {
        let dir = temp_dir("clock-start");
        chitala_node::hosted::init_domain(&dir).unwrap();
        let loaded = load_config(&dir);
        let real = now_ms();
        {
            let mut node = node_from_config(&loaded).unwrap();
            assert!(node.handle(&sign_as(&loaded, "person:alice", LIGHT, "light.turn_on", Payload::new())).is_ok());
        }
        let on_clock = |t: Arc<MemoryTime>| {
            let mut domain = loaded.domain().unwrap();
            domain.platform.time = t;
            chitala_node::start_node(&domain, &loaded.node_env().unwrap())
        };
        // two hours back: refuse
        let err = on_clock(controllable(real - 2 * 3_600_000)).err().expect("must refuse").to_string();
        assert!(err.contains("clock"), "{err}");
        // a few seconds of skew: start, but never earlier than the audit
        let node = on_clock(controllable(real - 10_000)).unwrap();
        assert!(node.now() >= real);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
