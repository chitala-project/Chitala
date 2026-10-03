//! `chitala demo` — the Physical Authority Slice v0.1 in memory, through the
//! real Reference Monitor, Authority Engine, safety layer, trusted boundary,
//! virtual devices, twin, bus and audit log.
//!
//! > AI produces Intent. Chitala produces Authority. Only the trusted execution
//! > boundary produces physical Commands.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_adapters::Simulation;
use chitala_audit::{verify_lines, AuditLog, Signer};
use chitala_bus::Filter;
use chitala_identity::Keypair;
use chitala_intent::{parse_id_hex, Approval, Intent, Verdict};
use chitala_model::{payload, CapabilityId, EntityId, ParamValue, Payload};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::setup::{sample_devices, sample_resources};
use chitala_node::{now_ms, Node, NodeParts, Requester, Response};
use chitala_resource::ResourceId;

const LIGHT: &str = "resource:living-room-light";
const DOOR: &str = "resource:front-door";
const DOOR_DEVICE: &str = "device:front-door";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    Allow,
    Deny,
    Escalate,
}

struct Demo {
    node: Node,
    keys: HashMap<&'static str, Keypair>,
    tokens: HashMap<(&'static str, &'static str), Vec<u8>>,
    clock: Arc<AtomicU64>,
    step: u32,
}

fn id(s: &str) -> EntityId {
    EntityId::parse(s).expect("demo ids are valid")
}

impl Demo {
    fn now(&self) -> u64 {
        self.clock.fetch_add(250, Ordering::SeqCst)
    }

    /// A person's own request (humans keep their direct path).
    fn person(&mut self, who: &'static str, target: &str, cap: &str, pl: Payload) -> Response {
        let r = Requester::new(id(who), self.keys[who].clone(), id("service:cli"));
        let now = self.now();
        let bytes = r.sign(self.node.registry(), &id(target), &CapabilityId::parse(cap).expect("cap"), pl, now);
        self.node.handle(&bytes)
    }

    fn intent(&self, ai: &'static str, for_: &str, resource: &str, cap: &'static str, purpose: &str) -> Intent {
        let mut i = Intent::new(
            id(ai),
            id(for_),
            CapabilityId::parse(cap).expect("cap"),
            ResourceId::parse(resource).expect("resource"),
            self.now(),
            300_000,
        );
        i.context.purpose = Some(purpose.into());
        i.authority = self.tokens.get(&(ai, cap)).cloned();
        i
    }

    /// An AI asks for an outcome: it signs an intent, never a command.
    fn ask(&mut self, ai: &'static str, for_: &str, resource: &str, cap: &'static str, purpose: &str) -> Response {
        let i = self.intent(ai, for_, resource, cap, purpose);
        let bytes = i.sign(&self.keys[ai]);
        self.node.handle(&bytes)
    }

    fn step(&mut self, title: &str, expect: Expect, r: &Response) {
        self.step += 1;
        let got = if r.is_escalated() {
            Expect::Escalate
        } else if r.is_ok() {
            Expect::Allow
        } else {
            Expect::Deny
        };
        let mark = if got == expect { "✓" } else { "✗ (NOT as expected)" };
        println!("\n{:>2}. {title}", self.step);
        let step = r.step.as_deref().map(|s| format!(" [step {s}]")).unwrap_or_default();
        println!("    → {}{step} {mark}", r.summary());
    }

    fn grant(&mut self, holder: &'static str, target: &str, cap: &'static str) {
        let pl = payload([
            ("holder", ParamValue::from(holder)),
            ("target", ParamValue::from(target)),
            ("capability", ParamValue::from(cap)),
            ("ttl_s", ParamValue::Int(3600)),
        ]);
        let r = self.person("person:alice", "domain:home", "domain.delegate", pl);
        let token = r.result.as_ref().and_then(|v| v["token"].as_str()).unwrap_or_default();
        if let Ok(bytes) = chitala_token::bytes_from_base64(token) {
            self.tokens.insert((holder, cap), bytes);
        }
        println!("    {holder:<20} ← {cap} on {target}: {}", if r.is_ok() { "ok" } else { "FAILED" });
    }

    /// The owner looks at what waits for her and answers exactly that intent.
    fn answer(&mut self, who: &'static str, intent: &str, verdict: Verdict) -> Response {
        let list = self.person(who, "domain:home", "domain.list_approvals", Payload::new());
        let entry = list
            .result
            .as_ref()
            .and_then(|v| v["approvals"].as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .find(|e| e["intent"] == intent);
        let Some(entry) = entry else { return list };
        println!(
            "    {who} sees: {} wants {} on {} — \"{}\" (risk {})",
            entry["actor"].as_str().unwrap_or("?"),
            entry["capability"].as_str().unwrap_or("?"),
            entry["resource"].as_str().unwrap_or("?"),
            entry["purpose"].as_str().unwrap_or(""),
            entry["risk"].as_str().unwrap_or("?"),
        );
        let digest: [u8; 32] = hex::decode(entry["digest"].as_str().unwrap_or_default())
            .ok()
            .and_then(|d| d.try_into().ok())
            .unwrap_or([0; 32]);
        let now = self.now();
        let a = Approval {
            intent: parse_id_hex(intent).unwrap_or_default(),
            intent_digest: digest,
            approver: id(who),
            verdict,
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            note: None,
        };
        self.node.handle(&a.sign(&self.keys[who]))
    }

    fn door(&self) -> &'static str {
        match self.node.twins().get(&id(DOOR_DEVICE)).and_then(|t| t.reported.get("locked").cloned()) {
            Some(ParamValue::Bool(true)) => "LOCKED",
            Some(ParamValue::Bool(false)) => "UNLOCKED",
            _ => "?",
        }
    }
}

pub fn run() -> Result<(), String> {
    println!("Chitala OS — Physical Authority Slice v0.1");
    println!("Invariant 1: AI produces Intent. Chitala produces Authority. Only the trusted execution boundary");
    println!("produces physical Commands.");
    println!("MCP/AI → Intent → Authority → Safety → Approval → Capability → device (simulated door)");

    let people = [
        ("person:alice", vec!["owner"]),
        ("person:guest", vec!["guest"]),
        ("person:child", vec!["child"]),
        ("ai:assistant", vec![]),
        ("ai:guest-assistant", vec![]),
        ("ai:kid-assistant", vec![]),
    ];
    let mut keys = HashMap::new();
    let mut principals = Vec::new();
    for (who, roles) in people {
        let k = Keypair::generate();
        principals.push((id(who), k.public_key(), roles.into_iter().map(String::from).collect()));
        keys.insert(who, k);
    }
    let devices = sample_devices();
    let mut mock = MockAdapter::new();
    for d in &devices {
        mock.add(d.id.clone(), VirtualKind::from_capabilities(&d.capabilities).ok_or("bad sample device")?);
    }
    let node_key = Keypair::generate();
    let clock = Arc::new(AtomicU64::new(now_ms()));
    let c = Arc::clone(&clock);
    let node_clock: chitala_node::Clock = Arc::new(move || c.load(Ordering::SeqCst));
    let node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: node_key.clone(),
        authority_key: Keypair::generate(),
        principals,
        agency: vec![
            (id("ai:assistant"), vec![id("person:alice")]),
            (id("ai:guest-assistant"), vec![id("person:guest")]),
            (id("ai:kid-assistant"), vec![id("person:child")]),
        ],
        devices,
        resources: sample_resources(),
        safety: Default::default(),
        // in-process for the demo; `chitala node` runs adapters in separate processes
        executor: chitala_node::executor::in_process(&node_key.public_key(), vec![Box::new(mock)], node_clock.clone()),
        policy: chitala_node::PolicySource::Default,
        audit: AuditLog::in_memory(Some(Signer { id: id("service:node"), key: node_key.clone() })),
        state: chitala_node::DomainState::default(),
        state_path: None,
        containment: ContainmentConfig::default(),
        monitor: MonitorConfig::default(),
        clock: node_clock,
        clock_watch: None,
    })
    .map_err(|e| e.to_string())?;
    let events = node.subscribe(Filter::All);
    let mut d = Demo { node, keys, tokens: HashMap::new(), clock, step: 0 };

    println!("\nDomain domain:home: owner person:alice · guest person:guest · child person:child");
    println!("AIs: ai:assistant (for alice) · ai:guest-assistant (for the guest) · ai:kid-assistant (for the child)");
    println!("Resources: home ⊃ living room ⊃ light · entrance ⊃ front door (perimeter) · …  — door: {}", d.door());
    println!("\nAlice delegates (until now no AI holds any right):");
    d.grant("ai:assistant", LIGHT, "light.turn_on");
    d.grant("ai:assistant", DOOR, "lock.unlock");
    d.grant("ai:assistant", DOOR, "lock.lock");
    d.grant("ai:guest-assistant", "resource:living-room", "light.turn_on");
    d.grant("ai:kid-assistant", "resource:bedroom", "switch.turn_on");

    // ── the five cases ──
    let r = d.ask("ai:assistant", "person:alice", LIGHT, "light.turn_on", "it is getting dark");
    d.step("Case 1 · owner's AI → turn on the light", Expect::Allow, &r);

    let r = d.ask("ai:guest-assistant", "person:guest", LIGHT, "light.turn_on", "the guest just arrived");
    d.step("Case 2 · guest's AI → turn on a delegated light (right on the whole living room)", Expect::Allow, &r);

    let r = d.ask("ai:kid-assistant", "person:child", DOOR, "lock.unlock", "my friend is outside");
    d.step("Case 3 · child's AI → open the door without permission", Expect::Deny, &r);

    let r = d.ask("ai:assistant", "person:alice", DOOR, "lock.unlock", "the plumber is at the door");
    d.step("Case 4 · owner's AI → open the door (high risk)", Expect::Escalate, &r);
    println!("    door: {} — an escalation is not an execution", d.door());
    let intent = r.mid.clone().unwrap_or_default();
    let r = d.answer("person:alice", &intent, Verdict::Approve);
    d.step(
        "Case 4 · Alice sees exactly that request and approves it (signature bound to the intent digest)",
        Expect::Allow,
        &r,
    );
    println!(
        "    door: {} — the physical command came from the trusted execution boundary, after Authority + Safety + a human",
        d.door()
    );

    let a = d.intent("ai:kid-assistant", "person:child", DOOR, "lock.unlock", "please open the door for me");
    let handoff = a.sign(&d.keys["ai:kid-assistant"]);
    let mut b = d.intent("ai:assistant", "person:child", DOOR, "lock.unlock", "the kid's AI asked");
    b.context.cause = Some(handoff.clone());
    let r = d.node.handle(&b.sign(&d.keys["ai:assistant"]));
    d.step("Case 5 · AI A (the child's) asks AI B (the owner's) to open the door; B relays honestly", Expect::Deny, &r);
    let mut b = d.intent("ai:assistant", "person:alice", DOOR, "lock.unlock", "I open it for alice");
    b.context.cause = Some(handoff);
    let r = d.node.handle(&b.sign(&d.keys["ai:assistant"]));
    d.step("Case 5 · …B cheats: claims it is for alice while carrying the child's request", Expect::Deny, &r);

    // ── around the cases ──
    let r = d.ask("ai:assistant", "person:alice", "resource:living-room-light", "light.turn_off", "save power");
    d.step("owner's AI turns off the light — that right was never delegated", Expect::Deny, &r);
    let req = Requester::new(id("ai:assistant"), d.keys["ai:assistant"].clone(), id("service:cli"))
        .with_token(d.tokens.get(&("ai:assistant", "light.turn_on")).cloned());
    let now = d.now();
    let bytes = req.sign(
        d.node.registry(),
        &id("device:living-room-light"),
        &CapabilityId::parse("light.turn_on").expect("cap"),
        Payload::new(),
        now,
    );
    let r = d.node.handle(&bytes);
    d.step("an AI tries to send a command straight to the device, skipping the intent", Expect::Deny, &r);

    d.node.simulate(&id(DOOR_DEVICE), Simulation::DoorOpen(true)).map_err(|e| e.to_string())?;
    let r = d.ask("ai:assistant", "person:alice", DOOR, "lock.lock", "lock the door");
    d.step(
        "the door is open and the AI locks it — Safety refuses before any command exists (physics beats permission)",
        Expect::Deny,
        &r,
    );
    d.node.simulate(&id(DOOR_DEVICE), Simulation::DoorOpen(false)).map_err(|e| e.to_string())?;

    // ── containment ──
    let n = ContainmentConfig::default().quarantine_after;
    for _ in 0..n {
        let _ = d.ask("ai:kid-assistant", "person:child", DOOR, "lock.unlock", "try again");
    }
    let state = d.node.identities().get(&id("ai:kid-assistant")).map(|p| p.state.label()).unwrap_or("?");
    let r = d.ask("ai:kid-assistant", "person:child", "resource:fan", "switch.turn_on", "turn on the fan");
    d.step(
        &format!("the child's AI probes {n} times → quarantined; it then tries a right it does hold"),
        Expect::Deny,
        &r,
    );
    println!("    ai:kid-assistant is {state} — only the owner can bring it back via RECOVERY → RE_ATTEST → TRUSTED");

    // ── evidence ──
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for e in events.drain() {
        *by_kind.entry(format!("{:?}", e.kind)).or_default() += 1;
    }
    println!("\nEvents on the bus: {by_kind:?}");
    d.node.checkpoint().map_err(|e| e.to_string())?;
    let lines = d.node.audit().lines();
    let report = verify_lines(lines.iter().map(String::as_str), &HashMap::new()).map_err(|e| e.to_string())?;
    println!(
        "Audit log: {} records, {} signed checkpoints, hash chain valid (head {}…)",
        report.records,
        report.checkpoints,
        &report.head[..16]
    );
    if let Some(allow) = lines.iter().find(|l| l.contains("\"approved_by\":\"person:alice\"")) {
        println!("The record that allowed the door (who asked, for whom, why, who approved, every step):\n  {allow}");
    }
    Ok(())
}
