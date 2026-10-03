//! `chitala demo` — milestone 0.0.1 and 0.0.2 (Blueprint v17 §4, §18) in memory,
//! through the real Reference Monitor, adapters, twin, bus and audit log.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chitala_adapters::mock::{MockAdapter, VirtualKind};
use chitala_adapters::Simulation;
use chitala_audit::{verify_lines, AuditLog, Signer};
use chitala_bus::Filter;
use chitala_identity::Keypair;
use chitala_model::{payload, CapabilityId, EntityId, ParamValue, Payload};
use chitala_monitor::MonitorConfig;
use chitala_node::config::ContainmentConfig;
use chitala_node::setup::sample_devices;
use chitala_node::{now_ms, Node, NodeParts, Requester, Response};

const LIGHT: &str = "device:living-room-light";
const DOOR: &str = "device:front-door";

struct Demo {
    node: Node,
    keys: HashMap<&'static str, Keypair>,
    clock: Arc<AtomicU64>,
    step: u32,
}

fn id(s: &str) -> EntityId {
    EntityId::parse(s).expect("demo ids are valid")
}

impl Demo {
    fn send(&mut self, who: &'static str, target: &str, cap: &str, pl: Payload, token: Option<&[u8]>) -> Response {
        let r =
            Requester::new(id(who), self.keys[who].clone(), id("service:cli")).with_token(token.map(<[u8]>::to_vec));
        let bytes =
            r.sign(self.node.registry(), &id(target), &CapabilityId::parse(cap).expect("cap"), pl, self.node.now());
        self.clock.fetch_add(250, Ordering::SeqCst);
        self.node.handle(&bytes)
    }

    fn step(&mut self, title: &str, expect_allow: bool, r: &Response) {
        self.step += 1;
        let ok = r.is_ok() == expect_allow;
        let mark = if ok { "✓" } else { "✗ (KHÔNG như kỳ vọng)" };
        println!("\n{:>2}. {title}", self.step);
        println!("    → {} {mark}", r.summary());
    }

    fn delegate(&mut self, who: &'static str, holder: &str, target: &str, cap: &str, ttl_s: i64) -> Response {
        let pl = payload([
            ("holder", ParamValue::from(holder)),
            ("target", ParamValue::from(target)),
            ("capability", ParamValue::from(cap)),
            ("ttl_s", ParamValue::Int(ttl_s)),
        ]);
        self.send(who, "domain:home", "domain.delegate", pl, None)
    }
}

pub fn run() -> Result<(), String> {
    println!("Chitala OS — demo milestone 0.0.1 / 0.0.2 (Blueprint v17)");
    println!("Chuỗi tin cậy: Identity → Capability → Authority → Reference Monitor → Device → State → Audit");

    let mut keys = HashMap::new();
    let mut principals = Vec::new();
    for (who, roles) in [("person:alice", vec!["owner"]), ("person:bob", vec!["adult"]), ("ai:assistant", vec![])] {
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
    let node = Node::new(NodeParts {
        domain: id("domain:home"),
        node_id: id("service:node"),
        node_key: node_key.clone(),
        authority_key: Keypair::generate(),
        principals,
        devices,
        adapters: vec![Box::new(mock)],
        policy: chitala_node::PolicySource::Default,
        audit: AuditLog::in_memory(Some(Signer { id: id("service:node"), key: node_key.clone() })),
        state: chitala_node::DomainState::default(),
        state_path: None,
        containment: ContainmentConfig::default(),
        monitor: MonitorConfig::default(),
        clock: Box::new(move || c.load(Ordering::SeqCst)),
    })
    .map_err(|e| e.to_string())?;
    let events = node.subscribe(Filter::All);
    let mut d = Demo { node, keys, clock, step: 0 };

    println!("\nDomain domain:home · owner person:alice · adult person:bob · AI ai:assistant (chưa có quyền gì)");
    println!("Thiết bị ảo: đèn phòng khách, ổ cắm quạt, điều hòa, khóa cửa chính");

    // ── 0.0.1 ──
    let r = d.send("person:alice", LIGHT, "light.turn_on", Payload::new(), None);
    d.step("Alice (owner) bật đèn phòng khách", true, &r);
    if let Some(res) = &r.result {
        println!("    twin: reported={} version={}", res["reported"], res["version"]);
    }

    let r = d.send("ai:assistant", LIGHT, "light.turn_off", Payload::new(), None);
    d.step("AI chưa được ủy quyền thử tắt đèn (test bắt buộc của v17 §4)", false, &r);

    // ── 0.0.2 ──
    let r = d.delegate("person:alice", "ai:assistant", LIGHT, "light.set_brightness", 600);
    d.step("Alice ủy quyền light.set_brightness trên đèn phòng khách cho AI trong 10 phút", true, &r);
    let res = r.result.clone().unwrap_or_default();
    let ai_token =
        chitala_token::bytes_from_base64(res["token"].as_str().unwrap_or_default()).map_err(|e| e.to_string())?;
    let ai_rid = res["revocation_id"].as_str().unwrap_or_default().to_string();
    println!("    token holder-bound, revocation id {}…", &ai_rid[..16.min(ai_rid.len())]);

    let r =
        d.send("ai:assistant", LIGHT, "light.set_brightness", payload([("brightness_pct", 30i64)]), Some(&ai_token));
    d.step("AI giảm độ sáng xuống 30% bằng token", true, &r);

    let r =
        d.send("ai:assistant", LIGHT, "light.set_brightness", payload([("brightness_pct", 140i64)]), Some(&ai_token));
    d.step("AI đặt độ sáng 140% — ngoài safety envelope của registry", false, &r);

    let r = d.send("ai:assistant", DOOR, "lock.unlock", Payload::new(), Some(&ai_token));
    d.step("AI dùng token đèn để mở khóa cửa", false, &r);

    let r = d.delegate("person:alice", "ai:assistant", DOOR, "lock.unlock", 60);
    d.step("Alice định ủy quyền mở khóa cửa cho AI — Constitution C11 chặn ngay khi cấp", false, &r);

    let r = d.send("person:bob", DOOR, "lock.unlock", Payload::new(), None);
    d.step("Bob (adult) mở khóa cửa — role adult chỉ có rủi ro low/medium", false, &r);

    let r = d.send("person:alice", DOOR, "lock.unlock", Payload::new(), None);
    d.step("Alice mở khóa cửa", true, &r);
    d.node.simulate(&id(DOOR), Simulation::DoorOpen(true)).map_err(|e| e.to_string())?;
    let r = d.send("person:alice", DOOR, "lock.lock", Payload::new(), None);
    d.step("Cửa đang mở, Alice khóa cửa — lệnh hợp lệ nhưng thiết bị từ chối (C5)", false, &r);

    let r = d.send(
        "person:alice",
        "domain:home",
        "domain.revoke_token",
        payload([("revocation_id", ai_rid.as_str())]),
        None,
    );
    d.step("Alice thu hồi token của AI", true, &r);
    let r =
        d.send("ai:assistant", LIGHT, "light.set_brightness", payload([("brightness_pct", 80i64)]), Some(&ai_token));
    d.step("AI dùng lại token đã bị thu hồi", false, &r);

    // ── containment ──
    let n = ContainmentConfig::default().quarantine_after;
    for _ in 0..n {
        let _ = d.send("ai:assistant", DOOR, "lock.unlock", Payload::new(), None);
    }
    let state = d.node.identities().get(&id("ai:assistant")).map(|p| p.state.label()).unwrap_or("?");
    let r = d.send("ai:assistant", LIGHT, "device.read_state", Payload::new(), None);
    d.step(&format!("AI dò quyền {n} lần liên tiếp → bị cách ly tự động (v8 §9); thử đọc trạng thái đèn"), false, &r);
    println!("    trạng thái ai:assistant: {state} — chỉ owner đưa về được qua RECOVERY → RE_ATTEST → TRUSTED");

    // ── evidence ──
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for e in events.drain() {
        *by_kind.entry(format!("{:?}", e.kind)).or_default() += 1;
    }
    println!("\nSự kiện trên bus: {by_kind:?}");
    d.node.checkpoint().map_err(|e| e.to_string())?;
    let lines = d.node.audit().lines();
    let report = verify_lines(lines.iter().map(String::as_str), &HashMap::new()).map_err(|e| e.to_string())?;
    println!(
        "Audit log: {} bản ghi, {} checkpoint ký, chuỗi hash hợp lệ (head {}…)",
        report.records,
        report.checkpoints,
        &report.head[..16]
    );
    if let Some(deny) = lines.iter().find(|l| l.contains("E_TOKEN_MISSING")) {
        println!("Ví dụ bản ghi từ chối:\n  {deny}");
    }
    Ok(())
}
