//! Chitala Native spike (v0.2 step 5, spec 20).
//!
//! The node core — Reference Monitor, Authority Engine, Safety, Trusted
//! Execution Boundary, adapter host, audit — boots on the Native platform and
//! decides a fixed series of requests and intents:
//!
//! ```text
//! Boot → Identity → Intent → Authority → Safety → ALLOW / DENY
//! ```
//!
//! Built for `aarch64-unknown-hermit` it is a unikernel: the Hermit kernel and
//! this program in one image, on QEMU or a board, with no Linux, Windows or
//! macOS underneath. No AI model runs here: an agent only ever sends signed
//! intents, and Chitala alone decides authority and execution.
//!
//! The exit code is 0 only if every decision is the expected one and the audit
//! log verifies.
//!
//! With `--latency ROUNDS`, after the series it measures the core's latency
//! (N1.6): orders that execute, to a verified receipt; decisions through
//! Identity, Authority and Safety; and stops. Each is timed from submission to
//! answer and each answer is checked. The latency lines are the same on every
//! platform, so hosted, QEMU and seL4 runs compare.

#![forbid(unsafe_code)]

#[cfg(target_os = "hermit")]
use hermit as _;

mod channel;
mod platform;

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chitala_identity::Keypair;
use chitala_intent::{Approval, Intent, Verdict};
use chitala_model::{payload, CapabilityId, CapabilityRegistry, EntityId, ExecCode, ParamValue, Payload};
use chitala_node::{Domain, Node, NodeClient, NodeConfig, NodeEnv, Requester, Response, StoredObject, Submit};
use chitala_platform::{Endpoint, EntropyHealth, EntropyProvider, Platform, StoragePath, TimeSource, Visibility};
use chitala_resource::ResourceId;

const RULE: &str = "──────────────────────────────────────────────────────────────────────────";

/// Unix ms below which the board clock is known to be wrong (see `build.rs`).
const CLOCK_FLOOR_MS: &str = env!("CHITALA_CLOCK_FLOOR_MS");

/// `YYYY-MM-DD HH:MM UTC` for Unix milliseconds (days to civil date, H. Hinnant).
fn utc(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let z = days + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02} UTC", rem / 3600, rem % 3600 / 60)
}

fn id(s: &str) -> EntityId {
    EntityId::parse(s).expect("static ids are valid")
}

fn cap(s: &str) -> CapabilityId {
    CapabilityId::parse(s).expect("static ids are valid")
}

/// What a step must come out as.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    Allow,
    Escalate,
    /// refused at this stage of the pipeline
    Deny(Column),
    /// allowed and sent, and nobody can tell whether the device acted (spec 22)
    Unknown,
}

/// The pipeline as printed: Identity → Intent (or request) → Authority → Safety.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Column {
    Identity,
    Intent,
    Authority,
    Safety,
}

impl Column {
    /// Where a monitor stage (`Response.stage`) sits in the printed pipeline.
    fn of(stage: &str) -> Column {
        match stage {
            "envelope" | "identity" | "freshness" => Column::Identity,
            "capability" => Column::Intent,
            "safety" => Column::Safety,
            _ => Column::Authority,
        }
    }
}

struct Demo {
    domain: Domain,
    client: NodeClient,
    registry: CapabilityRegistry,
    keys: HashMap<String, Keypair>,
    step: usize,
    unexpected: usize,
}

impl Demo {
    fn now(&self) -> u64 {
        self.domain.platform.time.wall_ms()
    }

    fn key(&self, who: &str) -> Keypair {
        self.keys[who].clone()
    }

    fn requester(&self, who: &str, key_of: &str) -> Requester {
        Requester::new(id(who), self.key(key_of), id("service:native-demo"), Arc::clone(&self.domain.platform.entropy))
    }

    /// A person's signed request (CSME).
    fn request(&mut self, who: &str, target: &str, capability: &str, pl: Payload, expect: Expect) -> Response {
        self.request_as(who, who, target, capability, pl, expect, "")
    }

    /// A request claiming to come from `who`, signed with `key_of`'s key.
    #[allow(clippy::too_many_arguments)]
    fn request_as(
        &mut self,
        who: &str,
        key_of: &str,
        target: &str,
        capability: &str,
        pl: Payload,
        expect: Expect,
        note: &str,
    ) -> Response {
        let bytes = self.requester(who, key_of).sign(&self.registry, &id(target), &cap(capability), pl, self.now());
        let what = format!("{capability} @ {target}{note}");
        self.submit(who, "request", &what, &bytes, capability.starts_with("domain."), expect)
    }

    /// An agent's signed intent, with the token it was given (if any).
    fn intent(&mut self, agent: &str, person: &str, action: &str, resource: &str, token: Option<&[u8]>) -> Intent {
        let mut i = Intent::new(
            chitala_intent::new_intent_id(self.domain.platform.entropy.as_ref()),
            id(agent),
            id(person),
            cap(action),
            ResourceId::parse(resource).expect("static ids are valid"),
            self.now(),
            60_000,
        );
        i.authority = token.map(<[u8]>::to_vec);
        i
    }

    fn send_intent(&mut self, i: &Intent, expect: Expect) -> Response {
        let actor = i.actor.to_string();
        let bytes = i.sign(&self.key(&actor));
        let what = format!("{} @ {} for {}", i.action, i.resource, i.on_behalf_of);
        self.submit(&actor, "intent", &what, &bytes, false, expect)
    }

    fn approve(&mut self, who: &str, i: &Intent) -> Response {
        let now = self.now();
        let bytes = Approval {
            intent: i.id,
            intent_digest: i.digest(),
            approver: id(who),
            verdict: Verdict::Approve,
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            note: None,
        }
        .sign(&self.key(who));
        let what = format!("approves {} @ {}", i.action, i.resource);
        self.submit(who, "approval", &what, &bytes, false, Expect::Allow)
    }

    fn submit(&mut self, who: &str, kind: &str, what: &str, bytes: &[u8], domain_op: bool, expect: Expect) -> Response {
        self.step += 1;
        let r = self.client.submit(bytes).unwrap_or_else(|e| panic!("the node did not answer: {e}"));
        let (outcome, got) = if r.is_escalated() {
            ("ESCALATE", Expect::Escalate)
        } else if r.error.as_ref().is_some_and(|e| e.code == ExecCode::ExecutionUnknown) {
            ("UNKNOWN", Expect::Unknown)
        } else if r.is_ok() {
            ("ALLOW", Expect::Allow)
        } else {
            ("DENY", Expect::Deny(Column::of(r.stage.as_deref().unwrap_or("authority"))))
        };
        let ok = got == expect;
        if !ok {
            self.unexpected += 1;
        }

        // the pipeline: ✓ passed, ✗ refused here, ? waiting for a person, · not reached, – not applicable
        let reached = match got {
            Expect::Deny(c) => Some(c),
            _ => None,
        };
        let mark = |c: Column| match (reached, got) {
            (_, Expect::Escalate) if c == Column::Authority => "?",
            (_, Expect::Escalate) if c > Column::Authority => "·",
            (Some(at), _) if c == at => "✗",
            (Some(at), _) if c > at => "·",
            _ if c == Column::Safety && domain_op => "–",
            _ => "✓",
        };
        let middle = if kind == "intent" { "intent" } else { "request" };
        println!("{:>2}  {who:<14} {kind:<8} {what}", self.step);
        println!(
            "    identity {}  {middle} {}  authority {}  safety {}   → {outcome}  {}{}",
            mark(Column::Identity),
            mark(Column::Intent),
            mark(Column::Authority),
            mark(Column::Safety),
            detail(&r),
            if ok { "" } else { "   ‼ UNEXPECTED" }
        );
        r
    }

    /// N1.6, with `--latency ROUNDS`. Each round waits for the Reference
    /// Monitor's rate window to pass (it admits 30 requests per principal in
    /// 10 s, chitala-monitor's default), so no sample is a rate-limit
    /// refusal. First, ROUNDS rounds of orders (criterion 6), a minute apart,
    /// as Safety's rate rule allows (6 actuations of a resource a minute): in
    /// each, alice gives the light 6 orders (off, on) and the thermostat 6
    /// (20 °C, 21 °C). Each order is timed from submission to the node's
    /// answer, executed with its receipt verified; the platform times the same
    /// orders from their line going out to the adapter host to the receipt's
    /// line coming back ([`platform::order_times`]). Then, in each of ROUNDS
    /// rounds of decisions:
    /// - bob makes 25 decisions through the node's IPC, as a client does:
    ///   Identity, Authority and Safety, refused by the hold on the door;
    /// - alice, in even rounds (the first is round 0), makes 25 of the same
    ///   decisions submitted to the node directly on this thread: no IPC and
    ///   no other thread, the decision itself;
    /// - alice, in odd rounds, makes 12 stops through the node's IPC: a
    ///   safety hold placed on the light (timed), then lifted (not timed).
    ///
    /// Each answer is checked; a wrong one counts against the verdict.
    fn latency(&mut self, node: &Arc<Mutex<Node>>, door: &str, light: &str, light_r: &str, rounds: usize) -> Timings {
        const WINDOW: Duration = Duration::from_millis(10_100);
        // Safety lets a resource be actuated 6 times a minute (SAFE-6-RATE)
        const ORDER_WINDOW: Duration = Duration::from_millis(60_500);
        let mut t = Timings::default();
        let refused = |r: &Response| {
            !r.is_ok() && !r.is_escalated() && Column::of(r.stage.as_deref().unwrap_or("authority")) == Column::Safety
        };
        // the series' own orders are not samples
        platform::order_times();
        for round in 0..rounds {
            std::thread::sleep(ORDER_WINDOW);
            t.marks.push((format!("orders, round {round} starts"), counter()));
            for i in 0..12 {
                let n = i / 2;
                let (target, capability, pl) = if i % 2 == 0 {
                    (light, if n % 2 == 0 { "light.turn_off" } else { "light.turn_on" }, Payload::new())
                } else {
                    let celsius = payload([("celsius", ParamValue::Int(20 + i64::from(n % 2 == 1)))]);
                    ("device:thermostat", "climate.set_target_temperature", celsius)
                };
                let bytes = self.signed("person:alice", target, capability, pl);
                let start = Instant::now();
                let r = self.client.submit(&bytes).unwrap_or_else(|e| panic!("the node did not answer: {e}"));
                let took = start.elapsed().as_micros() as u64;
                if took > 100_000 {
                    t.slow.push((took, counter(), wall_us()));
                }
                t.order.push(took);
                if !r.is_ok() {
                    println!("[latency]   ✗ {capability} @ {target}: {}", detail(&r));
                }
                t.wrong += usize::from(!r.is_ok());
            }
        }
        t.channel = platform::order_times();
        if t.channel.len() != t.order.len() {
            println!("[latency]   ✗ {} orders on the channel for {} orders", t.channel.len(), t.order.len());
            t.wrong += 1;
        }
        for round in 0..rounds {
            std::thread::sleep(WINDOW);
            t.marks.push((format!("round {round} starts"), counter()));
            for _ in 0..25 {
                let bytes = self.signed("person:bob", door, "lock.lock", Payload::new());
                let start = Instant::now();
                let r = self.client.submit(&bytes).unwrap_or_else(|e| panic!("the node did not answer: {e}"));
                let took = start.elapsed().as_micros() as u64;
                if took > 100_000 {
                    t.slow.push((took, counter(), wall_us()));
                }
                t.ipc.push(took);
                t.wrong += usize::from(!refused(&r));
            }
            if round % 2 == 0 {
                for _ in 0..25 {
                    let bytes = self.signed("person:alice", door, "lock.lock", Payload::new());
                    let mut direct = Arc::clone(node);
                    let start = Instant::now();
                    let r = direct.submit(&bytes).unwrap_or_else(|e| panic!("the node did not decide: {e}"));
                    let took = start.elapsed().as_micros() as u64;
                    if took > 100_000 {
                        t.slow.push((took, counter(), wall_us()));
                    }
                    t.direct.push(took);
                    t.wrong += usize::from(!refused(&r));
                }
            } else {
                for _ in 0..12 {
                    let hold = payload([("resource", ParamValue::from(light_r)), ("reason", ParamValue::from("N1.6"))]);
                    let bytes = self.signed("person:alice", "domain:home", "domain.safety_hold", hold);
                    let start = Instant::now();
                    let r = self.client.submit(&bytes).unwrap_or_else(|e| panic!("the node did not answer: {e}"));
                    t.stop.push(start.elapsed().as_micros() as u64);
                    t.wrong += usize::from(!r.is_ok());
                    let lift = payload([("resource", ParamValue::from(light_r))]);
                    let bytes = self.signed("person:alice", "domain:home", "domain.safety_release", lift);
                    let r = self.client.submit(&bytes).unwrap_or_else(|e| panic!("the node did not answer: {e}"));
                    t.wrong += usize::from(!r.is_ok());
                }
            }
        }
        t
    }

    /// A person's request, signed now (before any timer starts).
    fn signed(&self, who: &str, target: &str, capability: &str, pl: Payload) -> Vec<u8> {
        self.requester(who, who).sign(&self.registry, &id(target), &cap(capability), pl, self.now())
    }
}

/// What N1.6 times, each sample in µs.
#[derive(Default)]
struct Timings {
    order: Vec<u64>,
    channel: Vec<u64>,
    ipc: Vec<u64>,
    direct: Vec<u64>,
    stop: Vec<u64>,
    wrong: usize,
    /// N1.6 diagnosis: each sample over 100 ms, with the virtual counter when
    /// it ended, to set it against a trace taken outside the guest
    slow: Vec<(u64, u64, u64)>,
    marks: Vec<(String, u64)>,
}

/// The wall clock in µs (N1.6 diagnosis): the same clock in every crate.
fn wall_us() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

/// The CPU's virtual counter, on Native (N1.6 diagnosis); 0 elsewhere.
fn counter() -> u64 {
    #[cfg(all(target_os = "hermit", target_arch = "aarch64"))]
    {
        use aarch64_cpu::registers::{Readable, CNTVCT_EL0};
        CNTVCT_EL0.get()
    }
    #[cfg(not(all(target_os = "hermit", target_arch = "aarch64")))]
    {
        0
    }
}

/// One latency line, and the samples sorted on the next, so that clusters
/// (a scheduler's period, a timer's tick) show.
fn report(what: &str, mut micros: Vec<u64>) {
    if micros.is_empty() {
        return;
    }
    micros.sort_unstable();
    let at = |q: usize| micros[((micros.len() - 1) * q) / 100];
    println!(
        "[latency]   {what} · n={} · median {} µs · p99 {} µs · max {} µs",
        micros.len(),
        at(50),
        at(99),
        micros[micros.len() - 1]
    );
    let all: Vec<String> = micros.iter().map(u64::to_string).collect();
    println!("[latency]   samples µs, {what}: {}", all.join(" "));
}

/// `--latency ROUNDS`: how many rounds of measurements after the series
/// (N1.6). On Hermit the arguments come from the device tree's boot arguments.
fn latency_rounds() -> Option<usize> {
    arg_value("--latency")
}

/// The positive number after `name` in the arguments, if any.
fn arg_value(name: &str) -> Option<usize> {
    let args: Vec<String> = std::env::args().collect();
    let at = args.iter().position(|a| a == name)?;
    args.get(at + 1)?.parse().ok().filter(|n| *n > 0)
}

/// One short line about the outcome.
fn detail(r: &Response) -> String {
    if r.is_escalated() {
        return format!("waiting for {}", r.approvers.as_deref().unwrap_or_default().join(" or "));
    }
    if !r.is_ok() {
        let code = r
            .code
            .map(|c| c.to_string())
            .or_else(|| r.error.as_ref().map(|e| e.code.as_str().to_string()))
            .unwrap_or_default();
        let mut why = r.reason.clone().or_else(|| r.error.as_ref().map(|e| e.message.clone())).unwrap_or_default();
        if why.chars().count() > 72 {
            why = why.chars().take(71).collect::<String>() + "…";
        }
        return format!("{code}: {why}");
    }
    let Some(res) = &r.result else { return String::new() };
    if let Some(reported) = res.get("reported").and_then(|v| v.as_object()) {
        let state: Vec<String> = reported.iter().map(|(k, v)| format!("{k}={v}")).collect();
        return format!("executed, device reports {}", state.join(" "));
    }
    if let Some(rid) = res.get("revocation_id").and_then(|v| v.as_str()) {
        return format!("token issued ({}…)", &rid[..12.min(rid.len())]);
    }
    String::new()
}

fn token_of(r: &Response) -> Vec<u8> {
    let b64 = r.result.as_ref().and_then(|v| v["token"].as_str()).expect("a delegation returns a token");
    chitala_token::bytes_from_base64(b64).expect("the node returns valid base64")
}

fn delegate(holder: &str, target: &str, capability: &str) -> Payload {
    payload([
        ("holder", ParamValue::from(holder)),
        ("target", ParamValue::from(target)),
        ("capability", ParamValue::from(capability)),
        ("ttl_s", ParamValue::Int(600)),
    ])
}

/// `chitala init` in the platform, and the node's environment.
fn boot_domain(platform: Platform) -> (Domain, NodeEnv, Vec<(EntityId, Vec<String>)>) {
    let summary = chitala_node::setup::init_domain(platform.storage.as_ref(), platform.keys.as_ref())
        .unwrap_or_else(|e| panic!("init: {e}"));
    let text = platform.storage.read(&summary.config, Visibility::Shared).expect("config readable").expect("config");
    let config: NodeConfig = serde_json::from_slice(&text).expect("config parses");
    let stored = |path: &str| {
        StoredObject::new(Arc::clone(&platform.storage), StoragePath::new(path).expect("valid storage path"))
    };
    let env = NodeEnv {
        audit_log: stored(&config.audit_log),
        state_file: stored(&config.state_file),
        policy_file: None,
        adapter_host: platform::ADAPTER_HOST.into(),
        home_assistant_env: Vec::new(),
        // no history evaluator process on Native yet: governed actions fail closed
        history_evaluator: None,
    };
    let domain = Domain { config, platform, endpoint: Endpoint::new("node").expect("valid endpoint") };
    (domain, env, summary.principals)
}

fn main() -> ExitCode {
    println!("Chitala Native spike (v0.2 step 5)");
    println!("{RULE}");

    // ── Boot ──
    let os = if cfg!(target_os = "hermit") {
        "Hermit unikernel: no Linux, Windows or macOS underneath"
    } else {
        "development host (the same program; build for aarch64-unknown-hermit to boot it)"
    };
    println!("[boot]      {}-{} · {os}", std::env::consts::ARCH, std::env::consts::OS);
    // no admitted hardware entropy provider, or one that fails its health
    // test, no keys: refuse before anything is generated (spec 20)
    let entropy = match platform::NativeEntropy::new() {
        Ok(e) => Arc::new(e),
        Err(e) => {
            println!("[boot]      ✗ no admitted hardware entropy provider: {e} · refusing to run");
            return ExitCode::from(3);
        }
    };
    let health = entropy.health();
    if let EntropyHealth::Failed(why) = &health {
        println!(
            "[boot]      ✗ the entropy provider {} failed its health test: {why} · refusing to run",
            entropy.provenance().provider_id
        );
        println!("[evidence]  {}", entropy.evidence(&health));
        return ExitCode::from(3);
    }
    // a board clock before this image's source was committed is wrong: a dead RTC
    // battery, or a clock set back to revive expired tokens. A hosted node anchors
    // its clock to the last audited event; a Native node keeps no audit across
    // boots yet, so the image carries a floor (spec 13, Hosted and Native, N6)
    let floor = CLOCK_FLOOR_MS.parse::<u64>().unwrap_or(0);
    let board = platform::NativeTime::new().wall_ms();
    if board < floor {
        println!(
            "[boot]      ✗ the board clock reads {}, before this image's floor {} · set the clock · refusing to run",
            utc(board),
            utc(floor)
        );
        return ExitCode::from(4);
    }
    let provider = entropy.provenance();
    println!(
        "[boot]      platform native-hermit · entropy: {}, {}, health ✓ · clock {} (floor {}) · keys, storage: RAM",
        provider.provider_id,
        provider.source,
        utc(board),
        utc(floor)
    );
    println!("[evidence]  {}", entropy.evidence(&health));
    let checked = platform::check_contract(&entropy);
    println!("[boot]      PAL contract (spec 18): {} ✓", checked.join(" ✓ "));

    // ── Identity ──
    let (domain, env, principals) = boot_domain(platform::platform(Arc::clone(&entropy)));
    let who: Vec<String> = principals
        .iter()
        .map(|(p, roles)| if roles.is_empty() { p.to_string() } else { format!("{p} ({})", roles.join(",")) })
        .collect();
    println!(
        "[identity]  {} · authority key, node key and {} principal keys generated in the key store",
        domain.config.domain,
        principals.len()
    );
    println!("[identity]  {}", who.join(" · "));
    let keys: HashMap<String, Keypair> = principals
        .iter()
        .map(|(p, _)| (p.to_string(), domain.keypair(p).unwrap_or_else(|e| panic!("key of {p}: {e}"))))
        .collect();

    // ── the node: Reference Monitor → Authority → Safety → Execution Boundary → adapter host ──
    let node = chitala_node::start_node(&domain, &env).unwrap_or_else(|e| panic!("node: {e}"));
    let node = Arc::new(Mutex::new(node));
    {
        let (node, domain) = (Arc::clone(&node), domain.clone());
        std::thread::spawn(move || chitala_node::ipc::serve(node, domain.platform.ipc.as_ref(), &domain.endpoint));
    }
    let client = domain.client().unwrap_or_else(|e| panic!("client: {e}"));
    let mut hello = None;
    for _ in 0..500 {
        if let Ok(v) = client.hello() {
            hello = Some(v);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let hello = hello.expect("the node answers on its endpoint");
    println!(
        "[node]      {} up · {} devices behind the execution boundary · audit log and state in RAM",
        hello["node"].as_str().unwrap_or("node"),
        domain.config.devices.len()
    );
    println!("[node]      adapter host {}", platform::adapter_host_place());
    println!("{RULE}");

    let mut d = Demo { domain, client, registry: CapabilityRegistry::core_v0_1(), keys, step: 0, unexpected: 0 };
    let light = "device:living-room-light";
    let light_r = "resource:living-room-light";
    let door = "device:front-door";
    let door_r = "resource:front-door";

    // a person acts for themselves
    d.request("person:alice", light, "light.turn_on", Payload::new(), Expect::Allow);
    // an agent impersonates its owner: the signature is not alice's
    d.request_as(
        "person:alice",
        "ai:assistant",
        door,
        "lock.unlock",
        Payload::new(),
        Expect::Deny(Column::Identity),
        "  (signed by ai:assistant)",
    );
    // an agent holds no authority until a person delegates some
    let i = d.intent("ai:assistant", "person:alice", "light.turn_off", light_r, None);
    d.send_intent(&i, Expect::Deny(Column::Authority));
    let r = d.request(
        "person:alice",
        "domain:home",
        "domain.delegate",
        delegate("ai:assistant", light_r, "light.turn_off"),
        Expect::Allow,
    );
    let light_token = token_of(&r);
    let i = d.intent("ai:assistant", "person:alice", "light.turn_off", light_r, Some(&light_token));
    d.send_intent(&i, Expect::Allow);
    // the token is for the light, and only for alice
    let i = d.intent("ai:assistant", "person:alice", "lock.unlock", door_r, Some(&light_token));
    d.send_intent(&i, Expect::Deny(Column::Authority));
    // a child may not open the front door
    d.request("person:child", door, "lock.unlock", Payload::new(), Expect::Deny(Column::Authority));
    // high risk: an agent with a token for the door still needs its owner, every time (C11)
    let r = d.request(
        "person:alice",
        "domain:home",
        "domain.delegate",
        delegate("ai:assistant", door_r, "lock.unlock"),
        Expect::Allow,
    );
    let door_token = token_of(&r);
    let i = d.intent("ai:assistant", "person:alice", "lock.unlock", door_r, Some(&door_token));
    d.send_intent(&i, Expect::Escalate);
    d.approve("person:alice", &i);
    // the capability's physical envelope (16–30 °C) holds before anyone's authority is weighed
    let too_hot = payload([("celsius", ParamValue::Int(40))]);
    d.request(
        "person:alice",
        "device:thermostat",
        "climate.set_target_temperature",
        too_hot,
        Expect::Deny(Column::Intent),
    );
    // Safety: a hold stops everyone, the owner included, until it is lifted
    let hold = payload([("resource", ParamValue::from(door_r)), ("reason", ParamValue::from("alarm armed"))]);
    d.request("person:alice", "domain:home", "domain.safety_hold", hold, Expect::Allow);
    d.request("person:bob", door, "lock.lock", Payload::new(), Expect::Deny(Column::Safety));
    // N1.4, with the adapter host in another guest: that guest takes an order
    // off the channel and disappears before it answers. The order crossed into
    // the other guest, so its fate is unknown: never "not sent" (spec 22, R1).
    // N1.6 times orders the adapter host answers, so --latency leaves R1 to N1.4
    if channel::present() && latency_rounds().is_none() {
        d.request("person:alice", light, "light.turn_on", Payload::new(), Expect::Unknown);
    }

    // ── N1.6, with --latency ROUNDS: the core's latency ──
    let mut latency_ok = true;
    if let Some(rounds) = latency_rounds() {
        println!("{RULE}");
        let t = d.latency(&node, door, light, light_r, rounds);
        report("order through the node's IPC to a verified receipt (boundary → channel → adapter → receipt)", t.order);
        report("order on the channel, out to its receipt back (channel → adapter → receipt)", t.channel);
        report("decision through the node's IPC (Identity, Authority, Safety; refused by the hold)", t.ipc);
        report("decision submitted directly on this thread (no IPC, no thread switch)", t.direct);
        report("stop through the node's IPC (a safety hold placed)", t.stop);
        for (what, at) in &t.marks {
            println!("[latency]   mark: {what} at virtual counter {at}");
        }
        for (us, at, wall) in &t.slow {
            println!(
                "[latency]   slow: {} ms, ended at virtual counter {at}, wall {}..{wall} us",
                us / 1000,
                wall - us
            );
        }
        if t.wrong > 0 {
            println!("[latency]   ✗ {} answers were not the expected ones", t.wrong);
            latency_ok = false;
        }
    }

    // ── the record ──
    println!("{RULE}");
    let node_pk = d.domain.node_public_key().expect("node key");
    let trusted = HashMap::from([(chitala_identity::key_id_of(&node_pk), node_pk)]);
    node.lock().unwrap_or_else(|p| p.into_inner()).checkpoint().expect("checkpoint");
    let audit_ok = match chitala_node::verify_audit(&env.audit_log, &trusted) {
        Ok(report) => {
            println!(
                "[audit]     {} records · hash chain ✓ · signed by the node through seq {}",
                report.records,
                report.last_signed_seq.map(|s| s.to_string()).unwrap_or_else(|| "-".into())
            );
            report.last_signed_seq.is_some()
        }
        Err(e) => {
            println!("[audit]     ✗ {e}");
            false
        }
    };
    let expected = d.step - d.unexpected;
    if d.unexpected == 0 && audit_ok && latency_ok {
        println!("[halt]      {expected}/{} decisions as expected · CHITALA NATIVE OK", d.step);
        ExitCode::SUCCESS
    } else {
        println!("[halt]      {expected}/{} decisions as expected · CHITALA NATIVE FAILED", d.step);
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::utc;

    #[test]
    fn utc_formats_civil_dates() {
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(951_782_400_000), "2000-02-29 00:00 UTC");
        assert_eq!(utc(1_790_000_000_000), "2026-09-21 14:13 UTC");
        assert_eq!(utc(4_107_542_399_000), "2100-02-28 23:59 UTC");
    }
}
