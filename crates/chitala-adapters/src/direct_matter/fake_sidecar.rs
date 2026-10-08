//! A fake matter.js sidecar (spec 28): the sidecar's protocol (spec 27),
//! served in process over pipes, on a [`FakeBackend`]'s devices. It crashes
//! before or after the device acts, stalls, and sends malformed lines on
//! demand, so the matter.js backend can be put through everything a sidecar
//! can do, without Node.js or a device. Compiled for this crate's tests and
//! with the `conformance` feature; never part of a node or an adapter host.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, PipeWriter, Write};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use chitala_model::CapabilityId;
use serde_json::{json, Value};

use super::backend::{DirectMatterBackend, InvokeError, ProfileAttributes, ProfileCommand, Target};
use super::fake::FakeBackend;
use super::matter_js::{Spawn, Started, PROTOCOL};
use crate::profile::HomeProfile;

/// Where the sidecar dies during the next invoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Crash {
    /// Having read the request, before the device gets the command.
    BeforeTheDevice,
    /// After the device took the command, before answering.
    AfterTheDevice,
}

#[derive(Default)]
struct Control {
    crash_on_invoke: Option<Crash>,
    /// Answer nothing more (a hung sidecar), until cleared.
    stalled: bool,
    /// Raw lines to send next, as they are (malformed, oversized, forged).
    inject: Vec<String>,
    /// Bumped to kill the running sidecar.
    kills: u64,
    spawns: usize,
    /// Sidecars whose life is over: both their threads have ended.
    ended: usize,
    /// Injected lines written to the backend so far.
    written: usize,
    /// Every operation received, in order.
    received: Vec<String>,
    /// The same, with the number of the sidecar that received it (its spawn).
    ops: Vec<(usize, String)>,
}

/// The test's hand on the fake sidecars a spawner starts.
#[derive(Clone, Default)]
pub struct SidecarControl(Arc<Mutex<Control>>);

impl SidecarControl {
    fn get(&self) -> MutexGuard<'_, Control> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The sidecar dies during the next invoke, at `at`.
    pub fn crash_on_next_invoke(&self, at: Crash) {
        self.get().crash_on_invoke = Some(at);
    }

    /// The running sidecar dies now.
    pub fn kill(&self) {
        self.get().kills += 1;
    }

    /// The sidecar stops answering (it hangs), or answers again.
    pub fn stall(&self, stalled: bool) {
        self.get().stalled = stalled;
    }

    /// Send `line` as it is.
    pub fn inject(&self, line: impl Into<String>) {
        self.get().inject.push(line.into());
    }

    /// How many sidecars were started.
    pub fn spawns(&self) -> usize {
        self.get().spawns
    }

    /// The operations every sidecar received, in order.
    pub fn received(&self) -> Vec<String> {
        self.get().received.clone()
    }

    /// How many sidecars have ended: their requests and their reports have
    /// both stopped. A test waits on it, not on time.
    pub fn ended(&self) -> usize {
        self.get().ended
    }

    /// How many injected lines have been written to the backend. The pipe
    /// keeps order: an answer written later is read after them.
    pub fn injections_written(&self) -> usize {
        self.get().written
    }

    /// The operations sidecar `number` (its spawn, from 1) received, in order.
    pub fn ops_of(&self, number: usize) -> Vec<String> {
        self.get().ops.iter().filter(|(n, _)| *n == number).map(|(_, op)| op.clone()).collect()
    }

    /// What the fake sidecars have done, for a test's failure message.
    pub fn describe(&self) -> String {
        let c = self.get();
        let last: Vec<String> = c.ops.iter().rev().take(6).rev().map(|(n, op)| format!("#{n} {op}")).collect();
        format!(
            "sidecars: {} spawned, {} ended, {} kills; injected {} written, {} waiting; last operations: [{}]",
            c.spawns,
            c.ended,
            c.kills,
            c.written,
            c.inject.len(),
            last.join(", ")
        )
    }
}

/// Start fake sidecars on `world`, steered by `control`.
pub fn spawner(world: FakeBackend, control: SidecarControl) -> Spawn {
    Box::new(move || start(world.clone(), control.clone()))
}

/// One running fake sidecar.
struct Running {
    world: FakeBackend,
    control: SidecarControl,
    /// Its stdout; none once it died.
    out: Arc<Mutex<Option<PipeWriter>>>,
    /// The kill count when it started: a later kill is its own death.
    born: u64,
    /// Its spawn: the first sidecar is 1.
    number: usize,
    subscribed: Arc<Mutex<BTreeSet<(Target, String)>>>,
}

fn start(world: FakeBackend, control: SidecarControl) -> Result<Started, String> {
    let (from_sidecar, to_backend) = std::io::pipe().map_err(|e| e.to_string())?;
    let (from_backend, to_sidecar) = std::io::pipe().map_err(|e| e.to_string())?;
    let (born, number) = {
        let mut c = control.get();
        c.spawns += 1;
        (c.kills, c.spawns)
    };
    let running = Arc::new(Running {
        world,
        control,
        out: Arc::new(Mutex::new(Some(to_backend))),
        born,
        number,
        subscribed: Arc::new(Mutex::new(BTreeSet::new())),
    });
    let r = Arc::clone(&running);
    std::thread::spawn(move || {
        // the requests end with the sidecar: its stdin closes with this thread
        let mut lines = BufReader::new(from_backend).lines();
        while let Some(Ok(line)) = lines.next() {
            if !r.alive() {
                return;
            }
            r.handle(&line);
        }
        r.die();
    });
    let r = Arc::clone(&running);
    std::thread::spawn(move || r.report());
    Ok(Started { reader: Box::new(from_sidecar), writer: Box::new(to_sidecar), child: None })
}

fn target_of(v: &Value) -> Option<Target> {
    Some(Target { node: v["node"].as_str()?.parse().ok()?, endpoint: u16::try_from(v["endpoint"].as_u64()?).ok()? })
}

impl Running {
    fn alive(&self) -> bool {
        let killed = self.control.get().kills != self.born;
        if killed {
            self.die();
        }
        !killed && self.out.lock().is_ok_and(|o| o.is_some())
    }

    fn die(&self) {
        if let Ok(mut out) = self.out.lock() {
            out.take();
        }
    }

    fn send(&self, v: &Value) {
        self.send_raw(&v.to_string());
    }

    fn send_raw(&self, line: &str) {
        if let Ok(mut out) = self.out.lock() {
            if let Some(w) = out.as_mut() {
                if writeln!(w, "{line}").is_err() {
                    out.take();
                }
            }
        }
    }

    fn handle(&self, line: &str) {
        let Ok(v) = serde_json::from_str::<Value>(line) else { return };
        let id = v["id"].clone();
        let op = v["op"].as_str().unwrap_or_default().to_string();
        {
            let mut c = self.control.get();
            c.received.push(op.clone());
            c.ops.push((self.number, op.clone()));
        }
        if self.control.get().stalled {
            return;
        }
        let profile = HomeProfile::v0_1();
        let class = v["class"].as_str().and_then(|c| profile.class(c));
        let answer = match (op.as_str(), target_of(&v["target"]), class) {
            ("Hello", _, _) => json!({"ok": {"protocol": PROTOCOL, "mode": "serve",
                "profile": format!("{}@{}", profile.name(), profile.version()), "fabric": {"nodes": 1}}}),
            ("SubscribeProfileAttributes", Some(t), Some(c)) => {
                match self.world.subscribe(t, &ProfileAttributes::of_class(c)) {
                    Ok(()) => {
                        if let Ok(mut s) = self.subscribed.lock() {
                            s.insert((t, c.class.clone()));
                        }
                        json!({"ok": {}})
                    }
                    Err(e) => json!({"error": {"kind": "refused", "message": e}}),
                }
            }
            ("ReadProfileAttributes", Some(t), Some(c)) => match self.world.read(t, &ProfileAttributes::of_class(c)) {
                Ok(values) => json!({"ok": {"values": raw(&values)}}),
                Err(e) => json!({"error": {"kind": "read", "message": e}}),
            },
            ("InvokeProfileCommand", Some(t), Some(c)) => {
                let command = v["capability"]
                    .as_str()
                    .and_then(|cap| CapabilityId::parse(cap).ok())
                    .and_then(|cap| ProfileCommand::of(c, &cap));
                let Some(command) = command else {
                    self.send(&json!({"id": id, "error": {"kind": "refused", "message": "not the profile's"}}));
                    return;
                };
                let crash = self.control.get().crash_on_invoke.take();
                if crash == Some(Crash::BeforeTheDevice) {
                    self.die();
                    return;
                }
                let result = self.world.invoke(t, &command);
                if crash == Some(Crash::AfterTheDevice) {
                    self.die();
                    return;
                }
                match result {
                    Ok(()) => json!({"ok": {}}),
                    Err(InvokeError::NotSent(m)) => json!({"error": {"kind": "not_sent", "message": m}}),
                    Err(InvokeError::Rejected(m)) => json!({"error": {"kind": "refused", "message": m}}),
                    Err(InvokeError::Status { status, cluster_status }) => json!({"error": {"kind": "status",
                        "message": "status", "status": status, "cluster_status": cluster_status}}),
                    Err(InvokeError::Indeterminate(m)) => {
                        json!({"error": {"kind": "indeterminate", "message": m}})
                    }
                }
            }
            _ => json!({"error": {"kind": "refused", "message": "not an operation of serve mode"}}),
        };
        let mut answer = answer;
        answer["id"] = id;
        self.send(&answer);
    }

    /// The subscription's events, as the real sidecar sends them: the link
    /// going up or down, changed values, and keep-alives.
    fn report(&self) {
        let mut live: BTreeMap<Target, bool> = BTreeMap::new();
        let mut last: BTreeMap<Target, Value> = BTreeMap::new();
        while self.alive() {
            let injected = std::mem::take(&mut self.control.get().inject);
            for line in injected {
                self.send_raw(&line);
                self.control.get().written += 1;
            }
            let stalled = self.control.get().stalled;
            let targets: Vec<Target> =
                self.subscribed.lock().map(|s| s.iter().map(|(t, _)| *t).collect()).unwrap_or_default();
            for t in targets {
                if stalled {
                    break;
                }
                let Some(s) = self.world.subscribed(t) else { continue };
                let node = t.node.to_string();
                let interval = s.max_interval.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                if live.insert(t, s.live) != Some(s.live) {
                    self.send(&json!({"event": "link", "node": node, "live": s.live, "max_interval_ms": interval}));
                }
                if !s.live || !self.world.world().nodes.get(&t.node).is_some_and(|n| n.alive && !n.quiet) {
                    continue;
                }
                let values = Value::Array(raw(&s.values));
                if last.get(&t) != Some(&values) {
                    self.send(&json!({"event": "values", "node": node, "endpoint": t.endpoint, "values": values}));
                    last.insert(t, values);
                }
                self.send(&json!({"event": "heard", "node": node, "max_interval_ms": interval}));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// A sidecar's life ends when both its threads have let it go.
impl Drop for Running {
    fn drop(&mut self) {
        self.control.get().ended += 1;
    }
}

fn raw(values: &super::backend::Values) -> Vec<Value> {
    values.iter().map(|(p, v)| json!([p.cluster(), p.attribute(), v])).collect()
}
