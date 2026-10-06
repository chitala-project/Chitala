//! The matter.js backend (spec 27): Chitala's Matter controller sidecar
//! (`sidecars/matter-js`), a child process spoken to over its stdio with the
//! sidecar's typed protocol. No socket, no network API.
//!
//! - **Its own fabric.** The sidecar keeps Chitala's fabric in a private
//!   directory, which this backend claims exclusively for as long as it
//!   runs: a second sidecar on the same fabric cannot start.
//! - **Typed requests.** Built from the profile's paths only; the sidecar
//!   checks them again against its own copy of the profile.
//! - **What a failure says.** A request line that could not be written was
//!   certainly not sent. Once written, a command whose answer does not come
//!   (a timeout, or the sidecar dying) has an unknown fate.
//! - **The subscription.** The sidecar reports values, keep-alives and the
//!   link's state as events; the backend keeps them per target.
//! - **A sidecar that dies, or hangs** (it does not answer in time), is
//!   stopped and started again at most every [`RESPAWN_EVERY`], and its
//!   devices are subscribed again.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::backend::{
    DirectMatterBackend, InvokeError, ProfileAttribute, ProfileAttributes, ProfileCommand, Subscribed, Target, Values,
};
use crate::profile::HomeProfile;

/// The sidecar protocol's version this backend speaks.
pub const PROTOCOL: u64 = 1;
/// The longest line read from the sidecar.
const MAX_LINE: u64 = 256 * 1024;
/// A sidecar that died is not started again sooner than this.
pub const RESPAWN_EVERY: Duration = Duration::from_secs(5);

/// How long the backend waits for the sidecar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Hello, subscribe, read.
    pub call: Duration,
    /// An invoke: longer than matter.js gives a silent device (13.5 s, step
    /// ⑤ spike), shorter than the node gives the adapter host.
    pub invoke: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self { call: Duration::from_secs(12), invoke: Duration::from_secs(20) }
    }
}

/// How the sidecar is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sidecar {
    /// The Node.js runtime.
    pub runtime: PathBuf,
    /// The sidecar's entry point (`sidecars/matter-js/src/main.ts`).
    pub entry: PathBuf,
    /// Chitala's fabric: a private directory.
    pub storage: PathBuf,
    pub subscription_ceiling_s: u32,
}

impl Sidecar {
    /// Claim the fabric's storage for this process: a second sidecar on the
    /// same fabric cannot start (as one node per domain, R2). The storage
    /// must be a private directory; it is created so if missing.
    pub fn claim(&self) -> Result<File, String> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
        let s = &self.storage;
        if !s.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(s)
                .map_err(|e| format!("{}: {e}", s.display()))?;
        }
        let meta = std::fs::metadata(s).map_err(|e| format!("{}: {e}", s.display()))?;
        if !meta.is_dir() || meta.mode() & 0o077 != 0 {
            return Err(format!("{}: Chitala's fabric must be in a private directory (0700)", s.display()));
        }
        let lock = s.with_extension("lock");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&lock)
            .map_err(|e| format!("{}: {e}", lock.display()))?;
        f.try_lock().map_err(|_| format!("{}: Chitala's fabric is in use by another process", s.display()))?;
        Ok(f)
    }

    fn command(&self, mode: &str) -> Command {
        let mut c = Command::new(&self.runtime);
        c.arg(&self.entry)
            .arg(mode)
            .arg("--storage")
            .arg(&self.storage)
            .arg("--subscription-ceiling")
            .arg(self.subscription_ceiling_s.to_string())
            // nothing of the host's environment: matter.js reads options from it
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        c
    }
}

/// A sidecar just started: what it writes, what it reads, and its process
/// if it has one.
pub struct Started {
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    pub child: Option<Child>,
}

/// Starts a serving sidecar: the matter.js process, or a test's own.
pub type Spawn = Box<dyn Fn() -> Result<Started, String> + Send + Sync>;

impl Sidecar {
    /// Start this sidecar in serve mode.
    pub fn serve(&self) -> Result<Started, String> {
        let mut child = self.command("serve").spawn().map_err(|e| format!("cannot start the sidecar: {e}"))?;
        let writer = Box::new(child.stdin.take().ok_or("the sidecar has no stdin")?);
        let reader = Box::new(child.stdout.take().ok_or("the sidecar has no stdout")?);
        Ok(Started { reader, writer, child: Some(child) })
    }
}

/// An answer to a request.
enum Answer {
    Ok(Value),
    Error(Value),
}

/// Why a request got no answer.
enum Failure {
    /// The line could not be written: the sidecar never saw it.
    NotWritten(String),
    /// Written, and no answer came.
    NoAnswer(String),
}

struct Sub {
    attributes: ProfileAttributes,
    values: BTreeMap<ProfileAttribute, Value>,
    last_heard: Option<Instant>,
    live: bool,
    max_interval: Option<Duration>,
}

impl Sub {
    fn new(attributes: ProfileAttributes) -> Self {
        Self { attributes, values: BTreeMap::new(), last_heard: None, live: false, max_interval: None }
    }
}

struct Link {
    writer: Box<dyn Write + Send>,
    child: Option<Child>,
    /// Bumped when the link is replaced: a reader of an older link stops.
    generation: u64,
}

struct Inner {
    link: Mutex<Option<Link>>,
    pending: Mutex<BTreeMap<u64, Sender<Answer>>>,
    subs: Mutex<BTreeMap<Target, Sub>>,
    next_id: AtomicU64,
    generation: AtomicU64,
}

/// The matter.js backend.
pub struct MatterJsBackend {
    inner: Arc<Inner>,
    /// How a dead sidecar is started again; none for a sidecar given once.
    spawn: Option<Spawn>,
    timeouts: Timeouts,
    respawned: Mutex<Option<Instant>>,
    /// Held for the backend's life: the fabric's storage claim.
    _claim: Option<File>,
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl MatterJsBackend {
    /// Start the sidecar in serve mode on Chitala's fabric, and check that it
    /// speaks this protocol with this profile.
    pub fn spawn(sidecar: Sidecar, timeouts: Timeouts) -> Result<Self, String> {
        let claim = sidecar.claim()?;
        Self::with(Box::new(move || sidecar.serve()), timeouts, Some(claim))
    }

    /// A backend on sidecars started by `spawn`, again whenever one dies
    /// (tests start their own).
    pub fn with(spawn: Spawn, timeouts: Timeouts, claim: Option<File>) -> Result<Self, String> {
        let backend = Self {
            inner: Arc::new(Inner::new()),
            spawn: Some(spawn),
            timeouts,
            respawned: Mutex::new(None),
            _claim: claim,
        };
        backend.start()?;
        Ok(backend)
    }

    /// A backend on a sidecar already running at the other end of `reader`
    /// and `writer` (tests).
    pub fn over(
        reader: impl Read + Send + 'static,
        writer: impl Write + Send + 'static,
        timeouts: Timeouts,
    ) -> Result<Self, String> {
        let backend =
            Self { inner: Arc::new(Inner::new()), spawn: None, timeouts, respawned: Mutex::new(None), _claim: None };
        backend.attach(Box::new(reader), Box::new(writer), None);
        backend.hello()?;
        Ok(backend)
    }

    fn start(&self) -> Result<(), String> {
        let spawn = self.spawn.as_ref().ok_or("no sidecar to start")?;
        let Started { reader, writer, child } = spawn()?;
        self.attach(reader, writer, child);
        self.hello()?;
        // the devices it served before
        let subs: Vec<(Target, ProfileAttributes)> =
            guard(&self.inner.subs).iter().map(|(t, s)| (*t, s.attributes.clone())).collect();
        for (target, attributes) in subs {
            self.subscribe(target, &attributes)?;
        }
        Ok(())
    }

    fn attach(&self, reader: Box<dyn Read + Send>, writer: Box<dyn Write + Send>, child: Option<Child>) {
        let generation = self.inner.generation.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(mut old) = guard(&self.inner.link).replace(Link { writer, child, generation }) {
            stop(&mut old);
        }
        let inner = Arc::clone(&self.inner);
        std::thread::spawn(move || inner.read_events(reader, generation));
    }

    fn hello(&self) -> Result<(), String> {
        let ok = match self.request(json!({"op": "Hello"}), self.timeouts.call) {
            Ok(Answer::Ok(v)) => v,
            Ok(Answer::Error(e)) => return Err(format!("the sidecar refused hello: {e}")),
            Err(Failure::NotWritten(why) | Failure::NoAnswer(why)) => return Err(why),
        };
        let profile = HomeProfile::v0_1();
        let ours = format!("{}@{}", profile.name(), profile.version());
        if ok["protocol"].as_u64() != Some(PROTOCOL) || ok["mode"] != "serve" || ok["profile"] != ours.as_str() {
            return Err(format!("the sidecar is not a serving one of protocol {PROTOCOL} on {ours}: {ok}"));
        }
        Ok(())
    }

    /// Start a dead sidecar again, at most every [`RESPAWN_EVERY`].
    fn revive(&self) {
        if self.spawn.is_none() || guard(&self.inner.link).is_some() {
            return;
        }
        let mut last = guard(&self.respawned);
        if last.is_some_and(|t| t.elapsed() < RESPAWN_EVERY) {
            return;
        }
        *last = Some(Instant::now());
        drop(last);
        let _ = self.start();
    }

    /// Send one request and wait for its answer.
    fn request(&self, mut body: Value, timeout: Duration) -> Result<Answer, Failure> {
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        body["id"] = json!(id);
        let (tx, rx) = channel();
        guard(&self.inner.pending).insert(id, tx);
        let written = {
            let mut link = guard(&self.inner.link);
            match link.as_mut() {
                None => Err("the sidecar is not running".to_string()),
                Some(l) => writeln!(l.writer, "{body}").and_then(|()| l.writer.flush()).map_err(|e| e.to_string()),
            }
        };
        if let Err(why) = written {
            guard(&self.inner.pending).remove(&id);
            return Err(Failure::NotWritten(format!("the sidecar could not be reached: {why}")));
        }
        match rx.recv_timeout(timeout) {
            Ok(answer) => Ok(answer),
            Err(RecvTimeoutError::Timeout) => {
                guard(&self.inner.pending).remove(&id);
                // a sidecar that does not answer in time is hung: it is
                // stopped, and the next call starts another
                if self.spawn.is_some() {
                    if let Some(mut l) = guard(&self.inner.link).take() {
                        stop(&mut l);
                    }
                    for s in guard(&self.inner.subs).values_mut() {
                        s.live = false;
                    }
                }
                Err(Failure::NoAnswer(format!("the sidecar did not answer in {timeout:?}")))
            }
            Err(RecvTimeoutError::Disconnected) => Err(Failure::NoAnswer("the sidecar stopped".into())),
        }
    }
}

/// The sidecar in admin mode, for `chitala matter`: it commissions devices
/// onto Chitala's fabric, lists and removes them. It claims the fabric's
/// storage like a serving sidecar, so it runs only while no node serves the
/// fabric. One request at a time; events are not read.
pub struct MatterJsAdmin {
    child: Child,
    writer: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
    next_id: u64,
    _claim: File,
}

impl MatterJsAdmin {
    /// Start the sidecar in admin mode. `accept_test_attestation` lets it
    /// commission development devices that carry test certificates (a lab
    /// only, never a home).
    pub fn spawn(sidecar: &Sidecar, accept_test_attestation: bool) -> Result<Self, String> {
        let claim = sidecar.claim()?;
        let mut command = sidecar.command("admin");
        if accept_test_attestation {
            command.arg("--accept-test-attestation");
        }
        let mut child = command.spawn().map_err(|e| format!("cannot start the sidecar: {e}"))?;
        let writer = child.stdin.take().ok_or("the sidecar has no stdin")?;
        let reader = BufReader::new(child.stdout.take().ok_or("the sidecar has no stdout")?);
        let mut admin = Self { child, writer, reader, next_id: 1, _claim: claim };
        let ok = admin.call(json!({"op": "Hello"}))?;
        let profile = HomeProfile::v0_1();
        let ours = format!("{}@{}", profile.name(), profile.version());
        if ok["protocol"].as_u64() != Some(PROTOCOL) || ok["mode"] != "admin" || ok["profile"] != ours.as_str() {
            return Err(format!("the sidecar is not an admin one of protocol {PROTOCOL} on {ours}: {ok}"));
        }
        Ok(admin)
    }

    /// One request, and its answer.
    fn call(&mut self, mut body: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        body["id"] = json!(id);
        writeln!(self.writer, "{body}").and_then(|()| self.writer.flush()).map_err(|e| format!("the sidecar: {e}"))?;
        loop {
            let mut line = String::new();
            let n = (&mut self.reader).take(MAX_LINE + 1).read_line(&mut line).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("the sidecar stopped".into());
            }
            let Ok(v) = serde_json::from_str::<Value>(line.trim()) else { continue };
            if v["id"].as_u64() != Some(id) {
                continue;
            }
            return match v.get("ok") {
                Some(ok) => Ok(ok.clone()),
                None => Err(why(&v["error"])),
            };
        }
    }

    /// Commission the device that `code` (a manual pairing code, or a QR
    /// code `MT:…`) opens onto Chitala's fabric: its node id.
    pub fn commission(&mut self, code: &str) -> Result<u64, String> {
        let ok = self.call(json!({"op": "CommissionDevice", "code": code}))?;
        ok["node"].as_str().and_then(|n| n.parse().ok()).ok_or_else(|| format!("no node id in {ok}"))
    }

    /// The fabric's devices: each node's endpoints and their device types.
    pub fn devices(&mut self) -> Result<Value, String> {
        Ok(self.call(json!({"op": "ListDevices"}))?["devices"].clone())
    }

    /// Remove a node from Chitala's fabric, and Chitala's fabric from it.
    pub fn remove(&mut self, node: u64) -> Result<(), String> {
        self.call(json!({"op": "RemoveDevice", "node": node.to_string()})).map(|_| ())
    }
}

impl Drop for MatterJsAdmin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl std::fmt::Debug for MatterJsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatterJsBackend")
            .field("respawns", &self.spawn.is_some())
            .field("running", &guard(&self.inner.link).is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for MatterJsBackend {
    fn drop(&mut self) {
        if let Some(mut l) = guard(&self.inner.link).take() {
            stop(&mut l);
        }
    }
}

fn stop(link: &mut Link) {
    if let Some(child) = link.child.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Inner {
    fn new() -> Self {
        Self {
            link: Mutex::new(None),
            pending: Mutex::new(BTreeMap::new()),
            subs: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            generation: AtomicU64::new(0),
        }
    }

    /// The sidecar's lines, until it stops: answers to their requests,
    /// events to the subscriptions.
    fn read_events(&self, reader: Box<dyn Read + Send>, generation: u64) {
        let mut reader = BufReader::new(reader);
        loop {
            let mut line = String::new();
            match (&mut reader).take(MAX_LINE + 1).read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(n) if n as u64 > MAX_LINE => break,
                Ok(_) => {}
            }
            let Ok(v) = serde_json::from_str::<Value>(line.trim()) else { continue };
            if let Some(event) = v["event"].as_str() {
                self.event(event, &v);
            } else if let Some(id) = v["id"].as_u64() {
                if let Some(tx) = guard(&self.pending).remove(&id) {
                    let _ = tx.send(match v.get("ok") {
                        Some(ok) => Answer::Ok(ok.clone()),
                        None => Answer::Error(v["error"].clone()),
                    });
                }
            }
        }
        // the sidecar is gone: nothing more is heard, and nothing pending will be answered
        let mut link = guard(&self.link);
        if link.as_ref().is_some_and(|l| l.generation == generation) {
            if let Some(mut l) = link.take() {
                stop(&mut l);
            }
            drop(link);
            guard(&self.pending).clear();
            for s in guard(&self.subs).values_mut() {
                s.live = false;
            }
        }
    }

    fn event(&self, event: &str, v: &Value) {
        let Some(node) = v["node"].as_str().and_then(|n| n.parse::<u64>().ok()) else { return };
        let now = Instant::now();
        let mut subs = guard(&self.subs);
        // the interval the device agreed to, as the sidecar learns it
        if let Some(ms) = v["max_interval_ms"].as_u64() {
            for (_, s) in subs.iter_mut().filter(|(t, _)| t.node == node) {
                s.max_interval = Some(Duration::from_millis(ms));
            }
        }
        match event {
            "values" => {
                let Some(endpoint) = v["endpoint"].as_u64().and_then(|e| u16::try_from(e).ok()) else { return };
                let Some(s) = subs.get_mut(&Target { node, endpoint }) else { return };
                for item in v["values"].as_array().into_iter().flatten() {
                    let (Some(c), Some(a)) = (item[0].as_u64(), item[1].as_u64()) else { continue };
                    // only what this target was subscribed to
                    let wanted = s
                        .attributes
                        .attributes()
                        .iter()
                        .find(|p| u64::from(p.cluster()) == c && u64::from(p.attribute()) == a);
                    if let Some(p) = wanted {
                        s.values.insert(*p, item[2].clone());
                        s.last_heard = Some(now);
                    }
                }
            }
            "heard" => {
                for (_, s) in subs.iter_mut().filter(|(t, _)| t.node == node) {
                    s.last_heard = Some(now);
                }
            }
            "link" => {
                let live = v["live"] == true;
                for (_, s) in subs.iter_mut().filter(|(t, _)| t.node == node) {
                    s.live = live;
                    if live {
                        s.last_heard = Some(now);
                    }
                }
            }
            _ => {}
        }
    }
}

fn target_json(t: Target) -> Value {
    json!({"node": t.node.to_string(), "endpoint": t.endpoint})
}

fn attributes_json(a: &ProfileAttributes) -> Value {
    Value::Array(a.attributes().iter().map(|p| json!([p.cluster(), p.attribute()])).collect())
}

fn why(e: &Value) -> String {
    let m: String = e["message"].as_str().unwrap_or_default().chars().take(300).collect();
    format!("{} ({})", m, e["kind"].as_str().unwrap_or("error"))
}

impl DirectMatterBackend for MatterJsBackend {
    fn subscribe(&self, target: Target, attributes: &ProfileAttributes) -> Result<(), String> {
        guard(&self.inner.subs).entry(target).or_insert_with(|| Sub::new(attributes.clone())).attributes =
            attributes.clone();
        let body = json!({"op": "SubscribeProfileAttributes", "target": target_json(target),
            "class": attributes.class(), "attributes": attributes_json(attributes)});
        match self.request(body, self.timeouts.call) {
            Ok(Answer::Ok(_)) => Ok(()),
            Ok(Answer::Error(e)) => Err(why(&e)),
            Err(Failure::NotWritten(w) | Failure::NoAnswer(w)) => Err(w),
        }
    }

    fn read(&self, target: Target, attributes: &ProfileAttributes) -> Result<Values, String> {
        self.revive();
        let body = json!({"op": "ReadProfileAttributes", "target": target_json(target),
            "class": attributes.class(), "attributes": attributes_json(attributes)});
        let ok = match self.request(body, self.timeouts.call) {
            Ok(Answer::Ok(ok)) => ok,
            Ok(Answer::Error(e)) => return Err(why(&e)),
            Err(Failure::NotWritten(w) | Failure::NoAnswer(w)) => return Err(w),
        };
        let values: Values = ok["values"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| {
                let (c, a) = (item[0].as_u64()?, item[1].as_u64()?);
                let p = attributes
                    .attributes()
                    .iter()
                    .find(|p| u64::from(p.cluster()) == c && u64::from(p.attribute()) == a)?;
                Some((*p, item[2].clone()))
            })
            .collect();
        if values.is_empty() {
            return Err("the device answered none of the attributes".into());
        }
        if let Some(s) = guard(&self.inner.subs).get_mut(&target) {
            s.last_heard = Some(Instant::now());
        }
        Ok(values)
    }

    fn invoke(&self, target: Target, command: &ProfileCommand) -> Result<(), InvokeError> {
        self.revive();
        let body = json!({"op": "InvokeProfileCommand", "target": target_json(target), "class": command.class(),
            "capability": command.capability().as_str(), "cluster": command.cluster(),
            "command": command.command(), "timed": command.timed()});
        match self.request(body, self.timeouts.invoke) {
            Ok(Answer::Ok(_)) => Ok(()),
            Ok(Answer::Error(e)) => Err(match e["kind"].as_str() {
                Some("not_sent") => InvokeError::NotSent(why(&e)),
                Some("refused") => InvokeError::Rejected(why(&e)),
                Some("status") => InvokeError::Status {
                    status: e["status"].as_u64().and_then(|s| u8::try_from(s).ok()).unwrap_or(0x01),
                    cluster_status: e["cluster_status"].as_u64().and_then(|s| u8::try_from(s).ok()),
                },
                // "indeterminate", or anything this backend does not know
                _ => InvokeError::Indeterminate(why(&e)),
            }),
            Err(Failure::NotWritten(w)) => Err(InvokeError::NotSent(w)),
            Err(Failure::NoAnswer(w)) => {
                Err(InvokeError::Indeterminate(format!("{w}; the command may have been sent")))
            }
        }
    }

    fn subscribed(&self, target: Target) -> Option<Subscribed> {
        self.revive();
        let subs = guard(&self.inner.subs);
        let s = subs.get(&target)?;
        let last_heard = s.last_heard?;
        Some(Subscribed {
            values: s.values.iter().map(|(p, v)| (*p, v.clone())).collect(),
            last_heard,
            live: s.live,
            max_interval: s.max_interval,
        })
    }
}

#[cfg(test)]
#[path = "matter_js_tests.rs"]
mod tests;
