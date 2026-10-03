//! Where device actions run (spec `specs/10-twin-and-events.md` §"Cô lập adapter").
//!
//! The trusted core never links adapter code into its decision path. It hands a
//! node-signed [`chitala_csme::order::ExecOrder`] to an [`Executor`]:
//!
//! - [`ChildHost`] — production: an adapter host *process* per adapter type,
//!   reached over the child's stdin/stdout, started with an empty environment
//!   (plus, for Home Assistant, only its token variable). A host that crashes,
//!   hangs or answers garbage is killed and restarted (rate-limited); the node
//!   answers `X_DEVICE_UNAVAILABLE` meanwhile and the Reference Monitor keeps
//!   working.
//! - [`InProcess`] — tests, the demo and fuzzing only.
//! - [`Routed`] — dispatch by device to several executors.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chitala_adapters::host::{parse_reply, AdapterHost, HostInit, HostRequest, SimChange, MAX_LINE};
use chitala_adapters::{AdapterError, Simulation};
use chitala_model::{EntityId, Payload};

pub trait Executor: Send + Sync {
    fn manages(&self, device: &EntityId) -> bool;
    /// Execute a node-signed order on `device`; returns the reported state.
    fn execute(&self, device: &EntityId, order: &[u8]) -> Result<Payload, AdapterError>;
    fn observe(&self, device: &EntityId) -> Result<Payload, AdapterError>;
    fn simulate(&self, device: &EntityId, change: &Simulation) -> Result<(), AdapterError>;
}

fn unavailable(msg: impl Into<String>) -> AdapterError {
    AdapterError::Unavailable(msg.into())
}

// ───────────────────────────── in process ─────────────────────────────

/// Adapters inside the node process. Tests, the demo and fuzzing only: it gives
/// up the isolation that [`ChildHost`] provides.
pub struct InProcess {
    host: Mutex<AdapterHost>,
}

impl InProcess {
    pub fn new(host: AdapterHost) -> Self {
        Self { host: Mutex::new(host) }
    }

    fn with<R>(&self, f: impl FnOnce(&mut AdapterHost) -> Result<R, AdapterError>) -> Result<R, AdapterError> {
        let mut h = self.host.lock().map_err(|_| unavailable("adapter host failed"))?;
        f(&mut h)
    }
}

impl Executor for InProcess {
    fn manages(&self, device: &EntityId) -> bool {
        self.host.lock().map(|h| h.manages(device)).unwrap_or(false)
    }
    fn execute(&self, device: &EntityId, order: &[u8]) -> Result<Payload, AdapterError> {
        self.with(|h| h.execute(device, order))
    }
    fn observe(&self, device: &EntityId) -> Result<Payload, AdapterError> {
        self.with(|h| h.observe(device))
    }
    fn simulate(&self, device: &EntityId, change: &Simulation) -> Result<(), AdapterError> {
        self.with(|h| h.simulate(device, change))
    }
}

// ───────────────────────────── child process ─────────────────────────────

/// Minimum time between two host starts (a crash loop must not become a fork storm).
pub const MIN_RESPAWN_INTERVAL: Duration = Duration::from_secs(1);

struct Running {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<std::io::Result<String>>,
}

impl Running {
    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct ProcState {
    running: Option<Running>,
    last_spawn: Option<Instant>,
    restarts: u64,
}

/// Failure of the link itself (as opposed to an error the host reported).
struct Transport(String);

/// An adapter host in its own process.
pub struct ChildHost {
    program: PathBuf,
    init_line: String,
    env: Vec<(String, String)>,
    timeout: Duration,
    devices: Vec<EntityId>,
    state: Mutex<ProcState>,
}

impl ChildHost {
    /// Start the host and complete the init handshake.
    pub fn start(
        program: PathBuf,
        init: HostInit,
        env: Vec<(String, String)>,
        timeout: Duration,
    ) -> Result<Self, AdapterError> {
        let devices = init.devices.iter().map(|d| d.id.clone()).collect();
        let init_line = serde_json::to_string(&HostRequest::Init(init))
            .map_err(|e| AdapterError::Failed(format!("cannot encode init: {e}")))?;
        let host = Self {
            program,
            init_line,
            env,
            timeout,
            devices,
            state: Mutex::new(ProcState { running: None, last_spawn: None, restarts: 0 }),
        };
        {
            let mut st = host.state.lock().map_err(|_| unavailable("adapter host link failed"))?;
            st.last_spawn = Some(Instant::now());
            st.running = Some(host.spawn()?);
        }
        Ok(host)
    }

    /// Number of times the host process had to be restarted.
    pub fn restarts(&self) -> u64 {
        self.state.lock().map(|s| s.restarts).unwrap_or(0)
    }

    /// Process id of the running host (tests: crash injection).
    pub fn pid(&self) -> Option<u32> {
        self.state.lock().ok()?.running.as_ref().map(|r| r.child.id())
    }

    fn spawn(&self) -> Result<Running, AdapterError> {
        let mut cmd = Command::new(&self.program);
        cmd.env_clear()
            .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd
            .spawn()
            .map_err(|e| unavailable(format!("cannot start adapter host {}: {e}", self.program.display())))?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            return Err(unavailable("adapter host has no stdio"));
        };
        let (tx, rx) = mpsc::sync_channel::<std::io::Result<String>>(4);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match (&mut reader).take(MAX_LINE as u64 + 1).read_line(&mut line) {
                    Ok(0) => break,
                    Ok(n) if n > MAX_LINE => {
                        let _ =
                            tx.send(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "reply line too long")));
                        break;
                    }
                    Ok(_) => {
                        if tx.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        break;
                    }
                }
            }
        });
        let mut running = Running { child, stdin, lines: rx };
        match Self::exchange(&mut running, &self.init_line, self.timeout) {
            Ok(Ok(_)) => Ok(running),
            Ok(Err(e)) => {
                running.kill();
                Err(e)
            }
            Err(Transport(why)) => {
                running.kill();
                Err(unavailable(format!("adapter host failed to start: {why}")))
            }
        }
    }

    fn exchange(
        r: &mut Running,
        line: &str,
        timeout: Duration,
    ) -> Result<Result<Option<Payload>, AdapterError>, Transport> {
        writeln!(r.stdin, "{line}")
            .and_then(|_| r.stdin.flush())
            .map_err(|_| Transport("adapter host is not running".into()))?;
        match r.lines.recv_timeout(timeout) {
            // a reply that does not follow the protocol means the host is broken
            Ok(Ok(reply)) => parse_reply(reply.trim_end()).map_err(|m| Transport(m.to_string())),
            Ok(Err(e)) => Err(Transport(format!("adapter host output: {e}"))),
            Err(RecvTimeoutError::Disconnected) => Err(Transport("adapter host exited".into())),
            Err(RecvTimeoutError::Timeout) => {
                Err(Transport(format!("adapter host did not answer within {} ms", timeout.as_millis())))
            }
        }
    }

    fn request(&self, req: &HostRequest) -> Result<Option<Payload>, AdapterError> {
        let line = serde_json::to_string(req).map_err(|e| AdapterError::Failed(e.to_string()))?;
        let mut st = self.state.lock().map_err(|_| unavailable("adapter host link failed"))?;
        if st.running.is_none() {
            if st.last_spawn.is_some_and(|t| t.elapsed() < MIN_RESPAWN_INTERVAL) {
                return Err(unavailable("adapter host is restarting"));
            }
            st.last_spawn = Some(Instant::now());
            st.restarts += 1;
            st.running = Some(self.spawn()?);
        }
        let running = st.running.as_mut().expect("just ensured");
        match Self::exchange(running, &line, self.timeout) {
            Ok(result) => result,
            Err(Transport(why)) => {
                if let Some(r) = st.running.take() {
                    r.kill();
                }
                Err(unavailable(format!("{why}; adapter host stopped and will be restarted")))
            }
        }
    }
}

impl Drop for ChildHost {
    fn drop(&mut self) {
        if let Ok(mut st) = self.state.lock() {
            if let Some(r) = st.running.take() {
                r.kill();
            }
        }
    }
}

impl Executor for ChildHost {
    fn manages(&self, device: &EntityId) -> bool {
        self.devices.contains(device)
    }
    fn execute(&self, device: &EntityId, order: &[u8]) -> Result<Payload, AdapterError> {
        self.request(&HostRequest::Execute { device: device.clone(), order: hex::encode(order) })?
            .ok_or_else(|| AdapterError::Failed("adapter host returned no state".into()))
    }
    fn observe(&self, device: &EntityId) -> Result<Payload, AdapterError> {
        self.request(&HostRequest::Observe { device: device.clone() })?
            .ok_or_else(|| AdapterError::Failed("adapter host returned no state".into()))
    }
    fn simulate(&self, device: &EntityId, change: &Simulation) -> Result<(), AdapterError> {
        self.request(&HostRequest::Simulate { device: device.clone(), change: SimChange::from(change) }).map(|_| ())
    }
}

// ───────────────────────────── routing ─────────────────────────────

/// Several executors, chosen by device.
#[derive(Default)]
pub struct Routed {
    routes: HashMap<EntityId, Arc<dyn Executor>>,
}

impl Routed {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, executor: Arc<dyn Executor>, devices: &[EntityId]) {
        for d in devices {
            self.routes.insert(d.clone(), Arc::clone(&executor));
        }
    }

    fn route(&self, device: &EntityId) -> Result<&Arc<dyn Executor>, AdapterError> {
        self.routes.get(device).ok_or_else(|| AdapterError::Failed(format!("no adapter host serves {device}")))
    }
}

impl Executor for Routed {
    fn manages(&self, device: &EntityId) -> bool {
        self.routes.get(device).is_some_and(|e| e.manages(device))
    }
    fn execute(&self, device: &EntityId, order: &[u8]) -> Result<Payload, AdapterError> {
        self.route(device)?.execute(device, order)
    }
    fn observe(&self, device: &EntityId) -> Result<Payload, AdapterError> {
        self.route(device)?.observe(device)
    }
    fn simulate(&self, device: &EntityId, change: &Simulation) -> Result<(), AdapterError> {
        self.route(device)?.simulate(device, change)
    }
}

/// Convenience for tests and the demo: adapters in-process behind the same
/// order gate a real adapter host uses.
pub fn in_process(
    node_key: &chitala_identity::PublicKey,
    adapters: Vec<Box<dyn chitala_adapters::DeviceAdapter>>,
    clock: crate::Clock,
) -> Arc<dyn Executor> {
    Arc::new(InProcess::new(AdapterHost::new(*node_key, adapters, clock)))
}
