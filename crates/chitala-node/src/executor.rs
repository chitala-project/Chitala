//! Where device actions run (spec `specs/10-twin-and-events.md` §"Adapter isolation").
//!
//! The trusted core never links adapter code into its decision path. It hands a
//! node-signed [`chitala_csme::order::ExecOrder`] to an [`Executor`]:
//!
//! - [`ComponentHost`] — production: one adapter host per adapter type, run by
//!   the platform's [`ExecutionHost`] (PAL, spec 18; on hosted platforms an OS
//!   process with its own address space), reached over its private byte channel
//!   and started with exactly the environment it is granted (for Home Assistant
//!   only its token variable). A host that crashes, hangs or answers garbage is
//!   stopped and restarted (rate-limited on the platform's monotonic clock); the
//!   node answers `X_DEVICE_UNAVAILABLE` meanwhile and the Reference Monitor
//!   keeps working.
//! - [`InProcess`] — tests, the demo and fuzzing only.
//! - [`Routed`] — dispatch by device to several executors.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chitala_adapters::host::{parse_reply, AdapterHost, HostInit, HostRequest, SimChange, MAX_LINE};
use chitala_adapters::{AdapterError, Simulation};
use chitala_model::{EntityId, Payload};
use chitala_platform::{ComponentHandle, ComponentSpec, ExecutionHost, Spawned, TimeSource};

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

/// Adapters inside the node. Tests, the demo and fuzzing only: it gives up the
/// isolation that [`ComponentHost`] provides.
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

// ───────────────────────────── isolated component ─────────────────────────────

/// Minimum time between two host starts (a crash loop must not become a spawn storm).
pub const MIN_RESPAWN_INTERVAL: Duration = Duration::from_secs(1);
/// Lower bound for the init handshake: starting a component can legitimately
/// take longer than answering a request.
pub const MIN_INIT_TIMEOUT: Duration = Duration::from_secs(10);

struct Running {
    handle: Box<dyn ComponentHandle>,
    input: Box<dyn Write + Send>,
    lines: Receiver<std::io::Result<String>>,
}

impl Running {
    fn kill(mut self) {
        self.handle.kill();
    }
}

struct HostState {
    running: Option<Running>,
    /// Monotonic time of the last start.
    last_spawn_ms: Option<u64>,
    restarts: u64,
}

/// Failure of the link itself (as opposed to an error the host reported).
struct Transport(String);

/// An adapter host as a component of the platform's [`ExecutionHost`] (a
/// process on hosted platforms), reached over its private byte channel.
pub struct ComponentHost {
    exec: Arc<dyn ExecutionHost>,
    time: Arc<dyn TimeSource>,
    component: ComponentSpec,
    init_line: String,
    timeout: Duration,
    devices: Vec<EntityId>,
    state: Mutex<HostState>,
}

impl ComponentHost {
    /// Start the host and complete the init handshake. `component.env` is the
    /// host's complete environment.
    pub fn start(
        exec: Arc<dyn ExecutionHost>,
        time: Arc<dyn TimeSource>,
        component: ComponentSpec,
        init: HostInit,
        timeout: Duration,
    ) -> Result<Self, AdapterError> {
        let devices = init.devices.iter().map(|d| d.id.clone()).collect();
        let init_line = serde_json::to_string(&HostRequest::Init(init))
            .map_err(|e| AdapterError::Failed(format!("cannot encode init: {e}")))?;
        let host = Self {
            exec,
            time,
            component,
            init_line,
            timeout,
            devices,
            state: Mutex::new(HostState { running: None, last_spawn_ms: None, restarts: 0 }),
        };
        {
            let mut st = host.state.lock().map_err(|_| unavailable("adapter host link failed"))?;
            st.last_spawn_ms = Some(host.time.monotonic_ms());
            st.running = Some(host.spawn()?);
        }
        Ok(host)
    }

    /// Number of times the host had to be restarted.
    pub fn restarts(&self) -> u64 {
        self.state.lock().map(|s| s.restarts).unwrap_or(0)
    }

    /// Backend identifier of the running host, if the platform has one (tests:
    /// crash injection).
    pub fn component_id(&self) -> Option<u32> {
        self.state.lock().ok()?.running.as_ref().and_then(|r| r.handle.id())
    }

    /// Whether the platform gives the host its own address space.
    pub fn isolated(&self) -> bool {
        self.exec.isolated()
    }

    fn spawn(&self) -> Result<Running, AdapterError> {
        let Spawned { input, output, handle } = self
            .exec
            .spawn(&self.component)
            .map_err(|e| unavailable(format!("cannot start adapter host {}: {e}", self.component.program)))?;
        let (tx, rx) = mpsc::sync_channel::<std::io::Result<String>>(4);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(output);
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
        let mut running = Running { handle, input, lines: rx };
        match Self::exchange(&mut running, &self.init_line, self.timeout.max(MIN_INIT_TIMEOUT)) {
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
        writeln!(r.input, "{line}")
            .and_then(|_| r.input.flush())
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
            let now = self.time.monotonic_ms();
            if st.last_spawn_ms.is_some_and(|t| now.saturating_sub(t) < MIN_RESPAWN_INTERVAL.as_millis() as u64) {
                return Err(unavailable("adapter host is restarting"));
            }
            st.last_spawn_ms = Some(now);
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

impl Drop for ComponentHost {
    fn drop(&mut self) {
        if let Ok(mut st) = self.state.lock() {
            if let Some(r) = st.running.take() {
                r.kill();
            }
        }
    }
}

impl Executor for ComponentHost {
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
