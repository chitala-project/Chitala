//! Where device actions run (spec `specs/10-twin-and-events.md` §"Adapter isolation").
//!
//! The trusted core never links adapter code into its decision path. It hands a
//! [`MintedOrder`] — the only thing an executor accepts, and only the Trusted
//! Execution Boundary can make one (spec 19) — to an [`Executor`]:
//!
//! - [`ComponentHost`] — production: one adapter host per adapter type, run by
//!   the platform's [`ExecutionHost`] (PAL, spec 18; on hosted platforms an OS
//!   process with its own address space), reached over its private byte channel
//!   and started with exactly the environment it is granted (for Home Assistant
//!   only its token variable). A host that crashes, hangs or answers garbage is
//!   stopped and restarted (rate-limited on the platform's monotonic clock); the
//!   node answers `X_DEVICE_UNAVAILABLE` meanwhile and the Reference Monitor
//!   keeps working. Every instance gets its own executor session; orders are
//!   bound to it, so an order can never be executed by another host or by a
//!   restarted one (whose replay set is empty).
//! - [`InProcess`] — tests, the demo and fuzzing only.
//! - [`Routed`] — dispatch by device to several executors.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chitala_adapters::home_assistant::HomeAssistantConfig;
use chitala_adapters::host::{parse_reply, AdapterHost, HostInit, HostReply, HostRequest, SimChange, MAX_LINE};
use chitala_adapters::{AdapterError, Observed, Provenance, Simulation};
use chitala_boundary::{ExecutorSession, MintedOrder, TrustedExecutionBoundary};
use chitala_csme::order::ExecutionReceipt;
use chitala_identity::PublicKey;
use chitala_model::{DeviceDescriptor, EntityId, Payload};
use chitala_platform::{random_array, ComponentHandle, ComponentSpec, Entropy, ExecutionHost, Spawned, TimeSource};

/// What an executed order came back with. The receipt is the adapter host's
/// claim; the node trusts the state only after `chitala_boundary::verify_receipt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executed {
    pub state: Payload,
    pub receipt: Option<ExecutionReceipt>,
    /// For an observation: how old the state is, if its adapter can tell (F9).
    pub age_ms: Option<u64>,
    /// For an observation: whether its adapter confirmed it current (F9b).
    pub provenance: Provenance,
}

impl Executed {
    /// What an executed order reported: no age, no confirmation.
    pub fn reported(state: Payload, receipt: Option<ExecutionReceipt>) -> Self {
        Self { state, receipt, age_ms: None, provenance: Provenance::Uncertain }
    }
}

/// The adapter host instance that will execute the next order for a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    pub executor: ExecutorSession,
    /// The order key that instance accepts.
    pub order_key: PublicKey,
}

pub trait Executor: Send + Sync {
    fn manages(&self, device: &EntityId) -> bool;
    /// The session to bind an order for `device` to.
    fn session(&self, device: &EntityId) -> Option<Session>;
    /// Execute a minted order on `device`, consuming it.
    fn execute(&self, device: &EntityId, order: MintedOrder) -> Result<Executed, AdapterError>;
    /// The device's state, and how old it is (finding F9).
    fn observe(&self, device: &EntityId) -> Result<Observed, AdapterError>;
    /// [`Executor::observe`] for evidence of what an order did: its adapter
    /// also tries to confirm the state is current (finding F9b).
    fn observe_evidence(&self, device: &EntityId) -> Result<Observed, AdapterError> {
        self.observe(device)
    }
    fn simulate(&self, device: &EntityId, change: &Simulation) -> Result<(), AdapterError>;
    /// The adapters whose host is not running now: their devices are
    /// unavailable, and orders to them are not sent.
    fn unavailable(&self) -> Vec<String> {
        Vec::new()
    }
}

fn unavailable(msg: impl Into<String>) -> AdapterError {
    AdapterError::Unavailable(msg.into())
}

// ───────────────────────────── in process ─────────────────────────────

/// Adapters inside the node. Tests, the demo and fuzzing only: it gives up the
/// isolation that [`ComponentHost`] provides.
pub struct InProcess {
    host: Mutex<AdapterHost>,
    session: Session,
}

impl InProcess {
    /// `order_key` must be the key `host` was built with.
    pub fn new(host: AdapterHost, order_key: PublicKey) -> Self {
        let session = Session { executor: *host.executor(), order_key };
        Self { host: Mutex::new(host), session }
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
    fn session(&self, device: &EntityId) -> Option<Session> {
        self.manages(device).then_some(self.session)
    }
    fn execute(&self, device: &EntityId, order: MintedOrder) -> Result<Executed, AdapterError> {
        let (state, receipt) = self.with(|h| h.execute(device, order.bytes()))?;
        Ok(Executed::reported(state, Some(receipt)))
    }
    fn observe(&self, device: &EntityId) -> Result<Observed, AdapterError> {
        self.with(|h| h.observe(device))
    }
    fn observe_evidence(&self, device: &EntityId) -> Result<Observed, AdapterError> {
        self.with(|h| h.observe_evidence(device))
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
    /// Session of the running instance, or of the next one to start. A new
    /// one is drawn whenever an instance stops: its orders die with it.
    session: ExecutorSession,
    /// Monotonic time of the last start.
    last_spawn_ms: Option<u64>,
    restarts: u64,
}

/// Failure of the link itself (as opposed to an error the host reported).
struct Transport {
    why: String,
    /// The request line was written to the host: it may have taken it.
    taken: bool,
}

impl Transport {
    fn before(why: impl Into<String>) -> Self {
        Self { why: why.into(), taken: false }
    }
    fn after(why: impl Into<String>) -> Self {
        Self { why: why.into(), taken: true }
    }
}

/// What an adapter host is started with.
pub struct HostSpec {
    pub component: ComponentSpec,
    pub devices: Vec<DeviceDescriptor>,
    pub home_assistant: Option<HomeAssistantConfig>,
    pub matter: Option<chitala_adapters::direct_matter::DirectMatterConfig>,
    /// The order key of the node's Trusted Execution Boundary.
    pub order_key: PublicKey,
    pub timeout: Duration,
}

/// An adapter host as a component of the platform's [`ExecutionHost`] (a
/// process on hosted platforms), reached over its private byte channel.
pub struct ComponentHost {
    exec: Arc<dyn ExecutionHost>,
    time: Arc<dyn TimeSource>,
    entropy: Arc<dyn Entropy>,
    spec: HostSpec,
    device_ids: Vec<EntityId>,
    state: Mutex<HostState>,
}

impl ComponentHost {
    /// Start the host and complete the init handshake. `spec.component.env` is
    /// the host's complete environment.
    pub fn start(
        exec: Arc<dyn ExecutionHost>,
        time: Arc<dyn TimeSource>,
        entropy: Arc<dyn Entropy>,
        spec: HostSpec,
    ) -> Result<Self, AdapterError> {
        match Self::start_or_stopped(exec, time, entropy, spec) {
            (host, None) => Ok(host),
            (_, Some(e)) => Err(e),
        }
    }

    /// [`ComponentHost::start`], except that a host that does not come up is
    /// returned stopped, with the reason. Its devices are then unavailable:
    /// orders to them are not sent. A later request starts it again, at most
    /// once per [`MIN_RESPAWN_INTERVAL`] and always in a new session, so an
    /// order minted for an earlier session is never sent to it.
    pub fn start_or_stopped(
        exec: Arc<dyn ExecutionHost>,
        time: Arc<dyn TimeSource>,
        entropy: Arc<dyn Entropy>,
        spec: HostSpec,
    ) -> (Self, Option<AdapterError>) {
        let device_ids = spec.devices.iter().map(|d| d.id.clone()).collect();
        let session = random_array(entropy.as_ref());
        let host = Self {
            exec,
            time,
            entropy,
            spec,
            device_ids,
            state: Mutex::new(HostState { running: None, session, last_spawn_ms: None, restarts: 0 }),
        };
        let failed = match host.state.lock() {
            Ok(mut st) => {
                st.last_spawn_ms = Some(host.time.monotonic_ms());
                match host.spawn(st.session) {
                    Ok(running) => {
                        st.running = Some(running);
                        None
                    }
                    Err(e) => {
                        host.stopped(&mut st);
                        Some(e)
                    }
                }
            }
            Err(_) => Some(unavailable("adapter host link failed")),
        };
        (host, failed)
    }

    /// The adapter this host serves.
    pub fn adapter(&self) -> &str {
        self.spec.devices.first().map(|d| d.adapter.as_str()).unwrap_or_default()
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

    fn init_line(&self, session: &ExecutorSession) -> Result<String, AdapterError> {
        let init = HostInit {
            order_key: hex::encode(self.spec.order_key),
            executor: hex::encode(session),
            devices: self.spec.devices.clone(),
            home_assistant: self.spec.home_assistant.clone(),
            matter: self.spec.matter.clone(),
        };
        serde_json::to_string(&HostRequest::Init(init))
            .map_err(|e| AdapterError::Failed(format!("cannot encode init: {e}")))
    }

    fn spawn(&self, session: ExecutorSession) -> Result<Running, AdapterError> {
        let init_line = self.init_line(&session)?;
        let Spawned { input, output, handle } = self
            .exec
            .spawn(&self.spec.component)
            .map_err(|e| unavailable(format!("cannot start adapter host {}: {e}", self.spec.component.program)))?;
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
        match Self::exchange(&mut running, &init_line, self.spec.timeout.max(MIN_INIT_TIMEOUT)) {
            Ok(Ok(_)) => Ok(running),
            Ok(Err(e)) => {
                running.kill();
                Err(e)
            }
            Err(Transport { why, .. }) => {
                running.kill();
                Err(unavailable(format!("adapter host failed to start: {why}")))
            }
        }
    }

    fn exchange(r: &mut Running, line: &str, timeout: Duration) -> Result<Result<HostReply, AdapterError>, Transport> {
        writeln!(r.input, "{line}")
            .and_then(|_| r.input.flush())
            .map_err(|_| Transport::before("adapter host is not running"))?;
        match r.lines.recv_timeout(timeout) {
            // a reply that does not follow the protocol means the host is broken
            Ok(Ok(reply)) => parse_reply(reply.trim_end()).map_err(|m| Transport::after(m.to_string())),
            Ok(Err(e)) => Err(Transport::after(format!("adapter host output: {e}"))),
            Err(RecvTimeoutError::Disconnected) => Err(Transport::after("adapter host exited")),
            Err(RecvTimeoutError::Timeout) => {
                Err(Transport::after(format!("adapter host did not answer within {} ms", timeout.as_millis())))
            }
        }
    }

    /// The instance stopped: its session (and every order bound to it) retires.
    fn stopped(&self, st: &mut HostState) {
        if let Some(r) = st.running.take() {
            r.kill();
        }
        st.session = random_array(self.entropy.as_ref());
    }

    /// Send one request. With `order_session`, the request carries an order
    /// bound to that session: if the instance it was minted for is gone, the
    /// order is not sent at all. Once the host has taken an order, a host that
    /// dies, hangs or answers outside the protocol leaves the order's fate
    /// unknown (`X_EXECUTION_UNKNOWN`): it may have acted. Only an order that
    /// never reached the host is unavailable (concurrency audit R1).
    fn request(&self, req: &HostRequest, order_session: Option<&ExecutorSession>) -> Result<HostReply, AdapterError> {
        let line = serde_json::to_string(req).map_err(|e| AdapterError::Failed(e.to_string()))?;
        let mut st = self.state.lock().map_err(|_| unavailable("adapter host link failed"))?;
        if st.running.is_none() {
            let now = self.time.monotonic_ms();
            if st.last_spawn_ms.is_some_and(|t| now.saturating_sub(t) < MIN_RESPAWN_INTERVAL.as_millis() as u64) {
                return Err(unavailable("adapter host is restarting"));
            }
            st.last_spawn_ms = Some(now);
            st.restarts += 1;
            match self.spawn(st.session) {
                Ok(r) => st.running = Some(r),
                Err(e) => {
                    self.stopped(&mut st);
                    return Err(e);
                }
            }
        }
        if order_session.is_some_and(|s| s != &st.session) {
            return Err(unavailable("adapter host was restarted after the order was issued; order not sent"));
        }
        let running = st.running.as_mut().expect("just ensured");
        match Self::exchange(running, &line, self.spec.timeout) {
            Ok(result) => result,
            Err(Transport { why, taken }) => {
                self.stopped(&mut st);
                if taken && order_session.is_some() {
                    Err(AdapterError::Indeterminate(format!(
                        "the adapter host took the order, then: {why}; it may have executed; \
                         the host was stopped and will be restarted"
                    )))
                } else {
                    Err(unavailable(format!("{why}; adapter host stopped and will be restarted")))
                }
            }
        }
    }

    fn observe_as(&self, device: &EntityId, evidence: bool) -> Result<Observed, AdapterError> {
        let reply = self.request(&HostRequest::Observe { device: device.clone(), evidence }, None)?;
        let provenance = reply.provenance();
        let state = reply.state.ok_or_else(|| AdapterError::Failed("adapter host returned no state".into()))?;
        Ok(Observed { state, age_ms: reply.age_ms, provenance })
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
        self.device_ids.contains(device)
    }
    fn session(&self, device: &EntityId) -> Option<Session> {
        if !self.manages(device) {
            return None;
        }
        let executor = self.state.lock().ok()?.session;
        Some(Session { executor, order_key: self.spec.order_key })
    }
    fn execute(&self, device: &EntityId, order: MintedOrder) -> Result<Executed, AdapterError> {
        let session = *order.expectation().executor();
        let req = HostRequest::Execute { device: device.clone(), order: hex::encode(order.bytes()) };
        let reply = self.request(&req, Some(&session))?;
        let state = reply.state.ok_or_else(|| AdapterError::Failed("adapter host returned no state".into()))?;
        Ok(Executed::reported(state, reply.receipt))
    }
    fn observe(&self, device: &EntityId) -> Result<Observed, AdapterError> {
        self.observe_as(device, false)
    }
    fn observe_evidence(&self, device: &EntityId) -> Result<Observed, AdapterError> {
        self.observe_as(device, true)
    }
    fn simulate(&self, device: &EntityId, change: &Simulation) -> Result<(), AdapterError> {
        self.request(&HostRequest::Simulate { device: device.clone(), change: SimChange::from(change) }, None)
            .map(|_| ())
    }
    fn unavailable(&self) -> Vec<String> {
        match self.state.lock() {
            Ok(st) if st.running.is_some() => Vec::new(),
            _ => vec![self.adapter().to_string()],
        }
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
    fn session(&self, device: &EntityId) -> Option<Session> {
        self.routes.get(device)?.session(device)
    }
    fn execute(&self, device: &EntityId, order: MintedOrder) -> Result<Executed, AdapterError> {
        self.route(device)?.execute(device, order)
    }
    fn observe(&self, device: &EntityId) -> Result<Observed, AdapterError> {
        self.route(device)?.observe(device)
    }
    fn observe_evidence(&self, device: &EntityId) -> Result<Observed, AdapterError> {
        self.route(device)?.observe_evidence(device)
    }
    fn simulate(&self, device: &EntityId, change: &Simulation) -> Result<(), AdapterError> {
        self.route(device)?.simulate(device, change)
    }
    fn unavailable(&self) -> Vec<String> {
        let mut down: Vec<String> = self.routes.values().flat_map(|e| e.unavailable()).collect();
        down.sort();
        down.dedup();
        down
    }
}

/// Convenience for tests and the demo: adapters in-process behind the same
/// order gate a real adapter host uses, accepting orders of `boundary`. Each
/// call is a separate instance with its own executor session.
pub fn in_process(
    boundary: &TrustedExecutionBoundary,
    adapters: Vec<Box<dyn chitala_adapters::DeviceAdapter>>,
    clock: crate::Clock,
) -> Arc<dyn Executor> {
    static INSTANCES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = INSTANCES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    use sha2::{Digest, Sha256};
    let order_key = boundary.order_key();
    let digest: [u8; 32] = Sha256::new().chain_update(order_key).chain_update(n.to_be_bytes()).finalize().into();
    let mut session = [0u8; 16];
    session.copy_from_slice(&digest[..16]);
    Arc::new(InProcess::new(AdapterHost::new(order_key, session, adapters, clock), order_key))
}
