//! The WebSocket link to Home Assistant (spec 25).
//!
//! One thread owns the connection:
//!
//! ```text
//! connect ─▶ auth ─▶ subscribe to state_changed ─▶ bootstrap (get_states) ─▶ live
//!    ▲                                                                         │
//!    └──── backoff ◀──── lost: not live, pending calls indeterminate ◀─────────┘
//! ```
//!
//! While live, the link keeps the latest state of every configured entity,
//! pushed by Home Assistant. Events older than the state it holds, or equal to
//! it, are ignored, so duplicates and reordering never move a state backwards.
//! When the link is not live it holds no state at all: an observation then
//! goes to the REST API, or fails. Nothing is ever kept as a state that was
//! not reported.
//!
//! A service call is written to the socket at most once. If the connection
//! breaks, or no result arrives in time, after the call was written, the
//! answer is [`CallError::Indeterminate`]: it may have executed. Nothing here
//! retries a call; Chitala's outcome verification observes the world and
//! decides (spec 22).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tungstenite::client::IntoClientRequest;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

/// How long the link waits for what.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// TCP connect, the WebSocket handshake and authentication.
    pub connect: Duration,
    /// A service call's result.
    pub call: Duration,
    /// How often the link thread looks at its queue between reads.
    pub poll: Duration,
    /// A ping after this much silence; no pong within `call` ends the connection.
    pub ping_every: Duration,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    /// After Home Assistant rejects the token: how long before it is presented
    /// again, doubling from `auth_min` up to `auth_max` ([`AuthGate`]).
    pub auth_min: Duration,
    pub auth_max: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            call: Duration::from_secs(10),
            poll: Duration::from_millis(100),
            ping_every: Duration::from_secs(20),
            min_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            auth_min: Duration::from_secs(5),
            auth_max: Duration::from_secs(600),
        }
    }
}

/// Why a service call over the link did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// The call was never written to the socket: it did not execute.
    NotSent(String),
    /// The call was written, then the connection broke or no result came in
    /// time: it may have executed.
    Indeterminate(String),
    /// Home Assistant answered that it did not run the call.
    Refused(String),
}

/// Home Assistant counts every request and WebSocket login with a rejected
/// token as a failed login, and with `login_attempts_threshold` set it bans the
/// address for good. So once it has rejected the token, the link and the REST
/// client wait before presenting it again (from `auth_min`, doubling up to
/// `auth_max`) and answer at once in between: nothing is sent. Any accepted
/// login opens the gate again.
#[derive(Debug, Clone)]
pub struct AuthGate(Arc<Mutex<Gate>>);

#[derive(Debug)]
struct Gate {
    closed_until: Option<Instant>,
    delay: Duration,
    min: Duration,
    max: Duration,
}

impl AuthGate {
    pub fn new(t: &Timing) -> Self {
        Self(Arc::new(Mutex::new(Gate { closed_until: None, delay: t.auth_min, min: t.auth_min, max: t.auth_max })))
    }

    fn gate(&self) -> std::sync::MutexGuard<'_, Gate> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `Err` with the time left before the token may be presented again.
    pub fn check(&self) -> Result<(), Duration> {
        match self.gate().closed_until {
            Some(until) if Instant::now() < until => Err(until - Instant::now()),
            _ => Ok(()),
        }
    }

    /// Home Assistant rejected the token.
    pub fn rejected(&self) {
        let mut g = self.gate();
        let now = Instant::now();
        g.delay = match g.closed_until {
            // closed already by a request that raced this one
            Some(until) if now < until => return,
            Some(_) => (g.delay * 2).min(g.max),
            None => g.min,
        };
        g.closed_until = Some(now + g.delay);
    }

    /// Home Assistant accepted the token.
    pub fn accepted(&self) {
        let mut g = self.gate();
        g.closed_until = None;
        g.delay = g.min;
    }
}

struct Call {
    domain: String,
    service: String,
    data: Value,
    entity: String,
    reply: Sender<Result<(), CallError>>,
}

#[derive(Debug, Default)]
struct Cache {
    live: bool,
    /// Bumped on every connection: a state from an earlier one is never served.
    generation: u64,
    /// Entity → its state, its `last_updated`, the connection it came on, and
    /// when the link heard it pushed (`None` for a state from the bootstrap:
    /// how old it is, nobody can tell).
    states: BTreeMap<String, (Value, String, u64, Option<Instant>)>,
    /// `get_states` succeeded on this connection: the states held from it are
    /// Home Assistant's whole inventory of the entities the link watches.
    inventory: bool,
    /// Entities Home Assistant reported removed on this connection.
    removed: BTreeSet<String>,
    last_error: Option<String>,
    connections: u64,
}

impl Cache {
    /// Keep `state` for `entity` unless it is not newer than what is held from
    /// this connection (a duplicate, or an event that arrived out of order).
    fn update(&mut self, entity: &str, state: Value, heard: Option<Instant>) {
        let updated = state.get("last_updated").and_then(Value::as_str).unwrap_or_default().to_string();
        if let Some((_, held, generation, _)) = self.states.get(entity) {
            if *generation == self.generation && updated <= *held {
                return;
            }
        }
        self.removed.remove(entity);
        self.states.insert(entity.to_string(), (state, updated, self.generation, heard));
    }
}

/// The link: a thread that keeps one connection to Home Assistant.
pub struct Link {
    calls: Sender<Call>,
    cache: Arc<Mutex<Cache>>,
    gate: AuthGate,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    timing: Timing,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link").field("live", &self.live()).finish_non_exhaustive()
    }
}

impl Link {
    /// Start the link to `ws_url` (`ws://…/api/websocket` or `wss://…`) for
    /// `entities`. It connects in the background.
    pub fn start(ws_url: String, token: String, entities: BTreeSet<String>, timing: Timing) -> Self {
        let (calls, queue) = mpsc::channel();
        let cache = Arc::new(Mutex::new(Cache::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let gate = AuthGate::new(&timing);
        let thread = {
            let (cache, stop, gate) = (Arc::clone(&cache), Arc::clone(&stop), gate.clone());
            std::thread::Builder::new()
                .name("chitala-ha-link".into())
                .spawn(move || run(&ws_url, &token, &entities, &cache, &queue, &stop, &gate, timing))
                .ok()
        };
        Self { calls, cache, gate, stop, thread, timing }
    }

    /// The gate this link shares with the REST client ([`AuthGate`]).
    pub fn gate(&self) -> &AuthGate {
        &self.gate
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Subscribed and bootstrapped on the current connection.
    pub fn live(&self) -> bool {
        self.cache().live
    }

    /// How many connections reached the live state so far.
    pub fn connections(&self) -> u64 {
        self.cache().connections
    }

    pub fn last_error(&self) -> Option<String> {
        self.cache().last_error.clone()
    }

    /// The latest state of `entity` pushed on the current connection; `None`
    /// when the link is not live or has not heard of it.
    pub fn state(&self, entity: &str) -> Option<Value> {
        self.observed(entity).map(|(state, _)| state)
    }

    /// [`Link::state`] and how long ago the link heard it pushed: `None` for a
    /// state from the bootstrap, whose age nobody can tell (finding F9).
    pub fn observed(&self, entity: &str) -> Option<(Value, Option<u64>)> {
        let c = self.cache();
        let (state, _, generation, heard) = c.states.get(entity)?;
        let age = heard.map(|at| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX));
        (c.live && *generation == c.generation).then(|| (state.clone(), age))
    }

    /// Whether Home Assistant has `entity`, by what it said on the current
    /// connection. `Some(false)` only when the link is live, `get_states`
    /// succeeded on this connection, and the entity was neither in it nor
    /// reported since, or was reported removed. `None` when that is not known
    /// (no live link, no inventory yet, or one that failed): absence is never
    /// inferred from anything less (v0.3 step ③A, finding F2).
    pub fn has(&self, entity: &str) -> Option<bool> {
        let c = self.cache();
        if !(c.live && c.inventory) {
            return None;
        }
        if c.removed.contains(entity) {
            return Some(false);
        }
        Some(c.states.get(entity).is_some_and(|(_, _, generation, _)| *generation == c.generation))
    }

    /// Call `domain.service` on `entity`, written to the socket at most once.
    pub fn call(&self, domain: &str, service: &str, data: Value, entity: &str) -> Result<(), CallError> {
        let (reply, answer) = mpsc::channel();
        let call =
            Call { domain: domain.to_string(), service: service.to_string(), data, entity: entity.to_string(), reply };
        self.calls.send(call).map_err(|_| CallError::NotSent("the link has stopped".into()))?;
        // the link thread answers every call it takes; the margin covers its own timeout
        match answer.recv_timeout(self.timing.call + self.timing.connect) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => {
                Err(CallError::Indeterminate("no answer from the Home Assistant link in time".into()))
            }
            Err(RecvTimeoutError::Disconnected) => {
                Err(CallError::Indeterminate("the Home Assistant link stopped while calling".into()))
            }
        }
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

#[allow(clippy::too_many_arguments)]
fn run(
    url: &str,
    token: &str,
    entities: &BTreeSet<String>,
    cache: &Mutex<Cache>,
    queue: &Receiver<Call>,
    stop: &AtomicBool,
    gate: &AuthGate,
    t: Timing,
) {
    let mut backoff = t.min_backoff;
    while !stop.load(Ordering::SeqCst) {
        // a rejected token is not presented again before the gate opens
        let reached_live = match gate.check() {
            Ok(()) => session(url, token, entities, cache, queue, stop, gate, t),
            Err(wait) => {
                idle(queue, stop, t, wait);
                continue;
            }
        };
        {
            let mut c = cache.lock().unwrap_or_else(|p| p.into_inner());
            c.live = false;
            if let Err(e) = &reached_live {
                c.last_error = Some(e.clone());
            }
        }
        if stop.load(Ordering::SeqCst) {
            break;
        }
        if matches!(reached_live, Ok(true)) {
            backoff = t.min_backoff;
        }
        idle(queue, stop, t, backoff);
        backoff = (backoff * 2).min(t.max_backoff);
    }
    while let Ok(call) = queue.try_recv() {
        let _ = call.reply.send(Err(CallError::NotSent("the link has stopped".into())));
    }
}

/// Wait `wait` while down: calls are answered at once, they were never sent.
fn idle(queue: &Receiver<Call>, stop: &AtomicBool, t: Timing, wait: Duration) {
    let until = Instant::now() + wait;
    while Instant::now() < until && !stop.load(Ordering::SeqCst) {
        while let Ok(call) = queue.try_recv() {
            let _ = call.reply.send(Err(CallError::NotSent("Home Assistant is not connected".into())));
        }
        std::thread::sleep(t.poll.min(until.saturating_duration_since(Instant::now())));
    }
}

fn connect(url: &str, t: Timing) -> Result<Socket, String> {
    let request = url.into_client_request().map_err(|e| format!("bad Home Assistant URL: {e}"))?;
    let host = request.uri().host().unwrap_or_default().trim_matches(['[', ']']).to_string();
    let tls = request.uri().scheme_str() == Some("wss");
    let port = request.uri().port_u16().unwrap_or(if tls { 443 } else { 80 });
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("cannot resolve {host}"))?;
    let tcp = TcpStream::connect_timeout(&addr, t.connect).map_err(|e| format!("cannot connect to {addr}: {e}"))?;
    tcp.set_read_timeout(Some(t.connect)).map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(t.connect)).map_err(|e| e.to_string())?;
    tcp.set_nodelay(true).map_err(|e| e.to_string())?;
    let (ws, _) = tungstenite::client_tls_with_config(request, tcp, None, None)
        .map_err(|e| format!("WebSocket handshake failed: {e}"))?;
    Ok(ws)
}

fn set_poll(ws: &Socket, poll: Duration) {
    let tcp = match ws.get_ref() {
        MaybeTlsStream::Plain(s) => s,
        MaybeTlsStream::Rustls(s) => s.get_ref(),
        _ => return,
    };
    let _ = tcp.set_read_timeout(Some(poll));
}

fn send(ws: &mut Socket, v: &Value) -> Result<(), String> {
    ws.send(Message::Text(v.to_string().into())).map_err(|e| format!("send failed: {e}"))
}

/// Read one JSON message, or `None` on a read timeout.
fn read(ws: &mut Socket) -> Result<Option<Value>, String> {
    match ws.read() {
        Ok(Message::Text(text)) => {
            serde_json::from_str(text.as_str()).map(Some).map_err(|e| format!("bad JSON from Home Assistant: {e}"))
        }
        Ok(Message::Close(_)) => Err("Home Assistant closed the connection".into()),
        Ok(_) => Ok(None),
        Err(tungstenite::Error::Io(e))
            if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
        {
            Ok(None)
        }
        Err(e) => Err(format!("connection lost: {e}")),
    }
}

/// Wait for the message that answers `pred`, within `within`.
fn expect(ws: &mut Socket, within: Duration, pred: impl Fn(&Value) -> bool) -> Result<Value, String> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Some(v) = read(ws)? {
            if pred(&v) {
                return Ok(v);
            }
        }
    }
    Err("Home Assistant did not answer in time".into())
}

fn kind(v: &Value) -> &str {
    v.get("type").and_then(Value::as_str).unwrap_or_default()
}

/// One connection, from connect to loss. `Ok(true)` if it reached the live
/// state, `Ok(false)` if it was stopped before; `Err` says why it ended.
#[allow(clippy::too_many_arguments)]
fn session(
    url: &str,
    token: &str,
    entities: &BTreeSet<String>,
    cache: &Mutex<Cache>,
    queue: &Receiver<Call>,
    stop: &AtomicBool,
    gate: &AuthGate,
    t: Timing,
) -> Result<bool, String> {
    let mut ws = connect(url, t)?;
    expect(&mut ws, t.connect, |v| kind(v) == "auth_required")?;
    send(&mut ws, &json!({"type": "auth", "access_token": token}))?;
    let auth = expect(&mut ws, t.connect, |v| matches!(kind(v), "auth_ok" | "auth_invalid"))?;
    if kind(&auth) != "auth_ok" {
        gate.rejected();
        return Err("Home Assistant rejected the access token".into());
    }
    gate.accepted();
    send(&mut ws, &json!({"id": 1, "type": "subscribe_events", "event_type": "state_changed"}))?;
    let mut early_events = Vec::new();
    let subscribed = expect(&mut ws, t.connect, |v| v["id"] == 1 && kind(v) == "result")?;
    if subscribed["success"] != true {
        return Err("Home Assistant refused the subscription".into());
    }
    send(&mut ws, &json!({"id": 2, "type": "get_states"}))?;
    let deadline = Instant::now() + t.connect;
    let states = loop {
        if Instant::now() >= deadline {
            return Err("Home Assistant did not send its states in time".into());
        }
        match read(&mut ws)? {
            Some(v) if v["id"] == 2 && kind(&v) == "result" => break v,
            Some(v) if kind(&v) == "event" => early_events.push((v, Instant::now())),
            _ => {}
        }
    };
    {
        let mut c = cache.lock().unwrap_or_else(|p| p.into_inner());
        c.generation += 1;
        c.inventory = states["success"] == true && states["result"].is_array();
        c.removed.clear();
        for s in states["result"].as_array().into_iter().flatten() {
            if let Some(e) = s["entity_id"].as_str().filter(|e| entities.contains(*e)) {
                c.update(e, s.clone(), None);
            }
        }
        for (v, heard) in &early_events {
            on_event(&mut c, entities, v, *heard);
        }
        c.live = true;
        c.connections += 1;
        c.last_error = None;
    }
    set_poll(&ws, t.poll);

    let mut next_id: u64 = 3;
    let mut pending: HashMap<u64, (Sender<Result<(), CallError>>, Instant)> = HashMap::new();
    let mut last_heard = Instant::now();
    let mut ping: Option<(u64, Instant)> = None;
    let ended = loop {
        if stop.load(Ordering::SeqCst) {
            break Ok(true);
        }
        let mut broken = None;
        while let Ok(call) = queue.try_recv() {
            let id = next_id;
            next_id += 1;
            let msg = json!({
                "id": id,
                "type": "call_service",
                "domain": call.domain,
                "service": call.service,
                "service_data": call.data,
                "target": {"entity_id": call.entity},
            });
            match send(&mut ws, &msg) {
                Ok(()) => {
                    pending.insert(id, (call.reply, Instant::now() + t.call));
                }
                Err(e) => {
                    // a frame may have left before the error: it may have executed
                    let _ = call.reply.send(Err(CallError::Indeterminate(format!("{e} while sending the command"))));
                    broken = Some(e);
                    break;
                }
            }
        }
        if let Some(e) = broken {
            break Err(e);
        }
        match read(&mut ws) {
            Ok(Some(v)) => {
                last_heard = Instant::now();
                match kind(&v) {
                    "event" => {
                        on_event(&mut cache.lock().unwrap_or_else(|p| p.into_inner()), entities, &v, Instant::now())
                    }
                    "pong" => ping = None,
                    "result" => {
                        if let Some((reply, _)) = v["id"].as_u64().and_then(|id| pending.remove(&id)) {
                            let _ = reply.send(result_of(&v));
                        }
                    }
                    _ => {}
                }
            }
            Ok(None) => {}
            Err(e) => break Err(e),
        }
        let now = Instant::now();
        let late: Vec<u64> = pending.iter().filter(|(_, (_, d))| now >= *d).map(|(id, _)| *id).collect();
        for id in late {
            if let Some((reply, _)) = pending.remove(&id) {
                let why = "no result from Home Assistant in time; the command may have executed";
                let _ = reply.send(Err(CallError::Indeterminate(why.into())));
            }
        }
        match ping {
            Some((_, sent)) if now.duration_since(sent) > t.call => break Err("no pong from Home Assistant".into()),
            None if now.duration_since(last_heard) > t.ping_every => {
                let id = next_id;
                next_id += 1;
                if let Err(e) = send(&mut ws, &json!({"id": id, "type": "ping"})) {
                    break Err(e);
                }
                ping = Some((id, now));
            }
            _ => {}
        }
    };
    // no longer live before anyone hears of the loss: a state from a
    // connection that is going away is never served
    cache.lock().unwrap_or_else(|p| p.into_inner()).live = false;
    for (_, (reply, _)) in pending {
        let why = "the connection to Home Assistant was lost after the command was sent; it may have executed";
        let _ = reply.send(Err(CallError::Indeterminate(why.into())));
    }
    let _ = ws.close(None);
    ended
}

fn on_event(c: &mut Cache, entities: &BTreeSet<String>, v: &Value, heard: Instant) {
    let data = &v["event"]["data"];
    let Some(entity) = data["entity_id"].as_str().filter(|e| entities.contains(*e)) else { return };
    match &data["new_state"] {
        // the entity was removed: unknown from now on, never its old state
        Value::Null => {
            c.states.insert(
                entity.to_string(),
                (json!({"state": "unavailable"}), String::new(), c.generation, Some(heard)),
            );
            c.removed.insert(entity.to_string());
        }
        s => c.update(entity, s.clone(), Some(heard)),
    }
}

/// A call's result. Home Assistant says it did not run a call it could not
/// find, could not parse, or refused to validate; any other error may have
/// come after it started, so it may have executed.
fn result_of(v: &Value) -> Result<(), CallError> {
    if v["success"] == true {
        return Ok(());
    }
    let code = v["error"]["code"].as_str().unwrap_or("unknown_error");
    let message: String = v["error"]["message"].as_str().unwrap_or_default().chars().take(200).collect();
    match code {
        "not_found" | "invalid_format" | "service_validation_error" | "unauthorized" => {
            Err(CallError::Refused(format!("Home Assistant did not run the call ({code}): {message}")))
        }
        _ => Err(CallError::Indeterminate(format!(
            "Home Assistant failed the call ({code}): {message}; it may have executed"
        ))),
    }
}
