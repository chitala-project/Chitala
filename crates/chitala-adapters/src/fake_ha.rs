//! A deterministic fake Home Assistant for tests (spec 25): its WebSocket and
//! REST APIs over loopback, with fault injection — lost connections, restarts,
//! silence, refused and unanswered calls, transitional, jammed and unavailable
//! states, duplicate and out-of-order events — and its entity registry and
//! Matter devices that answer or have died. Compiled only for this crate's
//! tests and with the `fake-ha` feature (other crates' tests); never part of a
//! node or an adapter host.

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// The access token the fake accepts.
pub const TOKEN: &str = "fake-ha-token";

/// What the fake does when it is asked to run a service.
#[derive(Debug, Clone, PartialEq)]
pub enum Behaviour {
    /// The device does it at once.
    Instant,
    /// A lock passes through `locking`/`unlocking` first; `settle` finishes.
    Moving,
    /// Home Assistant accepts the call, the device does nothing.
    Stuck,
    /// The device does it, then the connection breaks before the result.
    LoseAfterSend,
    /// The connection breaks before the result, and the device does it a
    /// moment later (1.2 s), as a motor does: its state arrives afterwards.
    LoseThenSlowEffect,
    /// The connection breaks before the result, and the device did nothing.
    LoseWithoutEffect,
    /// The device does it, the connection breaks before the result, and Home
    /// Assistant goes down: nothing can be observed until it is back.
    LoseAndDie,
    /// Home Assistant answers with an error of this code; nothing happens.
    Error(&'static str),
    /// No result ever comes.
    Silent,
    /// Home Assistant accepts the call and the device drops off: `unavailable`.
    DropsOff,
}

#[derive(Default)]
pub struct World {
    pub states: BTreeMap<String, Value>,
    /// The last timestamp handed out (µs since the epoch): they only go up.
    pub tick: u64,
    pub behaviour: BTreeMap<String, Behaviour>,
    /// Every service call that reached Home Assistant: (service, entity, transport).
    pub calls: Vec<(String, String, &'static str)>,
    /// Effects still on their way: when, which entity, which state.
    pub delayed: Vec<(Instant, String, String)>,
    pub rest_reads: u64,
    pub ws_up: bool,
    pub rest_up: bool,
    pub answer_pings: bool,
    /// Bumped to close every open WebSocket (a restart).
    pub restarts: u64,
    /// How many times a WebSocket client asked for every state (a bootstrap).
    pub bootstraps: u64,
    /// The token accepted now (an owner can revoke one or issue another).
    pub token: String,
    /// Requests and WebSocket logins with a token Home Assistant rejected. Home
    /// Assistant counts each one as a failed login, and may ban the address
    /// after `login_attempts_threshold` of them.
    pub rejected_logins: u64,
    /// `get_states` answers with an error (an inventory nobody can rely on).
    pub fail_get_states: bool,
    /// The entity registry's entries (entity → entry); an entity left out
    /// has none, as Home Assistant's demo locks do not.
    pub registry: BTreeMap<String, Value>,
    /// `config/entity_registry/get_entries` answers with an error.
    pub fail_registry: bool,
    /// How many times a client read the registry.
    pub registry_reads: u64,
    /// Matter devices (Home Assistant device id) → whether they answer.
    pub matter_nodes: BTreeMap<String, bool>,
    /// Every `matter/interview_node`, by device id.
    pub interviews: Vec<String>,
    /// A Matter device that answers takes this long.
    pub answer_after: Duration,
    pub subscribers: Vec<Sender<Value>>,
}

impl World {
    fn stamp(&mut self) -> String {
        // real UTC time, as Home Assistant writes it, never twice the same
        self.tick = now_us().max(self.tick + 1);
        iso_us(self.tick)
    }

    pub fn set(&mut self, entity: &str, state: &str, attributes: Value) -> Value {
        let stamp = self.stamp();
        let s = json!({
            "entity_id": entity,
            "state": state,
            "attributes": attributes,
            "last_changed": stamp.clone(),
            "last_updated": stamp.clone(),
            "last_reported": stamp,
        });
        self.states.insert(entity.into(), s.clone());
        let event = json!({"type": "event", "event": {"event_type": "state_changed",
            "data": {"entity_id": entity, "new_state": s}}});
        self.broadcast(event);
        s
    }

    pub fn broadcast(&mut self, event: Value) {
        self.subscribers.retain(|s| s.send(event.clone()).is_ok());
    }

    /// The physical effect of a service on an entity.
    fn effect(service: &str) -> Option<(&'static str, Option<&'static str>)> {
        Some(match service {
            "light.turn_on" | "switch.turn_on" => ("on", None),
            "light.turn_off" | "switch.turn_off" => ("off", None),
            "lock.lock" => ("locked", Some("locking")),
            "lock.unlock" => ("unlocked", Some("unlocking")),
            _ => return None,
        })
    }

    /// `entity` is a Matter device's (`device_id`) in the registry, which
    /// answers as long as it is `alive`.
    pub fn matter(&mut self, entity: &str, device_id: &str, alive: bool) {
        self.registry.insert(entity.into(), json!({"entity_id": entity, "platform": "matter", "device_id": device_id}));
        self.matter_nodes.insert(device_id.into(), alive);
    }

    /// The entity is removed from Home Assistant (`new_state: null`).
    pub fn remove(&mut self, entity: &str) {
        self.states.remove(entity);
        self.broadcast(json!({"type": "event", "event": {"event_type": "state_changed",
            "data": {"entity_id": entity, "new_state": null}}}));
    }

    /// Run a service call; `None` means no result is sent.
    fn call(&mut self, service: &str, entity: &str, transport: &'static str) -> Option<Value> {
        self.calls.push((service.to_string(), entity.to_string(), transport));
        // as a real Home Assistant does (2026.9.4, step ③A): a call on an
        // entity it does not have succeeds, and nothing happens
        if !self.states.contains_key(entity) {
            return Some(json!({"success": true, "result": {"context": {"id": "c"}}}));
        }
        let b = self.behaviour.get(entity).cloned().unwrap_or(Behaviour::Instant);
        let (done, moving) = Self::effect(service)?;
        match b {
            Behaviour::Instant | Behaviour::LoseAfterSend => {
                self.set(entity, done, json!({}));
            }
            Behaviour::LoseAndDie => {
                self.set(entity, done, json!({}));
                self.ws_up = false;
                self.rest_up = false;
            }
            Behaviour::LoseWithoutEffect => {}
            Behaviour::LoseThenSlowEffect => {
                self.delayed.push((
                    Instant::now() + Duration::from_millis(1_200),
                    entity.to_string(),
                    done.to_string(),
                ));
            }
            Behaviour::Moving => {
                self.set(entity, moving.unwrap_or(done), json!({}));
            }
            Behaviour::Stuck | Behaviour::Silent => {}
            Behaviour::DropsOff => {
                self.set(entity, "unavailable", json!({}));
            }
            Behaviour::Error(code) => {
                return Some(json!({"success": false, "error": {"code": code, "message": "fake"}}));
            }
        }
        match b {
            Behaviour::LoseAfterSend
            | Behaviour::LoseThenSlowEffect
            | Behaviour::LoseWithoutEffect
            | Behaviour::LoseAndDie
            | Behaviour::Silent => None,
            _ => Some(json!({"success": true, "result": {"context": {"id": "c"}}})),
        }
    }
}

pub struct FakeHa {
    pub addr: SocketAddr,
    world: Arc<Mutex<World>>,
    stop: Arc<AtomicBool>,
}

impl Drop for FakeHa {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

impl FakeHa {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let world = Arc::new(Mutex::new(World {
            ws_up: true,
            rest_up: true,
            answer_pings: true,
            token: TOKEN.into(),
            ..Default::default()
        }));
        {
            let mut w = world.lock().unwrap();
            w.set("light.living_room", "off", json!({"friendly_name": "Living room", "brightness": null}));
            w.set("switch.kettle", "off", json!({"friendly_name": "Kettle"}));
            w.set("lock.front_door", "locked", json!({"friendly_name": "Front door"}));
            w.set("sensor.outside", "12.5", json!({}));
        }
        let stop = Arc::new(AtomicBool::new(false));
        {
            // effects on their way take place when their time comes
            let (w, s) = (Arc::clone(&world), Arc::clone(&stop));
            std::thread::spawn(move || {
                while !s.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(10));
                    let mut w = w.lock().unwrap();
                    let now = Instant::now();
                    let due: Vec<(String, String)> = w
                        .delayed
                        .iter()
                        .filter(|(at, _, _)| *at <= now)
                        .map(|(_, e, s)| (e.clone(), s.clone()))
                        .collect();
                    w.delayed.retain(|(at, _, _)| *at > now);
                    for (entity, state) in due {
                        w.set(&entity, &state, json!({}));
                    }
                }
            });
        }
        let (w, s) = (Arc::clone(&world), Arc::clone(&stop));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if s.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(stream) = stream else { continue };
                let (w, s) = (Arc::clone(&w), Arc::clone(&s));
                std::thread::spawn(move || serve(stream, &w, &s));
            }
        });
        Self { addr, world, stop }
    }

    /// Home Assistant dies: open connections drop and new ones are refused,
    /// so nothing can be delivered any more.
    pub fn kill(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn world(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    pub fn behave(&self, entity: &str, b: Behaviour) {
        self.world().behaviour.insert(entity.into(), b);
    }

    pub fn calls(&self) -> Vec<(String, String, &'static str)> {
        self.world().calls.clone()
    }
}

fn serve(mut stream: TcpStream, world: &Mutex<World>, stop: &AtomicBool) {
    let mut first = [0u8; 32];
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut n = 0;
    while n < 18 && Instant::now() < deadline {
        n = stream.peek(&mut first).unwrap_or(0);
        if n < 18 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    if String::from_utf8_lossy(&first[..n]).starts_with("GET /api/websocket") {
        serve_ws(stream, world, stop);
    } else {
        serve_rest(&mut stream, world);
    }
}

fn respond(stream: &mut TcpStream, status: &str, body: &Value) {
    let body = body.to_string();
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nDate: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        http_date(now_us() / 1000),
        body.len()
    );
}

fn now_us() -> u64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    u64::try_from(since.as_micros()).unwrap_or(u64::MAX)
}

/// (year, month, day) of a day count since 1970-01-01 (H. Hinnant's algorithm).
fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + u64::from(m <= 2), m, d)
}

/// Home Assistant's timestamp format, UTC, to the microsecond.
fn iso_us(us: u64) -> String {
    let (secs, frac) = (us / 1_000_000, us % 1_000_000);
    let (y, m, d) = civil(secs / 86_400);
    let t = secs % 86_400;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{frac:06}+00:00", t / 3600, t % 3600 / 60, t % 60)
}

/// An HTTP date, as Home Assistant's server sends it.
fn http_date(ms: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let secs = ms / 1000;
    let days = secs / 86_400;
    let (y, m, d) = civil(days);
    let t = secs % 86_400;
    format!(
        "{}, {d:02} {} {y:04} {:02}:{:02}:{:02} GMT",
        DAYS[usize::try_from(days % 7).unwrap_or(0)],
        MONTHS[usize::try_from(m - 1).unwrap_or(0)],
        t / 3600,
        t % 3600 / 60,
        t % 60
    )
}

fn serve_rest(stream: &mut TcpStream, world: &Mutex<World>) {
    if !world.lock().unwrap().rest_up {
        return; // the connection just closes: unreachable
    }
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    let _ = reader.read_line(&mut line);
    let (mut auth, mut length) = (String::new(), 0usize);
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
            break;
        }
        let lower = h.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("authorization:") {
            auth = v.trim().to_string();
        }
        if let Some(v) = lower.strip_prefix("content-length:") {
            length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; length];
    let _ = reader.read_exact(&mut body);
    {
        let mut w = world.lock().unwrap();
        if auth != format!("bearer {}", w.token) {
            w.rejected_logins += 1;
            drop(w);
            return respond(stream, "401 Unauthorized", &json!({"message": "Unauthorized"}));
        }
    }
    let mut parts = line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let mut w = world.lock().unwrap();
    match (method, path) {
        ("GET", "/api/states") => {
            w.rest_reads += 1;
            let all: Vec<Value> = w.states.values().cloned().collect();
            respond(stream, "200 OK", &Value::Array(all));
        }
        ("GET", p) if p.starts_with("/api/states/") => {
            w.rest_reads += 1;
            match w.states.get(&p["/api/states/".len()..]).cloned() {
                Some(s) => respond(stream, "200 OK", &s),
                None => respond(stream, "404 Not Found", &json!({"message": "Entity not found."})),
            }
        }
        ("POST", p) if p.starts_with("/api/services/") => {
            let service = p["/api/services/".len()..].replace('/', ".");
            let data: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let entity = data["entity_id"].as_str().unwrap_or_default().to_string();
            match w.call(&service, &entity, "rest") {
                Some(r) if r["success"] == true => respond(stream, "200 OK", &json!([])),
                Some(_) => respond(stream, "400 Bad Request", &json!({"message": "refused"})),
                // the request was taken and the answer is lost
                None => {}
            }
        }
        _ => respond(stream, "404 Not Found", &json!({})),
    }
}

fn serve_ws(stream: TcpStream, world: &Mutex<World>, stop: &AtomicBool) {
    if !world.lock().unwrap().ws_up {
        return;
    }
    let Ok(mut ws) = tungstenite::accept(stream) else { return };
    let _ = ws.get_ref().set_read_timeout(Some(Duration::from_millis(5)));
    let text = |v: Value| tungstenite::Message::Text(v.to_string().into());
    let read = |ws: &mut tungstenite::WebSocket<TcpStream>| -> Result<Option<Value>, ()> {
        match ws.read() {
            Ok(tungstenite::Message::Text(t)) => Ok(serde_json::from_str(t.as_str()).ok()),
            Ok(_) => Ok(None),
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
            {
                Ok(None)
            }
            Err(_) => Err(()),
        }
    };
    if ws.send(text(json!({"type": "auth_required", "ha_version": "2026.10.0"}))).is_err() {
        return;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let auth = loop {
        match read(&mut ws) {
            Ok(Some(v)) => break v,
            Ok(None) if Instant::now() < deadline => {}
            _ => return,
        }
    };
    {
        let mut w = world.lock().unwrap();
        if auth["access_token"] != w.token.as_str() {
            w.rejected_logins += 1;
            drop(w);
            let _ = ws.send(text(json!({"type": "auth_invalid", "message": "Invalid access token"})));
            return;
        }
    }
    let _ = ws.send(text(json!({"type": "auth_ok", "ha_version": "2026.10.0"})));
    let epoch = world.lock().unwrap().restarts;
    let (events_tx, events): (Sender<Value>, Receiver<Value>) = mpsc::channel();
    let mut outbox: VecDeque<Value> = VecDeque::new();
    // answers that take time: a dead Matter device is given up on after a while
    let mut later: Vec<(Instant, Value)> = Vec::new();
    let mut subscription: Option<u64> = None;
    loop {
        if stop.load(Ordering::SeqCst) || world.lock().unwrap().restarts != epoch {
            return; // dropped without a close frame: a crash, a restart
        }
        let now = Instant::now();
        outbox.extend(later.iter().filter(|(at, _)| *at <= now).map(|(_, m)| m.clone()));
        later.retain(|(at, _)| *at > now);
        while let Ok(mut e) = events.try_recv() {
            if let Some(id) = subscription {
                e["id"] = json!(id);
                outbox.push_back(e);
            }
        }
        while let Some(m) = outbox.pop_front() {
            if ws.send(text(m)).is_err() {
                return;
            }
        }
        let Ok(msg) = read(&mut ws) else { return };
        let Some(m) = msg else { continue };
        let id = m["id"].clone();
        let mut w = world.lock().unwrap();
        match m["type"].as_str().unwrap_or_default() {
            "subscribe_events" => {
                subscription = id.as_u64();
                w.subscribers.push(events_tx.clone());
                outbox.push_back(json!({"id": id, "type": "result", "success": true, "result": null}));
            }
            "get_states" if w.fail_get_states => {
                w.bootstraps += 1;
                outbox.push_back(json!({"id": id, "type": "result", "success": false,
                    "error": {"code": "unknown_error", "message": "fake"}}));
            }
            "get_states" => {
                w.bootstraps += 1;
                let all: Vec<Value> = w.states.values().cloned().collect();
                outbox.push_back(json!({"id": id, "type": "result", "success": true, "result": all}));
            }
            "ping" if w.answer_pings => outbox.push_back(json!({"id": id, "type": "pong"})),
            "config/entity_registry/get_entries" if w.fail_registry => {
                w.registry_reads += 1;
                outbox.push_back(json!({"id": id, "type": "result", "success": false,
                    "error": {"code": "unknown_error", "message": "fake"}}));
            }
            "config/entity_registry/get_entries" => {
                w.registry_reads += 1;
                let entries: serde_json::Map<String, Value> = m["entity_ids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(|e| (e.to_string(), w.registry.get(e).cloned().unwrap_or(Value::Null)))
                    .collect();
                outbox.push_back(json!({"id": id, "type": "result", "success": true, "result": entries}));
            }
            "matter/interview_node" => {
                let device = m["device_id"].as_str().unwrap_or_default().to_string();
                w.interviews.push(device.clone());
                match w.matter_nodes.get(&device) {
                    Some(true) => later.push((
                        Instant::now() + w.answer_after,
                        json!({"id": id, "type": "result", "success": true, "result": null}),
                    )),
                    // as the Matter server does, after a while (15 s for real)
                    Some(false) => later.push((
                        Instant::now() + Duration::from_millis(300),
                        json!({"id": id, "type": "result", "success": false, "error": {"code": "0",
                            "message": "Peer is no longer responding to active session"}}),
                    )),
                    None => outbox.push_back(json!({"id": id, "type": "result", "success": false,
                        "error": {"code": "node_not_found", "message": format!("Invalid device ID: {device}")}})),
                }
            }
            "call_service" => {
                let service = format!("{}.{}", m["domain"].as_str().unwrap_or(""), m["service"].as_str().unwrap_or(""));
                let entity = m["target"]["entity_id"].as_str().unwrap_or_default().to_string();
                let lose = matches!(
                    w.behaviour.get(&entity),
                    Some(
                        Behaviour::LoseAfterSend
                            | Behaviour::LoseThenSlowEffect
                            | Behaviour::LoseWithoutEffect
                            | Behaviour::LoseAndDie
                    )
                );
                let result = w.call(&service, &entity, "ws");
                // the fake sends a call's state_changed before its result (a real
                // Home Assistant may not: the adapter takes the state it has)
                while let Ok(mut e) = events.try_recv() {
                    if let Some(sid) = subscription {
                        e["id"] = json!(sid);
                        outbox.push_back(e);
                    }
                }
                match result {
                    Some(mut r) => {
                        r["id"] = id;
                        r["type"] = json!("result");
                        outbox.push_back(r);
                    }
                    None if lose => {
                        while let Some(m) = outbox.pop_front() {
                            let _ = ws.send(text(m));
                        }
                        return;
                    }
                    None => {}
                }
            }
            _ => {}
        }
    }
}
