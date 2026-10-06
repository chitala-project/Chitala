//! A fake Matter server for tests (finding F10): the WebSocket API's
//! `read_attribute` over loopback, with nodes that answer or have died. It
//! records every command it is sent, so tests can check that Chitala only
//! ever reads. Compiled only for this crate's tests and with the `fake-ha`
//! feature; never part of a node or an adapter host.

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

#[derive(Debug, Clone, Default)]
pub struct Node {
    /// A dead node never answers, as the real server does not.
    pub alive: bool,
    /// Attribute path (`endpoint/cluster/attribute`, decimal) → value.
    pub attributes: BTreeMap<String, Value>,
}

#[derive(Debug, Default)]
pub struct MatterWorld {
    pub nodes: BTreeMap<u64, Node>,
    /// Every command received, in order.
    pub commands: Vec<String>,
    /// How long a live node takes to answer.
    pub answer_after: Duration,
}

impl MatterWorld {
    /// A live node with a door lock on endpoint 1 in `lock_state` (1 locked, 2 unlocked).
    pub fn lock(&mut self, node: u64, lock_state: u64) {
        let n = self.nodes.entry(node).or_default();
        n.alive = true;
        n.attributes.insert("1/257/0".into(), json!(lock_state));
    }
}

pub struct FakeMatter {
    pub addr: SocketAddr,
    world: Arc<Mutex<MatterWorld>>,
    stop: Arc<AtomicBool>,
}

impl Drop for FakeMatter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

impl FakeMatter {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let world = Arc::new(Mutex::new(MatterWorld::default()));
        let stop = Arc::new(AtomicBool::new(false));
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

    pub fn url(&self) -> String {
        format!("ws://{}/ws", self.addr)
    }

    pub fn world(&self) -> std::sync::MutexGuard<'_, MatterWorld> {
        self.world.lock().unwrap()
    }

    /// The world itself, for a fake Home Assistant to act on.
    pub fn shared(&self) -> Arc<Mutex<MatterWorld>> {
        Arc::clone(&self.world)
    }

    /// The commands received so far.
    pub fn commands(&self) -> Vec<String> {
        self.world().commands.clone()
    }
}

fn serve(stream: TcpStream, world: &Mutex<MatterWorld>, stop: &AtomicBool) {
    let Ok(mut ws) = tungstenite::accept(stream) else { return };
    let text = |v: Value| tungstenite::Message::Text(v.to_string().into());
    let info = json!({"fabric_id": 1, "compressed_fabric_id": 1, "schema_version": 13, "sdk_version": "fake"});
    if ws.send(text(info)).is_err() {
        return;
    }
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let msg = match ws.read() {
            Ok(tungstenite::Message::Text(t)) => serde_json::from_str::<Value>(t.as_str()).unwrap_or(Value::Null),
            Ok(_) => continue,
            Err(_) => return,
        };
        let command = msg["command"].as_str().unwrap_or_default().to_string();
        let id = msg["message_id"].clone();
        let (answer, wait) = {
            let mut w = world.lock().unwrap();
            w.commands.push(command.clone());
            let answer = match command.as_str() {
                "read_attribute" => {
                    let node = msg["args"]["node_id"].as_u64().unwrap_or_default();
                    match w.nodes.get(&node) {
                        // a node that does not answer: the server says nothing
                        Some(n) if !n.alive => None,
                        Some(n) => {
                            let paths: Vec<String> = match &msg["args"]["attribute_path"] {
                                Value::Array(a) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
                                Value::String(p) => vec![p.clone()],
                                _ => Vec::new(),
                            };
                            // a path the node does not have is dropped; none at all is an error
                            let result: serde_json::Map<String, Value> =
                                paths.iter().filter_map(|p| Some((p.clone(), n.attributes.get(p)?.clone()))).collect();
                            Some(match result.is_empty() {
                                true => json!({"message_id": id, "error_code": 7,
                                    "details": "Failed to read attribute: no values returned"}),
                                false => json!({"message_id": id, "result": result}),
                            })
                        }
                        None => Some(
                            json!({"message_id": id, "error_code": 5, "details": format!("Node {node} does not exist")}),
                        ),
                    }
                }
                _ => Some(json!({"message_id": id, "error_code": 1, "details": "the fake only reads"})),
            };
            (answer, w.answer_after)
        };
        if let Some(a) = answer {
            std::thread::sleep(wait);
            if ws.send(text(a)).is_err() {
                return;
            }
        }
    }
}
