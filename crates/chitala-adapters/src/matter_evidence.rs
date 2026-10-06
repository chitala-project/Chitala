//! Evidence from Matter devices behind Home Assistant, read from the device
//! itself through the Matter server (finding F10 of v0.3 step ③A).
//!
//! Home Assistant's state of a Matter device cannot be tied to the device:
//! its `matter/interview_node` returns nothing, and under backpressure the
//! Matter server sends a command's result ahead of the attribute updates it
//! queued, so an interview's success can arrive while Home Assistant still
//! shows the old state. The Matter server's `read_attribute`, though, is a
//! Read interaction with the device, and it answers with the values read. So
//! for evidence of what an order did, the adapter reads those values here.
//!
//! The provider is deliberately narrow (Project Lead, 2026-10-06):
//!
//! - **read only, by construction**: the only command it can send is
//!   `read_attribute`; nothing here invokes, writes, commissions, manages a
//!   fabric or passes a command through;
//! - **allowlisted**: only the attributes the Home profile maps (spec 24);
//! - **loopback only**: the Matter server's API has no authentication, and
//!   anyone who reaches it controls every Matter device. Chitala connects to
//!   it only on this machine, never across a network. That is a deployment
//!   rule, not only a type restriction (spec 25).
//!
//! It is a bridge toward the direct Matter adapter (step ⑤), not a new
//! abstraction of the core: the core only sees the provenance of a state.

use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tungstenite::client::IntoClientRequest;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use crate::profile::{hex_id, HomeProfile};
use crate::AdapterError;

/// A Matter node's endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target {
    pub node: u64,
    pub endpoint: u16,
}

impl Target {
    /// The node and endpoint of a Matter entity, from its Home Assistant
    /// registry `unique_id`:
    /// `<fabric>-<node id, 16 hex digits>-MatterNodeDevice-<endpoint>-<key>-…`.
    pub fn of_unique_id(unique_id: &str) -> Option<Self> {
        let mut parts = unique_id.split('-');
        let (_fabric, node, kind, endpoint) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        if kind != "MatterNodeDevice" || node.len() != 16 {
            return None;
        }
        Some(Self { node: u64::from_str_radix(node, 16).ok()?, endpoint: endpoint.parse().ok()? })
    }
}

/// Attributes read: (cluster, attribute, value).
pub type Values = Vec<(u32, u32, Value)>;

/// Reads Matter attributes through the Matter server, on loopback only.
#[derive(Debug, Clone)]
pub struct MatterEvidence {
    url: String,
    timeout: Duration,
}

/// Every attribute the Home profile reads (spec 24): nothing else is asked.
fn allowed(cluster: u32, attribute: u32) -> bool {
    HomeProfile::v0_1()
        .classes()
        .iter()
        .flat_map(|c| &c.matter.attributes)
        .any(|a| hex_id(&a.cluster) == Some(cluster) && hex_id(&a.attribute) == Some(attribute))
}

impl MatterEvidence {
    /// A provider for the Matter server at `url` (`ws://127.0.0.1:5580/ws`):
    /// refused unless the host is this machine.
    pub fn new(url: &str, timeout: Duration) -> Result<Self, AdapterError> {
        let request = url
            .into_client_request()
            .map_err(|e| AdapterError::Failed(format!("bad Matter server URL {url:?}: {e}")))?;
        let uri = request.uri();
        let host = uri.host().unwrap_or_default().trim_matches(['[', ']']);
        let loopback =
            host.eq_ignore_ascii_case("localhost") || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !matches!(uri.scheme_str(), Some("ws" | "wss")) || !loopback {
            return Err(AdapterError::Failed(format!(
                "{url}: the Matter server's API has no authentication, so Chitala reaches it on this machine only \
                 (ws://127.0.0.1:…, ws://[::1]:… or ws://localhost:…), never across a network"
            )));
        }
        Ok(Self { url: url.to_string(), timeout })
    }

    /// Read `attributes` (cluster, attribute) of `target` from the device:
    /// one Read interaction through the Matter server, on a connection of its
    /// own, with no data version filter, so the device sends every value. The
    /// values read, or why there are none. A device that does not answer
    /// within the timeout gives none.
    ///
    /// An attribute the device does not have (an on/off light has no level)
    /// is left out: the server drops a path the device answers with a status.
    /// Whether what remains is a state is the profile's to say (its required
    /// keys), and whether it settles an outcome is outcome verification's
    /// (every key the action promised).
    pub fn read(&self, target: Target, attributes: &[(u32, u32)]) -> Result<Values, String> {
        if let Some((c, a)) = attributes.iter().find(|(c, a)| !allowed(*c, *a)) {
            return Err(format!("0x{c:04X}/0x{a:04X} is not an attribute the Home profile reads"));
        }
        let deadline = Instant::now() + self.timeout;
        let mut ws = connect(&self.url, self.timeout)?;
        // the server introduces itself first
        let info = next(&mut ws, deadline)?;
        if info.get("schema_version").is_none() {
            return Err("not a Matter server".into());
        }
        let paths: Vec<String> = attributes.iter().map(|(c, a)| format!("{}/{c}/{a}", target.endpoint)).collect();
        let request = json!({
            "message_id": "read",
            "command": "read_attribute",
            "args": {"node_id": target.node, "attribute_path": paths},
        });
        ws.send(Message::Text(request.to_string().into())).map_err(|e| format!("send failed: {e}"))?;
        let answer = loop {
            let m = next(&mut ws, deadline)?;
            if m["message_id"] == "read" {
                break m;
            }
        };
        let _ = ws.close(None);
        if let Some(code) = answer.get("error_code") {
            let details: String = answer["details"].as_str().unwrap_or_default().chars().take(200).collect();
            return Err(format!("the Matter server could not read the device ({code}): {details}"));
        }
        let values: Values = attributes
            .iter()
            .zip(&paths)
            .filter_map(|((c, a), path)| Some((*c, *a, answer["result"].get(path)?.clone())))
            .collect();
        if values.is_empty() {
            return Err(format!("the device answered none of {}", paths.join(", ")));
        }
        Ok(values)
    }
}

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

fn connect(url: &str, timeout: Duration) -> Result<Socket, String> {
    let request = url.into_client_request().map_err(|e| e.to_string())?;
    let host = request.uri().host().unwrap_or_default().trim_matches(['[', ']']).to_string();
    let port = request.uri().port_u16().unwrap_or(80);
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .find(|a| a.ip().is_loopback())
        .ok_or_else(|| format!("{host} is not this machine"))?;
    let tcp = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("cannot reach the Matter server: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_millis(50))).map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    let (ws, _) = tungstenite::client(request, MaybeTlsStream::Plain(tcp))
        .map_err(|e| format!("WebSocket handshake failed: {e}"))?;
    Ok(ws)
}

/// The next JSON message, before `deadline`.
fn next(ws: &mut Socket, deadline: Instant) -> Result<Value, String> {
    while Instant::now() < deadline {
        match ws.read() {
            Ok(Message::Text(t)) => return serde_json::from_str(t.as_str()).map_err(|e| format!("bad JSON: {e}")),
            Ok(Message::Close(_)) => return Err("the Matter server closed the connection".into()),
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(e) => return Err(format!("connection lost: {e}")),
        }
    }
    Err("the device did not answer in time".into())
}
