//! Local IPC (spec `specs/11-node-ipc.md`): newline-delimited JSON over a Unix
//! domain socket.
//!
//! ```text
//! → {"op":"hello"}
//! ← {"protocol":"chitala-node-ipc/1","csme_versions":[1],"registry":"chitala-core/0.1.0","domain":"domain:home","node":…,"kid":…,"sig":…}
//! → {"op":"submit","csme":"<hex COSE_Sign1>"}
//! ← {"decision":"allow","mid":"…","request":"…","result":{…},"audit_seq":12,"node":"service:node","kid":"…","sig":"…"}
//! ```
//!
//! Two directions of trust (v10 §2 "Device Authentication + Manager Authentication"):
//!
//! - **client → node**: every request is a signed CSME judged by the Reference
//!   Monitor; the socket is a transport, not a trust boundary (v9 §13).
//! - **node → client**: every reply is signed with the node's service key and
//!   bound to the exact request bytes (`request` = first 16 bytes of SHA-256 of
//!   the CSME). A client that does not verify the signature against the
//!   `node_public_key` pinned in its config MUST NOT act on the reply — otherwise
//!   whoever controls the socket path could fake an `allow` or hand out a forged
//!   token.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chitala_audit::canonical_json;
use chitala_identity::{key_id_of, verify, Keypair, PublicKey};
use chitala_model::{DenyCode, EntityId, ExecCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Node, NodeError};

pub const PROTOCOL: &str = "chitala-node-ipc/1";
/// Longest accepted request line (hex doubles the 16 KiB envelope limit).
pub const MAX_LINE: usize = 64 * 1024;
/// Concurrent client connections the server accepts.
pub const MAX_CONNECTIONS: usize = 64;
/// Read/write timeout per connection (slow clients cannot pin a thread forever).
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Domain separation for reply signatures.
pub const REPLY_DOMAIN: &[u8] = b"chitala-node-reply-v1\x00";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecError {
    pub code: ExecCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Response {
    /// `"allow"` or `"deny"`.
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mid: Option<String>,
    /// Hex of the first 16 bytes of SHA-256 over the request bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<DenyCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// Only given to authenticated requesters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// An allowed request that failed during execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ExecError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_seq: Option<u64>,
    /// Signing node and its key id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl Response {
    pub fn is_allow(&self) -> bool {
        self.decision == "allow"
    }

    /// Allowed and executed successfully.
    pub fn is_ok(&self) -> bool {
        self.is_allow() && self.error.is_none()
    }

    /// One-line human summary.
    pub fn summary(&self) -> String {
        match (&self.code, &self.error) {
            (Some(code), _) => {
                format!("DENY {code}{}", self.reason.as_deref().map(|r| format!(" — {r}")).unwrap_or_default())
            }
            (None, Some(e)) => format!("ALLOW, execution failed {} — {}", e.code, e.message),
            (None, None) => "ALLOW".to_string(),
        }
    }
}

/// `request` binding value for a request.
pub fn request_digest(request: &[u8]) -> String {
    hex::encode(&Sha256::digest(request)[..16])
}

fn reply_message(v: &Value) -> Result<Vec<u8>, String> {
    let mut unsigned = v.clone();
    unsigned.as_object_mut().ok_or("reply is not an object")?.remove("sig");
    let body = canonical_json(&unsigned).map_err(|e| e.to_string())?;
    let mut m = REPLY_DOMAIN.to_vec();
    m.extend_from_slice(body.as_bytes());
    Ok(m)
}

/// Sign a reply object in place (adds `node`, `kid`, `sig`).
pub fn sign_reply(v: &mut Value, node: &EntityId, key: &Keypair) {
    let Some(obj) = v.as_object_mut() else { return };
    obj.insert("node".into(), Value::String(node.to_string()));
    obj.insert("kid".into(), Value::String(hex::encode(key.key_id())));
    obj.remove("sig");
    if let Ok(m) = reply_message(v) {
        let sig = key.sign(&m);
        if let Some(obj) = v.as_object_mut() {
            obj.insert("sig".into(), Value::String(hex::encode(sig)));
        }
    }
}

/// Verify a reply against the pinned node key and, for submit replies, the
/// request it must answer.
pub fn verify_reply(v: &Value, node_key: &PublicKey, expected_request: Option<&str>) -> Result<(), String> {
    let fake = |why: &str| format!("reply is not authenticated by the pinned node key ({why}); refusing to trust it");
    let kid = v.get("kid").and_then(Value::as_str).ok_or_else(|| fake("no kid"))?;
    if kid != hex::encode(key_id_of(node_key)) {
        return Err(fake("unknown node key"));
    }
    let sig =
        v.get("sig").and_then(Value::as_str).and_then(|s| hex::decode(s).ok()).ok_or_else(|| fake("no signature"))?;
    let m = reply_message(v).map_err(|e| fake(&e))?;
    if !verify(node_key, &m, &sig) {
        return Err(fake("bad signature"));
    }
    if let Some(expected) = expected_request {
        if v.get("request").and_then(Value::as_str) != Some(expected) {
            return Err(fake("reply answers a different request"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum IpcRequest {
    Hello,
    Submit { csme: String },
}

/// Something that accepts signed CSMEs: a remote node or an in-process one.
pub trait Submit {
    fn submit(&mut self, csme: &[u8]) -> Result<Response, String>;
}

impl Submit for Node {
    fn submit(&mut self, csme: &[u8]) -> Result<Response, String> {
        Ok(self.handle(csme))
    }
}

/// Run `f` on the node. A poisoned lock means a request panicked half-way: the
/// node's state can no longer be trusted, so it fails closed until restarted.
pub fn with_node<R>(node: &Arc<Mutex<Node>>, f: impl FnOnce(&mut Node) -> R) -> Result<R, String> {
    match node.lock() {
        Ok(mut n) => Ok(f(&mut n)),
        Err(_) => Err("node is in a failed state and refuses requests until it is restarted".into()),
    }
}

impl Submit for Arc<Mutex<Node>> {
    fn submit(&mut self, csme: &[u8]) -> Result<Response, String> {
        with_node(self, |n| n.handle(csme))
    }
}

// ───────────────────────────── server ─────────────────────────────

#[cfg(unix)]
pub fn serve(node: Arc<Mutex<Node>>, socket: &Path) -> Result<(), NodeError> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};

    match std::fs::symlink_metadata(socket) {
        Ok(m) if m.file_type().is_socket() => {
            // a stale socket from a previous run; refuse if someone is listening
            if UnixStream::connect(socket).is_ok() {
                return Err(NodeError::Config(format!("{} is in use by another process", socket.display())));
            }
            std::fs::remove_file(socket)?;
        }
        Ok(_) => {
            return Err(NodeError::Config(format!(
                "{} exists and is not a socket; refusing to replace it",
                socket.display()
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;

    struct Slot(Arc<AtomicUsize>);
    impl Drop for Slot {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            let _ = writeln!(stream, "{}", serde_json::json!({"error": "node is busy"}));
            continue;
        }
        let slot = Slot(Arc::clone(&active));
        let node = Arc::clone(&node);
        std::thread::spawn(move || {
            let _slot = slot;
            let _ = handle_connection(node, stream);
        });
    }
    Ok(())
}

#[cfg(unix)]
fn handle_connection(node: Arc<Mutex<Node>>, stream: std::os::unix::net::UnixStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        let n = (&mut reader).take(MAX_LINE as u64 + 1).read_line(&mut line)?;
        if n == 0 {
            return Ok(());
        }
        if n > MAX_LINE {
            writeln!(writer, "{}", serde_json::json!({"error": "request too large"}))?;
            return Ok(());
        }
        let reply = match serde_json::from_str::<IpcRequest>(line.trim()) {
            Ok(IpcRequest::Hello) => with_node(&node, |n| n.hello()),
            Ok(IpcRequest::Submit { csme }) => match hex::decode(csme.trim()) {
                Ok(bytes) => with_node(&node, |n| n.handle_signed(&bytes)),
                Err(_) => Err("csme must be hex".into()),
            },
            Err(e) => Err(format!("bad request: {e}")),
        };
        let failed = reply.is_err();
        let v = reply.unwrap_or_else(|e| serde_json::json!({ "error": e }));
        writeln!(writer, "{v}")?;
        if failed {
            return Ok(());
        }
    }
}

// ───────────────────────────── client ─────────────────────────────

/// Client for a node listening on a Unix socket. Every reply is verified against
/// the node key pinned in the config.
#[derive(Debug, Clone)]
pub struct NodeClient {
    socket: PathBuf,
    node_key: PublicKey,
}

impl NodeClient {
    pub fn new(socket: impl Into<PathBuf>, node_key: PublicKey) -> Self {
        Self { socket: socket.into(), node_key }
    }

    #[cfg(unix)]
    fn round_trip(&self, req: &IpcRequest) -> Result<Value, String> {
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect(&self.socket).map_err(|e| {
            format!("cannot connect to node at {}: {e} (is `chitala node` running?)", self.socket.display())
        })?;
        stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|e| e.to_string())?;
        stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|e| e.to_string())?;
        let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
        writeln!(stream, "{line}").map_err(|e| e.to_string())?;
        let mut reply = String::new();
        BufReader::new(stream.take(MAX_LINE as u64 * 4)).read_line(&mut reply).map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_str(&reply).map_err(|e| format!("bad reply from node: {e}"))?;
        if let Some(err) = v.get("error").and_then(Value::as_str) {
            // unsigned by design: carries no decision, only a transport failure
            return Err(format!("node: {err}"));
        }
        Ok(v)
    }

    #[cfg(unix)]
    pub fn hello(&self) -> Result<Value, String> {
        let v = self.round_trip(&IpcRequest::Hello)?;
        verify_reply(&v, &self.node_key, None)?;
        Ok(v)
    }
}

#[cfg(unix)]
impl Submit for NodeClient {
    fn submit(&mut self, csme: &[u8]) -> Result<Response, String> {
        let v = self.round_trip(&IpcRequest::Submit { csme: hex::encode(csme) })?;
        verify_reply(&v, &self.node_key, Some(&request_digest(csme)))?;
        serde_json::from_value(v).map_err(|e| format!("bad response from node: {e}"))
    }
}
