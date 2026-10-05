//! Local IPC (spec `specs/11-node-ipc.md`): newline-delimited JSON over the
//! platform's [`IpcTransport`] (PAL, spec 18; a Unix socket on hosted platforms).
//!
//! ```text
//! → {"op":"hello"}
//! ← {"protocol":"chitala-node-ipc/1","csme_versions":[1],"registry":"chitala-core/0.1.2","domain":"domain:home","node":…,"kid":…,"sig":…}
//! → {"op":"submit","csme":"<hex COSE_Sign1>"}
//! ← {"decision":"allow","mid":"…","request":"…","result":{…},"audit_seq":12,"node":"service:node","kid":"…","sig":"…"}
//! ```
//!
//! Two directions of trust (v10 §2 "Device Authentication + Manager Authentication"):
//!
//! - **client → node**: every request is a signed CSME judged by the Reference
//!   Monitor; the transport is not a trust boundary (v9 §13).
//! - **node → client**: every reply is signed with the node's service key and
//!   bound to the exact request bytes (`request` = first 16 bytes of SHA-256 of
//!   the CSME). A client that does not verify the signature against the
//!   `node_public_key` pinned in its config MUST NOT act on the reply — otherwise
//!   whoever controls the endpoint could fake an `allow` or hand out a forged
//!   token.

use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chitala_audit::canonical_json;
use chitala_identity::{key_id_of, verify, Keypair, PublicKey};
use chitala_model::{DenyCode, EntityId, ExecCode};
use chitala_platform::{Endpoint, IpcListener, IpcStream, IpcTransport, PlatformError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::node::Step;
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
    /// `"allow"`, `"deny"` or — for intents — `"escalate"` (a human must answer).
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
    /// Intent path: the Authority Engine step that decided (spec §16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    /// Escalations: who may answer, and until when.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approvers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// Only given to authenticated requesters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// An allowed request that failed during execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ExecError>,
    /// Device actions: whether the world ended up as the action promised, as
    /// far as the resource's witness tells (spec 22).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Value>,
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

    /// Waiting for a human (intents only).
    pub fn is_escalated(&self) -> bool {
        self.decision == "escalate"
    }

    /// Allowed and executed successfully.
    pub fn is_ok(&self) -> bool {
        self.is_allow() && self.error.is_none()
    }

    /// One-line human summary.
    pub fn summary(&self) -> String {
        if self.is_escalated() {
            let who = self.approvers.as_deref().unwrap_or_default().join(" or ");
            return format!("ESCALATE — waiting for {who} (intent {})", self.mid.as_deref().unwrap_or("?"));
        }
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

/// A request line after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Hello,
    Submit(Vec<u8>),
}

/// Parse one request line (server side). The input is untrusted; this is a fuzz
/// target (`fuzz/fuzz_targets/ipc.rs`).
pub fn parse_request(line: &str) -> Result<Request, String> {
    match serde_json::from_str::<IpcRequest>(line.trim()) {
        Ok(IpcRequest::Hello) => Ok(Request::Hello),
        Ok(IpcRequest::Submit { csme }) => {
            hex::decode(csme.trim()).map(Request::Submit).map_err(|_| "csme must be hex".to_string())
        }
        Err(e) => Err(format!("bad request: {e}")),
    }
}

/// Parse and authenticate one reply line (client side). The input is untrusted
/// (whoever controls the endpoint wrote it); this is a fuzz target.
pub fn parse_reply(line: &str, node_key: &PublicKey, expected_request: Option<&str>) -> Result<Value, String> {
    let v: Value = serde_json::from_str(line).map_err(|e| format!("bad reply from node: {e}"))?;
    if let Some(err) = v.get("error").and_then(Value::as_str) {
        // unsigned by design: carries no decision, only a transport failure
        return Err(format!("node: {err}"));
    }
    verify_reply(&v, node_key, expected_request)?;
    Ok(v)
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

/// Judge and execute a request on a shared node. The adapter-host phase runs
/// without the node lock, so a slow device does not stall other requests.
pub fn submit_shared(node: &Arc<Mutex<Node>>, csme: &[u8]) -> Result<Value, String> {
    let first = with_node(node, |n| n.begin(csme))?;
    let response = drive(node, first)?;
    with_node(node, |n| n.seal(response, csme))
}

/// Run a step to its response, and the steps of its plan that may follow
/// without waiting (spec 23), each device operation without the node lock.
fn drive(node: &Arc<Mutex<Node>>, mut step: Step) -> Result<Response, String> {
    loop {
        let r = match step {
            Step::Done(r) => r,
            Step::Device(mut pending) => {
                let outcome = pending.run();
                with_node(node, |n| n.finish(pending, outcome))?
            }
        };
        match with_node(node, |n| n.continue_plan_of(&r))? {
            Some(next) => step = next,
            None => return Ok(r),
        }
    }
}

impl Submit for Arc<Mutex<Node>> {
    fn submit(&mut self, csme: &[u8]) -> Result<Response, String> {
        serde_json::from_value(submit_shared(self, csme)?).map_err(|e| e.to_string())
    }
}

// ───────────────────────────── server ─────────────────────────────

/// How often the server looks for work: devices whose state is getting old,
/// witnesses of pending outcomes, outcomes past their deadline (spec 22).
pub const TICK: Duration = Duration::from_secs(1);

/// Observe the devices whose state Safety relies on and is getting old and
/// the witnesses of pending outcomes, then settle the outcomes that ran out of
/// time and run the safe states that follow — never holding the node lock
/// while a device answers. Returns how many device operations ran.
pub fn refresh_state(node: &Arc<Mutex<Node>>) -> Result<usize, String> {
    // an unanswered step stops its plan even when no request comes in (C14)
    with_node(node, Node::expire_approvals)?;
    let due = with_node(node, |n| {
        let now = n.now();
        n.due_observations(now)
    })?;
    for o in &due {
        let outcome = o.run();
        with_node(node, |n| n.observed_by(o, outcome))?;
    }
    let work = with_node(node, Node::settle_outcomes)?;
    let mut ran = due.len() + work.len();
    for mut p in work {
        let outcome = p.run();
        with_node(node, |n| n.finish(p, outcome))?;
    }
    // plans whose step was verified go on (spec 23)
    let plans = with_node(node, Node::continue_plans)?;
    ran += plans.len();
    for step in plans {
        drive(node, step)?;
    }
    Ok(ran)
}

/// Listen on `endpoint` of the platform's IPC transport and serve forever,
/// keeping device state fresh in the background.
pub fn serve(node: Arc<Mutex<Node>>, ipc: &dyn IpcTransport, endpoint: &Endpoint) -> Result<(), NodeError> {
    let listener = ipc.listen(endpoint).map_err(|e| NodeError::Platform(format!("{}: {e}", ipc.describe(endpoint))))?;
    let watched = Arc::clone(&node);
    std::thread::spawn(move || loop {
        std::thread::sleep(TICK);
        if refresh_state(&watched).is_err() {
            return;
        }
    });
    serve_on(node, listener.as_ref());
    Ok(())
}

/// Pause after a failed accept.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(10);

/// Serve connections from an already open listener (never returns).
pub fn serve_on(node: Arc<Mutex<Node>>, listener: &dyn IpcListener) {
    struct Slot(Arc<AtomicUsize>);
    impl Drop for Slot {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let Ok(mut stream) = listener.accept() else {
            // e.g. out of descriptors: back off instead of spinning
            std::thread::sleep(ACCEPT_BACKOFF);
            continue;
        };
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
}

fn handle_connection(node: Arc<Mutex<Node>>, stream: Box<dyn IpcStream>) -> std::io::Result<()> {
    let io = |e: PlatformError| std::io::Error::other(e.to_string());
    stream.set_timeout(Some(IO_TIMEOUT)).map_err(io)?;
    let mut writer = stream.try_clone().map_err(io)?;
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
        let reply = match parse_request(&line) {
            Ok(Request::Hello) => with_node(&node, |n| n.hello()),
            Ok(Request::Submit(bytes)) => submit_shared(&node, &bytes),
            Err(e) => Err(e),
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

/// Client for a node on the platform's IPC transport. Every reply is verified
/// against the node key pinned in the config.
#[derive(Clone)]
pub struct NodeClient {
    ipc: Arc<dyn IpcTransport>,
    endpoint: Endpoint,
    node_key: PublicKey,
}

impl fmt::Debug for NodeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeClient").field("endpoint", &self.ipc.describe(&self.endpoint)).finish_non_exhaustive()
    }
}

impl NodeClient {
    pub fn new(ipc: Arc<dyn IpcTransport>, endpoint: Endpoint, node_key: PublicKey) -> Self {
        Self { ipc, endpoint, node_key }
    }

    fn round_trip(&self, req: &IpcRequest) -> Result<String, String> {
        let mut stream = self.ipc.connect(&self.endpoint).map_err(|e| {
            format!("cannot connect to node at {}: {e} (is `chitala node` running?)", self.ipc.describe(&self.endpoint))
        })?;
        stream.set_timeout(Some(IO_TIMEOUT)).map_err(|e| e.to_string())?;
        let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
        writeln!(stream, "{line}").and_then(|_| stream.flush()).map_err(|e| e.to_string())?;
        let mut reply = String::new();
        BufReader::new(stream.take(MAX_LINE as u64 * 4)).read_line(&mut reply).map_err(|e| e.to_string())?;
        Ok(reply)
    }

    pub fn hello(&self) -> Result<Value, String> {
        parse_reply(&self.round_trip(&IpcRequest::Hello)?, &self.node_key, None)
    }
}

impl Submit for NodeClient {
    fn submit(&mut self, csme: &[u8]) -> Result<Response, String> {
        let line = self.round_trip(&IpcRequest::Submit { csme: hex::encode(csme) })?;
        let v = parse_reply(&line, &self.node_key, Some(&request_digest(csme)))?;
        serde_json::from_value(v).map_err(|e| format!("bad response from node: {e}"))
    }
}
