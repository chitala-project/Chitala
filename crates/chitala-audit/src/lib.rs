//! Tamper-evident audit log (spec `specs/09-audit.md`, Blueprint v16 §7–8).
//!
//! One JSON object per line. Every record carries `seq`, `ts_ms`, `kind`, `prev`
//! (hash of the previous record, 64 zero hex digits for the first) and `hash`:
//!
//! ```text
//! hash = SHA-256( "chitala-audit-v1" 0x00 || prev(32 bytes) || JCS(record without "hash") )
//! ```
//!
//! `JCS` is RFC 8785 canonical JSON restricted to strings, integers, booleans,
//! null, arrays and objects (no floats). Periodic `checkpoint` records are signed
//! with the node's Ed25519 service key over
//! `"chitala-audit-checkpoint-v1" 0x00 || head(32) || seq(u64 BE)`, so a verifier
//! holding only the node's public key can detect edits, deletions, insertions and
//! truncation before the last checkpoint.
//!
//! Secrets never enter the log: parameters whose names look secret are replaced by
//! `"[REDACTED]"` and long texts are truncated ([`redact_payload`]).

#![forbid(unsafe_code)]

use std::collections::HashMap;

use chitala_identity::{key_id_of, verify, KeyId, Keypair, PublicKey};
use chitala_model::{EntityId, ParamValue, Payload};
use chitala_platform::{AppendLog, PlatformError, Storage, StoragePath, Visibility};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const HASH_DOMAIN: &[u8] = b"chitala-audit-v1\x00";
pub const CHECKPOINT_DOMAIN: &[u8] = b"chitala-audit-checkpoint-v1\x00";
pub const GENESIS: [u8; 32] = [0u8; 32];
/// Default number of records between automatic checkpoints.
pub const DEFAULT_CHECKPOINT_EVERY: u64 = 64;
/// Text parameter values longer than this are truncated in the log.
pub const MAX_LOGGED_TEXT: usize = 200;
const RESERVED: [&str; 6] = ["seq", "ts_ms", "kind", "prev", "hash", "v"];

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The storage failed, or holds the log with weaker protection than
    /// required (e.g. readable or writable by others).
    #[error("audit storage error: {0}")]
    Storage(#[from] PlatformError),
    #[error("audit log is corrupt or tampered at line {line}: {reason}")]
    Tampered { line: u64, reason: String },
    #[error("field {0:?} is reserved")]
    ReservedField(String),
    #[error("value not representable in canonical JSON: {0}")]
    NotCanonical(String),
}

// ───────────────────────────── canonical JSON ─────────────────────────────

/// RFC 8785 canonical form of the supported JSON subset.
pub fn canonical_json(v: &Value) -> Result<String, AuditError> {
    let mut out = String::new();
    write_canonical(v, &mut out)?;
    Ok(out)
}

fn write_canonical(v: &Value, out: &mut String) -> Result<(), AuditError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                return Err(AuditError::NotCanonical(format!("float {n}")));
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            // JCS orders object members by UTF-16 code units
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_canonical(&map[k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn record_hash(prev: &[u8; 32], body: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(HASH_DOMAIN);
    h.update(prev);
    h.update(body.as_bytes());
    h.finalize().into()
}

fn checkpoint_message(head: &[u8; 32], seq: u64) -> Vec<u8> {
    let mut m = CHECKPOINT_DOMAIN.to_vec();
    m.extend_from_slice(head);
    m.extend_from_slice(&seq.to_be_bytes());
    m
}

// ───────────────────────────── redaction ─────────────────────────────

const SECRET_MARKERS: [&str; 7] = ["password", "passwd", "secret", "token", "credential", "private", "pin"];

fn looks_secret(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SECRET_MARKERS.iter().any(|m| n.contains(m)) || n == "key" || n.ends_with("_key")
}

/// Payload as it may appear in the log (v16 §8: no credentials, minimal content).
pub fn redact_payload(payload: &Payload) -> Value {
    let mut out = Map::new();
    for (k, v) in payload {
        let logged = if looks_secret(k) {
            Value::String("[REDACTED]".into())
        } else {
            match v {
                ParamValue::Bool(b) => Value::Bool(*b),
                ParamValue::Int(i) => Value::from(*i),
                ParamValue::Text(t) if t.chars().count() > MAX_LOGGED_TEXT => {
                    let head: String = t.chars().take(MAX_LOGGED_TEXT).collect();
                    Value::String(format!("{head}…[TRUNCATED {} chars]", t.chars().count()))
                }
                ParamValue::Text(t) => Value::String(t.clone()),
            }
        };
        out.insert(k.clone(), logged);
    }
    Value::Object(out)
}

// ───────────────────────────── the log ─────────────────────────────

/// Key used to sign checkpoints.
pub struct Signer {
    pub id: EntityId,
    pub key: Keypair,
}

enum Sink {
    /// Durable, through the platform (PAL, spec 18): no file system API here.
    Stored {
        log: Box<dyn AppendLog>,
        path: StoragePath,
    },
    Memory(Vec<String>),
}

pub struct AuditLog {
    sink: Sink,
    seq: u64,
    head: [u8; 32],
    signer: Option<Signer>,
    checkpoint_every: u64,
    since_checkpoint: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appended {
    pub seq: u64,
    pub hash: String,
}

impl AuditLog {
    /// In-memory log (tests, `chitala demo`).
    pub fn in_memory(signer: Option<Signer>) -> Self {
        Self::with_sink(Sink::Memory(Vec::new()), 0, GENESIS, signer)
    }

    /// Open (or create) the log at `path` in the platform's storage. An
    /// existing log is fully verified first — a node never resumes on top of a
    /// broken chain.
    pub fn open(storage: &dyn Storage, path: &StoragePath, signer: Option<Signer>) -> Result<Self, AuditError> {
        Self::open_anchored(storage, path, signer, None).map(|(log, _)| log)
    }

    /// Like [`AuditLog::open`], and additionally require that the log still
    /// contains `anchor` — a `(seq, hash)` the caller recorded earlier in its own
    /// state. A missing, replaced or truncated log fails (anti-rollback, v13 §7).
    ///
    /// The log is [`Visibility::Private`]: tamper-evident is not public (v16 §7),
    /// and a log others can read or write is refused rather than used.
    pub fn open_anchored(
        storage: &dyn Storage,
        path: &StoragePath,
        signer: Option<Signer>,
        anchor: Option<&Anchor>,
    ) -> Result<(Self, VerifyReport), AuditError> {
        let trusted: HashMap<KeyId, PublicKey> = signer.iter().map(|s| (s.key.key_id(), s.key.public_key())).collect();
        let report = match storage.read(path, Visibility::Private)? {
            Some(bytes) => verify_bytes(&bytes, &trusted, anchor)?,
            None => verify_lines_anchored(std::iter::empty(), &trusted, anchor)?,
        };
        let (seq, head) = (report.records, report.head_bytes);
        let log = storage.open_append(path, Visibility::Private)?;
        Ok((Self::with_sink(Sink::Stored { log, path: path.clone() }, seq, head, signer), report))
    }

    fn with_sink(sink: Sink, seq: u64, head: [u8; 32], signer: Option<Signer>) -> Self {
        Self { sink, seq, head, signer, checkpoint_every: DEFAULT_CHECKPOINT_EVERY, since_checkpoint: 0 }
    }

    pub fn set_checkpoint_every(&mut self, n: u64) {
        self.checkpoint_every = n.max(1);
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn head(&self) -> String {
        hex::encode(self.head)
    }

    /// The current head as an [`Anchor`] (`None` for an empty log).
    pub fn anchor(&self) -> Option<Anchor> {
        (self.seq > 0).then(|| Anchor { seq: self.seq, hash: self.head() })
    }

    pub fn path(&self) -> Option<&StoragePath> {
        match &self.sink {
            Sink::Stored { path, .. } => Some(path),
            Sink::Memory(_) => None,
        }
    }

    /// Lines of an in-memory log (empty for stored logs).
    pub fn lines(&self) -> &[String] {
        match &self.sink {
            Sink::Memory(lines) => lines,
            Sink::Stored { .. } => &[],
        }
    }

    /// Append a record; writes a signed checkpoint automatically every
    /// `checkpoint_every` records when a signer is configured.
    pub fn append(&mut self, ts_ms: u64, kind: &str, fields: Map<String, Value>) -> Result<Appended, AuditError> {
        for k in fields.keys() {
            if RESERVED.contains(&k.as_str()) {
                return Err(AuditError::ReservedField(k.clone()));
            }
        }
        let appended = self.write_record(ts_ms, kind, fields)?;
        self.since_checkpoint += 1;
        if self.signer.is_some() && self.since_checkpoint >= self.checkpoint_every {
            self.checkpoint(ts_ms)?;
        }
        Ok(appended)
    }

    /// Write a signed checkpoint over the current head. No-op without a signer.
    pub fn checkpoint(&mut self, ts_ms: u64) -> Result<Option<Appended>, AuditError> {
        let Some(signer) = &self.signer else {
            return Ok(None);
        };
        let seq = self.seq + 1;
        let sig = signer.key.sign(&checkpoint_message(&self.head, seq));
        let mut fields = Map::new();
        fields.insert("signer".into(), Value::String(signer.id.to_string()));
        fields.insert("kid".into(), Value::String(hex::encode(signer.key.key_id())));
        fields.insert("sig".into(), Value::String(hex::encode(sig)));
        let a = self.write_record(ts_ms, "checkpoint", fields)?;
        self.since_checkpoint = 0;
        Ok(Some(a))
    }

    fn write_record(&mut self, ts_ms: u64, kind: &str, mut fields: Map<String, Value>) -> Result<Appended, AuditError> {
        let seq = self.seq + 1;
        fields.insert("v".into(), Value::from(1u64));
        fields.insert("seq".into(), Value::from(seq));
        fields.insert("ts_ms".into(), Value::from(ts_ms));
        fields.insert("kind".into(), Value::String(kind.to_string()));
        fields.insert("prev".into(), Value::String(hex::encode(self.head)));
        let mut record = Value::Object(fields);
        let body = canonical_json(&record)?;
        let hash = record_hash(&self.head, &body);
        record.as_object_mut().expect("object").insert("hash".into(), Value::String(hex::encode(hash)));
        let line = canonical_json(&record)?;
        match &mut self.sink {
            Sink::Stored { log, .. } => {
                // one durable append per record (the backend syncs)
                let mut record = line.into_bytes();
                record.push(b'\n');
                log.append(&record)?;
            }
            Sink::Memory(lines) => lines.push(line),
        }
        self.seq = seq;
        self.head = hash;
        Ok(Appended { seq, hash: hex::encode(hash) })
    }
}

// ───────────────────────────── verification ─────────────────────────────

/// A point in the chain that must still exist: record `seq` with hash `hash`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Anchor {
    pub seq: u64,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub records: u64,
    pub checkpoints: u64,
    /// Highest seq covered by a checkpoint signed by a trusted key.
    pub last_signed_seq: Option<u64>,
    pub head: String,
    /// Highest `epoch` field recorded in any entry (0 if none).
    pub max_epoch: u64,
    /// Latest `ts_ms` of any entry (0 if none): the time high-water mark.
    pub max_ts_ms: u64,
    head_bytes: [u8; 32],
}

impl VerifyReport {
    /// Records after the last trusted checkpoint (not protected against truncation).
    pub fn unsigned_tail(&self) -> u64 {
        self.records - self.last_signed_seq.unwrap_or(0)
    }
}

/// Verify a sequence of lines. Checkpoints signed by a key not in `trusted` are
/// still chained but do not count as signed; a checkpoint whose signature is
/// invalid for a trusted key is tampering.
pub fn verify_lines<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    trusted: &HashMap<KeyId, PublicKey>,
) -> Result<VerifyReport, AuditError> {
    verify_lines_anchored(lines, trusted, None)
}

/// [`verify_lines`] that also requires the chain to contain `anchor`.
pub fn verify_lines_anchored<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    trusted: &HashMap<KeyId, PublicKey>,
    anchor: Option<&Anchor>,
) -> Result<VerifyReport, AuditError> {
    let mut head = GENESIS;
    let mut seq = 0u64;
    let mut checkpoints = 0u64;
    let mut last_signed = None;
    let mut max_epoch = 0u64;
    let mut max_ts_ms = 0u64;
    for (i, line) in lines.into_iter().enumerate() {
        let n = i as u64 + 1;
        let bad = |reason: String| AuditError::Tampered { line: n, reason };
        let mut v: Value = serde_json::from_str(line).map_err(|e| bad(format!("not JSON: {e}")))?;
        if canonical_json(&v).ok().as_deref() != Some(line) {
            return Err(bad("record is not in canonical form".into()));
        }
        let obj = v.as_object_mut().ok_or_else(|| bad("record is not an object".into()))?;
        let hash = match obj.remove("hash") {
            Some(Value::String(h)) => h,
            _ => return Err(bad("missing hash".into())),
        };
        if obj.get("seq").and_then(Value::as_u64) != Some(seq + 1) {
            return Err(bad(format!("expected seq {}", seq + 1)));
        }
        if obj.get("prev").and_then(Value::as_str) != Some(hex::encode(head).as_str()) {
            return Err(bad("prev does not match the previous record".into()));
        }
        let body = canonical_json(&v).map_err(|e| bad(e.to_string()))?;
        let expected = record_hash(&head, &body);
        if hex::encode(expected) != hash {
            return Err(bad("hash mismatch".into()));
        }
        let obj = v.as_object().expect("object");
        if let Some(a) = anchor.filter(|a| a.seq == seq + 1) {
            if !a.hash.eq_ignore_ascii_case(&hash) {
                return Err(bad(format!("record #{} differs from the anchored hash: the log was replaced", a.seq)));
            }
        }
        max_epoch = max_epoch.max(obj.get("epoch").and_then(Value::as_u64).unwrap_or(0));
        max_ts_ms = max_ts_ms.max(obj.get("ts_ms").and_then(Value::as_u64).unwrap_or(0));
        if obj.get("kind").and_then(Value::as_str) == Some("checkpoint") {
            checkpoints += 1;
            let kid = obj.get("kid").and_then(Value::as_str).and_then(|k| hex::decode(k).ok());
            let sig = obj.get("sig").and_then(Value::as_str).and_then(|s| hex::decode(s).ok());
            let (Some(kid), Some(sig)) = (kid, sig) else {
                return Err(bad("checkpoint without kid/sig".into()));
            };
            if let Some(pk) = <[u8; 16]>::try_from(kid.as_slice()).ok().and_then(|k| trusted.get(&k)) {
                if key_id_of(pk).as_slice() != kid.as_slice() || !verify(pk, &checkpoint_message(&head, seq + 1), &sig)
                {
                    return Err(bad("checkpoint signature is invalid".into()));
                }
                last_signed = Some(seq + 1);
            }
        }
        head = expected;
        seq += 1;
    }
    if let Some(a) = anchor.filter(|a| a.seq > seq) {
        return Err(AuditError::Tampered {
            line: seq + 1,
            reason: format!("log ends at #{seq} but record #{} was anchored: truncated, deleted or replaced", a.seq),
        });
    }
    Ok(VerifyReport {
        records: seq,
        checkpoints,
        last_signed_seq: last_signed,
        head: hex::encode(head),
        max_epoch,
        max_ts_ms,
        head_bytes: head,
    })
}

fn verify_bytes(
    bytes: &[u8],
    trusted: &HashMap<KeyId, PublicKey>,
    anchor: Option<&Anchor>,
) -> Result<VerifyReport, AuditError> {
    let text =
        std::str::from_utf8(bytes).map_err(|e| AuditError::Tampered { line: 0, reason: format!("not UTF-8: {e}") })?;
    verify_lines_anchored(text.lines(), trusted, anchor)
}

/// Verify a stored log; `None` if there is none.
pub fn verify_stored(
    storage: &dyn Storage,
    path: &StoragePath,
    trusted: &HashMap<KeyId, PublicKey>,
) -> Result<Option<VerifyReport>, AuditError> {
    match storage.read(path, Visibility::Private)? {
        Some(bytes) => verify_bytes(&bytes, trusted, None).map(Some),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chitala_identity::test_seed;
    use chitala_model::payload;
    use serde_json::json;

    fn signer() -> Signer {
        Signer { id: EntityId::parse("service:node").unwrap(), key: Keypair::from_seed(&test_seed("service:node")) }
    }

    fn trusted() -> HashMap<KeyId, PublicKey> {
        let k = signer().key;
        HashMap::from([(k.key_id(), k.public_key())])
    }

    fn fields(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn sample_log(n: u64) -> AuditLog {
        let mut log = AuditLog::in_memory(Some(signer()));
        log.set_checkpoint_every(4);
        for i in 0..n {
            log.append(1_000 + i, "decision", fields(json!({"decision": "allow", "i": i}))).unwrap();
        }
        log
    }

    #[test]
    fn canonical_json_matches_rfc8785_subset() {
        let v = json!({"b": 1, "a": [true, null, "x\"\\\n\u{1}é"], "A": {"z": -5, "y": 18446744073709551615u64}});
        assert_eq!(
            canonical_json(&v).unwrap(),
            r#"{"A":{"y":18446744073709551615,"z":-5},"a":[true,null,"x\"\\\n\u0001é"],"b":1}"#
        );
        assert!(canonical_json(&json!({"f": 1.5})).is_err());
    }

    #[test]
    fn chain_verifies_and_checkpoints_are_signed() {
        let log = sample_log(10);
        // 10 records + a checkpoint after every 4 → 12 lines
        assert_eq!(log.lines().len(), 12);
        let report = verify_lines(log.lines().iter().map(String::as_str), &trusted()).unwrap();
        assert_eq!(report.records, 12);
        assert_eq!(report.checkpoints, 2);
        assert_eq!(report.last_signed_seq, Some(10));
        assert_eq!(report.unsigned_tail(), 2);
        assert_eq!(report.head, log.head());
        // without the trusted key the chain still verifies, but nothing counts as signed
        let r = verify_lines(log.lines().iter().map(String::as_str), &HashMap::new()).unwrap();
        assert_eq!(r.last_signed_seq, None);
    }

    #[test]
    fn tampering_is_detected() {
        let log = sample_log(10);
        let lines: Vec<String> = log.lines().to_vec();
        let check = |ls: &[String]| verify_lines(ls.iter().map(String::as_str), &trusted());

        // edit a field
        let mut edited = lines.clone();
        edited[2] = edited[2].replace("\"allow\"", "\"deny\"");
        assert!(matches!(check(&edited), Err(AuditError::Tampered { line: 3, .. })));
        // delete a record
        let mut deleted = lines.clone();
        deleted.remove(1);
        assert!(matches!(check(&deleted), Err(AuditError::Tampered { line: 2, .. })));
        // reorder
        let mut swapped = lines.clone();
        swapped.swap(0, 1);
        assert!(check(&swapped).is_err());
        // re-hash an edited record (attacker without the signing key): caught at the checkpoint
        let mut rehashed: Vec<Value> = lines.iter().map(|l| serde_json::from_str(l).unwrap()).collect();
        rehashed[0]["decision"] = json!("deny");
        let mut prev = GENESIS;
        let mut relines = Vec::new();
        for mut r in rehashed {
            r["prev"] = json!(hex::encode(prev));
            r.as_object_mut().unwrap().remove("hash");
            let h = record_hash(&prev, &canonical_json(&r).unwrap());
            r["hash"] = json!(hex::encode(h));
            relines.push(canonical_json(&r).unwrap());
            prev = h;
        }
        let err = check(&relines).unwrap_err();
        assert!(matches!(err, AuditError::Tampered { line: 5, .. }), "{err}");
        // non-canonical spacing
        let mut spaced = lines.clone();
        spaced[0] = spaced[0].replacen(':', ": ", 1);
        assert!(check(&spaced).is_err());
    }

    #[test]
    fn anchors_detect_truncation_and_replacement() {
        let log = sample_log(10);
        let lines: Vec<&str> = log.lines().iter().map(String::as_str).collect();
        let anchor = log.anchor().unwrap();
        assert!(verify_lines_anchored(lines.iter().copied(), &trusted(), Some(&anchor)).is_ok());
        // an anchor in the middle is fine
        let mid: Value = serde_json::from_str(lines[4]).unwrap();
        let a = Anchor { seq: 5, hash: mid["hash"].as_str().unwrap().to_string() };
        assert!(verify_lines_anchored(lines.iter().copied(), &trusted(), Some(&a)).is_ok());
        // truncated (or deleted: zero lines)
        assert!(verify_lines_anchored(lines[..6].iter().copied(), &trusted(), Some(&anchor)).is_err());
        assert!(verify_lines_anchored(std::iter::empty(), &trusted(), Some(&anchor)).is_err());
        // a different, internally valid log of the same length
        let other = sample_log(10);
        let mut other_lines: Vec<String> = other.lines().to_vec();
        other_lines[0] = {
            let mut l = AuditLog::in_memory(Some(signer()));
            l.set_checkpoint_every(4);
            l.append(999, "decision", fields(json!({"decision": "deny"}))).unwrap();
            l.lines()[0].clone()
        };
        assert!(verify_lines_anchored(other_lines.iter().map(String::as_str), &trusted(), Some(&a)).is_err());
    }

    #[test]
    fn max_epoch_is_reported() {
        let mut log = AuditLog::in_memory(None);
        log.append(1, "authority", fields(json!({"epoch": 3}))).unwrap();
        log.append(2, "decision", fields(json!({"epoch": 2}))).unwrap();
        let r = verify_lines(log.lines().iter().map(String::as_str), &HashMap::new()).unwrap();
        assert_eq!(r.max_epoch, 3);
        assert_eq!(r.max_ts_ms, 2);
    }

    #[test]
    fn redaction() {
        let p = payload([
            ("brightness_pct", ParamValue::from(40i64)),
            ("parent_token", ParamValue::from("EnQKCh...")),
            ("wifi_password", ParamValue::from("hunter2")),
            ("api_key", ParamValue::from("abc")),
            ("note", ParamValue::Text("x".repeat(500))),
        ]);
        let r = redact_payload(&p);
        assert_eq!(r["brightness_pct"], json!(40));
        assert_eq!(r["parent_token"], json!("[REDACTED]"));
        assert_eq!(r["wifi_password"], json!("[REDACTED]"));
        assert_eq!(r["api_key"], json!("[REDACTED]"));
        assert!(r["note"].as_str().unwrap().contains("TRUNCATED 500"));
        assert!(!r.to_string().contains("hunter2"));
    }

    #[test]
    fn reserved_fields_rejected() {
        let mut log = AuditLog::in_memory(None);
        assert!(matches!(log.append(1, "x", fields(json!({"hash": "00"}))), Err(AuditError::ReservedField(_))));
        assert!(log.checkpoint(1).unwrap().is_none());
    }

    #[test]
    fn stored_log_resumes_and_refuses_tampered_or_exposed_storage() {
        // any PAL storage backend; the hosted one runs the same code on files
        let storage = chitala_platform::memory::MemoryStorage::new();
        let path = StoragePath::new("test.audit.jsonl").unwrap();
        {
            let mut log = AuditLog::open(&storage, &path, Some(signer())).unwrap();
            log.append(1, "node", fields(json!({"event": "start"}))).unwrap();
            log.checkpoint(2).unwrap();
        }
        {
            let mut log = AuditLog::open(&storage, &path, Some(signer())).unwrap();
            assert_eq!(log.seq(), 2);
            log.append(3, "node", fields(json!({"event": "stop"}))).unwrap();
        }
        let report = verify_stored(&storage, &path, &trusted()).unwrap().unwrap();
        assert_eq!(report.records, 3);
        assert_eq!(report.last_signed_seq, Some(2));

        let text = String::from_utf8(storage.read(&path, Visibility::Private).unwrap().unwrap()).unwrap();
        storage.tamper(&path, text.replace("\"start\"", "\"strat\"").into_bytes());
        assert!(matches!(AuditLog::open(&storage, &path, Some(signer())), Err(AuditError::Tampered { line: 1, .. })));

        // a log others could read or write is refused, not used
        storage.weaken(&path);
        assert!(matches!(AuditLog::open(&storage, &path, Some(signer())), Err(AuditError::Storage(_))));
        // and a missing log is just empty
        let fresh = StoragePath::new("other.audit.jsonl").unwrap();
        assert!(verify_stored(&storage, &fresh, &trusted()).unwrap().is_none());
    }
}
