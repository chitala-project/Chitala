//! The history log (spec 29): one JSON line per record, in the domain's
//! private storage, through the platform layer.
//!
//! The log is hash-chained (spec 32): each line carries `h`, the SHA-256 of
//! the line before's `h` and its own record, from zeros. An edit shows; a
//! history evaluator measures only over an intact chain. Lines written
//! before the chain existed carry no `h`: they are not trusted, and their
//! time is unknown.

use std::sync::Arc;

use chitala_platform::{AppendLog, Storage, StoragePath, Visibility};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Record;

/// One line: a record and its link in the chain.
#[derive(Serialize, Deserialize)]
struct Line {
    #[serde(flatten)]
    record: Record,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    h: Option<String>,
}

/// The chain's link for `record` after `prev`.
fn link(prev: &[u8; 32], record: &Record) -> Result<[u8; 32], String> {
    let body = serde_json::to_vec(record).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    h.update(b"chitala-history-chain-v1");
    h.update(prev);
    h.update(&body);
    Ok(h.finalize().into())
}

fn line(prev: &[u8; 32], record: &Record) -> Result<([u8; 32], Vec<u8>), String> {
    let h = link(prev, record)?;
    let mut bytes =
        serde_json::to_vec(&Line { record: record.clone(), h: Some(hex::encode(h)) }).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    Ok((h, bytes))
}

pub struct HistoryLog {
    storage: Arc<dyn Storage>,
    path: StoragePath,
    log: Option<Box<dyn AppendLog>>,
    /// The chain's last link, once known.
    head: Option<[u8; 32]>,
}

impl HistoryLog {
    pub fn new(storage: Arc<dyn Storage>, path: StoragePath) -> Self {
        Self { storage, path, log: None, head: None }
    }

    /// Append a record, chained to the last one.
    pub fn append(&mut self, record: &Record) -> Result<(), String> {
        if self.log.is_none() {
            self.log = Some(self.storage.open_append(&self.path, Visibility::Private).map_err(|e| e.to_string())?);
        }
        if self.head.is_none() {
            // a line a crash cut short is ended, so the next record is a line of its own
            let bytes = self.storage.read(&self.path, Visibility::Private).map_err(|e| e.to_string())?;
            if bytes.as_ref().is_some_and(|b| b.last().is_some_and(|last| *last != b'\n')) {
                self.log.as_mut().expect("opened above").append(b"\n").map_err(|e| e.to_string())?;
            }
            // the last whole line's link; none (or a log from before the chain): a new chain
            self.head = Some(read_chained(self.storage.as_ref(), &self.path)?.tail.unwrap_or([0; 32]));
        }
        let (h, bytes) = line(self.head.as_ref().expect("set above"), record)?;
        self.log.as_mut().expect("opened above").append(&bytes).map_err(|e| e.to_string())?;
        self.head = Some(h);
        Ok(())
    }

    /// Every record, in the order recorded; a line that is not a record is
    /// skipped (a write cut short by a crash).
    pub fn read(&self) -> Result<Vec<Record>, String> {
        read(self.storage.as_ref(), &self.path)
    }

    /// Drop the records older than `keep_from`, keeping each device's last
    /// record before it, so that its state when the window opens stays
    /// known, and the last record for every device (a start or a gap)
    /// before it. The log is rewritten atomically.
    pub fn compact(&mut self, keep_from: u64) -> Result<usize, String> {
        let records = self.read()?;
        let mut keep = vec![false; records.len()];
        let mut last_device = std::collections::BTreeMap::new();
        let mut last_global = None;
        for (i, r) in records.iter().enumerate() {
            if r.at() >= keep_from {
                keep[i] = true;
            } else if let Some(d) = r.device() {
                last_device.insert(d.clone(), i);
            } else {
                last_global = Some(i);
            }
        }
        for i in last_device.values().copied().chain(last_global) {
            keep[i] = true;
        }
        let dropped = keep.iter().filter(|k| !**k).count();
        if dropped == 0 {
            return Ok(0);
        }
        // the records kept, chained anew from zeros
        let (mut text, mut head) = (Vec::new(), [0u8; 32]);
        for (r, _) in records.iter().zip(&keep).filter(|(_, k)| **k) {
            let (h, bytes) = line(&head, r)?;
            text.extend(bytes);
            head = h;
        }
        // the append handle is reopened on the next record, on the new file
        self.log = None;
        self.storage.write_atomic(&self.path, &text, Visibility::Private).map_err(|e| e.to_string())?;
        self.head = Some(head);
        Ok(dropped)
    }
}

/// The records of the log at `path`, in the order recorded.
pub fn read(storage: &dyn Storage, path: &StoragePath) -> Result<Vec<Record>, String> {
    let Some(bytes) = storage.read(path, Visibility::Private).map_err(|e| e.to_string())? else {
        return Ok(Vec::new());
    };
    Ok(bytes.split(|b| *b == b'\n').filter_map(|line| serde_json::from_slice(line).ok()).collect())
}

/// The history as a history evaluator may measure it (spec 32).
#[derive(Debug, Clone, PartialEq)]
pub struct Chained {
    /// The records of the chain, in order; none from before it.
    pub records: Vec<Record>,
    /// The chain's hash at its last record (zeros for an empty chain).
    pub head: [u8; 32],
    /// No link is broken: no line was edited, removed from the middle, or
    /// added unchained after the chain began.
    pub intact: bool,
    /// The last whole line's link, whatever came before: where the next
    /// record chains to.
    pub(crate) tail: Option<[u8; 32]>,
}

/// Read the log at `path` and verify its chain. A line cut short by a crash
/// is skipped: the next record chains to the last whole one.
pub fn read_chained(storage: &dyn Storage, path: &StoragePath) -> Result<Chained, String> {
    let bytes = storage.read(path, Visibility::Private).map_err(|e| e.to_string())?.unwrap_or_default();
    let mut c = Chained { records: Vec::new(), head: [0; 32], intact: true, tail: None };
    let mut began = false;
    for raw in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let Ok(l) = serde_json::from_slice::<Line>(raw) else { continue };
        let Some(h) = l.h.as_deref().and_then(|h| hex::decode(h).ok()).and_then(|h| <[u8; 32]>::try_from(h).ok())
        else {
            // unchained: from before the chain, or added after it began
            if began {
                c.intact = false;
            }
            c.tail = None;
            continue;
        };
        c.tail = Some(h);
        let prev = if began { c.head } else { [0; 32] };
        if link(&prev, &l.record)? != h {
            c.intact = false;
            continue;
        }
        began = true;
        c.head = h;
        c.records.push(l.record);
    }
    Ok(c)
}

/// Where a node reads history from to answer `device.read_history` (spec 29):
/// the records, never handed out themselves.
pub trait HistorySource: Send + Sync {
    fn records(&self) -> Result<Vec<Record>, String>;
}

/// The history log at a path, read as a source.
pub struct LogReader {
    storage: Arc<dyn Storage>,
    path: StoragePath,
}

impl LogReader {
    pub fn new(storage: Arc<dyn Storage>, path: StoragePath) -> Self {
        Self { storage, path }
    }
}

impl HistorySource for LogReader {
    fn records(&self) -> Result<Vec<Record>, String> {
        read(self.storage.as_ref(), &self.path)
    }
}

impl HistorySource for Vec<Record> {
    fn records(&self) -> Result<Vec<Record>, String> {
        Ok(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use chitala_model::{payload, EntityId, ParamValue};
    use chitala_platform::memory;

    use super::*;
    use crate::query::summary;

    fn id(s: &str) -> EntityId {
        EntityId::parse(s).unwrap()
    }

    #[test]
    fn records_are_kept_privately_and_read_back_in_order() {
        let (platform, _) = memory::platform("history", 0);
        let path = StoragePath::new("history.jsonl").unwrap();
        let mut log = HistoryLog::new(Arc::clone(&platform.storage), path.clone());
        let records = [
            Record::Start { at: 0 },
            Record::Observed { device: id("device:pump"), at: 10, observed_at: 12, state: payload([("on", true)]) },
            Record::Unobservable { device: id("device:pump"), at: 20 },
            Record::Gap { at: 30 },
        ];
        for r in &records {
            log.append(r).unwrap();
        }
        assert_eq!(log.read().unwrap(), records);
        // a private read fails on an object that is not private
        assert!(platform.storage.read(&path, Visibility::Private).unwrap().is_some(), "kept private");
    }

    /// The log is a chain: intact as written, and after compaction; an edit,
    /// or a line added unchained, shows. A line a crash cut short does not
    /// break it, and lines from before the chain are not part of it.
    #[test]
    fn the_log_is_a_chain_and_an_edit_shows() {
        let (platform, _) = memory::platform("history", 0);
        let path = StoragePath::new("history.jsonl").unwrap();
        let storage = Arc::clone(&platform.storage);
        let on = |at, v: bool| Record::Observed {
            device: id("device:pump"),
            at,
            observed_at: at,
            state: payload([("on", v)]),
        };
        // a log from before the chain: two unchained lines
        let legacy = [Record::Start { at: 0 }, on(5, true)];
        let mut text = Vec::new();
        for r in &legacy {
            text.extend(serde_json::to_vec(r).unwrap());
            text.push(b'\n');
        }
        storage.write_atomic(&path, &text, Visibility::Private).unwrap();
        let mut log = HistoryLog::new(Arc::clone(&storage), path.clone());
        for r in [on(10, false), on(20, true)] {
            log.append(&r).unwrap();
        }
        let c = read_chained(storage.as_ref(), &path).unwrap();
        assert!(c.intact);
        assert_eq!(c.records, [on(10, false), on(20, true)], "only the chain");
        assert_eq!(log.read().unwrap().len(), 4, "queries still read every record");
        // a crash cut a line short; the recorder goes on after it
        storage.open_append(&path, Visibility::Private).unwrap().append(b"{\"r\":\"observ").unwrap();
        let mut log = HistoryLog::new(Arc::clone(&storage), path.clone());
        log.append(&on(30, false)).unwrap();
        let c = read_chained(storage.as_ref(), &path).unwrap();
        assert!(c.intact, "a cut line breaks nothing");
        assert_eq!(c.records.last(), Some(&on(30, false)));
        // compaction re-chains what it keeps
        log.compact(15).unwrap();
        let c = read_chained(storage.as_ref(), &path).unwrap();
        assert!(c.intact);
        log.append(&on(40, true)).unwrap();
        assert!(read_chained(storage.as_ref(), &path).unwrap().intact);
        // an edit: a run made shorter
        let text = String::from_utf8(storage.read(&path, Visibility::Private).unwrap().unwrap()).unwrap();
        let edited = text.replacen("\"at\":20", "\"at\":25", 1);
        assert_ne!(edited, text);
        storage.write_atomic(&path, edited.as_bytes(), Visibility::Private).unwrap();
        assert!(!read_chained(storage.as_ref(), &path).unwrap().intact, "the edit shows");
        // a line added unchained after the chain began
        storage.write_atomic(&path, text.as_bytes(), Visibility::Private).unwrap();
        let mut forged = serde_json::to_vec(&on(50, false)).unwrap();
        forged.push(b'\n');
        storage.open_append(&path, Visibility::Private).unwrap().append(&forged).unwrap();
        assert!(!read_chained(storage.as_ref(), &path).unwrap().intact, "an unchained line shows");
    }

    /// Retention keeps each device's state when the window opens, so the
    /// durations at its start stay right.
    #[test]
    fn retention_keeps_the_state_at_the_window_s_start() {
        let (platform, _) = memory::platform("history", 0);
        let path = StoragePath::new("history.jsonl").unwrap();
        let mut log = HistoryLog::new(Arc::clone(&platform.storage), path);
        let on = |at, v: bool| Record::Observed {
            device: id("device:pump"),
            at,
            observed_at: at,
            state: payload([("on", v)]),
        };
        for r in [Record::Start { at: 0 }, on(10, true), on(20, false), on(30, true), on(500, false)] {
            log.append(&r).unwrap();
        }
        let before = summary(&log.read().unwrap(), &id("device:pump"), "on", &ParamValue::Bool(true), 100, 1_000);
        assert_eq!(log.compact(100).unwrap(), 2, "the first on, the off: the start and the last state are kept");
        let after = log.read().unwrap();
        assert_eq!(after, [Record::Start { at: 0 }, on(30, true), on(500, false)]);
        let s = summary(&after, &id("device:pump"), "on", &ParamValue::Bool(true), 100, 1_000);
        assert_eq!(s, before);
        assert_eq!(s.in_value_ms, 400);
        // and the log goes on
        log.append(&on(600, true)).unwrap();
        assert_eq!(log.read().unwrap().len(), 4);
    }
}
