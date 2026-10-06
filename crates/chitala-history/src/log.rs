//! The history log (spec 29): one JSON line per record, in the domain's
//! private storage, through the platform layer.

use std::sync::Arc;

use chitala_platform::{AppendLog, Storage, StoragePath, Visibility};

use crate::Record;

pub struct HistoryLog {
    storage: Arc<dyn Storage>,
    path: StoragePath,
    log: Option<Box<dyn AppendLog>>,
}

impl HistoryLog {
    pub fn new(storage: Arc<dyn Storage>, path: StoragePath) -> Self {
        Self { storage, path, log: None }
    }

    /// Append a record.
    pub fn append(&mut self, record: &Record) -> Result<(), String> {
        if self.log.is_none() {
            self.log = Some(self.storage.open_append(&self.path, Visibility::Private).map_err(|e| e.to_string())?);
        }
        let mut line = serde_json::to_vec(record).map_err(|e| e.to_string())?;
        line.push(b'\n');
        self.log.as_mut().expect("opened above").append(&line).map_err(|e| e.to_string())
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
        let mut text = Vec::new();
        for (r, _) in records.iter().zip(&keep).filter(|(_, k)| **k) {
            text.extend(serde_json::to_vec(r).map_err(|e| e.to_string())?);
            text.push(b'\n');
        }
        // the append handle is reopened on the next record, on the new file
        self.log = None;
        self.storage.write_atomic(&self.path, &text, Visibility::Private).map_err(|e| e.to_string())?;
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
