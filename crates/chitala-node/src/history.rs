//! The history recorder on the node (spec 29). It stays outside the Trusted
//! Core: it reads what the node published on its event bus, and the node's
//! twins when it has to resynchronise; it decides nothing, and the node never
//! waits for it.

use std::sync::{Arc, Mutex};

use chitala_history::log::HistoryLog;
use chitala_history::recorder::{self, Now, Recorder, Retention, Snapshot};
use chitala_state::Twin;

use crate::{Node, NodeError};

/// Record `node`'s history into `log` for as long as the returned recorder lives.
pub fn record(node: &Arc<Mutex<Node>>, log: HistoryLog, retention: Retention) -> Result<Recorder, NodeError> {
    let (events, clock) = {
        let n = node.lock().map_err(|_| NodeError::Config("the node lock is poisoned".into()))?;
        (n.subscribe_with_capacity(recorder::filter(), recorder::QUEUE), n.clock())
    };
    let weak = Arc::downgrade(node);
    let snapshot: Snapshot = Box::new(move || {
        let Some(node) = weak.upgrade() else { return Vec::new() };
        let Ok(n) = node.lock() else { return Vec::new() };
        let twins = n.twins();
        twins.ids().filter_map(|id| Some((id.clone(), now_of(twins.get(id)?)))).collect()
    });
    Ok(recorder::start(events, log, snapshot, clock, retention))
}

/// What a twin says about its device now, for the history.
fn now_of(t: &Twin) -> Now {
    match (t.unobservable_since_ms, t.reported_at_ms) {
        (Some(since), _) => Now::Unobservable { since },
        (None, Some(at)) => Now::Observed { state: t.reported.clone(), at: t.source_at_ms.unwrap_or(at).min(at) },
        (None, None) => Now::Unknown,
    }
}
