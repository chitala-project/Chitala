//! Queries over the history (spec 29): pure functions over records, in the
//! order they were recorded.

use chitala_model::{EntityId, ParamValue};
use serde::Serialize;

use crate::Record;

/// An interval of a device key's history: a value, or unknown (`None`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Segment {
    pub from: u64,
    pub to: u64,
    pub value: Option<ParamValue>,
}

impl Segment {
    pub fn len(&self) -> u64 {
        self.to.saturating_sub(self.from)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The history of `device`'s `key` up to `to`, from its first record on;
/// before any record it is unknown. A record's time never goes back before
/// the interval it ends (sources can disagree by a little).
fn history(records: &[Record], device: &EntityId, key: &str, to: u64) -> Vec<Segment> {
    let mut out = Vec::new();
    let (mut value, mut since): (Option<ParamValue>, u64) = (None, 0);
    for r in records {
        let next = match r {
            Record::Observed { device: d, state, .. } if d == device => state.get(key).cloned(),
            Record::Unobservable { device: d, .. } if d == device => None,
            Record::Start { .. } | Record::Gap { .. } => None,
            _ => continue,
        };
        let at = r.at().max(since).min(to);
        if next != value {
            out.push(Segment { from: since, to: at, value: value.take() });
            value = next;
            since = at;
        }
    }
    out.push(Segment { from: since, to: to.max(since), value });
    out.retain(|s| !s.is_empty());
    out
}

/// The intervals of `device`'s `key` within `[from, to)`: each with its
/// value, or unknown.
pub fn timeline(records: &[Record], device: &EntityId, key: &str, from: u64, to: u64) -> Vec<Segment> {
    history(records, device, key, to)
        .into_iter()
        .filter(|s| s.to > from && s.from < to)
        .map(|s| Segment { from: s.from.max(from), ..s })
        .collect()
}

/// How `device`'s `key` spent `[from, to)` with regard to `value`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Summary {
    /// Time in `value`.
    pub in_value_ms: u64,
    /// Time with any known value.
    pub known_ms: u64,
    /// Time with no known value: unobservable, before any observation,
    /// while the node was not running or the recorder missed events.
    pub unknown_ms: u64,
    /// Entries into `value` from a known other value, within the window.
    /// An entry from unknown is not counted: nobody saw it happen.
    pub cycles: u64,
    /// The longest unbroken interval in `value` within the window. Unknown
    /// time breaks a run: what happened meanwhile cannot be told.
    pub longest_run_ms: u64,
    /// How long it has been in `value`, if it still is at `to`; counted from
    /// the start of that run, even before `from`.
    pub current_run_ms: Option<u64>,
    /// `in_value_ms / known_ms`, if anything is known.
    pub utilization: Option<f64>,
}

pub fn summary(records: &[Record], device: &EntityId, key: &str, value: &ParamValue, from: u64, to: u64) -> Summary {
    let full = history(records, device, key, to);
    let current_run_ms = full.last().filter(|s| s.value.as_ref() == Some(value)).map(Segment::len);
    let window = timeline(records, device, key, from, to);
    let (mut in_value_ms, mut known_ms, mut unknown_ms, mut cycles, mut longest_run_ms) = (0, 0, 0, 0, 0);
    for (i, s) in window.iter().enumerate() {
        match &s.value {
            None => unknown_ms += s.len(),
            Some(v) => {
                known_ms += s.len();
                if v == value {
                    in_value_ms += s.len();
                    longest_run_ms = longest_run_ms.max(s.len());
                    let entered = i > 0 && window[i - 1].value.as_ref().is_some_and(|p| p != value);
                    cycles += u64::from(entered);
                }
            }
        }
    }
    // the window before the first record is unknown too
    let covered: u64 = window.iter().map(Segment::len).sum();
    unknown_ms += to.saturating_sub(from).saturating_sub(covered);
    let utilization = (known_ms > 0).then(|| in_value_ms as f64 / known_ms as f64);
    Summary { in_value_ms, known_ms, unknown_ms, cycles, longest_run_ms, current_run_ms, utilization }
}

#[cfg(test)]
mod tests {
    use chitala_model::payload;

    use super::*;

    fn id(s: &str) -> EntityId {
        EntityId::parse(s).unwrap()
    }

    fn on(device: &str, at: u64, on: bool) -> Record {
        Record::Observed { device: id(device), at, observed_at: at + 5, state: payload([("on", on)]) }
    }

    fn lost(device: &str, at: u64) -> Record {
        Record::Unobservable { device: id(device), at }
    }

    const PUMP: &str = "device:pump";
    const TRUE: ParamValue = ParamValue::Bool(true);

    #[test]
    fn time_on_cycles_and_runs_by_the_source_s_time() {
        let r = [
            Record::Start { at: 0 },
            on(PUMP, 100, false),
            on(PUMP, 200, true),
            on(PUMP, 500, false),
            on(PUMP, 600, true),
            on(PUMP, 700, true), // the same fact again: one run
            on(PUMP, 800, false),
        ];
        let s = summary(&r, &id(PUMP), "on", &TRUE, 0, 1_000);
        assert_eq!(s.in_value_ms, 300 + 200);
        assert_eq!(s.known_ms, 900);
        assert_eq!(s.unknown_ms, 100, "before the first observation");
        assert_eq!(s.cycles, 2);
        assert_eq!(s.longest_run_ms, 300);
        assert_eq!(s.current_run_ms, None, "off at the end");
        assert_eq!(s.utilization, Some(500.0 / 900.0));
        let t = timeline(&r, &id(PUMP), "on", 0, 1_000);
        assert_eq!(
            t.iter().map(|s| (s.from, s.to, s.value.clone())).collect::<Vec<_>>(),
            [
                (0, 100, None),
                (100, 200, Some(ParamValue::Bool(false))),
                (200, 500, Some(TRUE)),
                (500, 600, Some(ParamValue::Bool(false))),
                (600, 800, Some(TRUE)),
                (800, 1_000, Some(ParamValue::Bool(false))),
            ]
        );
    }

    /// Unobservable time is unknown, never the last state; a run broken by
    /// it is two runs, and coming back on after it is no counted cycle.
    #[test]
    fn unobservable_time_is_unknown_and_breaks_a_run() {
        let r = [on(PUMP, 0, true), lost(PUMP, 300), on(PUMP, 400, true), on(PUMP, 600, false)];
        let s = summary(&r, &id(PUMP), "on", &TRUE, 0, 1_000);
        assert_eq!((s.in_value_ms, s.unknown_ms, s.known_ms), (300 + 200, 100, 900));
        assert_eq!((s.cycles, s.longest_run_ms), (0, 300), "nobody saw it switched on");
    }

    /// A key the device stops reporting is unknown from then on (a lock
    /// moving or jammed reports no `locked`).
    #[test]
    fn a_key_no_longer_reported_is_unknown() {
        let lock = "device:lock";
        let locked =
            |at, v: bool| Record::Observed { device: id(lock), at, observed_at: at, state: payload([("locked", v)]) };
        let moving =
            Record::Observed { device: id(lock), at: 200, observed_at: 200, state: payload([("moving", true)]) };
        let r = [locked(0, false), moving, locked(260, true)];
        let s = summary(&r, &id(lock), "locked", &ParamValue::Bool(true), 0, 1_000);
        assert_eq!((s.in_value_ms, s.unknown_ms), (740, 60));
        assert_eq!(s.current_run_ms, Some(740));
    }

    /// A restart or missed events: every device is unknown until its next
    /// record; other devices' records change nothing.
    #[test]
    fn restarts_and_gaps_are_unknown_until_observed_again() {
        let r = [
            on(PUMP, 0, true),
            Record::Gap { at: 100 },
            on("device:light", 150, true),
            Record::Start { at: 300 },
            on(PUMP, 350, true),
        ];
        let s = summary(&r, &id(PUMP), "on", &TRUE, 0, 500);
        assert_eq!((s.in_value_ms, s.unknown_ms, s.cycles), (100 + 150, 250, 0));
        assert_eq!(s.current_run_ms, Some(150));
    }

    /// A window that opens in the middle of a run: its time before the
    /// window is not counted, but the current run is measured from its start.
    #[test]
    fn a_window_counts_only_its_own_time() {
        let r = [on(PUMP, 0, false), on(PUMP, 100, true)];
        let s = summary(&r, &id(PUMP), "on", &TRUE, 400, 1_000);
        assert_eq!((s.in_value_ms, s.known_ms, s.unknown_ms, s.cycles), (600, 600, 0, 0));
        assert_eq!(s.current_run_ms, Some(900), "on since 100");
        assert_eq!(s.utilization, Some(1.0));
    }

    /// A source time older than the interval it would end never rewrites
    /// what was already recorded.
    #[test]
    fn a_late_source_time_never_goes_back() {
        let r = [on(PUMP, 100, true), on(PUMP, 50, false)];
        let t = timeline(&r, &id(PUMP), "on", 0, 200);
        assert_eq!(
            t.iter().map(|s| (s.from, s.to, s.value.clone())).collect::<Vec<_>>(),
            [(0, 100, None), (100, 200, Some(ParamValue::Bool(false))),]
        );
    }

    #[test]
    fn nothing_recorded_is_all_unknown() {
        let s = summary(&[], &id(PUMP), "on", &TRUE, 0, 1_000);
        assert_eq!((s.in_value_ms, s.known_ms, s.unknown_ms, s.utilization), (0, 0, 1_000, None));
    }
}
