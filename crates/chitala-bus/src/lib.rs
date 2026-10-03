//! Internal event bus (spec `specs/10-twin-and-events.md`, Blueprint v9 §3).
//!
//! Only [`Event`]s travel on the bus. There is deliberately no way to send a
//! command through it: commands go through the Reference Monitor, so the bus can
//! never become a path that bypasses Authority/Safety.
//!
//! Every subscriber has a bounded queue. When a queue is full the oldest
//! non-security event is dropped first; security events (denials, authority and
//! security-state changes) are only dropped when the queue holds nothing else
//! (v16 §27). Drops are counted, never silent.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;

use chitala_model::{EntityId, Event, EventKind};

pub const DEFAULT_CAPACITY: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    All,
    Kinds(Vec<EventKind>),
    Source(EntityId),
}

impl Filter {
    fn matches(&self, e: &Event) -> bool {
        match self {
            Filter::All => true,
            Filter::Kinds(kinds) => kinds.contains(&e.kind),
            Filter::Source(id) => &e.source == id,
        }
    }
}

struct Shared {
    filter: Filter,
    capacity: usize,
    queue: Mutex<VecDeque<Event>>,
    ready: Condvar,
    dropped: AtomicU64,
}

impl Shared {
    fn push(&self, e: Event) {
        let mut q = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        if q.len() >= self.capacity {
            if let Some(pos) = q.iter().position(|x| !x.kind.is_security()) {
                q.remove(pos);
            } else if e.kind.is_security() {
                q.pop_front();
            } else {
                // queue is full of security evidence: keep it, drop the newcomer
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        q.push_back(e);
        self.ready.notify_one();
    }
}

pub struct Subscription {
    shared: Arc<Shared>,
}

impl Subscription {
    pub fn try_recv(&self) -> Option<Event> {
        self.shared.queue.lock().unwrap_or_else(|p| p.into_inner()).pop_front()
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Option<Event> {
        let q = self.shared.queue.lock().unwrap_or_else(|p| p.into_inner());
        let (mut q, _) =
            self.shared.ready.wait_timeout_while(q, timeout, |q| q.is_empty()).unwrap_or_else(|p| p.into_inner());
        q.pop_front()
    }

    pub fn drain(&self) -> Vec<Event> {
        self.shared.queue.lock().unwrap_or_else(|p| p.into_inner()).drain(..).collect()
    }

    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Default)]
pub struct EventBus {
    subs: Arc<Mutex<Vec<Weak<Shared>>>>,
    published: Arc<AtomicU64>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subscribe(&self, filter: Filter) -> Subscription {
        self.subscribe_with_capacity(filter, DEFAULT_CAPACITY)
    }

    pub fn subscribe_with_capacity(&self, filter: Filter, capacity: usize) -> Subscription {
        let shared = Arc::new(Shared {
            filter,
            capacity: capacity.max(1),
            queue: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            dropped: AtomicU64::new(0),
        });
        self.subs.lock().unwrap_or_else(|p| p.into_inner()).push(Arc::downgrade(&shared));
        Subscription { shared }
    }

    /// Deliver to every live subscriber whose filter matches. Never blocks on a
    /// slow subscriber.
    pub fn publish(&self, event: Event) {
        self.published.fetch_add(1, Ordering::Relaxed);
        let live: Vec<Arc<Shared>> = {
            let mut subs = self.subs.lock().unwrap_or_else(|p| p.into_inner());
            subs.retain(|w| w.strong_count() > 0);
            subs.iter().filter_map(Weak::upgrade).collect()
        };
        for s in live {
            if s.filter.matches(&event) {
                s.push(event.clone());
            }
        }
    }

    pub fn published(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }

    pub fn subscriber_count(&self) -> usize {
        let mut subs = self.subs.lock().unwrap_or_else(|p| p.into_inner());
        subs.retain(|w| w.strong_count() > 0);
        subs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chitala_model::Payload;

    fn ev(kind: EventKind, n: u64) -> Event {
        Event {
            id: format!("{n:032x}"),
            kind,
            source: EntityId::parse("device:light-1").unwrap(),
            ts_ms: n,
            data: Payload::new(),
            caused_by: None,
        }
    }

    #[test]
    fn filters_and_delivery() {
        let bus = EventBus::new();
        let all = bus.subscribe(Filter::All);
        let sec = bus.subscribe(Filter::Kinds(vec![EventKind::SecurityDenied]));
        bus.publish(ev(EventKind::StateChanged, 1));
        bus.publish(ev(EventKind::SecurityDenied, 2));
        assert_eq!(all.drain().len(), 2);
        assert_eq!(sec.drain().iter().map(|e| e.ts_ms).collect::<Vec<_>>(), vec![2]);
        assert_eq!(bus.published(), 2);
    }

    #[test]
    fn overflow_keeps_security_events() {
        let bus = EventBus::new();
        let sub = bus.subscribe_with_capacity(Filter::All, 3);
        bus.publish(ev(EventKind::SecurityDenied, 1));
        bus.publish(ev(EventKind::StateChanged, 2));
        bus.publish(ev(EventKind::StateChanged, 3));
        bus.publish(ev(EventKind::SecurityDenied, 4)); // evicts #2
        bus.publish(ev(EventKind::StateChanged, 5)); // evicts #3
        let got: Vec<u64> = sub.drain().iter().map(|e| e.ts_ms).collect();
        assert_eq!(got, vec![1, 4, 5]);
        assert_eq!(sub.dropped(), 2);

        // full of security events: a state change is dropped, a denial evicts the oldest
        let sub =
            bus.subscribe_with_capacity(Filter::Kinds(vec![EventKind::SecurityDenied, EventKind::StateChanged]), 2);
        bus.publish(ev(EventKind::SecurityDenied, 10));
        bus.publish(ev(EventKind::SecurityDenied, 11));
        bus.publish(ev(EventKind::StateChanged, 12));
        bus.publish(ev(EventKind::SecurityDenied, 13));
        let got: Vec<u64> = sub.drain().iter().map(|e| e.ts_ms).collect();
        assert_eq!(got, vec![11, 13]);
        assert_eq!(sub.dropped(), 2);
    }

    #[test]
    fn dropped_subscriptions_are_pruned_and_recv_waits() {
        let bus = EventBus::new();
        {
            let _tmp = bus.subscribe(Filter::All);
            assert_eq!(bus.subscriber_count(), 1);
        }
        assert_eq!(bus.subscriber_count(), 0);
        let sub = bus.subscribe(Filter::All);
        let b2 = bus.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            b2.publish(ev(EventKind::StateChanged, 7));
        });
        assert_eq!(sub.recv_timeout(Duration::from_secs(5)).map(|e| e.ts_ms), Some(7));
        t.join().unwrap();
        assert!(sub.recv_timeout(Duration::from_millis(5)).is_none());
    }
}
