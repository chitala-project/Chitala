//! A fake [`DirectMatterBackend`]: Matter devices that answer, refuse, lose
//! answers or fall silent on demand (spec 26, 27). Compiled for this crate's
//! tests and with the `conformance` feature; never part of a node or an
//! adapter host.
//!
//! It plays a controller as the step ⑤ spike measured matter.js: a device
//! that stops answering is still subscribed until the subscription's
//! interval and a margin have passed (`notice_after`), and a command whose
//! answer is lost is never sent again.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::backend::{
    DirectMatterBackend, InvokeError, ProfileAttribute, ProfileAttributes, ProfileCommand, Subscribed, Target, Values,
};

/// One endpoint of a fake node: (cluster, attribute) → value.
pub type Attributes = BTreeMap<(u32, u32), Value>;

#[derive(Debug, Clone)]
pub struct FakeNode {
    pub alive: bool,
    pub endpoints: BTreeMap<u16, Attributes>,
    /// When the node was last heard (it keeps alive while it is alive).
    pub last_heard: Instant,
    /// Its subscription goes quiet: no reports, no keep-alives, while it
    /// still answers reads, and before the controller notices.
    pub quiet: bool,
}

/// What happens to the next command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextCommand {
    /// It takes effect, and its answer is lost.
    LoseAnswer,
    /// It does nothing, and its answer is lost.
    LoseAnswerWithoutEffect,
    /// It takes effect, its answer is lost, and the node stops answering.
    LoseAnswerAndGoSilent,
    /// The device answers this Interaction Model status, and does nothing.
    Status(u8),
    /// It takes effect, the device answers success, and then stops answering.
    SucceedThenGoSilent,
    /// A lock that jams: the bolt stops part way (`LockState` 0, not fully
    /// locked) and the device answers `FAILURE`.
    Jam,
}

#[derive(Debug)]
pub struct FakeWorld {
    pub nodes: BTreeMap<u64, FakeNode>,
    /// Every command invoked, in order: "<node>/<endpoint> <cluster>/<command> timed|untimed".
    pub invokes: Vec<String>,
    pub reads: usize,
    pub next: Option<NextCommand>,
    pub subscriptions: BTreeSet<Target>,
    /// How long after a node falls silent the controller notices.
    pub notice_after: Duration,
    /// How long a read takes.
    pub read_takes: Duration,
    /// The subscription interval the devices agree to.
    pub max_interval: Duration,
}

/// A handle on a fake Matter world; clones share it.
#[derive(Debug, Clone)]
pub struct FakeBackend {
    world: Arc<Mutex<FakeWorld>>,
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeBackend {
    pub fn new() -> Self {
        Self {
            world: Arc::new(Mutex::new(FakeWorld {
                nodes: BTreeMap::new(),
                invokes: Vec::new(),
                reads: 0,
                next: None,
                subscriptions: BTreeSet::new(),
                notice_after: Duration::from_millis(300),
                read_takes: Duration::ZERO,
                max_interval: Duration::from_millis(200),
            })),
        }
    }

    pub fn world(&self) -> MutexGuard<'_, FakeWorld> {
        self.world.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A live door lock at `target`, locked or not.
    pub fn lock(&self, target: Target, locked: bool) {
        self.set(target, (0x0101, 0x0000), json!(if locked { 1 } else { 2 }));
    }

    /// A live on/off light or plug at `target`.
    pub fn on_off(&self, target: Target, on: bool) {
        self.set(target, (0x0006, 0x0000), json!(on));
    }

    /// The device at `target` changes an attribute by itself, or by hand.
    pub fn set(&self, target: Target, path: (u32, u32), value: Value) {
        let mut w = self.world();
        let node = w.nodes.entry(target.node).or_insert_with(|| FakeNode {
            alive: true,
            endpoints: BTreeMap::new(),
            last_heard: Instant::now(),
            quiet: false,
        });
        node.endpoints.entry(target.endpoint).or_default().insert(path, value);
    }

    pub fn get(&self, target: Target, path: (u32, u32)) -> Option<Value> {
        self.world().nodes.get(&target.node)?.endpoints.get(&target.endpoint)?.get(&path).cloned()
    }

    /// The node stops answering, or answers again.
    pub fn alive(&self, node: u64, alive: bool) {
        let mut w = self.world();
        if let Some(n) = w.nodes.get_mut(&node) {
            if n.alive && !alive {
                n.last_heard = Instant::now();
            }
            n.alive = alive;
        }
    }

    /// The node's subscription goes quiet, or reports again.
    pub fn quiet(&self, node: u64, quiet: bool) {
        let mut w = self.world();
        if let Some(n) = w.nodes.get_mut(&node) {
            if !n.quiet && quiet {
                n.last_heard = Instant::now();
            }
            n.quiet = quiet;
        }
    }

    pub fn next(&self, what: NextCommand) {
        self.world().next = Some(what);
    }

    pub fn invokes(&self) -> Vec<String> {
        self.world().invokes.clone()
    }
}

/// What a command does to a device that takes it.
fn effect(endpoint: &mut Attributes, command: &ProfileCommand) {
    match (command.cluster(), command.command()) {
        (0x0101, 0x00) => {
            endpoint.insert((0x0101, 0x0000), json!(1));
        }
        (0x0101, 0x01) => {
            endpoint.insert((0x0101, 0x0000), json!(2));
        }
        (0x0006, 0x00) => {
            endpoint.insert((0x0006, 0x0000), json!(false));
        }
        (0x0006, 0x01) => {
            endpoint.insert((0x0006, 0x0000), json!(true));
        }
        _ => {}
    }
}

impl DirectMatterBackend for FakeBackend {
    fn subscribe(&self, target: Target, _attributes: &ProfileAttributes) -> Result<(), String> {
        let mut w = self.world();
        if !w.nodes.contains_key(&target.node) {
            return Err(format!("node {} is not on the fabric", target.node));
        }
        w.subscriptions.insert(target);
        Ok(())
    }

    fn read(&self, target: Target, attributes: &ProfileAttributes) -> Result<Values, String> {
        let takes = self.world().read_takes;
        std::thread::sleep(takes);
        let mut w = self.world();
        w.reads += 1;
        let node = w.nodes.get(&target.node).ok_or_else(|| format!("node {} is not on the fabric", target.node))?;
        if !node.alive {
            return Err("the device did not answer".into());
        }
        let endpoint = node.endpoints.get(&target.endpoint).ok_or("no such endpoint")?;
        let values: Values = attributes
            .attributes()
            .iter()
            .filter_map(|a| Some((*a, endpoint.get(&(a.cluster(), a.attribute()))?.clone())))
            .collect();
        if values.is_empty() {
            return Err("the device answered none of the attributes".into());
        }
        Ok(values)
    }

    fn invoke(&self, target: Target, command: &ProfileCommand) -> Result<(), InvokeError> {
        let mut w = self.world();
        let alive = w.nodes.get(&target.node).is_some_and(|n| n.alive);
        if !alive {
            // the read before the command got no answer: nothing was sent
            return Err(InvokeError::NotSent("the device did not answer".into()));
        }
        let timed = if command.timed() { "timed" } else { "untimed" };
        w.invokes.push(format!(
            "{}/{} 0x{:04X}/0x{:02X} {timed}",
            target.node,
            target.endpoint,
            command.cluster(),
            command.command()
        ));
        let next = w.next.take();
        let node = w.nodes.get_mut(&target.node).expect("alive");
        let endpoint = node.endpoints.entry(target.endpoint).or_default();
        let lost = || InvokeError::Indeterminate("no answer came".into());
        match next {
            None => {
                effect(endpoint, command);
                Ok(())
            }
            Some(NextCommand::LoseAnswer) => {
                effect(endpoint, command);
                Err(lost())
            }
            Some(NextCommand::LoseAnswerWithoutEffect) => Err(lost()),
            Some(NextCommand::LoseAnswerAndGoSilent) => {
                effect(endpoint, command);
                node.alive = false;
                node.last_heard = Instant::now();
                Err(lost())
            }
            Some(NextCommand::Status(status)) => Err(InvokeError::Status { status, cluster_status: None }),
            Some(NextCommand::Jam) => {
                endpoint.insert((0x0101, 0x0000), json!(0));
                Err(InvokeError::Status { status: 0x01, cluster_status: None })
            }
            Some(NextCommand::SucceedThenGoSilent) => {
                effect(endpoint, command);
                node.alive = false;
                node.last_heard = Instant::now();
                Ok(())
            }
        }
    }

    fn subscribed(&self, target: Target) -> Option<Subscribed> {
        let w = self.world();
        if !w.subscriptions.contains(&target) {
            return None;
        }
        let node = w.nodes.get(&target.node)?;
        let endpoint = node.endpoints.get(&target.endpoint)?;
        let values = endpoint.iter().map(|(&(c, a), v)| (attribute(c, a), v.clone())).collect();
        // a live node keeps alive; a silent one is heard no more, and the
        // controller notices after a while
        let last_heard = if node.alive && !node.quiet { Instant::now() } else { node.last_heard };
        Some(Subscribed {
            values,
            last_heard,
            live: node.alive || last_heard.elapsed() < w.notice_after,
            max_interval: Some(w.max_interval),
        })
    }
}

/// A profile attribute by its ids: the fake's own values only ever hold
/// paths the profile maps, as a controller's subscription does.
fn attribute(cluster: u32, attribute: u32) -> ProfileAttribute {
    crate::profile::HomeProfile::v0_1()
        .classes()
        .iter()
        .flat_map(ProfileAttribute::of_class)
        .find(|a| a.cluster() == cluster && a.attribute() == attribute)
        .expect("the fake holds profile attributes only")
}
