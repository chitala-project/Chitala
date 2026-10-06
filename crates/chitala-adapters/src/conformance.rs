//! The adapter conformance suite (v0.3, spec 26): one contract, checked
//! against every adapter. An adapter executes an admitted order once and
//! never again; says so when it cannot know what an order did; never makes
//! up a state; and confirms a state only when it is tied to the device.
//!
//! A [`Rig`] is an adapter and the world behind it: the device, the faults
//! that can be put in its way, and the physical truth the adapter is checked
//! against. The checks themselves are test code: the adapter's half of the
//! contract in `chitala-adapters/tests/conformance.rs`, and the node's half,
//! outcome verification and recovery through the whole chain, in
//! `chitala-node/tests/conformance.rs`. Nothing here builds, admits or sends
//! an order.
//!
//! Compiled only with the `conformance` feature; never part of a node or an
//! adapter host.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use chitala_model::{EntityId, ParamValue};
use serde_json::json;

use crate::fake_ha::{Behaviour, FakeHa, TOKEN};
use crate::fake_matter::FakeMatter;
use crate::home_assistant::link::Timing;
use crate::home_assistant::HomeAssistantAdapter;
use crate::mock::{Lost, MockAdapter, VirtualKind};
use crate::{AdapterError, DeviceAdapter};

/// What can be put in the way of the next command, or of the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The device cannot be reached any more: nothing gets to it, and
    /// nothing is heard from it.
    Offline,
    /// The next command reaches the device and takes effect; its answer is lost.
    LoseAnswer,
    /// The next command reaches the device, which does nothing; its answer is lost.
    LoseAnswerWithoutEffect,
    /// The next command reaches the device and takes effect; its answer is
    /// lost, and the device cannot be reached from then on.
    LoseAnswerAndGoSilent,
    /// The next command is refused, and the backend says so; nothing moves.
    Refuse,
}

/// An adapter and the world behind it.
pub trait Rig {
    /// The adapter's name, as device descriptors use it.
    fn adapter_name(&self) -> &'static str;
    /// The adapter on this world, ready to serve. Called once per rig.
    fn adapter(&mut self) -> Box<dyn DeviceAdapter>;
    /// The door lock the rig drives (Home profile class `lock`).
    fn lock(&self) -> EntityId;
    /// Whether the bolt is thrown, physically.
    fn bolt(&self) -> Option<bool>;
    /// Someone turns the bolt by hand, outside Chitala.
    fn by_hand(&mut self, locked: bool);
    /// Commands that reached the device, or the backend in front of it.
    fn commands(&self) -> usize;
    fn fault(&mut self, fault: Fault);
    /// The device can be reached again, and no fault is pending.
    fn heal(&mut self);
}

// ───────────────────────────── the mock ─────────────────────────────

const MOCK_LOCK: &str = "device:lock";

/// The mock adapter's virtual lock. The rig keeps a handle on the same
/// virtual devices as the adapter it hands out.
pub struct MockRig {
    world: MockAdapter,
}

impl MockRig {
    pub fn new() -> Self {
        let mut world = MockAdapter::new();
        world.add(EntityId::parse(MOCK_LOCK).expect("valid"), VirtualKind::Lock);
        Self { world }
    }
}

impl Default for MockRig {
    fn default() -> Self {
        Self::new()
    }
}

impl Rig for MockRig {
    fn adapter_name(&self) -> &'static str {
        "mock"
    }

    fn adapter(&mut self) -> Box<dyn DeviceAdapter> {
        Box::new(self.world.clone())
    }

    fn lock(&self) -> EntityId {
        EntityId::parse(MOCK_LOCK).expect("valid")
    }

    fn bolt(&self) -> Option<bool> {
        self.world.state(&self.lock())?.get("locked").and_then(ParamValue::as_bool)
    }

    fn by_hand(&mut self, locked: bool) {
        let lock = self.lock();
        self.world.by_hand(&lock, "locked", locked.into());
    }

    fn commands(&self) -> usize {
        self.world.commands(&self.lock())
    }

    fn fault(&mut self, fault: Fault) {
        let lock = self.lock();
        match fault {
            Fault::Offline => self.world.set_offline(&lock, true),
            Fault::LoseAnswer => self.world.lose_next(&lock, Lost::AfterEffect),
            Fault::LoseAnswerWithoutEffect => self.world.lose_next(&lock, Lost::WithoutEffect),
            Fault::LoseAnswerAndGoSilent => self.world.lose_next(&lock, Lost::AndOffline),
            Fault::Refuse => self.world.fail_next(&lock, AdapterError::Refused("the device refused".into())),
        }
    }

    fn heal(&mut self) {
        let lock = self.lock();
        self.world.set_offline(&lock, false);
    }
}

// ───────────────────────────── Home Assistant ─────────────────────────────

const HA_LOCK: &str = "lock.front_door";
const HA_NODE: u64 = 4;
const TOKEN_ENV: &str = "CHITALA_CONFORMANCE_FAKE_HA_TOKEN";

/// A Matter lock behind a (fake) Home Assistant, read for evidence through a
/// (fake) Matter server (finding F10).
pub struct HaRig {
    pub ha: FakeHa,
    pub matter: FakeMatter,
}

impl HaRig {
    pub fn new() -> Self {
        static ENV: OnceLock<()> = OnceLock::new();
        ENV.get_or_init(|| std::env::set_var(TOKEN_ENV, TOKEN));
        let ha = FakeHa::start();
        let matter = FakeMatter::start();
        matter.world().lock(HA_NODE, 1);
        ha.wire(HA_LOCK, HA_NODE, &matter);
        Self { ha, matter }
    }

    /// The timing the rig's adapter runs on: fast, for tests.
    pub fn timing() -> Timing {
        Timing {
            connect: Duration::from_secs(2),
            call: Duration::from_millis(400),
            poll: Duration::from_millis(5),
            ping_every: Duration::from_millis(150),
            min_backoff: Duration::from_millis(20),
            max_backoff: Duration::from_millis(80),
            auth_min: Duration::from_millis(20),
            auth_max: Duration::from_millis(80),
        }
    }
}

impl Default for HaRig {
    fn default() -> Self {
        Self::new()
    }
}

impl Rig for HaRig {
    fn adapter_name(&self) -> &'static str {
        "home-assistant"
    }

    fn adapter(&mut self) -> Box<dyn DeviceAdapter> {
        let timing = Self::timing();
        let entities = [(self.lock(), HA_LOCK.to_string())].into_iter().collect();
        let a = HomeAssistantAdapter::with_link(&self.ha.url(), TOKEN_ENV, entities, false, Some(timing))
            .and_then(|a| a.with_matter_evidence(&self.matter.url(), timing.call))
            .expect("the adapter starts");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !a.link().is_some_and(|l| l.live() && l.registered(HA_LOCK).is_some()) {
            assert!(Instant::now() < deadline, "home-assistant: the link is not live, or the registry not read");
            std::thread::sleep(Duration::from_millis(5));
        }
        Box::new(a)
    }

    fn lock(&self) -> EntityId {
        EntityId::parse("device:lock").expect("valid")
    }

    fn bolt(&self) -> Option<bool> {
        match self.matter.world().nodes.get(&HA_NODE)?.attributes.get("1/257/0")?.as_u64()? {
            1 => Some(true),
            2 => Some(false),
            _ => None,
        }
    }

    fn by_hand(&mut self, locked: bool) {
        self.ha.world().act(HA_LOCK, if locked { "locked" } else { "unlocked" });
    }

    fn commands(&self) -> usize {
        self.ha.calls().len()
    }

    fn fault(&mut self, fault: Fault) {
        match fault {
            Fault::Offline => {
                if let Some(n) = self.matter.world().nodes.get_mut(&HA_NODE) {
                    n.alive = false;
                }
                // Home Assistant marks it unavailable, and fails a call to it
                self.ha.world().set(HA_LOCK, "unavailable", json!({}));
                self.ha.behave(HA_LOCK, Behaviour::Error("home_assistant_error"));
            }
            Fault::LoseAnswer => self.ha.behave(HA_LOCK, Behaviour::LoseAfterSend),
            Fault::LoseAnswerWithoutEffect => self.ha.behave(HA_LOCK, Behaviour::LoseWithoutEffect),
            Fault::LoseAnswerAndGoSilent => {
                // the lock does it and is heard from no more; Home Assistant goes down
                if let Some(n) = self.matter.world().nodes.get_mut(&HA_NODE) {
                    n.alive = false;
                }
                self.ha.behave(HA_LOCK, Behaviour::LoseAndDie);
            }
            // Home Assistant refuses it before running it
            Fault::Refuse => self.ha.behave(HA_LOCK, Behaviour::Error("service_validation_error")),
        }
    }

    fn heal(&mut self) {
        if let Some(n) = self.matter.world().nodes.get_mut(&HA_NODE) {
            n.alive = true;
        }
        self.ha.behave(HA_LOCK, Behaviour::Instant);
        let bolt = self.bolt();
        if let Some(locked) = bolt {
            self.by_hand(locked);
        }
    }
}
