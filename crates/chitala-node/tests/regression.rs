//! The concurrency and lifecycle regression suite (v0.3 step ⑥, spec 28):
//! the audit's findings R1, R2, R3/R3b and F11 stay fixed, and on every path.
//! Their own tests stay where they were written; this suite adds what runs
//! them on every adapter: seeded runs of faults, crashes at the write-ahead
//! record's critical points, restarts and time, and F11 on the direct Matter
//! path.

mod common;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use chitala_adapters::conformance::{Fault, HaRig, MatterRig, MockRig, Rig};
use chitala_adapters::direct_matter::fake::NextCommand;
use chitala_model::{ExecCode, Payload};
use chitala_node::Step;
use common::*;
use serde_json::Value;

/// A small deterministic random source.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Orders the node minted (decisions of physical actions, safe states included).
fn minted(h: &Home) -> usize {
    h.records("decision").iter().filter(|d| d["decision"] == "allow" && d.get("context").is_some()).count()
}

/// Random runs, on `make`'s rig: commands with faults (lost answers, with
/// or without effect, a device going silent, a refusal, a device offline),
/// changes by hand, crashes at the write-ahead record's critical points
/// (after the order is on record; after it was sent), restarts, and time.
/// After every run, once the device is back and time has passed:
/// - no command reached the device more often than orders were minted:
///   nothing is ever sent twice (R1);
/// - nothing is left uncertain: no pending outcome, nothing in flight;
/// - every order a crash caught is judged exactly once;
/// - the door is in recovery exactly when a promise on it was broken or
///   could not be established.
///
/// `CHITALA_PROPERTY_SEEDS` raises the number of runs (default 8 per path).
fn random_faults_crashes_and_restarts(name: &str, make: &dyn Fn() -> Box<dyn Rig>) {
    let seeds: u64 = std::env::var("CHITALA_PROPERTY_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
    for seed in 1..=seeds {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed.wrapping_mul(0x2545_F491_4F6C_DD1D));
        let mut h = home(make());
        let (mut minted_total, mut outcomes) = (0usize, Vec::<Value>::new());
        let mut crashed = Vec::<String>::new();
        let mut log = Vec::new();
        for step in 0..16 {
            let op = rng.below(9);
            log.push(op);
            // shown only if the test fails: where in which sequence (issue #88)
            eprintln!("{name}: seed {seed}, step {step}, op {op}");
            match op {
                0..=3 => {
                    match rng.below(7) {
                        0 => h.rig.fault(Fault::LoseAnswer),
                        1 => h.rig.fault(Fault::LoseAnswerWithoutEffect),
                        2 => h.rig.fault(Fault::LoseAnswerAndGoSilent),
                        3 => h.rig.fault(Fault::Refuse),
                        4 => h.rig.fault(Fault::Offline),
                        _ => h.rig.heal(),
                    }
                    let c = if rng.below(2) == 0 { "lock.lock" } else { "lock.unlock" };
                    let _ = h.req(c);
                }
                4 => {
                    // crash at a critical point of a lock command
                    let lock = h.lock();
                    let bytes = h.signed(&lock, "lock.lock", Payload::new());
                    if let Step::Device(mut p) = h.node.begin(&bytes) {
                        if rng.below(2) == 0 {
                            let _ = p.run();
                        }
                        let decided = h.records("decision").pop().unwrap();
                        crashed.push(decided["mid"].as_str().unwrap().to_string());
                    }
                    minted_total += minted(&h);
                    outcomes.extend(h.records("outcome"));
                    h = restart(h);
                }
                5 => {
                    minted_total += minted(&h);
                    outcomes.extend(h.records("outcome"));
                    h = restart(h);
                }
                6 => {
                    let locked = rng.below(2) == 0;
                    h.rig.by_hand(locked);
                }
                7 => h.rig.heal(),
                _ => {
                    for _ in 0..rng.below(4) + 1 {
                        h.clock.fetch_add(1_500, Ordering::SeqCst);
                        h.node.tick();
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            }
        }
        // quiescence: the device is back, time passes
        h.rig.heal();
        for _ in 0..20 {
            h.clock.fetch_add(1_000, Ordering::SeqCst);
            h.node.tick();
            std::thread::sleep(Duration::from_millis(10));
        }
        minted_total += minted(&h);
        outcomes.extend(h.records("outcome"));
        let ctx = format!("{name}, seed {seed}, ops {log:?}");
        assert!(h.rig.commands() <= minted_total, "{ctx}: {} commands for {minted_total} orders", h.rig.commands());
        assert!(h.node.pending_outcomes().is_empty(), "{ctx}: still pending");
        assert!(h.node.domain_state().inflight.is_empty(), "{ctx}: still in flight");
        for mid in &crashed {
            let judged = outcomes.iter().filter(|o| o["mid"] == mid.as_str()).count();
            assert_eq!(judged, 1, "{ctx}: the order {mid} caught by a crash was judged {judged} times");
        }
        let broken = outcomes.iter().any(|o| {
            o["resource"] == "resource:front-door"
                && o["safe_state"] != true
                && matches!(o["status"].as_str(), Some("diverged" | "unconfirmed"))
        });
        assert_eq!(h.in_recovery(), broken, "{ctx}: recovery iff a broken or unknowable promise on the door");
    }
}

#[test]
fn random_faults_crashes_and_restarts_on_the_mock() {
    random_faults_crashes_and_restarts("mock", &|| Box::new(MockRig::new()));
}

#[test]
fn random_faults_crashes_and_restarts_on_home_assistant() {
    random_faults_crashes_and_restarts("home-assistant", &|| Box::new(HaRig::new()));
}

#[test]
fn random_faults_crashes_and_restarts_on_the_direct_matter_adapter() {
    random_faults_crashes_and_restarts("matter", &|| Box::new(MatterRig::new()));
}

#[test]
fn random_faults_crashes_and_restarts_through_the_matter_sidecar() {
    random_faults_crashes_and_restarts("matter over the sidecar", &|| Box::new(MatterRig::over_sidecar()));
}

/// F11 on the direct Matter path. An unlock whose answer is lost did
/// nothing: the lock's read confirms it locked, and the outcome waits for
/// its deadline. Then the lock is unlocked by hand, reports it, and stops
/// answering: its newer state is unlocked, and nobody can confirm it. The
/// confirmed `locked` is no longer evidence: `unconfirmed`, recovery, never
/// `not_applied` while the door may stand unlocked.
#[test]
fn f11_a_confirmed_state_superseded_by_one_nobody_can_confirm_on_the_matter_path() {
    let rig = MatterRig::over_sidecar();
    let world = rig.backend.clone();
    let mut h = home(Box::new(rig));
    world.next(NextCommand::LoseAnswerWithoutEffect);
    let r = h.req("lock.unlock");
    assert_eq!(code(&r), Some(ExecCode::ExecutionUnknown), "{}", r.summary());
    assert_eq!(status(&r), "pending", "the lock's read says locked; the deadline has not come: {}", r.summary());
    h.rig.by_hand(false);
    // the lock's report of the hand unlock must reach Chitala's side before
    // the lock goes silent: that is the case under test
    let deadline = Instant::now() + Duration::from_secs(10);
    while h.rig.heard_locked() != Some(false) {
        assert!(
            Instant::now() < deadline,
            "the hand unlock was never heard: Chitala's side last heard {:?}",
            h.rig.heard_locked()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    world.alive(1, false);
    // the next passes: no read answers; the subscription still holds what the lock reported
    for _ in 0..3 {
        h.clock.fetch_add(100, Ordering::SeqCst);
        h.node.tick();
        std::thread::sleep(Duration::from_millis(20));
    }
    h.ticks_until("settled", |n| n.pending_outcomes().is_empty());
    let o = h.last_outcome();
    assert_eq!(o["status"], "unconfirmed", "{o}");
    assert!(h.in_recovery(), "the door may stand unlocked");
}
