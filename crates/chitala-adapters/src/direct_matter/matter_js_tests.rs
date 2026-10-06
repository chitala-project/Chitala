//! The matter.js backend's side of the sidecar protocol, against a scripted
//! sidecar over in-process pipes.

use std::io::{BufRead, BufReader, PipeWriter, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chitala_model::CapabilityId;
use serde_json::{json, Value};

use super::*;
use crate::profile::HomeProfile;

const AT: Target = Target { node: 1, endpoint: 1 };

/// A scripted sidecar: it answers Hello as a serving sidecar of this
/// profile, and every other request as `script` says (no answer for None).
struct Fake {
    out: Arc<Mutex<Option<PipeWriter>>>,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl Fake {
    fn emit(&self, v: Value) {
        if let Some(w) = self.out.lock().unwrap().as_mut() {
            writeln!(w, "{v}").unwrap();
        }
    }

    /// The sidecar stops: its stdout closes.
    fn die(&self) {
        self.out.lock().unwrap().take();
    }

    fn requests(&self) -> Vec<Value> {
        self.requests.lock().unwrap().iter().filter(|r| r["op"] != "Hello").cloned().collect()
    }
}

fn hello_ok() -> Value {
    let p = HomeProfile::v0_1();
    json!({"protocol": 1, "mode": "serve", "profile": format!("{}@{}", p.name(), p.version()), "fabric": {"nodes": 1}})
}

fn start_with(
    hello: Value,
    script: impl Fn(&Value) -> Option<Value> + Send + 'static,
) -> (Result<MatterJsBackend, String>, Fake) {
    let (from_sidecar, to_backend) = std::io::pipe().unwrap();
    let (from_backend, to_sidecar) = std::io::pipe().unwrap();
    let out = Arc::new(Mutex::new(Some(to_backend)));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (o, r) = (Arc::clone(&out), Arc::clone(&requests));
    std::thread::spawn(move || {
        for line in BufReader::new(from_backend).lines() {
            let Ok(line) = line else { return };
            let v: Value = serde_json::from_str(&line).unwrap();
            r.lock().unwrap().push(v.clone());
            let answer = if v["op"] == "Hello" { Some(json!({"ok": hello})) } else { script(&v) };
            if let Some(mut a) = answer {
                a["id"] = v["id"].clone();
                if let Some(w) = o.lock().unwrap().as_mut() {
                    writeln!(w, "{a}").unwrap();
                }
            }
        }
    });
    let timeouts = Timeouts { call: Duration::from_millis(300), invoke: Duration::from_millis(300) };
    (MatterJsBackend::over(from_sidecar, to_sidecar, timeouts), Fake { out, requests })
}

fn start(script: impl Fn(&Value) -> Option<Value> + Send + 'static) -> (MatterJsBackend, Fake) {
    let (b, fake) = start_with(hello_ok(), script);
    (b.unwrap(), fake)
}

fn lock_attributes() -> ProfileAttributes {
    ProfileAttributes::of_class(HomeProfile::v0_1().class("lock").unwrap())
}

fn lock_command(capability: &str) -> ProfileCommand {
    ProfileCommand::of(HomeProfile::v0_1().class("lock").unwrap(), &CapabilityId::parse(capability).unwrap()).unwrap()
}

fn ok() -> Option<Value> {
    Some(json!({"ok": {}}))
}

/// Only a serving sidecar of this protocol on this very profile is used.
#[test]
fn the_sidecar_must_serve_this_protocol_on_this_profile() {
    let mut wrong = hello_ok();
    wrong["profile"] = json!("chitala-home@9.9.9");
    assert!(start_with(wrong, |_| ok()).0.unwrap_err().contains("not a serving one"));
    let mut admin = hello_ok();
    admin["mode"] = json!("admin");
    assert!(start_with(admin, |_| ok()).0.is_err());
    let mut old = hello_ok();
    old["protocol"] = json!(0);
    assert!(start_with(old, |_| ok()).0.is_err());
}

/// The requests are the protocol's typed operations, built from the
/// profile: node ids as decimal strings, the class, the profile's paths.
#[test]
fn requests_are_typed_profile_requests() {
    let (b, fake) = start(|r| match r["op"].as_str() {
        Some("ReadProfileAttributes") => Some(json!({"ok": {"values": [[257, 0, 1]]}})),
        _ => ok(),
    });
    let far = Target { node: 0xFFFF_FFEF_FFFF_FFFF, endpoint: 2 };
    b.subscribe(far, &lock_attributes()).unwrap();
    b.read(AT, &lock_attributes()).unwrap();
    b.invoke(AT, &lock_command("lock.unlock")).unwrap();
    let mut requests = fake.requests();
    for r in &mut requests {
        r.as_object_mut().unwrap().remove("id");
    }
    assert_eq!(
        requests,
        [
            json!({"op": "SubscribeProfileAttributes", "target": {"node": "18446744004990074879", "endpoint": 2},
                "class": "lock", "attributes": [[257, 0]]}),
            json!({"op": "ReadProfileAttributes", "target": {"node": "1", "endpoint": 1},
                "class": "lock", "attributes": [[257, 0]]}),
            json!({"op": "InvokeProfileCommand", "target": {"node": "1", "endpoint": 1}, "class": "lock",
                "capability": "lock.unlock", "cluster": 257, "command": 1, "timed": true}),
        ]
    );
}

/// What each answer to an invoke says about the command.
#[test]
fn what_each_answer_to_an_invoke_says() {
    let invoke = |answer: Option<Value>| {
        let (b, _fake) = start(move |_| answer.clone());
        b.invoke(AT, &lock_command("lock.lock"))
    };
    assert_eq!(invoke(ok()), Ok(()));
    let error = |e: Value| Some(json!({"error": e}));
    assert!(matches!(invoke(error(json!({"kind": "not_sent", "message": "no read"}))), Err(InvokeError::NotSent(_))));
    assert!(matches!(
        invoke(error(json!({"kind": "refused", "message": "not a lock"}))),
        Err(InvokeError::Rejected(_))
    ));
    assert_eq!(
        invoke(error(json!({"kind": "status", "message": "", "status": 203, "cluster_status": 2}))),
        Err(InvokeError::Status { status: 0xCB, cluster_status: Some(2) })
    );
    for kind in ["indeterminate", "failed", "something new"] {
        let r = invoke(error(json!({"kind": kind, "message": "?"})));
        assert!(matches!(r, Err(InvokeError::Indeterminate(_))), "{kind}: {r:?}");
    }
    // no answer: the command was written, so it may have been sent
    let r = invoke(None);
    assert!(matches!(&r, Err(InvokeError::Indeterminate(w)) if w.contains("may have been sent")), "{r:?}");
}

/// A sidecar that dies: a command written before it died has an unknown
/// fate; one that could not be written was certainly not sent.
#[test]
fn a_sidecar_that_dies_mid_command_leaves_it_unknown_and_takes_no_more() {
    let (b, fake) = start(|_| None);
    let out = Arc::clone(&fake.out);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        out.lock().unwrap().take();
    });
    let r = b.invoke(AT, &lock_command("lock.lock"));
    assert!(matches!(r, Err(InvokeError::Indeterminate(_))), "{r:?}");
    std::thread::sleep(Duration::from_millis(50));
    let r = b.invoke(AT, &lock_command("lock.lock"));
    assert!(matches!(r, Err(InvokeError::NotSent(_))), "{r:?}");
    assert_eq!(fake.requests().len(), 1, "the second command never reached the sidecar");
}

/// The subscription follows the sidecar's events: values of the subscribed
/// attributes only, keep-alives, the link's state; and nothing once the
/// sidecar is gone.
#[test]
fn the_subscription_follows_the_sidecar_s_events() {
    let (b, fake) = start(|_| ok());
    assert!(b.subscribed(AT).is_none(), "not subscribed");
    b.subscribe(AT, &lock_attributes()).unwrap();
    assert!(b.subscribed(AT).is_none(), "nothing heard yet");
    fake.emit(json!({"event": "link", "node": "1", "live": true}));
    fake.emit(json!({"event": "values", "node": "1", "endpoint": 1, "values": [[257, 0, 2], [6, 0, true]]}));
    fake.emit(json!({"event": "values", "node": "1", "endpoint": 2, "values": [[257, 0, 1]]}));
    std::thread::sleep(Duration::from_millis(50));
    let s = b.subscribed(AT).unwrap();
    let lock_state = ProfileAttribute::of_class(HomeProfile::v0_1().class("lock").unwrap())[0];
    assert_eq!((s.values, s.live), (vec![(lock_state, json!(2))], true), "only what was subscribed");
    let before = b.subscribed(AT).unwrap().last_heard;
    std::thread::sleep(Duration::from_millis(30));
    fake.emit(json!({"event": "heard", "node": "1"}));
    std::thread::sleep(Duration::from_millis(30));
    assert!(b.subscribed(AT).unwrap().last_heard > before, "a keep-alive");
    fake.emit(json!({"event": "link", "node": "1", "live": false}));
    std::thread::sleep(Duration::from_millis(30));
    assert!(!b.subscribed(AT).unwrap().live, "the link is down");
    fake.emit(json!({"event": "link", "node": "1", "live": true}));
    std::thread::sleep(Duration::from_millis(30));
    assert!(b.subscribed(AT).unwrap().live);
    fake.die();
    std::thread::sleep(Duration::from_millis(50));
    assert!(!b.subscribed(AT).unwrap().live, "the sidecar is gone");
}

/// A read returns the values of the attributes asked only; none is an error.
#[test]
fn a_read_returns_what_was_asked() {
    let (b, _fake) = start(|_| Some(json!({"ok": {"values": [[257, 0, 1], [6, 0, true]]}})));
    let values = b.read(AT, &lock_attributes()).unwrap();
    assert_eq!(values.len(), 1);
    let (b, _fake) = start(|_| Some(json!({"ok": {"values": [[6, 0, true]]}})));
    assert!(b.read(AT, &lock_attributes()).is_err());
    let (b, _fake) = start(|_| Some(json!({"error": {"kind": "read", "message": "no answer"}})));
    assert!(b.read(AT, &lock_attributes()).unwrap_err().contains("no answer"));
}

/// Chitala's fabric is a private directory, claimed by one sidecar at a
/// time (as one node per domain, R2): a second claim is refused while the
/// first holds, and works once it is released.
#[test]
fn the_fabric_is_private_and_claimed_by_one_sidecar_at_a_time() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("chitala-fabric-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sidecar = |storage: &str| Sidecar {
        runtime: "/nonexistent/node".into(),
        entry: "main.ts".into(),
        storage: dir.join(storage),
        subscription_ceiling_s: 60,
    };
    let fabric = sidecar("fabric");
    let first = fabric.claim().unwrap();
    let mode = std::fs::metadata(dir.join("fabric")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700, "created private");
    assert!(fabric.claim().unwrap_err().contains("in use"), "a second sidecar on the same fabric");
    drop(first);
    assert!(fabric.claim().is_ok(), "free again once released");
    let open = sidecar("open");
    std::fs::create_dir_all(dir.join("open")).unwrap();
    std::fs::set_permissions(dir.join("open"), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(open.claim().unwrap_err().contains("private"), "a fabric others can read is refused");
    let _ = std::fs::remove_dir_all(&dir);
}
