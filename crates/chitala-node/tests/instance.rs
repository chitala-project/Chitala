//! One node per domain (concurrency audit R2 of v0.3). A second node started
//! on a domain whose node runs must stop before it writes anything: before it
//! starts adapter hosts, reads the state, or opens the audit log. Before the
//! fix it appended to the running node's audit log, broke its hash chain, and
//! the running node could not start again.

use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chitala_adapters::host::{AdapterHost, HostRequest};
use chitala_node::{Domain, NodeConfig, NodeEnv, StoredObject};
use chitala_platform::memory::{self, Program};
use chitala_platform::{StoragePath, TimeSource, TrustedClock, Visibility};

const T0: u64 = 1_790_000_000_000;

#[test]
fn a_second_node_on_a_running_domain_writes_nothing() {
    let (platform, ctl) = memory::platform("one-node", T0);
    let time: Arc<dyn TimeSource> = Arc::clone(&platform.time);
    let hosts = Arc::new(AtomicUsize::new(0));
    let started = Arc::clone(&hosts);
    let program: Program = Arc::new(move |input, mut output, _env| {
        started.fetch_add(1, Ordering::SeqCst);
        let clock = Arc::new(TrustedClock::new(Arc::clone(&time), 0)).as_clock();
        let mut reader = BufReader::new(input);
        let mut line = String::new();
        let _ = reader.read_line(&mut line);
        let Ok(HostRequest::Init(init)) = serde_json::from_str(line.trim()) else { return };
        let Ok(mut host) = AdapterHost::from_init(init, clock) else { return };
        let _ = writeln!(output, "{{\"ok\":true}}");
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let _ = writeln!(output, "{}", host.handle_line(&line));
        }
    });
    ctl.exec.register("adapter-host", program);
    let summary = chitala_node::setup::init_domain(platform.storage.as_ref(), platform.keys.as_ref()).unwrap();
    let text = platform.storage.read(&summary.config, Visibility::Shared).unwrap().unwrap();
    let config: NodeConfig = serde_json::from_slice(&text).unwrap();
    let path = |p: &str| StoragePath::new(p).unwrap();
    let stored = |p: &str| StoredObject::new(Arc::clone(&platform.storage), path(p));
    let env = NodeEnv {
        audit_log: stored(&config.audit_log),
        state_file: stored(&config.state_file),
        policy_file: None,
        adapter_host: "adapter-host".into(),
        home_assistant_env: Vec::new(),
    };
    let (audit_log, state_file) = (path(&config.audit_log), path(&config.state_file));
    let domain = Domain { config, platform, endpoint: chitala_platform::Endpoint::new("node").unwrap() };
    let snapshot = || {
        let read = |p: &StoragePath| domain.platform.storage.read(p, Visibility::Private).unwrap();
        (read(&audit_log), read(&state_file))
    };

    let first = chitala_node::start_node(&domain, &env).expect("the first node starts");
    let before = snapshot();
    let starts = hosts.load(Ordering::SeqCst);

    let second = chitala_node::start_node(&domain, &env);
    let why = second.err().expect("a second node on the same domain does not start").to_string();
    assert!(why.contains("another node"), "{why}");
    assert_eq!(snapshot(), before, "the second node wrote nothing: no audit record, no state");
    assert_eq!(hosts.load(Ordering::SeqCst), starts, "and started no adapter host");

    // the claim ends with the first node: the domain starts again, its audit intact
    drop(first);
    let again = chitala_node::start_node(&domain, &env).expect("the domain starts again once its node stopped");
    drop(again);
}
