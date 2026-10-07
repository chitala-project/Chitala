#!/usr/bin/env python3
"""N1.6 diagnosis: put timestamps on the phases of chitala-node's refresh pass and
set its TICK, in the working tree, for a diagnostic build only. Undo with
`git checkout -- crates/chitala-node/src/ipc.rs`. Usage: refresh-diag.py TICK_MS"""
import sys
tick = int(sys.argv[1])
p = "crates/chitala-node/src/ipc.rs"
s = open(p).read()
pairs = [
    ("pub const TICK: Duration = Duration::from_secs(1);",
     f"pub const TICK: Duration = Duration::from_millis({tick}); // N1.6 diagnosis\n"
     "fn diag_us() -> u64 {\n"
     "    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)\n"
     "}"),
    ("""    with_node(node, Node::expire_approvals)?;
    let due = with_node(node, |n| {
        let now = n.now();
        n.due_observations(now)
    })?;
    for o in &due {
        let outcome = o.run();
        with_node(node, |n| n.observed_by(o, outcome))?;
    }
    let work = with_node(node, Node::settle_outcomes)?;
    let mut ran = due.len() + work.len();
    for mut p in work {
        let outcome = p.run();
        with_node(node, |n| n.finish(p, outcome))?;
    }
    // plans whose step was verified go on (spec 23)
    let plans = with_node(node, Node::continue_plans)?;
    ran += plans.len();
    for step in plans {
        drive(node, step)?;
    }
    Ok(ran)""",
     """    let t0 = diag_us();
    with_node(node, Node::expire_approvals)?;
    let t1 = diag_us();
    let due = with_node(node, |n| {
        let now = n.now();
        n.due_observations(now)
    })?;
    let t2 = diag_us();
    let (mut run_us, mut fold_us) = (0, 0);
    for o in &due {
        let a = diag_us();
        let outcome = o.run();
        let b = diag_us();
        with_node(node, |n| n.observed_by(o, outcome))?;
        run_us += b - a;
        fold_us += diag_us() - b;
    }
    let t3 = diag_us();
    let work = with_node(node, Node::settle_outcomes)?;
    let t4 = diag_us();
    let mut ran = due.len() + work.len();
    let nwork = work.len();
    for mut p in work {
        let outcome = p.run();
        with_node(node, |n| n.finish(p, outcome))?;
    }
    let t5 = diag_us();
    // plans whose step was verified go on (spec 23)
    let plans = with_node(node, Node::continue_plans)?;
    ran += plans.len();
    for step in plans {
        drive(node, step)?;
    }
    let t6 = diag_us();
    eprintln!(
        "[refresh] {t0}..{t6} us · total {} · expire {} · due {} (n={}) · observe run {} fold {} · settle {} (n={nwork}) · work {} · plans {}",
        t6 - t0, t1 - t0, t2 - t1, due.len(), run_us, fold_us, t4 - t3, t5 - t4, t6 - t5
    );
    Ok(ran)"""),
    ("""    std::thread::spawn(move || loop {
        std::thread::sleep(TICK);
        if refresh_state(&watched).is_err() {""",
     """    std::thread::spawn(move || loop {
        let slept = diag_us();
        std::thread::sleep(TICK);
        let woke = diag_us();
        eprintln!("[refresh] woke at {woke} us, {} us after the tick was due", (woke - slept).saturating_sub(TICK.as_micros() as u64));
        if refresh_state(&watched).is_err() {"""),
]
for o, n in pairs:
    assert s.count(o) == 1, o[:60]
    s = s.replace(o, n)
open(p, "w").write(s)
print(f"refresh diagnosis applied, TICK {tick} ms")
