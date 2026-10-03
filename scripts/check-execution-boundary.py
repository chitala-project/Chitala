#!/usr/bin/env python3
"""Check the single execution path (spec 19, Trusted Execution Boundary v0.2).

    Authority → Safety → TrustedExecutionBoundary → ExecOrder → AdapterExecutor

Rust visibility and the boundary's private order key already make this the
only path through the public APIs. This script is the second layer: it fails
if the non-test code of any crate builds, signs, admits or dispatches an
execution order, starts an adapter host, or touches device I/O anywhere but in
the modules below — so a new path to an actuator cannot be added without
editing this allowlist, which is a reviewed, code-owned file.

    python3 scripts/check-execution-boundary.py            # check the tree
    python3 scripts/check-execution-boundary.py --self-test # prove every rule fires

Test code is exempt by the same rules as scripts/core-purity.py.
"""

import importlib.util
import pathlib
import re
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

# share core-purity's notion of test code, without leaving bytecode in the tree
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("core_purity", ROOT / "scripts" / "core-purity.py")
_purity = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_purity)
non_test_lines = _purity.non_test_lines
strip_comments = _purity.strip_comments

# (name, what it guards, patterns, files allowed to match — paths relative to the
# repository root; a trailing "/" allows a whole directory)
RULES = [
    (
        "mint",
        "building or signing an execution order",
        # a struct literal, not a return type or definition followed by a block
        [r"(?<!->)(?<!-> )(?<!-> &)(?<!->&)(?<!struct )(?<!impl )\bExecOrder\s*\{", r"\bORDER_CONTENT_TYPE\b"],
        ["crates/chitala-csme/src/order.rs", "crates/chitala-boundary/src/lib.rs"],
    ),
    (
        "boundary",
        "creating a Trusted Execution Boundary or calling its mint",
        [r"\bTrustedExecutionBoundary::new\b", r"\.mint\("],
        [
            "crates/chitala-node/src/lib.rs",  # start_node: one boundary per node process
            "crates/chitala-node/src/node.rs",  # Node::mint, the only caller of the boundary
            "crates/chitala-node/src/intents.rs",  # the intent path hands grants to Node::mint
            "crates/chitala-cli/src/demo.rs",  # the in-memory demo node
        ],
    ),
    (
        "admit",
        "decoding or admitting an execution order",
        [r"\bExecOrder::(open|from_cbor)\b", r"\bOrderGate::new\b", r"\.admit\(", r"\bVerifiedOrder\s*\{"],
        [
            "crates/chitala-csme/src/order.rs",
            "crates/chitala-adapters/src/lib.rs",
            "crates/chitala-adapters/src/host.rs",
        ],
    ),
    (
        "dispatch",
        "sending an order to an executor or a device adapter",
        [r"\.execute\(", r"\bHostRequest::Execute\b"],
        [
            "crates/chitala-node/src/node.rs",  # PendingDevice::run
            "crates/chitala-node/src/executor.rs",  # executors and routing
            "crates/chitala-adapters/src/host.rs",  # AdapterHost: gate → adapter
        ],
    ),
    (
        "host",
        "starting an adapter host (it pins the order key it is given)",
        [r"\bHostInit\s*\{", r"\bComponentHost::start\b", r"\bAdapterHost::(new|from_init)\b"],
        [
            "crates/chitala-node/src/executor.rs",
            "crates/chitala-node/src/lib.rs",  # start_adapter_hosts
            "crates/chitala-adapters/src/host.rs",
        ],
    ),
    (
        "device-io",
        "device I/O (only adapters, behind the order gate, may reach hardware)",
        [r"\bDeviceIo\b", r"\bDeviceChannel\b"],
        ["crates/chitala-platform/", "crates/chitala-platform-host/", "crates/chitala-adapters/"],
    ),
]


def allowed(rel: str, allow) -> bool:
    return any(rel == a or (a.endswith("/") and rel.startswith(a)) for a in allow)


def scan(root: pathlib.Path):
    problems = []
    hits = {name: 0 for name, *_ in RULES}
    for _, _, _, allow in RULES:
        for a in allow:
            if not (root / a).exists():
                problems.append(f"allowlisted path {a} does not exist (moved? update this script)")
    for path in sorted((root / "crates").rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if "/tests/" in rel or path.name == "tests.rs" or path.name.endswith("_tests.rs"):
            continue
        for n, line in non_test_lines(path):
            code = strip_comments(line)
            for name, what, patterns, allow in RULES:
                if any(re.search(p, code) for p in patterns):
                    if allowed(rel, allow):
                        hits[name] += 1
                    else:
                        problems.append(f"{rel}:{n}: [{name}] {what} outside the boundary (`{code.strip()}`)")
    # a rule that matches nothing in its own allowlist has gone stale
    for name, count in hits.items():
        if count == 0:
            problems.append(f"rule [{name}] matched nothing in its allowlist: the patterns are stale")
    return problems


def report(problems) -> int:
    if problems:
        print("The execution path must stay Authority → Safety → Boundary → ExecOrder → AdapterExecutor (spec 19):")
        for p in problems:
            print(f"  {p}")
        return 1
    print(f"execution boundary: {len(RULES)} rules hold — one path from authority to actuator")
    return 0


# Violating lines per rule, each injected into a file outside every allowlist.
INJECTIONS = {
    "mint": [
        "fn __x() { let _ = chitala_csme::order::ORDER_CONTENT_TYPE; }",
        "fn __x() { f(&chitala_csme::order::ExecOrder { ..todo!() }); }",
        "fn __x() { let o = ExecOrder { ..todo!() }; }",
    ],
    "boundary": [
        "fn __x(e: std::sync::Arc<dyn chitala_platform::Entropy>) { let _ = chitala_boundary::TrustedExecutionBoundary::new(e); }",
        "fn __x(b: &B) { b.mint(a, c, x, 0, s, 0); }",
    ],
    "admit": [
        "fn __x(b: &[u8], k: &chitala_identity::PublicKey) { let _ = chitala_csme::order::ExecOrder::open(b, k); }",
        "fn __x(g: &mut Gate) { let _ = g.admit(b); }",
    ],
    "dispatch": [
        "fn __x(e: &dyn Exec) { e.execute(); }",
        "fn __x() { let _ = HostRequest::Execute { device, order }; }",
    ],
    "host": [
        "fn __x() { let _ = chitala_adapters::host::AdapterHost::new; }",
        "fn __x() { let _ = HostInit { order_key, executor, devices, home_assistant }; }",
    ],
    "device-io": ["fn __x(d: &dyn chitala_platform::DeviceIo) { let _ = d; }"],
}
VICTIM = "crates/chitala-mcp/src/lib.rs"


def self_test() -> int:
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        shutil.copytree(ROOT / "crates", tmp / "crates", ignore=shutil.ignore_patterns("target"))
        if scan(tmp):
            failures.append("the clean tree does not pass")
        victim = tmp / VICTIM
        original = victim.read_text(encoding="utf-8")
        # put the line before any trailing #[cfg(test)] module, so it counts as product code
        cut = original.find("\n#[cfg(test)]")
        for name, lines in INJECTIONS.items():
            for line in lines:
                text = original + "\n" + line + "\n" if cut < 0 else original[:cut] + "\n" + line + "\n" + original[cut:]
                victim.write_text(text, encoding="utf-8")
                if not any(f"[{name}]" in p for p in scan(tmp)):
                    failures.append(f"rule [{name}] did not catch: {line}")
        victim.write_text(original, encoding="utf-8")
    if failures:
        print("execution boundary self-test FAILED:")
        for f in failures:
            print(f"  {f}")
        return 1
    n = sum(len(v) for v in INJECTIONS.values())
    print(f"execution boundary self-test: all {len(INJECTIONS)} rules catch all {n} injected violations")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(report(scan(ROOT)))
