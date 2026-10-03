#!/usr/bin/env python3
"""Check that the Trusted Core never talks to the host operating system.

Blueprint v20 §2/§4 and spec 18: the Trusted Core reaches the machine only
through the Platform Abstraction Layer (`chitala-platform`). This script fails
if the non-test code of a core crate uses an OS API directly, or if a core
crate depends directly on a crate that does.

What it cannot see — an OS call hidden inside a third-party library — is
covered by behavioural tests instead (e.g. tokens are byte-for-byte
reproducible from a deterministic entropy source, which fails if any code path
falls back to the OS RNG).

Test code is exempt: files named `tests.rs` / `*_tests.rs`, the `tests/`
directory, and a `#[cfg(test)] mod …` that must be the last item of its file.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

CORE = [
    "chitala-model",
    "chitala-identity",
    "chitala-token",
    "chitala-policy",
    "chitala-resource",
    "chitala-intent",
    "chitala-safety",
    "chitala-csme",
    "chitala-audit",
    "chitala-state",
    "chitala-bus",
    "chitala-monitor",
    "chitala-platform",
]

FORBIDDEN_CODE = [
    (r"\bstd::fs\b", "file system"),
    (r"\bstd::net\b", "network sockets"),
    (r"\bstd::process\b", "processes"),
    (r"\bstd::os::", "OS-specific extensions"),
    (r"\bstd::env\b", "environment variables"),
    (r"\bstd::io::(stdin|stdout|stderr)\b", "standard streams"),
    (r"\bSystemTime::now\b", "the system clock"),
    (r"\bInstant\b", "the OS monotonic clock"),
    (r"\bOsRng\b", "the OS random number generator"),
    (r"\bthread_rng\b", "the OS random number generator"),
    (r"\bgetrandom\b", "the OS random number generator"),
    (r"\blibc::", "libc"),
]

FORBIDDEN_DEPS = {
    "rand": "draws from the OS RNG; take chitala_platform::Entropy instead",
    "getrandom": "the OS RNG",
    "libc": "raw OS calls",
    "nix": "raw OS calls",
    "ureq": "a host network stack; use NetworkTransport",
    "tokio": "a host async runtime",
    "chitala-platform-host": "a host backend; the core may only see the PAL traits",
    "chitala-adapters": "adapters live outside the Trusted Core",
    "chitala-node": "the hosted runtime depends on the core, not the reverse",
}


def strip_comments(line: str) -> str:
    # good enough for this code base: no `//` inside string literals that matter
    i = line.find("//")
    return line if i < 0 else line[:i]


def non_test_lines(path: pathlib.Path):
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "#[cfg(test)]" and not line.startswith(" "):
            nxt = next((l for l in lines[i + 1 :] if l.strip()), "")
            if nxt.startswith("mod ") or nxt.startswith("#[path"):
                # the test module must be the file's last item
                rest = [l for l in lines[i:] if l.strip()]
                if nxt.startswith("mod ") and nxt.rstrip().endswith("{") and rest[-1] != "}":
                    raise SystemExit(f"{path}: the #[cfg(test)] module must be the last item of the file")
                return [(n + 1, l) for n, l in enumerate(lines[:i])]
    return [(n + 1, l) for n, l in enumerate(lines)]


def dependencies(manifest: pathlib.Path):
    section = None
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("["):
            section = line
            continue
        if section == "[dependencies]" and "=" in line and not line.startswith("#"):
            yield line.split("=", 1)[0].strip().split(".")[0]


def main() -> int:
    problems = []
    for crate in CORE:
        base = ROOT / "crates" / crate
        for dep in dependencies(base / "Cargo.toml"):
            if dep in FORBIDDEN_DEPS:
                problems.append(f"{crate}/Cargo.toml: depends on `{dep}` — {FORBIDDEN_DEPS[dep]}")
        for path in sorted((base / "src").rglob("*.rs")):
            if path.name == "tests.rs" or path.name.endswith("_tests.rs"):
                continue
            for n, line in non_test_lines(path):
                code = strip_comments(line)
                for pattern, what in FORBIDDEN_CODE:
                    if re.search(pattern, code):
                        rel = path.relative_to(ROOT)
                        problems.append(f"{rel}:{n}: uses {what} directly (`{code.strip()}`)")
    if problems:
        print("The Trusted Core must reach the machine only through chitala-platform (spec 18):")
        for p in problems:
            print(f"  {p}")
        return 1
    print(f"core purity: {len(CORE)} crates reach the OS only through the PAL")
    return 0


if __name__ == "__main__":
    sys.exit(main())
