#!/usr/bin/env python3
"""Keep the safety case true (docs/safety/README.md).

    python3 scripts/check-safety-case.py                    # check the case against the tree
    python3 scripts/check-safety-case.py --self-test        # prove every check fires
    python3 scripts/check-safety-case.py --impact BASE HEAD # a pull request's safety impact

The case: every hazard of the log has exactly one row in the traceability
matrix, and every row names a hazard of the log, at least one test, rules that
spec 17 defines and tests that exist; every safety-critical path matches a file
or a directory.

On a pull request (`--impact`): the safety-critical files changed between BASE
and HEAD. If there are any, the description (environment variable PR_BODY)
must have a filled-in "Safety impact" section: what the change does to which
hazards, and whether anything becomes less restrictive. The independent review
it then needs (CONTRIBUTING.md) is for people, not for this script.
"""

import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOG = "docs/safety/hazard-log.md"
MATRIX = "docs/safety/traceability.md"
PATHS = "docs/safety/critical-paths.txt"
SPEC = "specs/17-safety.md"

HAZARD = re.compile(r"^### (H-[A-Z]+-\d{3}):", re.M)
ROW = re.compile(r"^\| (H-[A-Z]+-\d{3}) \|(.*)\|\s*$", re.M)
RULE = re.compile(r"SAFE-\d+-[A-Z]+")
DEFINED = re.compile(r"^\| `(SAFE-\d+-[A-Z]+)` \|", re.M)
TICKED = re.compile(r"`([a-z0-9_]+)`")
TEST_FN = re.compile(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+([a-z0-9_]+)")
SECTION = re.compile(r"^#{2,3}[ \t]*Safety impact[ \t]*$", re.M | re.I)
COMMENT = re.compile(r"<!--.*?-->", re.S)
EMPTY = {"", "none", "n/a", "na", "-", "no"}


def test_names(root: pathlib.Path) -> set:
    names = set()
    for f in (root / "crates").rglob("*.rs"):
        names.update(TEST_FN.findall(f.read_text(encoding="utf-8")))
    return names


def critical_paths(text: str) -> list:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


def check(log: str, matrix: str, spec: str, paths: str, tests: set, exists) -> list:
    problems = []
    hazards = HAZARD.findall(log)
    rules = set(DEFINED.findall(spec))
    rows = {}
    for hazard, rest in ROW.findall(matrix):
        if hazard in rows:
            problems.append(f"{hazard}: two rows in the matrix")
        rows[hazard] = rest
    for hazard in hazards:
        if hazard not in rows:
            problems.append(f"{hazard}: no row in the matrix")
    for hazard, rest in rows.items():
        if hazard not in hazards:
            problems.append(f"{hazard}: a row for a hazard that is not in the log")
        cells = [c.strip() for c in rest.split("|")]
        if len(cells) != 4:
            problems.append(f"{hazard}: a row needs 5 cells, has {len(cells) + 1}")
            continue
        for rule in RULE.findall(rest):
            if rule not in rules:
                problems.append(f"{hazard}: {rule} is not a rule of {SPEC}")
        named = TICKED.findall(cells[2])
        if not named:
            problems.append(f"{hazard}: no test named")
        for name in named:
            if name not in tests:
                problems.append(f"{hazard}: no test `{name}` in crates/")
    for path in critical_paths(paths):
        if not exists(path):
            problems.append(f"{PATHS}: `{path}` matches nothing")
    return problems


def touched(changed: list, paths: list) -> list:
    return [f for f in changed if any(f.startswith(p) if p.endswith("/") else f == p for p in paths)]


def impact_stated(body: str) -> bool:
    m = SECTION.search(body or "")
    if not m:
        return False
    rest = body[m.end() :]
    end = re.search(r"^#{1,3}[ \t]", rest, re.M)
    text = COMMENT.sub("", rest[: end.start()] if end else rest).strip()
    return text.lower().rstrip(".") not in EMPTY


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def exists(rel: str) -> bool:
    p = ROOT / rel
    return p.is_dir() if rel.endswith("/") else p.is_file()


def main() -> int:
    problems = check(read(LOG), read(MATRIX), read(SPEC), read(PATHS), test_names(ROOT), exists)
    if problems:
        print("safety case: FAILED")
        for p in problems:
            print(f"  {p}")
        return 1
    print(f"safety case: {len(HAZARD.findall(read(LOG)))} hazards, each traced to tests that exist")
    return 0


def impact(base: str, head: str) -> int:
    changed = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.split()
    hits = touched(changed, critical_paths(read(PATHS)))
    if not hits:
        print("safety impact: no safety-critical path touched")
        return 0
    print("safety impact: this change touches safety-critical paths:")
    for f in hits:
        print(f"  {f}")
    if not impact_stated(os.environ.get("PR_BODY", "")):
        print(
            "::error::A change to a safety-critical path needs a filled-in '## Safety impact' section in the "
            "pull request's description: the hazards it touches (docs/safety/hazard-log.md), what changes for "
            "them, and whether anything becomes less restrictive (CONTRIBUTING.md, 'Safety-affecting changes')."
        )
        return 1
    print("safety impact: stated. The change needs an independent reviewer (CONTRIBUTING.md).")
    return 0


def self_test() -> int:
    log, matrix, spec, paths = read(LOG), read(MATRIX), read(SPEC), read(PATHS)
    tests = test_names(ROOT)
    failures = []
    if check(log, matrix, spec, paths, tests, exists):
        failures.append("the case as it is does not pass")
    first = ROW.search(matrix)
    hazard, row = first.group(1), first.group(0)
    test = TICKED.findall(row.split("|")[4])[0]
    injections = {
        "no row in the matrix": (log, matrix.replace(row + "\n", ""), paths),
        "two rows in the matrix": (log, matrix.replace(row, row + "\n" + row), paths),
        "not in the log": (log, matrix.replace(row, row + "\n" + row.replace(hazard, "H-GEN-999")), paths),
        "is not a rule of": (log, matrix.replace(row, row.replace(" | ", " | `SAFE-99-NOWHERE`; ", 1)), paths),
        "no test `": (log, matrix.replace(row, row.replace(f"`{test}`", "`no_such_test_anywhere`")), paths),
        "no test named": (log, matrix.replace(row, re.sub(r"`[a-z0-9_]+`", "x", row)), paths),
        "matches nothing": (log, matrix, paths + "\ncrates/no-such-crate/\n"),
    }
    for expected, (log_, matrix_, paths_) in injections.items():
        found = check(log_, matrix_, spec, paths_, tests, exists)
        if not any(expected in p for p in found):
            failures.append(f"not caught: {expected} (got {found})")
    crit = critical_paths(paths)
    if touched(["README.md", "crates/chitala-node/src/main.rs"], crit):
        failures.append("an unrelated change counted as safety-critical")
    if touched(["crates/chitala-safety/src/lib.rs"], crit) != ["crates/chitala-safety/src/lib.rs"]:
        failures.append("a change to Safety not counted as safety-critical")
    template = "## What and why\n\nx\n\n## Safety impact\n\n<!-- Which hazards? -->\n\n## Checklist\n"
    for body, stated in [
        ("", False),
        ("## What and why\n\nx\n", False),
        (template, False),
        (template.replace("<!-- Which hazards? -->", "None."), False),
        (template.replace("<!-- Which hazards? -->", "H-ROB-001: a stop is no longer counted."), True),
        ("## Safety impact\nH-GEN-007: unchanged, a refactor.", True),
    ]:
        if impact_stated(body) != stated:
            failures.append(f"impact section judged {not stated} for: {body!r}")
    if failures:
        print("safety case self-test FAILED:")
        for f in failures:
            print(f"  {f}")
        return 1
    print(f"safety case self-test: all {len(injections)} injected faults caught; the impact rules hold")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["--self-test"]:
        sys.exit(self_test())
    if args[:1] == ["--impact"] and len(args) == 3:
        sys.exit(impact(args[1], args[2]))
    sys.exit(main())
