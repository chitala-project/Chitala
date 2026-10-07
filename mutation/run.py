#!/usr/bin/env python3
"""Mutation runs: put a fault back into the code, on purpose, and show that a
test fails (mutation/README.md).

    python3 mutation/run.py                  # every set
    python3 mutation/run.py safety robot     # some sets
    python3 mutation/run.py safety --only SAFE-1-a SAFE-3-b
    python3 mutation/run.py --list           # the sets and their mutations
    python3 mutation/run.py --anchors        # every edit still applies (fast; no tests)
    python3 mutation/run.py --names-json     # the set names, for CI

The run works on the committed HEAD, in a git worktree of its own, so the
working tree is never touched. Cargo builds into CARGO_TARGET_DIR when it is
set; MUTATION_WORKTREE names the worktree's directory (default: a new
temporary directory).

Each mutation is one or more exact text edits. The outcome of each one:

    CAUGHT    a test failed                                      (good)
    MASKED    survived, and the set says why it must             (good)
    SURVIVED  every test passed                                  (a gap)
    STALE     an edit's text is not in its file exactly once     (the set needs updating)
    INVALID   the mutated code does not compile                  (the mutation needs fixing)

The exit status is 0 only when every mutation is CAUGHT or MASKED.
"""

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SETS = ROOT / "mutation" / "sets"
TEST_NAME = re.compile(r"^[A-Za-z0-9_:]+$")
COMPILE_ERROR = ("error[E", "error: could not compile", "error: expected", "error: cannot find")


def load(name: str) -> dict:
    with open(SETS / f"{name}.toml", "rb") as f:
        spec = tomllib.load(f)
    for m in spec["mutation"]:
        if "edits" not in m:
            m["edits"] = [{"file": m["file"], "old": m["old"], "new": m["new"]}]
    return spec


def failing_tests(out: str) -> list:
    lines = out.splitlines()
    names = [l.split()[1] for l in lines if l.startswith("test ") and l.endswith("FAILED")]
    if "failures:" in lines:  # with -q, the names follow the last "failures:"
        tail = lines[len(lines) - lines[::-1].index("failures:") :]
        names += [l.strip() for l in tail if l.startswith("    ") and TEST_NAME.match(l.strip())]
    return sorted(set(names))


def run_one(work: pathlib.Path, m: dict, tests: list, env: dict) -> tuple:
    touched = []
    try:
        for e in m["edits"]:
            p = work / e["file"]
            current = p.read_text(encoding="utf-8")
            n = current.count(e["old"])
            if n != 1:
                return "STALE", f"{e['file']}: the text to replace occurs {n} times"
            if e["file"] not in touched:
                touched.append(e["file"])
            p.write_text(current.replace(e["old"], e["new"]), encoding="utf-8")
        for t in m.get("tests", tests):
            r = subprocess.run(t, cwd=work, env=env, capture_output=True, text=True)
            if r.returncode != 0:
                out = r.stdout + r.stderr
                names = failing_tests(out)
                if not names and any(marker in out for marker in COMPILE_ERROR):
                    return "INVALID", "does not compile"
                return "CAUGHT", ", ".join(names) or f"`{' '.join(t)}` failed"
        if "masked" in m:
            return "MASKED", m["masked"]
        return "SURVIVED", "every test passed"
    finally:
        for f in touched:
            subprocess.run(["git", "checkout", "--", f], cwd=work, check=True)


def anchors(names: list) -> int:
    """Without running anything: every edit's text is in its file exactly once,
    in the tree as it is. A change that moves code a mutation edits updates
    the set in the same pull request."""
    stale = []
    for name in names:
        for m in load(name)["mutation"]:
            for e in m["edits"]:
                n = (ROOT / e["file"]).read_text(encoding="utf-8").count(e["old"]) if (ROOT / e["file"]).is_file() else 0
                if n != 1:
                    stale.append(f"{name} {m['id']}: {e['file']}: the text to replace occurs {n} times")
    for s in stale:
        print(f"STALE  {s}")
    total = sum(len(load(n)["mutation"]) for n in names)
    print(f"mutation anchors: {len(names)} sets, {total} mutations, " + (f"{len(stale)} stale" if stale else "all apply"))
    return 1 if stale else 0


def main(argv: list) -> int:
    names = sorted(p.stem for p in SETS.glob("*.toml"))
    if "--anchors" in argv:
        return anchors(names)
    if "--names-json" in argv:
        print(json.dumps(names))
        return 0
    if "--list" in argv:
        for n in names:
            spec = load(n)
            print(f"{n}: {spec['description']}")
            for m in spec["mutation"]:
                print(f"  {m['id']:<10} {m['what']}")
        return 0
    only = set(argv[argv.index("--only") + 1 :]) if "--only" in argv else set()
    chosen = [a for a in (argv[: argv.index("--only")] if "--only" in argv else argv) if not a.startswith("-")]
    unknown = [c for c in chosen if c not in names]
    if unknown:
        print(f"no such set: {', '.join(unknown)} (sets: {', '.join(names)})")
        return 2
    if subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip():
        print("note: uncommitted changes are not part of the run; it tests HEAD")
    work = pathlib.Path(os.environ.get("MUTATION_WORKTREE") or tempfile.mkdtemp(prefix="chitala-mutation-"))
    if work.exists():
        shutil.rmtree(work)
    subprocess.run(["git", "worktree", "add", "--detach", str(work), "HEAD"], cwd=ROOT, check=True, capture_output=True)
    env = dict(os.environ)
    bad = 0
    try:
        for name in chosen or names:
            spec = load(name)
            counts = {}
            print(f"== {name}: {spec['description']}", flush=True)
            for m in spec["mutation"]:
                if only and m["id"] not in only:
                    continue
                verdict, detail = run_one(work, m, spec["tests"], env)
                counts[verdict] = counts.get(verdict, 0) + 1
                bad += verdict not in ("CAUGHT", "MASKED")
                print(f"{verdict:<8}  {m['id']:<10} {m['what']}: {detail[:300]}", flush=True)
            print(f"   {name}: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())), flush=True)
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(work)], cwd=ROOT, capture_output=True)
    print("mutation runs: all caught" if bad == 0 else f"mutation runs: {bad} not caught (see above)")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
