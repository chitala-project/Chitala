# Mutation runs

A test suite proves a guarantee only if it fails when the guarantee is broken. A mutation run checks exactly that. It puts a fault back into the code on purpose, runs the tests that should notice, and expects one of them to fail. Each spec records the results of its runs, and so does the [safety case's traceability matrix](../docs/safety/traceability.md).

Every set used as evidence lives here, so anyone can run it again.

## Running

```bash
python3 mutation/run.py                      # every set
python3 mutation/run.py safety-rules         # one set
python3 mutation/run.py robot-profile --only RB-4 RB-7
python3 mutation/run.py --list               # the sets and their mutations
python3 mutation/run.py --anchors            # fast: every edit still applies; no tests run
```

- **What it tests:** the committed `HEAD`, in a git worktree of its own. The working tree is never touched.
- **Where it builds:** `CARGO_TARGET_DIR`, when it is set. `MUTATION_WORKTREE` names the worktree's directory; by default it is a new temporary directory.
- **How long it takes:** a set takes minutes to an hour, since each mutation recompiles what it touches.
- **In CI:** [`.github/workflows/mutation.yml`](../.github/workflows/mutation.yml) runs every set in its own job. It runs weekly on `main`, on demand, and on a pull request that changes the sets. The anchors are checked on every pull request, in CI's safety case job.

## Outcomes

| Outcome | Meaning | Acceptable |
|---|---|---|
| `CAUGHT` | a test failed | yes |
| `MASKED` | it survived, and the set says why it must | yes |
| `SURVIVED` | every test passed: the tests miss this fault | no: add a test |
| `STALE` | an edit's text is not in its file exactly once: the code moved | no: update the set |
| `INVALID` | the mutated code does not compile | no: fix the mutation |

The run exits with 0 only when every mutation is `CAUGHT` or `MASKED`.

## Writing a set

A set is a TOML file in [`sets/`](sets/):

```toml
description = "What the set covers (the spec)"
tests = [
  ["cargo", "test", "-q", "-p", "chitala-safety"],
]

[[mutation]]
id = "SAFE-1-a"
what = "a hold covers the resource only, not what is below it"
file = "crates/chitala-safety/src/lib.rs"
old = "graph.lineage(p.resource).iter().find_map(|r| self.holds.get_key_value(&r.id))"
new = "self.holds.get_key_value(p.resource)"
```

- **One fault per mutation.** Name it by what goes wrong, not by what the code does.
- **Exact text.** `old` must occur exactly once in its file. Use enough context to make it unique; TOML's `'''` strings take several lines as they are.
- **Several edits** in one mutation: use `[[mutation.edits]]` tables (`file`, `old`, `new`) instead of `file`/`old`/`new`.
- **Tests of its own:** a mutation may carry `tests`, which replace the set's.
- **Masking.** When two guards each cover the other's fault, each alone survives. Give each one a `masked` reason, and add a mutation that removes both, which must be caught. `safe8-new-evidence` has an example (`S8-1+9`).
- **Retired mutations.** A mutation the code has made impossible moves to a `[[retired]]` table (`id`, `what`, `why`). It is never just deleted.
- **When code changes.** A change that moves code a mutation edits updates the set in the same pull request. `--anchors` tells which mutations no longer apply.
