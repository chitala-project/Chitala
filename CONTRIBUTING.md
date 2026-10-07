# Contributing to Chitala OS

Thank you for helping. Chitala decides whether people, AIs and devices may act on the physical world, so contributions are held to a high bar for correctness and security. This guide explains how to get a change in.

How decisions are made is in [`GOVERNANCE.md`](GOVERNANCE.md). Security vulnerabilities are **not** reported here: see [`SECURITY.md`](SECURITY.md).

## Before you start

- For anything larger than a fix, **open an issue first**. Describe the problem, the proposed design, and its security impact.
- The Trusted Core is in a **core freeze** (see [`ROADMAP.md`](ROADMAP.md) "Scope discipline"). Changes that make it more verifiable, more isolated or more portable are welcome; new Trusted Core abstractions need a step of the current milestone that cannot work without them. Adapters and profiles of the current milestone (v0.3: the Home Capability Profile, Home Assistant and Matter) are in scope, outside the Trusted Core. Other protocols and profiles wait.
- Specification changes follow [`SPECIFICATION_POLICY.md`](SPECIFICATION_POLICY.md).

## Workflow

1. **Fork** the repository and create a branch.
2. **Commit with a sign-off** (`git commit -s`) under the [Developer Certificate of Origin](DCO.md).
3. **Run the local gate**:
   ```bash
   scripts/check.sh   # fmt → core purity → clippy → tests → fuzz harnesses → audit → deny (+ workflow lint)
   ```
4. **Open a pull request** against `main` and fill in the template.
5. **CI** must be green: formatting, core purity, the execution boundary, the safety case, clippy, tests on Linux x86_64/ARM64 and macOS, MSRV, `cargo audit`, `cargo deny`, CodeQL, workflow security, SBOM and the DCO check. Fuzzing runs on changes to code.
6. **Review.** A code owner of each affected area reviews it (see [`.github/CODEOWNERS`](.github/CODEOWNERS)). Every conversation is resolved before merging.
7. **Merge.** A maintainer squash-merges it.

## Rules for code

- **Invariant 1.** AI produces Intent. Chitala produces Authority. Only the trusted execution boundary produces physical Commands (spec 15). Nothing may add a second path to an actuator.
- **Core purity.** The Trusted Core crates reach the machine only through `chitala-platform` (spec 18). `scripts/core-purity.py` enforces this.
- **No `unsafe`.** Every crate is `#![forbid(unsafe_code)]`.
- **Tests that prove security changes.** A fix or hardening comes with a test that fails without it. A new trust boundary comes with a fuzz target. Update the threat model (spec 13) when an attack is blocked or a risk is accepted.
- **Fail closed.** On doubt, errors or missing evidence, deny.
- **Specs move with code.** A behaviour change updates the relevant spec in the same pull request.
- **Style.** Run `cargo fmt`. Keep clippy clean with `-D warnings`. Match the surrounding code and its comment density.
- **English** for code, comments, documentation, commit messages and user-visible text.

## Safety-affecting changes

A change is **safety-affecting** when it touches a path in [`docs/safety/critical-paths.txt`](docs/safety/critical-paths.txt), or when it changes what Safety, the trusted boundary, outcome verification or recovery refuse, allow or do. Such a change needs, before it merges:

1. **A hazard impact analysis.** A filled-in *Safety impact* section in the pull request's description:
   - the hazards it touches, from the [hazard log](docs/safety/hazard-log.md);
   - what changes for each of them;
   - whether anything becomes less restrictive.

   CI fails a change to a critical path without one.
2. **An independent reviewer.** Someone who did not write the change; an AI that wrote a change is not its reviewer. A safety-affecting change merges only with the Project Lead's approval, or that of a reviewer the Lead names.
3. **Regression tests** for the behaviour, with the [traceability matrix](docs/safety/traceability.md) updated in the same pull request.
4. **Mutation or adversarial evidence** for a new or changed control. With the control taken out on purpose, a test must fail. The result is recorded in the spec, and in the matrix.

**The highest scrutiny** goes to a change that makes Chitala less restrictive:
- a DENY that becomes an ALLOW;
- an UNKNOWN that is allowed to pass;
- a limit that widens: an envelope, a maximum age, a rate, more retries.

Such a change says why in its *Safety impact* section, and the Lead approves it explicitly. No change adds a switch, a flag or a debug mode that turns a safety rule off (spec 17: no policy can switch a rule off).

## Licensing of contributions

Contributions are licensed under the project license, Apache-2.0 (section 5 of the license). The `Signed-off-by` line records your certification under the [DCO](DCO.md). Using the Chitala name and logo is governed separately by [`TRADEMARK.md`](TRADEMARK.md).
