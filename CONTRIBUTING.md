# Contributing to Chitala OS

Thank you for helping. Chitala decides whether people, AIs and devices may act on the physical world, so contributions are held to a high bar for correctness and security. This guide explains how to get a change in.

How decisions are made is in [`GOVERNANCE.md`](GOVERNANCE.md). Security vulnerabilities are **not** reported here: see [`SECURITY.md`](SECURITY.md).

## Before you start

- For anything larger than a fix, **open an issue first**. Describe the problem, the proposed design, and its security impact.
- The `0.x` line has a **feature freeze** (see [`ROADMAP.md`](ROADMAP.md)). Changes that make the Trusted Core more verifiable, more isolated or more portable are welcome. New capabilities, adapters, protocols or profiles generally wait.
- Specification changes follow [`SPECIFICATION_POLICY.md`](SPECIFICATION_POLICY.md).

## Workflow

1. **Fork** the repository and create a branch.
2. **Commit with a sign-off** (`git commit -s`) under the [Developer Certificate of Origin](DCO.md).
3. **Run the local gate**:
   ```bash
   scripts/check.sh   # fmt → core purity → clippy → tests → fuzz harnesses → audit → deny (+ workflow lint)
   ```
4. **Open a pull request** against `main` and fill in the template.
5. **CI** must be green: formatting, core purity, clippy, tests on Linux x86_64/ARM64 and macOS, MSRV, `cargo audit`, `cargo deny`, CodeQL, workflow security, SBOM and the DCO check. Fuzzing runs on changes to code.
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

## Licensing of contributions

Contributions are licensed under the project license, Apache-2.0 (section 5 of the license). The `Signed-off-by` line records your certification under the [DCO](DCO.md). Using the Chitala name and logo is governed separately by [`TRADEMARK.md`](TRADEMARK.md).
