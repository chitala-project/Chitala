#!/usr/bin/env bash
# Run the same gate as CI locally: fmt → clippy → test → audit → deny (+ workflow lint).
# Tools: cargo-audit, cargo-deny, actionlint and zizmor (e.g. `brew install cargo-audit cargo-deny actionlint zizmor`).
set -euo pipefail
cd "$(dirname "$0")/.."

# Use rustup's proxies so rust-toolchain.toml (the pinned toolchain) applies,
# even when another cargo (e.g. Homebrew's) comes first in PATH.
if [ -x "$HOME/.cargo/bin/rustup" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
    rustup toolchain install --no-self-update >/dev/null
fi
echo "toolchain: $(rustc --version)"

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

step "cargo fmt --check";  cargo fmt --all -- --check
step "cargo clippy";       cargo clippy --workspace --all-targets --locked -- -D warnings
step "cargo test";         cargo test --workspace --locked
step "cargo audit";        cargo audit --deny warnings
step "cargo deny";         cargo deny check advisories bans licenses sources
if command -v actionlint >/dev/null; then step "actionlint"; actionlint; fi
if command -v zizmor >/dev/null; then step "zizmor"; zizmor --offline --persona auditor .github/workflows; fi
printf '\n\033[1;32mall checks passed\033[0m\n'
