#!/usr/bin/env bash
# Run the same gate as CI locally: fmt → core purity → execution boundary → clippy → test → audit → deny (+ workflow lint),
# and the native unikernel boot when QEMU is installed.
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

# one command per line: `set -e` ignores a failure on the left of `&&`
step "cargo fmt --check"
cargo fmt --all -- --check
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo fmt --manifest-path native/Cargo.toml --all -- --check
step "core purity (PAL)";  python3 scripts/core-purity.py
step "execution boundary";  python3 scripts/check-execution-boundary.py
python3 scripts/check-execution-boundary.py --self-test
step "cargo clippy";       cargo clippy --workspace --all-targets --locked -- -D warnings
step "cargo test";         cargo test --workspace --locked
step "fuzz harnesses";     cargo test --manifest-path fuzz/Cargo.toml --locked
step "cargo audit";        cargo audit --deny warnings
step "cargo deny";         cargo deny check advisories bans licenses sources
step "native (host)";     cargo clippy --manifest-path native/Cargo.toml --all-targets --locked -- -D warnings
cargo test -q --manifest-path native/Cargo.toml --locked
cargo audit --file native/Cargo.lock --deny warnings
cargo run -q --manifest-path native/Cargo.toml --locked >/dev/null
if command -v qemu-system-aarch64 >/dev/null; then
    step "native (Hermit unikernel on QEMU)"
    log="$(mktemp)"
    native/run.sh >"$log" 2>&1 || { cat "$log"; exit 1; }
    grep -q "CHITALA NATIVE OK" "$log"
    if grep -q "Fallback to a naive implementation" "$log"; then echo "the kernel fell back to its weak generator" >&2; exit 1; fi
    rm -f "$log"
    status=0
    native/run.sh --no-build --no-rng >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 3 ]; then echo "booted without a hardware RNG (exit $status)" >&2; exit 1; fi
    status=0
    native/run.sh --no-build --rtc=2020-01-01T00:00:00 >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 4 ]; then echo "booted with the board clock set back (exit $status)" >&2; exit 1; fi
fi
if command -v actionlint >/dev/null; then step "actionlint"; actionlint; fi
if command -v zizmor >/dev/null; then step "zizmor"; zizmor --offline --persona auditor .github/workflows; fi
printf '\n\033[1;32mall checks passed\033[0m\n'
