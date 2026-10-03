//! `chitala-adapter-host` — runs device adapters outside the trusted core.
//!
//! Started by the node, one process per adapter type, with an empty environment.
//! It speaks the line protocol of `chitala_adapters::host` on stdin/stdout, holds
//! no private key and executes only execution orders signed by the node.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(chitala_adapters::host::run_stdio().clamp(0, 255) as u8)
}
