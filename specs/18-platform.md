# 18 — Platform Abstraction Layer (PAL)

Sources: Blueprint v20 §2 (the Trusted Core does not depend on the host OS), §4 (the PAL is the earliest architectural change), §19; milestone *Chitala v0.2 — Platform Independence & Trusted Execution Boundary*. Crates `chitala-platform` (contracts, trusted clock, memory backend, contract tests) and `chitala-platform-host` (the hosted backend).

```text
          Chitala Trusted Core
                 │
 ┌───────────────┼────────────────┐
 │ Identity / Capability          │
 │ Resource / Intent              │
 │ Authority / Safety             │
 │ Reference Monitor              │
 │ Audit / State                  │
 └───────────────┬────────────────┘
                 │
        CHITALA PLATFORM API (this spec)
                 │
       ┌─────────┼─────────┐
       │         │         │
    Linux     macOS     Chitala Native
   Backend    Backend      Backend
```

## The rule

**The Trusted Core never talks to a host operating system.** Everything it needs from the machine comes through one of the PAL traits below. A new platform — Windows, an RTOS, Chitala Native booting on bare metal — is a new backend. The Trusted Core does not change.

## Traits

| Area | Trait | Replaces | Security requirement every backend must meet |
|---|---|---|---|
| Clock | `TimeSource` (+ `TrustedClock`) | the system clock | wall time + a monotonic clock that never decreases; `TrustedClock` never goes backwards and reports regressions (spec 11 "Time") |
| Entropy | `Entropy` | the OS RNG | a CSPRNG; fails closed (panics) rather than returning weak bytes |
| Key store | `SecureKeyStore`, `Signer` | key files | keys are named (`KeyRef`), never paths; a key that is not adequately protected is refused (`Insecure`); hardware stores may be non-exportable |
| Storage | `Storage`, `AppendLog` | POSIX paths and mode bits | logical paths (`StoragePath`: relative, no `..`, no absolute paths); `Visibility::Private` = owner-only, and existing private data that others can reach, or that is a symlink, is refused; atomic writes; durable appends |
| IPC | `IpcTransport` | Unix sockets | endpoints private to the platform owner; a live endpoint cannot be taken over; never replaces something that is not an endpoint |
| Network | `NetworkTransport` | a host HTTP/TCP stack | used by adapters only; bounded responses |
| Execution | `ExecutionHost` | the Linux process model | components get exactly the environment they are given (nothing inherited), a private byte channel and, where possible, their own address space (`isolated()`) |
| Device I/O | `DeviceIo`, `DeviceChannel` | device files, serial ports, GPIO; UART/MMIO on Native | only devices the operator configured can be opened, by name (`<bus>:<name>`, never a host path); channels are exclusive; adapters only — the Trusted Core never uses it |

A `Platform` value bundles one implementation of each.

## Backends

| Backend | Crate | Use |
|---|---|---|
| memory | `chitala-platform::memory` | tests and the simulator: deterministic entropy, a clock driven by the test, storage that can be weakened or tampered with, components as threads (**no isolation, never in production**) |
| hosted (Linux, macOS) | `chitala-platform-host` | files with owner-only permissions and symlink refusal, Unix sockets in a private directory, processes with an empty environment, the system clock, the OS CSPRNG, HTTP, configured character devices |
| native | (planned) | the Native QEMU spike: entropy, time and storage from firmware/hardware |

## Contract

`chitala_platform::contract` is a test suite every backend runs from its own tests: `time`, `entropy`, `key_store`, `storage`, `ipc`, `exec`, `devices`. A backend is admissible only if it passes them. Among other things the suite checks that:

- monotonic time never decreases;
- two entropy draws differ;
- a weakened private key or log is refused;
- a live IPC endpoint cannot be hijacked;
- an unconfigured device does not open, and channels are exclusive;
- an executed component sees only its given environment.

## Core purity

The Trusted Core crates are `chitala-model`, `-identity`, `-token`, `-policy`, `-resource`, `-intent`, `-safety`, `-csme`, `-audit`, `-state`, `-bus`, `-monitor`, plus `chitala-platform` itself. In their non-test code:

| Not allowed | Instead |
|---|---|
| `std::fs`, `std::os::*` | `Storage` |
| `std::net` | `IpcTransport`, `NetworkTransport` (adapters) |
| `std::process` | `ExecutionHost` |
| `std::env`, standard streams | configuration passed in by the runtime |
| `SystemTime::now`, `Instant` | `TimeSource` / `TrustedClock`, or a time passed in |
| `OsRng`, `thread_rng`, `getrandom` | `Entropy` |
| direct dependencies on `rand`, `getrandom`, `libc`, `nix`, `ureq`, `tokio`, `chitala-platform-host`, `chitala-adapters`, `chitala-node` | the PAL traits |

Concretely:

- keys are generated with `Keypair::generate(&dyn Entropy)`;
- message and intent ids come from `new_message_id(&dyn Entropy)` / `new_intent_id(&dyn Entropy)`;
- the token authority draws the key chain of every Biscuit block from the platform's `Entropy`;
- the audit log is an `AppendLog` in the platform's `Storage`.

Enforcement has two halves:

1. `scripts/core-purity.py` (CI job "core purity (PAL)" and `scripts/check.sh`) fails on any of the uses above. It was checked to report every OS use of the pre-PAL code base.
2. Behavioural tests catch what a source scan cannot, namely an OS call hidden inside a third-party library. For example, `tokens_draw_randomness_only_from_the_platform`: the same authority key and the same deterministic entropy must give byte-identical tokens. Any fallback to Biscuit's own OS-RNG path breaks the test.

Test code (`tests.rs`, `*_tests.rs`, `tests/`, a trailing `#[cfg(test)]` module) is exempt.

### The node runtime

`chitala-node` is held to the same rule, and stricter. Except for its hosted binding (`src/hosted.rs`) and its executables (`src/bin/`), it may not use any of the above, nor:

- file system paths (`std::path`, `Path`, `PathBuf`);
- the hosted backend (`chitala_platform_host`);
- Unix sockets, child-process pipes or permission bits (`UnixStream`, `UnixListener`, `Stdio`, `ChildStdin`, `set_permissions`, `from_mode`, …);
- a host temporary directory (`"/tmp…"`).

The hosted binding turns a config file into a `Domain` (config + `Platform` + endpoint) and a `NodeEnv` (stored objects, adapter host component, granted environment); everything else takes those. The script was checked to report all 110 OS uses of the node before this change, and to catch injected file, path, `/tmp` and hosted-backend uses. Its behavioural half is `memory_platform::node_runs_end_to_end_on_the_memory_platform`: the node starts, serves a client, runs an adapter host and keeps a verifiable audit log on a platform with no files, sockets, processes or pipes, which fails if any of them is still reached directly.

## Status (v0.2)

- **Done (v0.2 step 1, part 1):** the Trusted Core crates are pure; all eight trait areas exist with memory and hosted backends passing the contract.
- **Done (v0.2 step 1, part 2):** the node runtime is on the PAL — keys through `SecureKeyStore`, the domain state and the audit log through `Storage`, the IPC server and client through `IpcTransport`, adapter hosts through `ExecutionHost` (restart rate limit on the monotonic clock), time through `TrustedClock`, ids through `Entropy`. Existing domains keep working unchanged (same key files, config, state and audit formats).
- **Remaining host assumptions in the node:** it uses Rust `std` threads and `std::sync` (a native backend must provide them, or the node needs a task abstraction), and it still loads the node and authority keys as seeds (`export_seed`, decision D3).
- **Next:** Trusted Execution Boundary hardening (v0.2 step 2, see `ROADMAP.md`); later the Native QEMU spike runs identity → intent verification → authority decision on a native backend.

## Open decision

D3 (see `docs/v20-alignment.md`): the token authority still needs the raw seed of its key (`export_seed`), so it cannot use a non-exportable hardware key yet. This needs an ADR on Biscuit signing with an external signer. The node key (reply signatures, audit checkpoints, execution orders) is loaded the same way today; moving it to `Signer` is part of that ADR.
