# Compatibility

## Versions

Chitala is in the `0.x` series. Until 1.0, any minor version may change behaviour, interfaces or wire formats. Such changes are announced in the pull request and in [`ROADMAP.md`](ROADMAP.md), and they keep the rules below for wire formats and identifiers. Nothing is `stable` yet (see [`SPECIFICATION_POLICY.md`](SPECIFICATION_POLICY.md)).

## Wire formats

Every signed message kind has its own content type, so a signature of one kind can never be accepted as another.

| Format | Identifier | Version | Spec |
|---|---|---|---|
| Chitala Secure Message Envelope | `application/chitala-csme` | 1 | 07 |
| Intent | `application/chitala-intent` | 1; 2 with an execution lease clause or follow-up steps (a plan) | 15, 21, 23 |
| Approval | `application/chitala-approval` | 1 | 15 |
| Execution order | `application/chitala-order` | 2 | 10, 19 |
| Execution receipt | `receipt` in the adapter host protocol | 1 | 19 |
| Decision context (digest in orders) | `"v": 2` | 2 | 19 |
| Capability token (Biscuit) | `chitala_token(2)` | 2 | 05 |
| Audit record | `"v": 1`, hash domain `chitala-audit-v1` | 1 | 09 |
| Node reply signature | domain `chitala-node-reply-v1` | 1 | 11 |
| Capability Registry | `chitala-core` | 0.1.4 (0.1.0 + an `outcome` for every device action, 0.1.1; `domain.plan_cancel` and `domain.list_plans`, 0.1.2; `device.read_history`, 0.1.3; `robot.stop`, `robot.move_linear`, `robot.rotate`, `robot.goto_pose` and an outcome's `pose`, 0.1.4; additive) | 04, 22, 23, 29, 30 |
| Home Capability Profile | `chitala-home` | 0.1.0 (the Matter lock command ids confirmed with matter.js and the Matter SDK's lock; `LockState` 3, which that lock reports for a moment on unlock, stays provisional until physical devices) | 24, 27 |
| Matter sidecar protocol | JSON Lines on the matter.js sidecar's stdio (`Hello` → `"protocol": 1`) | 1 | 27 |
| Adapter host init | the `matter` section (additive, optional) | — | 27 |
| Event kinds | `observed`, `unobservable` (additive) | — | 10, 29 |
| History log | JSON Lines, records `start`, `observed`, `unobservable`, `gap` (`"r"` tag) | 1 | 29 |
| Node config | the `history` section (optional; recording is on by default) | — | 29 |
| Home Assistant API | WebSocket (`auth`, `subscribe_events` `state_changed`, `get_states`, `call_service`, `ping`) and REST (`/api/states`, `/api/services`) | the API of current Home Assistant releases; verified against Home Assistant Core 2026.9.4 (its Demo integration) in v0.3 step ③A ([lab report](docs/lab/v0.3-step3a-home-assistant.md)); physical devices follow in step ③B | 25 |

Rules:

- A breaking change to a format means a new version, and implementations refuse versions they do not know (`E_VERSION`). Envelopes reject unknown critical extensions (`E_CRITICAL_EXT`). Intents, approvals and orders accept exactly their defined keys.
- Error codes (`E_*`, `X_*`) are part of the conformance contract: their meaning never changes and they are never reused.
- `X_EXECUTION_UNKNOWN` was added on 2026-10-05: a command that may have executed and nobody can say (spec 22). `X_DEVICE_UNAVAILABLE` keeps its meaning, a device or backend that could not be reached: the command was not delivered.
- Capability ids, resource kinds and entity kinds are never reused with another meaning.

## Platforms

| Tier | Platform | Meaning |
|---|---|---|
| 1 | Linux x86_64, Linux ARM64, macOS ARM64 | built and fully tested in CI on every change |
| 2 | other Unix systems supported by the hosted PAL backend | expected to work, not tested in CI |
| lab | Chitala Native: `aarch64-unknown-hermit` (Hermit unikernel) on QEMU or Arm boards with FEAT_RNG | built and booted in CI on every change (spec 20); not for controlling real devices until the gates of spec 13 *Hosted and Native* are met |

- **Rust**: the toolchain is pinned in `rust-toolchain.toml`. The minimum supported Rust version is declared in `Cargo.toml` (`rust-version`) and checked in CI.
- **PAL backends**: every backend must pass the contract suite in `chitala_platform::contract` (spec 18).

## Deprecation

A feature, capability or format to be removed is first marked deprecated, with its replacement, for at least one minor version. Security fixes may shorten this when keeping the old behaviour would be unsafe.
