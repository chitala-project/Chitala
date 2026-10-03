# Compatibility

## Versions

Chitala is in the `0.x` series. Until 1.0, any minor version may change behaviour, interfaces or wire formats. Such changes are announced in the pull request and in [`ROADMAP.md`](ROADMAP.md), and they keep the rules below for wire formats and identifiers. Nothing is `stable` yet (see [`SPECIFICATION_POLICY.md`](SPECIFICATION_POLICY.md)).

## Wire formats

Every signed message kind has its own content type, so a signature of one kind can never be accepted as another.

| Format | Identifier | Version | Spec |
|---|---|---|---|
| Chitala Secure Message Envelope | `application/chitala-csme` | 1 | 07 |
| Intent | `application/chitala-intent` | 1 | 15 |
| Approval | `application/chitala-approval` | 1 | 15 |
| Execution order | `application/chitala-order` | 1 | 10 |
| Capability token (Biscuit) | `chitala_token(1)` | 1 | 05 |
| Audit record | `"v": 1`, hash domain `chitala-audit-v1` | 1 | 09 |
| Node reply signature | domain `chitala-node-reply-v1` | 1 | 11 |
| Capability Registry | `chitala-core` | 0.1.0 | 04 |

Rules:

- A breaking change to a format means a new version, and implementations refuse versions they do not know (`E_VERSION`). Envelopes reject unknown critical extensions (`E_CRITICAL_EXT`). Intents, approvals and orders accept exactly their defined keys.
- Error codes (`E_*`, `X_*`) are part of the conformance contract: their meaning never changes and they are never reused.
- Capability ids, resource kinds and entity kinds are never reused with another meaning.

## Platforms

| Tier | Platform | Meaning |
|---|---|---|
| 1 | Linux x86_64, Linux ARM64, macOS ARM64 | built and fully tested in CI on every change |
| 2 | other Unix systems supported by the hosted PAL backend | expected to work, not tested in CI |
| — | Chitala Native | planned (v0.2 Native spike); the Trusted Core is already platform-independent (spec 18) |

- **Rust**: the toolchain is pinned in `rust-toolchain.toml`. The minimum supported Rust version is declared in `Cargo.toml` (`rust-version`) and checked in CI.
- **PAL backends**: every backend must pass the contract suite in `chitala_platform::contract` (spec 18).

## Deprecation

A feature, capability or format to be removed is first marked deprecated, with its replacement, for at least one minor version. Security fixes may shorten this when keeping the old behaviour would be unsafe.
