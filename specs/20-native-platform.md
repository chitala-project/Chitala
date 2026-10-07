# 20 — Native Platform (spike)

Sources: Blueprint v20 §1, §2, §19 (Chitala Native, booting without a host operating system); milestone v0.2 step 5 *Native QEMU spike*; the Project Lead's decision to start with an existing unikernel (Hermit) and to write an Architecture ADR for an own kernel or a `no_std` core later. Code: `native/` (its own workspace and lock file, like `fuzz/`).

## What the spike proves

The node core boots and decides **with no Linux, Windows or macOS underneath**:

```text
Boot → Identity → Intent → Authority → Safety → ALLOW / DENY
```

The code is the code the hosted node runs: the Reference Monitor, the Authority Engine with the Cedar policy and the Security Constitution, Biscuit tokens, Safety, the Trusted Execution Boundary, the adapter host and the hash-chained audit log. Only the platform beneath them changes (spec 18). No AI model runs inside the image. An agent only sends signed intents, and Chitala decides authority and execution. The agent could run in the cloud, on another machine, or later inside Chitala.

```text
QEMU virt board (aarch64, Neoverse-N2)   — or an Arm board with FEAT_RNG
└─ hermit-loader v0.5.7 (SHA-256 pinned)
   └─ one image: Hermit kernel 0.13 + chitala-native
      Native PAL backend → start_node → IPC → Reference Monitor → Authority Engine
        → Safety → Trusted Execution Boundary → adapter host component → virtual devices
```

**Pass criterion:** the image boots in QEMU and makes all 13 decisions below as expected. The audit log must verify (hash chain + node signature), and the unikernel must exit with code 0. The kernel must never fall back to its weak generator. On a CPU without a hardware random number generator the same image must refuse to run (exit code 3), and so must it with a board clock before the image's floor (exit code 4). CI checks all of this on every pull request (job *native (Hermit unikernel on QEMU)*, a required check).

## The Native backend

| PAL (spec 18) | Native (this spike) | Hosted, for comparison |
|---|---|---|
| `TimeSource` | the board's real-time clock and generic timer, through the Hermit kernel | system clock |
| `Entropy` | the CPU's random number generator (Armv8.5 FEAT_RNG, `RNDR`), read directly; **no RNG, no start** (below) | OS CSPRNG |
| `SecureKeyStore` | RAM | key files, owner-only |
| `Storage` | RAM (the audit log and domain state live as long as the boot) | files, owner-only |
| `IpcTransport` | in-process | Unix sockets in a private directory |
| `ExecutionHost` | in-process components (threads), **no isolation**; under the N1 spike on seL4, the adapter host in another guest, over a channel (N1.4) | separate processes, empty environment |
| `NetworkTransport` | none | HTTP |
| `DeviceIo` | none (the devices are virtual, inside the adapter host) | configured character devices |

The backend passes the PAL contract at every boot, before any key exists (`[boot] PAL contract …`).

## Entropy: a finding

On aarch64, Hermit 0.13 has no entropy source: `seed_entropy()` returns `None`. `sys_read_entropy` then fills the caller's buffer from a 31-bit Park–Miller linear congruential generator and still reports success. The only sign is a kernel log warning (`Unable to read entropy! Fallback to a naive implementation!`). Every key, token and order id drawn that way would be predictable. The PAL contract's entropy check is statistical and cannot tell an LCG from a CSPRNG.

What the Native backend does instead:

- **It never calls the kernel's entropy.** `NativeEntropy` reads `RNDR` through `aarch64-cpu`'s `ArmRng`, a reviewed wrapper, so `native/` stays free of `unsafe`. The wrapper detects the feature in `ID_AA64ISAR0_EL1` and checks the instruction's status flag. A failing read is retried up to 1,000 times; after that the node panics rather than continue.
- **It fails closed.** Without FEAT_RNG the image prints `no secure entropy source … refusing to run` and exits with code 3, before generating a single key. CI boots it on a Cortex-A76, which has no RNG, to prove it.
- **The token path draws only from the PAL.** Biscuit attenuation uses `append_with_keypair` with an ephemeral key from `Entropy`. The node never calls the `append` that would draw from the operating system.

**The kernel is patched.** Rust `std` on Hermit seeds each thread's `HashMap` (`RandomState`) through the same syscall, which made those seeds predictable (a hash-flooding risk, not a key risk). `native/patches/hermit-kernel-aarch64-rndr.patch` makes the kernel seed its ChaCha20 pool from `RNDRSS` when the CPU has FEAT_RNG: 24 lines, the aarch64 counterpart of the kernel's x86_64 `RDSEED` seeding. `run.sh` applies it to a copy of the pinned kernel, and a patch that no longer applies stops the build. CI fails if the kernel log shows the fallback on a CPU with an RNG.

Upstream merged an equivalent fix on 2026-07-26 (hermit-os/kernel#2528, which reads `RNDR` without retries), after the last release (hermit-0.13.2). The patch is dropped when the pin moves to a release that contains it. Upstream main still falls back to the Park–Miller generator when there is no entropy source, which is what makes failing closed in Chitala necessary. Upstream also added a virtio-rng driver (#2547), a possible entropy source for boards and VMs without FEAT_RNG once released. Chitala keeps its own `RNDR` source either way: a kernel that falls back to a weak generator instead of failing is not trusted for keys. On a CPU without an RNG the unpatched fallback remains, but Chitala refuses to run before anything is generated. Other architectures are refused for now (`no admitted entropy source on x86_64 yet`). On x86_64, `RDSEED` is the candidate source.

## What changed in the hosted crates

- `chitala-node`: the hosted binding is the `hosted` feature, on by default. It covers `chitala_node::hosted`, `node_from_config`, `LoadedConfig` and the `chitala-adapter-host` binary. The workspace takes the node without default features; `chitala-cli` and `chitala-mcp` ask for `hosted`.
- `chitala-adapters`: `hosted` covers the adapter host's stdio entry point on the host clock. `home-assistant` covers the REST bridge: an HTTP client with TLS, whose `ring` dependency needs a C library. The bridge's config and service mapping are always present, so a config that needs the bridge is refused on a platform built without it. On Native, the bridge will go through `NetworkTransport`.

Hosted behaviour is unchanged: every hosted crate builds with the same features as before.

## The run

| # | Who | What | Expected | Refused at |
|---|---|---|---|---|
| 1 | person:alice (owner) | `light.turn_on` the living-room light | ALLOW, executed | — |
| 2 | "person:alice", signed by ai:assistant | `lock.unlock` the front door | DENY `E_ACTOR_KEY_MISMATCH` | Identity |
| 3 | ai:assistant for alice, no token | intent `light.turn_off` | DENY `E_TOKEN_MISSING` | Authority |
| 4 | alice | delegates `light.turn_off` on the light resource to ai:assistant | ALLOW, token issued | — |
| 5 | ai:assistant for alice, with the token | intent `light.turn_off` | ALLOW, executed | — |
| 6 | ai:assistant, the light token | intent `lock.unlock` the front door | DENY `E_TOKEN_DENIED` | Authority |
| 7 | person:child | `lock.unlock` the front door | DENY `E_POLICY_DENIED` (`child-no-high-risk`) | Authority |
| 8 | alice | delegates `lock.unlock` on the front door to ai:assistant | ALLOW, token issued | — |
| 9 | ai:assistant for alice, with that token | intent `lock.unlock` | ESCALATE to alice (C11: high risk needs the owner each time) | — |
| 10 | alice | approves the intent | ALLOW, executed (door unlocked) | — |
| 11 | alice | thermostat to 40 °C | DENY `E_SAFETY_ENVELOPE` (registry envelope 16–30 °C) | Request (capability) |
| 12 | alice | `domain.safety_hold` on the front door, "alarm armed" | ALLOW | — |
| 13 | person:bob | `lock.lock` the front door | DENY `E_SAFETY` `SAFE-1-HOLD` | Safety |

Every message travels over the node's IPC, signed, and every reply is signed by the node and checked by the client. The audit log holds 29 records. On QEMU (TCG), the run from kernel start to shutdown takes about 0.6 s of guest time.

## Running it

```sh
native/run.sh              # build for aarch64-unknown-hermit (release) and boot on a CPU with an RNG
native/run.sh --no-rng     # boot on a Cortex-A76: must refuse to run (exit 3)
cd native && cargo run     # the same program on the development host
```

`run.sh` needs `rustup`, `clang` (and `llvm-ar` on Linux), `patch`, `python3`, `qemu-system-aarch64` and `curl`. The image is built with the nightly that the Hermit kernel pins (`native/rust-toolchain.toml`, `-Zbuild-std`), against the pinned kernel with `native/patches/` applied. The loader is downloaded once and checked against its SHA-256.

QEMU's `max` CPU advertises FEAT_LPA2, which Hermit 0.13's page-table setup misreads. `run.sh` therefore uses Neoverse-N2, or `max,lpa2=off` where the installed QEMU lacks that model.

## Trust on Native, against hosted

The full analysis, with the gates Native must pass before it controls real devices, is spec 13 *Hosted and Native* (v0.2 step 6). In short:

- **What is trusted changes.** Hosted Chitala trusts the Linux or macOS kernel, libc and the process boundary. Native Chitala trusts the Hermit kernel (Rust, a library OS, with Chitala's entropy patch), the loader, the Rust standard library built for Hermit, the `aarch64-cpu` register wrapper, and the board firmware (or QEMU).
- **One address space.** A unikernel has no processes. The adapter host is a component in the same address space as the Trusted Core, as on the memory platform. Spec 19 guarantees the logical isolation: only the boundary mints orders, and orders are bound to one executor session and used once. Memory isolation is not guaranteed. Adapter isolation on Native needs an own kernel, a microkernel or a hypervisor, which is the ADR's question. The N1 partitioning spike runs the same image's adapter host in another guest on seL4 ([`native/spike/`](../native/spike/README.md#n14-two-guests-and-the-relay), N1.4), and N1.5 tests that isolation.
- **Nothing outside the image speaks to it yet.** No network, no disk, no devices: the attack surface is the boot path and the image itself. Clients are inside the image for this spike.
- **No persistence, no anti-rollback.** State and audit live in RAM, so safety holds and quarantines do not survive a reboot (spec 13 N8). With no audited event to anchor the clock, the image carries a floor: its commit time minus one day (`native/build.rs`). A board clock before that is refused (exit 4; CI boots with the clock set to 2020). A rewind to a moment after the floor still goes unnoticed (N6).

## Not yet

- Persistent, integrity-protected storage (virtio-blk or flash), with the audit anchor surviving reboots.
- A hardware key store: non-exportable keys, which needs decision D3 (spec 18).
- An external transport, so clients outside the image can reach the node (virtio-net plus an authenticated channel).
- Real devices through `DeviceIo` (UART, GPIO).
- Isolation of adapter hosts; SMP; measured or secure boot and attestation; x86_64 admission.
- The Native Architecture ADR (own kernel or a `no_std` core, microkernel, hypervisor), decision D4.
