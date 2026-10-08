# 20 — Native Platform (spike)

Sources: Blueprint v20 §1, §2, §19 (Chitala Native, booting without a host operating system); milestone v0.2 step 5 *Native QEMU spike*; the Project Lead's decision to start with an existing unikernel (Hermit) and to write an Architecture ADR for an own kernel or a `no_std` core later. Code: `native/` (its own workspace and lock file, like `fuzz/`).

## What the spike proves

The node core boots and decides **with no Linux, Windows or macOS underneath**:

```text
Boot → Identity → Intent → Authority → Safety → ALLOW / DENY
```

The code is the code the hosted node runs: the Reference Monitor, the Authority Engine with the Cedar policy and the Security Constitution, Biscuit tokens, Safety, the Trusted Execution Boundary, the adapter host and the hash-chained audit log. Only the platform beneath them changes (spec 18). No AI model runs inside the image. An agent only sends signed intents, and Chitala decides authority and execution. The agent could run in the cloud, on another machine, or later inside Chitala.

```text
QEMU virt board (aarch64, Neoverse-N2)   — or a board with an admitted hardware entropy provider
└─ hermit-loader v0.5.7 (SHA-256 pinned)
   └─ one image: Hermit kernel 0.13 + chitala-native
      Native PAL backend → start_node → IPC → Reference Monitor → Authority Engine
        → Safety → Trusted Execution Boundary → adapter host component → virtual devices
```

**Pass criterion:** the image boots in QEMU and makes all 13 decisions below as expected. The audit log must verify (hash chain + node signature), and the unikernel must exit with code 0. The kernel must never fall back to its weak generator. On a CPU with no admitted hardware entropy provider the same image must refuse to run (exit code 3), and so must it with a board clock before the image's floor (exit code 4). CI checks all of this on every pull request (job *native (Hermit unikernel on QEMU)*, a required check).

## The Native backend

| PAL (spec 18) | Native (this spike) | Hosted, for comparison |
|---|---|---|
| `TimeSource` | the board's real-time clock and generic timer, through the Hermit kernel | system clock |
| `Entropy` (`EntropyProvider`) | an admitted hardware entropy provider (below): `arm-rndr`, the CPU's `RNDR` (Armv8.5 FEAT_RNG), read directly; **no provider, no start** | OS CSPRNG (`os-csprng`) |
| `SecureKeyStore` | RAM | key files, owner-only |
| `Storage` | RAM (the audit log and domain state live as long as the boot) | files, owner-only |
| `IpcTransport` | in-process | Unix sockets in a private directory |
| `ExecutionHost` | in-process components (threads), **no isolation**; under the N1 spike on seL4, the adapter host in another guest, over a channel (N1.4) | separate processes, empty environment |
| `NetworkTransport` | none | HTTP |
| `DeviceIo` | none (the devices are virtual, inside the adapter host) | configured character devices |

The backend passes the PAL contract at every boot, before any key exists (`[boot] PAL contract …`).

## Entropy: an admitted hardware entropy provider

> **Native Chitala must obtain boot entropy from an admitted hardware entropy provider. No deterministic, software-only, fixed, or silent fallback is permitted.**

`RNDR` is one admitted provider, not the architecture (Project Lead, 2026-10-08). Chitala is not to be locked to one instruction set or one source of entropy.

**The contract.** A provider is a PAL `EntropyProvider` (spec 18). Besides `fill`, which panics rather than return weak bytes, it says what it is in an `EntropyProvenance`:
- `provider_id`: a stable name, such as `arm-rndr`;
- `source_class`: `cpu-instruction`, `board-device`, `security-module`, `operating-system` or `deterministic`;
- `hardware_backed`: the bytes come from a hardware noise source, not from software alone;
- `source`: the source in words.

A provider also has a `health` test, which runs before the first key is generated.

**Health.**
- At start, the provider must answer: for `arm-rndr`, `RNDR` through its retries.
- 64 words must then pass a repetition test: no two equal 64-bit words in a row, and no all-zero word.
- While it runs, `arm-rndr` checks each word against the one before it, and stops the node on a repeat.
- These tests catch a broken source. They cannot prove a good one.

**No provider, no start.** The image exits with code 3, before any key exists, in either case:
- no provider is admitted on the platform;
- the admitted provider fails its health test.

**Provenance as data.** At boot the image prints its provider as one machine-readable line (`chitala.native.evidence/1`):

```text
[evidence]  {"schema":"chitala.native.evidence/1","entropy":{"provider_id":"arm-rndr","source_class":"cpu-instruction","hardware_backed":true,"source":"the CPU's RNDR (Armv8.5 FEAT_RNG)","health":"ok"}}
```

An H0 report names its `entropy_provider` from that record ([spec 33](33-hardware-qualification.md)), not from the prose of a log. The adapter's partition cannot write a line of the core's (N1.5a). Nothing in Authority or Safety reads the provenance: it is evidence for H0 and, later, for Typed Evidence.

| `provider_id` | Source | Class | Status |
|---|---|---|---|
| `arm-rndr` | the CPU's `RNDR` (Armv8.5 FEAT_RNG) | cpu-instruction | **admitted**, implemented |
| `x86-rdseed` | the CPU's `RDSEED` | cpu-instruction | **admitted** (Project Lead, 2026-10-08), and **implemented** (H0.1x). It is the CSPRNG's primary seed, with no step down to `RDRAND` just to boot |
| a board RNG, such as `bcm-rng200` (Raspberry Pi 5) | a random number generator of the board, through a driver | board-device | admissible only with a trusted driver, health and failure tests, and its provenance in H0 evidence (H0.1e). `bcm-rng200` is **specified** (*Entropy: `bcm-rng200`*, below): not implemented, and not verified on a board |
| a TPM, or a TRNG outside the SoC | a security module | security-module | later, as a provider of its own, once its source and trust boundary are described |

**Never admitted:**
- the kernel's own generator, or its fallback;
- a deterministic or fixed seed (`test-seeded` is for tests only);
- a software-only generator;
- `RDRAND` as the only source;
- the development host's CSPRNG (`os-csprng`, never a Native provider);
- a silent fallback of any kind.

**`x86-rdseed`, as built (H0.1x).** `RDSEED` is read through the `rdrand` crate (0.8), a reviewed wrapper that checks the carry flag and retries, so `native/` stays free of `unsafe`. Two cautions are built in:
- **The CPU is asked, not the build.** The `x86_64-unknown-hermit` target is compiled with `+rdrand,+rdseed`. `is_x86_feature_detected!` and the wrapper would take that for the CPU's word, and on a CPU without `RDSEED` the instruction would fault (#UD) instead of the node refusing. So the provider asks the CPU through CPUID (leaf 7, EBX bit 18) before using it.
- **An AMD CPU before Zen** (family 0x17) is not used: the wrapper refuses it, because of AMD's early `RDRAND` defects. A CPU without `RDSEED`, or one the wrapper refuses, makes the node refuse to run before any key exists.

Hermit hands QEMU only success or failure on x86, so a refusal there exits 1, not 3. CI boots the image on x86-64 both with and without `RDSEED` (job *native x86-64*).

A platform with no admitted provider is UNSUPPORTED for `hardware_entropy` in H0. That holds for the ZynqMP until a TPM, a TRNG or another real provider exists. A weaker policy is never the answer.

## Entropy: a finding

On aarch64, Hermit 0.13 has no entropy source: `seed_entropy()` returns `None`. `sys_read_entropy` then fills the caller's buffer from a 31-bit Park–Miller linear congruential generator and still reports success. The only sign is a kernel log warning (`Unable to read entropy! Fallback to a naive implementation!`). Every key, token and order id drawn that way would be predictable. The PAL contract's entropy check is statistical and cannot tell an LCG from a CSPRNG.

What the Native backend does instead:

- **It never calls the kernel's entropy.** `NativeEntropy` reads `RNDR` through `aarch64-cpu`'s `ArmRng`, a reviewed wrapper, so `native/` stays free of `unsafe`. The wrapper detects the feature in `ID_AA64ISAR0_EL1` and checks the instruction's status flag. A failing read is retried up to 1,000 times; after that the node panics rather than continue.
- **It fails closed.** Without FEAT_RNG the image prints `no admitted hardware entropy provider … refusing to run` and exits with code 3, before generating a single key. CI boots it on a Cortex-A76, which has no RNG, to prove it.
- **The token path draws only from the PAL.** Biscuit attenuation uses `append_with_keypair` with an ephemeral key from `Entropy`. The node never calls the `append` that would draw from the operating system.

**The kernel is patched.** Rust `std` on Hermit seeds each thread's `HashMap` (`RandomState`) through the same syscall, which made those seeds predictable (a hash-flooding risk, not a key risk). `native/patches/hermit-kernel-aarch64-rndr.patch` makes the kernel seed its ChaCha20 pool from `RNDRSS` when the CPU has FEAT_RNG: 24 lines, the aarch64 counterpart of the kernel's x86_64 `RDSEED` seeding. `run.sh` applies it to a copy of the pinned kernel, and a patch that no longer applies stops the build. CI fails if the kernel log shows the fallback on a CPU with an RNG.

Upstream merged an equivalent fix on 2026-07-26 (hermit-os/kernel#2528, which reads `RNDR` without retries), after the last release (hermit-0.13.2). The patch is dropped when the pin moves to a release that contains it. Upstream main still falls back to the Park–Miller generator when there is no entropy source, which is what makes failing closed in Chitala necessary. Upstream also added a virtio-rng driver (#2547), a possible entropy source for boards and VMs without FEAT_RNG once released. Chitala keeps its own `RNDR` source either way: a kernel that falls back to a weak generator instead of failing is not trusted for keys. On a CPU without an RNG the unpatched fallback remains, but Chitala refuses to run before anything is generated. Other architectures are refused for now. On x86_64 the provider is `x86-rdseed` (H0.1x, above).

## Entropy: `bcm-rng200`, the Raspberry Pi 5's RNG (H0.1e)

**Status: `experimental` ([SPECIFICATION_POLICY.md](../SPECIFICATION_POLICY.md)): specified; not implemented; not verified.** No board test has run. So no report names `bcm-rng200` as an admitted provider, and the Pi 5 stays UNSUPPORTED for `hardware_entropy` until the board test below passes (Project Lead, 2026-10-08). This section fixes what the provider must do, so that its implementation and its board test have a target.

### The source

- **The block.** The Raspberry Pi kernel's device tree describes the BCM2712's RNG as `rng@7d208000`, with 0x28 bytes of registers. Its compatible is the BCM2711's: `brcm,bcm2711-rng200`.
  - The node is in `bcm2712-ds.dtsi`, not in `bcm2712.dtsi` (raspberrypi/linux, branch `rpi-6.18.y`; the file's last change is `ec0e437`).
  - Through the SoC bus's `ranges`, its physical address is `0x10_7d20_8000`.
- **The registers,** as Linux's driver uses them (`drivers/char/hw_random/iproc-rng200.c`, `rpi-6.18.y`, last change `5f8f7ef`):

  | Offset | Register | What the provider uses |
  |---|---|---|
  | `0x00` | `RNG_CTRL` | `RBGEN` (bits 0–12) enables the block; `DIV_CTRL` (from bit 13) sets its sample rate |
  | `0x04`, `0x08` | `RNG_SOFT_RESET`, `RBG_SOFT_RESET` | bit 0: the restart |
  | `0x0c`, `0x10` | `TOTAL_BIT_COUNT` and its threshold | the warm-up: the bits produced, and how many are discarded before any output |
  | `0x18` | `RNG_INT_STATUS` | bit 31 `MASTER_FAIL_LOCKOUT`, bit 17 `STARTUP_TRANSITIONS_MET`, bit 5 `NIST_FAIL`, bit 0 `TOTAL_BITS_COUNT` |
  | `0x20`, `0x24` | `RNG_FIFO_DATA`, `RNG_FIFO_COUNT` | one 32-bit word per read; the words waiting (bits 0–7) |

- **What is not known.** Chitala found no public description of the noise source, of any conditioning, or of what `NIST_FAIL` and `MASTER_FAIL_LOCKOUT` test. Their names suggest health tests in the hardware. That is an inference, not a fact. So:
  - the block's flags are one input to health, never the only one;
  - its words are never handed out raw (*Use*, below);
  - its provenance says that `hardware_backed` rests on the vendor's driver and device tree, not on Chitala's measurement.
- **No emulator stands in.**
  - Upstream QEMU has no BCM2712 machine. Its newest Raspberry Pi is `raspi4b` (checked 2026-10-08).
  - An RNG200 model for `raspi4b` was posted to qemu-devel in 2026-07. It has had no review, and it cannot inject a fault.
  - An emulator would establish nothing anyway.

### Linux's driver is a reference, not a model

The Raspberry Pi driver has two paths, and Chitala copies neither.

- **The path for `brcm,bcm2711-rng200`, the Pi 5's compatible:**
  - its read never reads `RNG_INT_STATUS`, so it never sees `NIST_FAIL` or a lockout;
  - it waits without a limit, for the warm-up count and then for the FIFO;
  - its init keeps whatever configuration it finds when the block is already enabled. That is the boot firmware's configuration.
- **The path for the other compatibles** reads both failure flags. On a failure it resets the block once and carries on, and returns a short read if the flags stay set.

What Chitala rejects in both: an unbounded wait, an unread flag, and a reset that carries on.

### Trust boundary

**Trusted, for this provider:**
- the RNG200 block;
- the boot chain that runs before Chitala: the Pi 5's boot ROM, its EEPROM bootloader and its firmware. They can read and configure the block first. Chitala restarts and configures the block itself, so it does not depend on their settings. It cannot rule out that they observed or changed it before. Whether the Pi 5 boots securely is a separate question, not answered here;
- the seL4 kernel and the system description, which map the block's page;
- the driver, which is part of the core's TCB. `scripts/tcb-size.py` counts it.

**Where the driver runs: in the core's partition, and nowhere else.**
- The block's 4 KiB page is mapped into the core's partition and into no other. The adapter's partition, the adapter's VMM and the relay never have it.
- PlatformIsolationEvidence must show that the core alone owns the page, as for the core's other devices.
- The block has no DMA. The driver polls it, so it takes no interrupt.

**Not trusted:**
- **the guest kernel's entropy call.** On Hermit, it falls back to a weak generator (*Entropy: a finding*, above), so the driver never goes through it. On the Pi 5's Cortex-A76, which has no `RNDR`, the kernel's own pool, the one that seeds `HashMap`s, stays on that fallback. That is a hash-flooding risk, not a key risk. Seeding the pool from this provider is a separate decision;
- **the adapter's partition;**
- **anything other than the core that could reach the block's page.**

**Open, for the Project Lead, with the board in hand:** how the core reaches the page. Register access needs volatile reads and writes, and `native/` has no `unsafe` today. The options are:
- a reviewed crate;
- a small reviewed unit admitted for memory-mapped I/O;
- a driver in the patched guest kernel, with a call of its own that has no fallback.

### At start, before the first key

1. **Restart.** Disable the block, clear `RNG_INT_STATUS`, then set and clear both soft resets.
2. **Configure.** Set Chitala's own warm-up threshold (the bits discarded before the first output) and its sample divider. The values are set on the board. Linux's values are the starting point: 0x40000 bits, and `DIV_CTRL` 3.
3. **Enable, and wait with a deadline** for `TOTAL_BIT_COUNT` to pass the threshold, and for `STARTUP_TRANSITIONS_MET`.
4. **Check the flags.** If `NIST_FAIL` or `MASTER_FAIL_LOCKOUT` is set, health fails.
5. **The start test**, on words the block delivers:
   - no two equal 32-bit FIFO words in a row. That is the device's own word size, where a stuck FIFO shows;
   - then the 64 words of the existing test: no two equal 64-bit words in a row, and no all-zero word.
6. **Any failure ends the start.** The image exits with code 3, before any key exists (*No provider, no start*, above).
   - There is no second try with weaker settings.
   - Every wait has a deadline, and a deadline that passes is a failure.

### While running

- **The flags are checked before each read.** `NIST_FAIL` or `MASTER_FAIL_LOCKOUT` makes the provider unhealthy, and the node stops, as it does on a repeat from `arm-rndr`.
- **Each 32-bit word is compared with the one before it,** and a repeat stops the node.
- **An empty FIFO past its deadline** stops the node.
- **No reset carries on.** Recovery is a new start, with the whole start test.

### Use: conditioned, never raw

The block's conditioning is not described, so its words are entropy input, never output.
- They seed a vetted DRBG.
- Each seed draws at least twice the bits it yields. That assumes 0.5 bit of min-entropy per bit, until the measurement on the board says otherwise.
- `RNDR` and `RDSEED` are different: their architectures define their outputs as conditioned.

The DRBG, its reseeding and the factor are settled when the provider is implemented. They are reviewed as any change to the entropy path is.

### Provenance

At start, the provider writes the same record as any other (`chitala.native.evidence/1`):

```text
[evidence]  {"schema":"chitala.native.evidence/1","entropy":{"provider_id":"bcm-rng200","source_class":"board-device","hardware_backed":true,"source":"the BCM2712's RNG200 block (0x107d208000), conditioned by Chitala's DRBG; its noise source is the vendor's, not measured by Chitala","health":"ok"}}
```

### The board test that admits it

On a Raspberry Pi 5, run through the H0 harness:

- **The provider.** The image starts with `bcm-rng200`, and H0 reads `entropy_provider` from the record ([spec 33](33-hardware-qualification.md), a structured observation).
- **Isolation.** PlatformIsolationEvidence shows the block's page in the core's partition alone. For two guests, libvmm must first know the BCM2712's GIC: libvmm 0.2.0 stops on `#error Need to define GIC addresses` (H0.2).
- **Failure.** A test build injects each failure at the driver's register reads:
  - a flag set at start;
  - a flag set while running;
  - a stuck word;
  - an empty FIFO past its deadline;
  - the page not mapped.

  Each must end in exit 3 at start, or in a stop while running. The injection exists only in test builds, and it can only make the provider fail, never pass.
- **Measurement.** Raw samples taken on the board get an entropy estimate (NIST SP 800-90B, its non-IID tests). The estimate is recorded, and it sets the conditioning factor. It is an estimate, not a proof.

Only then may the provider table say "admitted, verified on <board>". A run on an emulator, or on a board other than the one tested, does not count.

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
