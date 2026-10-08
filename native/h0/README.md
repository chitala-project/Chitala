# H0: the hardware qualification framework

[Spec 33](../../specs/33-hardware-qualification.md) defines H0, and [the H0 plan](../../docs/native/h0-hardware-gate.md) orders its steps. This directory holds the framework's parts:

| Path | What |
|---|---|
| [`properties.toml`](properties.toml) | The property catalogue: layers A–E, platform or Chitala level, the capabilities each property needs, and whether its subject is the hardware |
| [`platforms/`](platforms/) | One **manifest** per platform. Each capability says whether the hardware has it, whether the stack drives it, and its source. A manifest declares; it never proves |
| [`harness/`](harness/) | One **harness** per platform that can be run: its steps (commands), the lines of their logs that show each property, and what a report binds to |
| [`h0.py`](h0.py) | The tool, in Python 3.11+ with the standard library only |
| [`reports/`](reports/) | Kept reports, checked in CI like everything else here |

## Using it

```sh
native/h0/h0.py plan                       # what every platform is tested for, from its manifest
native/h0/h0.py plan --platform zcu102     # one platform, with the reasons
native/h0/h0.py check                      # the catalogue, manifests, harnesses and kept reports hold
native/h0/h0.py check --self-test          # every rule fires

# on the N1 Linux host (native/spike/env/vm.sh, or CI)
native/h0/h0.py run --platform qemu_virt_aarch64_gicv3 --fresh   # every step, in a new run
native/h0/h0.py run --platform qemu_virt_aarch64_gicv3 --step n1.5
native/h0/h0.py report --platform qemu_virt_aarch64_gicv3        # writes and validates report.json
native/h0/h0.py validate REPORT
native/h0/h0.py established REPORT         # what a report establishes: its PASS results, on hardware only
```

A run's output goes to `$N1_BUILD/h0/PLATFORM/` (`~/.cache/chitala-n1/build/h0/…`):
- `steps/ID.json`: each step's command, exit status, log digest, and the digests of what it built and booted;
- `logs/ID.log`: each step's log;
- `report.json`: the report.

A step that already ran in an output directory is refused there. Every run counts, and `--fresh` starts a new one.

## The platforms today

`h0.py plan` prints the full matrix. In short:

| Platform | Environment | Harness | What stands in the way |
|---|---|---|---|
| `qemu_virt_aarch64_gicv3` (Platform 0) | emulator | ✅ N1.1, N1.3–N1.6, stress | it establishes nothing (an emulator), and `dma_isolation` is UNSUPPORTED (no SMMU driver for `qemu-arm-virt`) |
| `qemu_virt_aarch64` | emulator | ✅ N1.1, N1.2, N1.3 (H0.1) | it establishes nothing (an emulator); the two-guests system does not run on the GICv2 board yet |
| `zcu102`, `kria_k26`, `ultra96v2` | hardware | — | no admitted entropy provider: the Cortex-A53 has no `RNDR` (H0.1e). The SMMU is not driven by seL4 or the Microkit (H0-PX). The GICv2 is driven since H0.1, not yet shown on the board |
| `rpi5b_2gb` | hardware | — | libvmm has no bcm2712 GIC; the board's RNG is not an admitted provider yet (H0.1e); no IOMMU. The GICv2 is driven since H0.1 |
| `x86_64_generic_vtx` | hardware | — | a Hermit guest under libvmm's x86 VMM is untested (H0.1x); `RDSEED` is not an admitted source yet; VT-d is the one DMA path the Microkit has |
| `jetson_tx2` | hardware | — | not a Microkit board |

## Adding a platform

1. Write `platforms/ID.toml` (the `id` is the file's name). Declare every capability of the catalogue with `hardware`, `stack` (`true`, `false` or `"unknown"`) and its `source`.
2. Run `h0.py plan --platform ID` and read why each property is required, unsupported or not applicable.
3. When the platform can be run, write `harness/ID.toml`:
   - its steps;
   - an `evidence` entry for each property its steps show: the step, the lines that must all be in its log, and optionally the line where the test starts;
   - its `[static]` section: the pins, patches, kernel configuration and files a report binds to.
4. Run it, then `report`.

A harness may not claim evidence for a property its manifest rules out; `check` refuses it.
