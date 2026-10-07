# Native N1: the partitioning spike

This directory is the code of [the N1 plan](../../docs/native/n1-partitioning-spike.md): seL4 first, Bao as the comparison and the fallback. Each step ends in a script and a check. The Trusted Core is not touched here.

| Step | Status | Run |
|---|---|---|
| N1.0 Tools, pinned: the Microkit SDK, libvmm, the build host | ✅ | `scripts/fetch.sh`, `scripts/check-env.sh` |
| N1.1 Microkit: two protection domains and a channel, on `qemu_virt_aarch64` | ✅ | `run-n1.1.sh` |
| N1.2 libvmm's Linux guest example, under a VMM on seL4 | ✅ | `run-n1.2.sh` |
| N1.3 The Chitala Native image as a libvmm guest: the go/no-go | next | |

## The build host

**Linux is the canonical build host** (Project Lead, 2026-10-07): Ubuntu 24.04, arm64 or x86_64, with the packages of [`env/provision.sh`](env/provision.sh). There are two of them:
- **The local VM, where N1 is developed.** Bring-up needs a loop of seconds, not one CI run per guess.
- **CI, which checks independently that the build reproduces.** [`.github/workflows/native-n1.yml`](../../.github/workflows/native-n1.yml) runs on both architectures, and on every change here.

On a Mac, the VM is [Lima](https://lima-vm.io) (`brew install lima`):

```bash
native/spike/env/vm.sh start              # create, mount this repository, provision (once)
native/spike/env/vm.sh run native/spike/run-n1.1.sh
native/spike/env/vm.sh shell              # work inside it; the repository is at the same path
```

`$LIMA_HOME` (default `~/.lima`) decides where the VM's disk lives.

On Apple silicon, the VM is arm64 on Virtualization.framework. The M1 and M2 have no nested virtualization, so QEMU emulates the board inside the VM. That is enough for N1, but times measured there are relative (criteria 6 and 7).

## The pins

[`tools.lock`](tools.lock) pins everything N1 builds with:
- **the Microkit SDK**, by version and by the sha256 of each host's tarball. With `N1_VERIFY_GPG=1` (as CI runs it) the signature is checked too, against the release key's fingerprint;
- **libvmm**, by tag and commit;
- **the host's compiler, QEMU and dtc**, by version.

`scripts/fetch.sh` downloads into `$N1_CACHE` (default `~/.cache/chitala-n1`) and refuses anything that does not match. `scripts/check-env.sh` checks the host.

The Microkit SDK is 2.3.1, which restricts the rights of endpoint and notification capabilities. libvmm 0.2.0 declares 2.3.0; N1.2 shows it works with 2.3.1.

The guest images libvmm's examples boot (a Linux kernel and a buildroot initrd) come from the publisher, and are not signed. They are pinned by the sha256 of their first download. `fetch.sh` resumes a broken transfer: the publisher's server is far away, and slow from here.

## N1.1

[`sel4/channel`](sel4/channel) is the smallest system with the shape N1 needs:
- **two protection domains:** `core`, at the higher priority, and `adapter`;
- **one channel** between them;
- **one shared page,** which the adapter maps read-write and the core read-only.

The adapter writes a line and notifies; the core reads it and answers; the adapter hears the answer. `run-n1.1.sh` builds it with clang and `ld.lld` and boots it on QEMU `virt` (aarch64, EL2, Cortex-A53), as the Microkit manual runs `qemu_virt_aarch64`. It passes when all of that shows on the console.

## N1.2

`run-n1.2.sh` builds libvmm's own example, `examples/simple`: a VMM protection domain on seL4 that runs a Linux guest, with its console. It builds with the pinned SDK and libvmm, from the pinned guest images, and boots on QEMU `virt`. It passes when the guest's Linux:
1. reaches its login prompt;
2. takes a login over the VMM's virtual console;
3. runs a command.

```
[    0.000000] Linux version 7.1.0 …
buildroot login: root
# echo N1.2 guest says: $(uname -sm)
N1.2 guest says: Linux aarch64
N1.2: passed
```

This is the VMM and the guest console the Chitala image needs next, in N1.3.
