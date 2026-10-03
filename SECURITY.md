# Security Policy

Chitala OS is security-critical software: its Reference Monitor decides whether people, applications, devices and AI agents may act on the physical world. We treat vulnerabilities accordingly.

## Supported versions

Only the latest commit on `main` (the `0.0.x` trusted core) receives security fixes. There are no stable releases yet.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub: *Security* tab → *Report a vulnerability* (private vulnerability reporting).

Please include the affected component (crate / spec section), a description of the impact, and a reproduction — ideally a failing test. We aim to acknowledge reports within 72 hours.

## Scope

In scope: anything that lets a principal act without authority or beyond it, bypass the Reference Monitor, amplify a delegation, forge or replay a request, reply or token, tamper with the audit log or roll back domain state undetected, leak keys/tokens/secrets, or crash/hang the trusted core from untrusted input.

The threat model, the attacks already covered by tests and the known residual risks are in [`specs/13-threat-model.md`](specs/13-threat-model.md). Residual risks listed there are known; reports that show a practical exploit of one are still welcome.

## Our process

Fixes land with a regression test reproducing the issue. Security-relevant changes are recorded in the audit-relevant specs (`specs/00`–`13`).

## Verifying release artifacts

Releases are built by `.github/workflows/release.yml` on GitHub-hosted runners. Every archive and binary carries a SLSA build-provenance attestation and a CycloneDX SBOM attestation (Sigstore, keyless), and `SHA256SUMS` is signed with cosign:

```bash
gh attestation verify chitala-<tag>-<target>.tar.gz --repo traderviet/Chitala
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/traderviet/Chitala/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c SHA256SUMS
cargo audit bin chitala   # binaries embed their dependency list (cargo-auditable)
```

Every change to `main` passes `scripts/check.sh` in CI: `cargo fmt --check` → `cargo clippy -D warnings` → `cargo test` (x86_64, ARM64, macOS) → `cargo audit --deny warnings` → `cargo deny`, plus MSRV, CodeQL and a workflow security lint (zizmor).
