# Certification

Chitala distinguishes three things that are easy to confuse. Because the project governs physical actuation, the difference matters to users:

| Level | Who decides | May say |
|---|---|---|
| **Based on Chitala** — a fork, a derived product, an integration | anyone | "based on / a fork of / works with Chitala OS" (see [`TRADEMARK.md`](TRADEMARK.md)) |
| **Chitala Compatible** — implements a stated version of the specification and passes its published conformance suite | the implementer runs the suite and publishes the results; the project lists the product and may remove it | "Chitala Compatible (specification vX.Y)" |
| **Chitala Certified** — compatible, and reviewed by the project for the security properties that matter for physical authority | the Project Lead, in writing, for a stated version and period | "Chitala Certified (specification vX.Y, until YYYY-MM)" |

## Status today

**The program is not open yet.** There is no published conformance suite. No product may describe itself as Chitala Compatible or Chitala Certified until the suite and this program's procedures are published (planned with the first stable specification).

## What certification will look at

A certified implementation must, at least:

- pass the conformance suite for the stated specification version, including the attack tests of the threat model (spec 13);
- keep **Invariant 1**: AI produces Intent; Chitala produces Authority; only the trusted execution boundary produces physical commands;
- keep the Security Constitution (spec 00) and the safety layer (spec 17) intact;
- keep a Trusted Core that is platform-independent and pure (spec 18), or document and justify each deviation;
- ship signed releases with provenance and an SBOM;
- run a vulnerability disclosure process.

Certification can be withdrawn when a product stops meeting these conditions or misuses the marks.

## Official releases

An **official Chitala release** is built by this repository's release workflow and published with:

- SLSA provenance and SBOM attestations;
- a cosign-signed `SHA256SUMS` (see [`SECURITY.md`](SECURITY.md) to verify).

Builds from other sources, including unmodified source code, are not official releases.
