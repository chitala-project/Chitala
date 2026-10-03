# Governance

> **Code is open. Implementation is forkable. Specification is implementable.
> The CHITALA identity, the official specification, conformance marks,
> certification and official releases remain governed.**
>
> Anyone may improve the code. Not everyone may redefine what "Official Chitala" means.

This document describes how decisions are made in the Chitala OS project. It is an initial technical governance design, not legal advice. The license, the contribution terms and the trademark policy are separate instruments:

| Instrument | Covers | Document |
|---|---|---|
| License | what anyone may do with the code and specification text | [`LICENSE`](LICENSE) (Apache-2.0), [`NOTICE`](NOTICE) |
| Contribution terms | what contributors certify | [`DCO.md`](DCO.md), [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Trademark policy | the CHITALA name, the logo, "Official / Compatible / Certified" | [`TRADEMARK.md`](TRADEMARK.md) |
| Specification policy | what the official Chitala Specification is and how it changes | [`SPECIFICATION_POLICY.md`](SPECIFICATION_POLICY.md) |
| Certification | fork → compatible → certified | [`CERTIFICATION.md`](CERTIFICATION.md) |
| Compatibility | versions, wire formats, supported platforms | [`COMPATIBILITY.md`](COMPATIBILITY.md) |
| Security | private reporting, supported versions | [`SECURITY.md`](SECURITY.md) |

## Roles

- **Users** run, study and adapt Chitala under the license.
- **Contributors** propose changes through pull requests. Every commit is signed off under the [DCO](DCO.md).
- **Maintainers** review and merge changes in the areas they own (see [`.github/CODEOWNERS`](.github/CODEOWNERS)). A contributor becomes a maintainer by invitation of the Project Lead after a sustained record of careful contributions and reviews.
- **The Project Lead** (currently [@traderviet](https://github.com/traderviet)) has the final say on the governed areas below, appoints maintainers, and is responsible for releases, the trademarks and certification.

## Who decides what

| Area | Includes | Decision |
|---|---|---|
| Trusted Core | `chitala-model`, `-identity`, `-token`, `-policy` (Authority Engine), `-resource`, `-intent`, `-safety`, `-csme`, `-audit`, `-state`, `-bus`, `-monitor`, `-platform`, and the node's trusted execution boundary | review by a code owner of the area; security-relevant changes need tests that reproduce the threat and an updated threat model |
| Security Constitution and Invariant 1 | `specs/00-security-constitution.md`, the `C*-` policies | Project Lead, after a public review period of at least 14 days; weakening an invariant is a breaking change |
| Specification | `specs/` | per [`SPECIFICATION_POLICY.md`](SPECIFICATION_POLICY.md) |
| Capability Registry | `specs/registry/` | maintainers of the specification; ids are never reused |
| Default policy | `specs/policy/default.cedar` | maintainers of the Trusted Core; the `C*-` policies follow the Constitution rule above |
| Everything else | adapters, CLI, MCP broker, tooling, docs | lazy consensus: a maintainer approves and nobody with standing objects |
| Official releases | signed release artifacts with attestations (`.github/workflows/release.yml`) | Project Lead |
| Trademarks and certification | the CHITALA name and logo, "Official / Compatible / Certified" | Project Lead, per [`TRADEMARK.md`](TRADEMARK.md) and [`CERTIFICATION.md`](CERTIFICATION.md) |
| This document | governance itself | Project Lead, after a public review period of at least 14 days |

## How decisions are made

1. **In the open.** Proposals are issues or pull requests. Larger changes start with an issue describing the problem, the design and its security impact.
2. **Lazy consensus.** A change that has a maintainer's approval and no unresolved objection may be merged once CI is green.
3. **Escalation.** When maintainers disagree, the Project Lead decides and records the reasoning on the issue or pull request.
4. **Security first.** A change that weakens an invariant of the Security Constitution, Invariant 1, core purity (spec 18) or the trust boundaries of the threat model is not merged without an explicit decision of the Project Lead.
5. **Vulnerabilities** are handled privately (see [`SECURITY.md`](SECURITY.md)) and disclosed after a fix is available.

## The `main` branch

`main` only changes through pull requests that pass the required CI and security checks. Force pushes and deletion are forbidden. Review conversations must be resolved before merging, and approvals are dismissed when new commits arrive. Code owner review applies to the sensitive areas listed in `.github/CODEOWNERS` once more than one maintainer exists.
