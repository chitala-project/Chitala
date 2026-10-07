# Safety case

This is Chitala's safety case in its first form. It records what can go physically wrong through Chitala, what Chitala does about it, and the evidence that it does. The Project Lead decided on 2026-10-07 to give the existing pieces a structure: the Safety rules, the threat model, the specs, the tests and the mutation runs. The structure has value with or without any certification.

## Its parts

| Part | What it holds |
|---|---|
| [`hazard-log.md`](hazard-log.md) | the hazards: causes, possible harm, controls, what Chitala relies on outside itself, status |
| [`traceability.md`](traceability.md) | hazard → requirement → control → test → evidence; and the gaps found |
| [`critical-paths.txt`](critical-paths.txt) | the files whose change is safety-affecting |
| [`CONTRIBUTING.md`, *Safety-affecting changes*](../../CONTRIBUTING.md#safety-affecting-changes) | the review rule for such changes |

## How it stays true

[`scripts/check-safety-case.py`](../../scripts/check-safety-case.py) runs in CI and in `scripts/check.sh`. It fails when:
- a hazard of the log has no row in the matrix, or a row names a hazard that is not in the log;
- a rule a row names is not defined in [spec 17](../../specs/17-safety.md);
- a test a row names does not exist;
- a path in `critical-paths.txt` matches no file.

It cannot check that a test proves what its row says: that is for the reviewer.

On a pull request, the same script lists the safety-critical files the change touches. If there are any, the pull request's description must have a filled-in **Safety impact** section, or the check fails.

## What it is not

- **No certification claim**, and no claim of conformance to any standard.
- **No risk estimate.** How likely a harm is, and how much risk is acceptable, depend on the deployment: its equipment, its site and its people. A deployment's own risk assessment (for machinery, ISO 12100) takes this log as one of its inputs.
- **Not the only layer.** Chitala is the layer before the command. The device's own invariants (Constitution C5) are the layer after it. For machines, so are the hardware E-stop and the watchdogs. Chitala never replaces them.

## Conventions

- **Hazard ids:** `H-GEN-`, `H-HOME-`, `H-ROB-`, `H-HIST-`, numbered. A number is never reused. A hazard that no longer applies stays in the log, marked *retired*, with the reason.
- **Gap ids:** `G-n`, numbered the same way. A change that closes a gap removes it from the list, and says so in its description.
- **Every change to Safety, to the trusted boundary, to outcomes or to recovery updates the matrix in the same pull request:** a new rule, a new test or a new mutation run.

## Standards this evidence may serve later

Formal certification is not a current goal (Project Lead, 2026-10-07). When a deployment needs it, these are the relevant frameworks:

| Field | Framework |
|---|---|
| Consumer IoT, smart home | ETSI EN 303 645; the EU Cyber Resilience Act |
| Industrial cybersecurity | IEC 62443-4-1 (the process), 4-2 (the component) |
| Machinery, industrial robots | ISO 13849, IEC 62061; IEC 61508 underneath |
| Automotive safety | ISO 26262 |
| Automotive cybersecurity | ISO/SAE 21434 |
| Aviation software | DO-178C |
| Partitioned avionics architecture | ARINC 653 |

Two of these are often misread:
- **The Cyber Resilience Act is a regulation, not a certificate.** It sets conformity obligations for products sold in the EU.
- **DO-178C is not a certificate for an operating system.** It is an assurance process for airborne software, applied within an aircraft's certification.

Whatever the framework, a certificate is issued for one product, at one version and in one configuration, by an accredited body, to an applicant. It cannot be inherited from another product, and the evidence must be the product's own. seL4's proofs can serve as evidence for its kernel, inside such a case.
