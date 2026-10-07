## What and why

<!-- What does this change do, and why? Link the issue. -->

## Security impact

<!-- Which trust boundary, invariant or threat does this touch? "None" is a valid answer if true. -->

## Safety impact

<!-- Which hazards (docs/safety/hazard-log.md) does this touch, and what changes for them? Does anything become less restrictive (a DENY that becomes an ALLOW, an UNKNOWN that passes, a wider limit)? Required when the change touches a path in docs/safety/critical-paths.txt; otherwise "None" is a valid answer if true. -->

## Checklist

- [ ] `scripts/check.sh` passes locally (fmt, core purity, clippy, tests, fuzz harnesses, audit, deny).
- [ ] Every commit is signed off (`git commit -s`, see [DCO.md](../DCO.md)).
- [ ] Tests prove the change; a security fix comes with a test that fails without it.
- [ ] **Invariant 1** holds: no new path from an AI, adapter, plugin or network input to an actuator except through the trusted execution boundary.
- [ ] **Core purity** holds: Trusted Core crates use the platform only through `chitala-platform` (spec 18).
- [ ] Specs, the threat model (spec 13) and docs are updated where behaviour changed.
- [ ] A safety-affecting change updates the safety case (`docs/safety/`) and has an independent reviewer (see CONTRIBUTING.md).
- [ ] Compatibility considered: wire formats, error codes, capability ids, config (see [COMPATIBILITY.md](../COMPATIBILITY.md)); breaking changes are called out.
- [ ] New dependencies are justified and pass `cargo deny`.
- [ ] Code, comments, docs and messages are in English.
