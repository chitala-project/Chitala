# Architecture Decision Records

An ADR records one architectural decision: the context, the options that were weighed, what was decided and what follows from it. ADRs are numbered and never rewritten. A later ADR may supersede an earlier one, and says so.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-native-architecture.md) | Native architecture: Hermit, seL4, a hypervisor or an own kernel | Proposed (amended after review) |

## Status

`Proposed` → `Accepted` (by the Project Lead) → possibly `Superseded by ADR-NNNN`. A rejected proposal stays in the index as `Rejected`, with the reason.

## Template

```markdown
# ADR NNNN — Title

Status: Proposed | Accepted (date, by) | Superseded by ADR-NNNN
Date: YYYY-MM-DD
Context: links to the specs and issues this rests on

## Context
## Decision drivers
## Options considered
## Evaluation
## Decision
## Consequences
## Revisit when
```
