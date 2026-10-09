# 35 — Typed evidence

**Status:** P2 of the software track ([ROADMAP](../ROADMAP.md#the-software-track-while-h0-waits-for-hardware)). The types, the validator and the test vectors are built (`chitala-evidence`). **Safety does not use them yet**: that is the Safety Contract's step, P3. Nothing here raises an assurance level, and nothing here shows that a sensor's data is right.

## Why

Safety today reads a device's state as flags and values: `obstacle_detected = false`, `emergency_stop = false` (gap G-6). A flag says nothing about:
- who measured it;
- when, and until when it holds;
- what it covers;
- how well it was measured;
- how it came to the node.

Typed evidence carries all of that, so that a contract can require it and Safety can judge it (P3). It is never a bare `safe = true`.

## Principles

- **A signature is not the truth.** It proves who sent the evidence, not that what it says is so. The types carry what is needed to judge evidence; they judge nothing on their own.
- **Unknown is a value.** A source may report that it does not know. That is never read as any known value.
- **A conflict stays a conflict.** When sources disagree, the combination says so. It never picks one, not even the more confident one or the safer value.
- **Expired evidence is no evidence.**
- **No assurance from these types.** Evidence that claims attestation is refused, because attestation does not exist yet (gap G-4).
- **Everything is bounded.**

## The evidence

| Field | Meaning |
|---|---|
| `kind` | what is observed: `obstacle`, `localization.x`, `lock.bolt`. A name, not a meaning: what a kind means is a contract's (P3). 1 to 64 characters of `a-z`, `0-9`, `.`, `_`, `-`, starting with a letter |
| `subject` | the resource it is about |
| `source` | the principal that observed it: a device, a sensor, a service |
| `observed_at_ms` | when the source observed it, by the source's clock |
| `received_at_ms` | when the node received it, by the node's clock |
| `valid_until_ms` | after this, it is no evidence |
| `scope` | `whole` (the whole subject), or `region`: a strictly convex region of it, as 3 to 16 corners in order (either direction), in millimetres within 1 000 km of the subject's origin |
| `reading` | `known` with a value (`bool`, `int` or `text`), or `unknown` with a reason |
| `quality` | the source's confidence (0 to 1000), and its accuracy when it states one (plus or minus, in a named unit) |
| `provenance` | the adapter that delivered it; the principals it passed through (at most 8); whether the source signed it; whether it was attested (always false) |

Unknown fields are refused. There is no field for a verdict.

## The validator

Evidence is decoded from JSON within 4 096 bytes, then checked. Each refusal has a stable code:

| Rule | Code |
|---|---|
| larger than 4 096 bytes | `too_large` |
| not the form above, or an unknown field (a bare `safe`, say) | `malformed` |
| a kind outside its form | `bad_kind` |
| observed after its receipt, beyond 5 s of clock skew | `from_the_future` |
| received after the node's now, beyond the skew | `received_in_the_future` |
| valid until a time at or before its observation | `valid_before_observed` |
| valid for more than an hour after its observation | `valid_too_long` |
| expired at the node's now | `expired` |
| a confidence above 1000 | `confidence_out_of_range` |
| a unit outside 1 to 16 characters of `a-z` and `_` | `bad_unit` |
| a region of fewer than 3 or more than 16 corners, a coordinate beyond 10⁹ mm, or corners that are not a strictly convex polygon in order: a dent, crossing edges, a repeated corner, three corners on a line | `bad_region` |
| a path of more than 8 hops | `path_too_long` |
| a text, a reason or an adapter's name above 256 characters | `text_too_long` |
| a claim of attestation | `attestation_unsupported` |

Only the validator makes a `Checked` piece of evidence.

## Combining

`combine` takes the pieces of one kind about one subject, as they stand at a given time (at most 32 at once):

| Result | When |
|---|---|
| `Agreed` | every valid source that knows reports the same value. The sources that do not know, or whose evidence expired, are listed apart: the caller decides what they mean |
| `Conflict` | valid sources that know disagree. Every reading is kept |
| `Unknown` | no valid source knows |

Pieces of another kind or subject are left out.

Combining is not independence. Two sources may share a cause: the same power, firmware, gateway or clock. Whether pieces are independent is a question for the contracts (P3) and for the hazard in question.

## Test vectors

[`evidence/vectors.json`](evidence/vectors.json) holds language-neutral cases: a base piece of evidence, and for each case a JSON Merge Patch (RFC 7396) to apply to it, the node's now, and the expected result (`ok`, or the refusal's code). `the_test_vectors_hold` runs them. Another implementation can run the same file.

Passing the vectors shows that an implementation reads and checks evidence as this one does. It does not show that any sensor is right.

## Not claimed

- That a sensor's data is true, or current beyond what its source says.
- That two sources are independent.
- Any assurance level: attestation is gap G-4.
- That Safety decides on evidence: not until P3, and until then G-6 stays open.

## Tests

`crates/chitala-evidence`:
- `the_test_vectors_hold`;
- `agreement_names_who_agreed_and_who_did_not_know`;
- `a_conflict_stays_a_conflict`;
- `expired_evidence_is_no_evidence`;
- `only_one_kind_about_one_subject_and_within_a_bound`;
- `evidence_round_trips_in_the_form_of_the_vectors`.
