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
- **Like with like.** Only evidence over the same scope is compared, and a combination keeps every piece whole: its times, scope, quality and provenance.
- **Expired evidence is no evidence.**
- **No assurance from these types.** Evidence that claims attestation is refused, because attestation does not exist yet (gap G-4).
- **Checked is not authenticated.** See [what checked means](#what-checked-means).
- **Everything is bounded.**

## The evidence

| Field | Meaning |
|---|---|
| `kind` | what is observed: `obstacle`, `localization.x`, `lock.bolt`. A name, not a meaning: what a kind means is a contract's (P3). 1 to 64 characters of `a-z`, `0-9`, `.`, `_`, `-`, starting with a letter |
| `subject` | the resource it is about |
| `source` | the principal that observed it: a device, a sensor, a service |
| `observed_at_ms` | when the source observed it, by the source's clock |
| `received_at_ms` | when the node received it, by the node's clock, as whoever built the evidence declares it: nothing stamps it yet (P3) |
| `valid_until_ms` | after this, it is no evidence |
| `scope` | `whole` (the whole subject), or `region`: a strictly convex region of it, as 3 to 16 corners in order (either direction), in millimetres within 1 000 km of the subject's origin |
| `reading` | `known` with a value (`bool`, `int` or `text`), or `unknown` with a reason |
| `quality` | the source's confidence (0 to 1000), and its accuracy when it states one (plus or minus, in a named unit) |
| `provenance` | the adapter that delivered it; the principals it passed through (at most 8); whether the source signed it, as declared and not verified (`signed_by_source`); whether it was attested (always false) |

Unknown fields are refused at every level: beside a scope (`whole` included), a reading, a value, the quality, the accuracy and the provenance. There is no field for a verdict.

### The encoding

Evidence is JSON. Its encoding has no whitespace outside strings, leaves an absent accuracy out (never `null`), escapes in strings only what JSON requires (`"`, `\`, and control characters), and writes integers in plain decimal. Its size is the size of that encoding.

## The validator

There are two paths to a checked piece of evidence, and they agree:
- `decode` refuses input above 4 096 bytes before it parses it, then validates. A sender sends the encoding above, without padding.
- `validate` checks a piece built in memory, its encoded size first.

Every test vector runs through both. Each refusal has a stable code:

| Rule | Code |
|---|---|
| its encoding larger than 4 096 bytes, even with every field within its own bound | `too_large` |
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

### What checked means

`Checked` means that the evidence is well-formed, within every bound, and valid at the node's now when it was checked. It does not mean:
- that the source is who it says, or that a signature was verified: the evidence carries none, and `signed_by_source` is a declaration that establishes nothing until P3 verifies a signature;
- that the node received it when `received_at_ms` says: nothing stamps it yet. The validator only checks that it is not ahead of the node's now;
- that what it says is true.

P3 must not rely on a declared field as if it were verified.

## Combining

`combine` answers one question: what do the pieces of one kind, about one subject, over one scope, say at the node's now? It takes at most 32 pieces. Pieces of another kind or subject are not part of the question. Every other piece is counted, or left out with its reason:

| Left out | When |
|---|---|
| `other_scope` | it covers another scope |
| `superseded` | its source observed again later |
| `expired` | it expired |
| `repeated` | the same piece, identical in every field, was given again |

**Scope.** Two scopes are the same when both are `whole`, or when both are the same region: the same corners in the same cyclic order, from any corner and in either direction. Nothing else is compared yet. A region never stands for the whole, the whole never stands for a region, and overlapping regions are not merged. So two clear halves are not a clear whole, and an obstacle in one region is no conflict with a clear region beside it. A piece left out for its scope is still returned, so the caller sees it. A question over a malformed region is refused.

**One source, one voice.** A source counts by its latest observation (by `observed_at_ms`). Its older pieces are superseded, and they never come back when the latest expires. An identical piece given twice is counted once. Pieces of one observation that differ in anything else (their validity, quality or provenance) are all counted, so the combination holds only until the first of them expires, whatever order they came in. Two different readings about one moment from one source are both counted, and they are a conflict. Two records from one source are one source, and the combination's list of sources says so.

**The verdict**, over the counted pieces:

| Verdict | When |
|---|---|
| `Agreed(value)` | every counted piece that knows says the same value; pieces that do not know are counted, and say so |
| `Conflict` | counted pieces that know disagree; every reading is kept |
| `Unknown` | no counted piece knows |

**Validity.** A combination holds from the time it was made until the first counted piece expires. With nothing counted, it holds at no time and is combined again. If the node's now is before the time a piece was checked, the clock went back: combining is refused (`time_went_back`), and the piece is valid at no such time.

The result keeps every counted and left-out piece whole: its times, scope, quality and provenance. `Agreed` over a region says nothing about the rest of the subject. P3 decides what coverage a contract needs.

Combining is not independence. Two sources may share a cause: the same power, firmware, gateway or clock. Distinct sources are not shown to be independent. Whether they are is a question for the contracts (P3) and for the hazard in question.

## Test vectors

[`evidence/vectors.json`](evidence/vectors.json) holds 43 language-neutral cases: a base piece of evidence, and for each case a JSON Merge Patch (RFC 7396) to apply to it, the node's now, and the expected result (`ok`, or the refusal's code). `the_test_vectors_hold_by_decode_and_by_validate` runs each case through both paths, and decodes every accepted piece again from its own encoding. Another implementation can run the same file.

Passing the vectors shows that an implementation reads and checks evidence as this one does. It does not show that any sensor is right.

## Not claimed

- That a sensor's data is true, or current beyond what its source says.
- That two sources are independent.
- That a source is authenticated, a signature verified, or a receipt stamped by the node: `Checked` is none of these.
- That evidence over a region covers the whole subject, or the reverse.
- Any assurance level: attestation is gap G-4.
- That Safety decides on evidence: not until P3, and until then G-6 stays open.

## Tests

`crates/chitala-evidence`:
- `the_test_vectors_hold_by_decode_and_by_validate`;
- `the_encoded_bound_holds_on_every_path`;
- `agreement_keeps_every_piece_whole`;
- `a_conflict_stays_a_conflict`;
- `only_pieces_over_the_same_scope_are_compared`;
- `a_region_is_the_same_from_any_corner_and_either_direction`;
- `a_source_counts_once_by_its_latest_observation`;
- `only_an_identical_piece_is_a_repeat`;
- `a_source_that_contradicts_itself_is_a_conflict`;
- `a_combination_holds_until_its_first_piece_expires`;
- `expired_evidence_is_no_evidence`;
- `a_clock_that_went_back_is_refused`;
- `only_one_kind_about_one_subject_and_within_a_bound`;
- `evidence_round_trips_in_the_form_of_the_vectors`.

Mutation set [`typed-evidence`](../mutation/sets/typed-evidence.toml): each control above, put out of action on purpose (TE-1 to TE-24).
