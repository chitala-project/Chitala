# Specification policy

The Chitala Specification is everything an independent implementation needs to interoperate with Chitala and to make the same security decisions. It covers:

- the documents in [`specs/`](specs/README.md);
- the normative [Capability Registry](specs/registry/capabilities-v0.1.json);
- the [default policy and Security Constitution](specs/policy/default.cedar);
- the wire formats (CSME, intents, approvals, execution orders, tokens, the audit log) and their error codes.

## Free to implement

Anyone may implement the specification, in any language, open or closed, commercial or not, without asking. The specification text is under Apache-2.0 like the code, including its patent grant from contributors.

Independent implementations are wanted: a specification only becomes **Stable** when at least two independent implementations interoperate and pass its conformance tests (Blueprint v19 §9).

## Modified versions

You may publish a modified version under the license. It must not be presented as the official Chitala Specification:

- give it a different title;
- say clearly that it is modified and how it differs;
- do not use "Chitala Specification", "Official Chitala" or the logo for it (see [`TRADEMARK.md`](TRADEMARK.md)).

The **official Chitala Specification** is the text published on the `main` branch of <https://github.com/traderviet/Chitala>, and the versions tagged in its releases.

## Status

Every document and the registry carry a status: `experimental → provisional → stable → deprecated` (spec 04). All of v0.1 is `provisional`.

- Moving to **stable** requires two interoperating implementations and published conformance tests.
- A **deprecated** item is kept for reference; its identifiers and error codes are never reused with another meaning.

## Changing the specification

1. **Open an issue** with the problem, the proposed change, its security impact (threat model, spec 13) and its compatibility impact ([`COMPATIBILITY.md`](COMPATIBILITY.md)).
2. **Open a pull request** that changes the specification text, the reference implementation and the tests together. A normative change without a test that pins it down is incomplete.
3. **Wire format and error codes**: a breaking change gets a new version (spec 07 §Versions); a code's meaning never changes and a code is never reused.
4. **The Security Constitution and Invariant 1** (spec 00) follow the stricter rule in [`GOVERNANCE.md`](GOVERNANCE.md): an explicit decision by the Project Lead, after a public review period of at least 14 days.
5. **Merging** needs a maintainer of the specification. Normative changes are recorded in the pull request and the specs' history.

## Reference implementation

The Rust code in `crates/` is the reference implementation. When the code and the specification disagree, it is a bug in one of them; the issue decides which one is fixed.
