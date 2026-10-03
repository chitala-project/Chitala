# 07 — Chitala Secure Message Envelope (CSME) v1

Sources: v4 §3 (CSME fields), §7 (versioning/extensions), §14 (against downgrade and protocol confusion), §16 (canonical representation), §21 (JSON + CBOR, CSME Core v0.1 frozen).

CSME is the stable layer of the communication stack: the transport below it (Unix socket, QUIC, MQTT, …) can change without changing CSME. Intents, approvals (spec 15) and execution orders (spec 10) use the same envelope format, each with its own content type.

## Structure

```
COSE_Sign1 (RFC 9052), tagged (CBOR tag 18)
  protected header:
    1  alg           = -19  (Ed25519, fully specified)           ← required, otherwise E_ALG
    3  content type  = "application/chitala-csme"                ← required
    4  kid           = 16-byte key id of the signer (spec 02)    ← required
  unprotected header: empty                                      ← required
  payload: deterministic CBOR map (below)                        ← not detached
  signature: Ed25519 over Sig_structure("Signature1", protected, b"", payload)
```

The deprecated `EdDSA (-8)`, the COSE `crit` parameter and unknown headers are all refused. The content type is inside the signed part, so a CSME signature can never be reinterpreted as a signature of another format (v4 §14).

| Content type | Message | Signed by |
|---|---|---|
| `application/chitala-csme` | direct request (this spec) | the actor |
| `application/chitala-intent` | intent (spec 15) | the actor |
| `application/chitala-approval` | a human's answer (spec 15) | the approver |
| `application/chitala-order` | execution order (specs 10, 19) | the Trusted Execution Boundary (order key) |

## Payload map

| Key | Field (v4 §3) | Type | Required |
|---:|---|---|---|
| 1 | protocolVersion | uint, = 1 | ✓ |
| 2 | messageId — also the anti-replay nonce | bstr(16), random | ✓ |
| 3 | correlationId | bstr(16) | |
| 4 | source (sending endpoint) | tstr EntityId | ✓ |
| 5 | destination (target) | tstr EntityId | ✓ |
| 6 | actorIdentity — MUST be the signer | tstr EntityId | ✓ |
| 7 | capabilityId | tstr | ✓ |
| 8 | capability version | uint | ✓ |
| 9 | messageType: 1 command · 2 event · 3 intent · 4 goal · 5 query · 6 response | uint | ✓ |
| 10 | timestamp (issued at, ms) | uint | ✓ |
| 11 | expiry (ms) | uint | ✓ |
| 12 | contextRef | tstr ≤ 128 | |
| 13 | authorityRef — capability token (spec 05) | bstr 1..4096 | |
| 14 | safetyClass = `RiskClass` | uint 0–3 | ✓ |
| 15 | payload `tstr → bool/int/tstr`, omitted when empty | map ≤ 32 entries | |
| 16 | critical extensions | array of uint | |

The whole COSE structure is ≤ 16 KiB, with nesting depth ≤ 8.

## Canonical encoding

The payload MUST be deterministic CBOR (RFC 8949 §4.2.1):

- integers in their shortest form and definite lengths;
- map keys sorted by the bytes of their encoding, with no duplicate keys;
- no floats, nulls or tags.

The receiver decodes and re-encodes. Any difference, even trailing bytes, → `E_NON_CANONICAL`. Every message therefore has exactly one representation, and hashes and signatures can be compared across implementations.

## Versions and extensions (v4 §7)

- `protocolVersion ≠ 1` or missing → `E_VERSION`. The core version only increases with breaking changes.
- Unknown keys (≥ 17) are **ignored safely**, unless listed in key 16 → `E_CRITICAL_EXT` (fail closed).
- Message type 3 (intent) is not sent inside a CSME: intents have their own format (spec 15). Type 4 (goal) is reserved. The monitor answers both with `E_UNSUPPORTED_TYPE`.

## Order of processing at the receiver

1. Check the COSE structure and the protected header, without touching the payload.
2. Look up the key by `kid` and **verify the signature**.
3. Only then decode the CBOR payload.

The payload parser therefore never sees bytes from an unauthenticated sender, which shrinks the parser attack surface (v13 §9). Fuzz/property tests: `garbage_never_opens`, `signed_garbage_never_panics`.

## Anti-replay

The 128-bit random `messageId` is the nonce: the pair `(kid, messageId)` can be used once within its validity window (spec 08), and `expiry − timestamp ≤ 60 s`.
