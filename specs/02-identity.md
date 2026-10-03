# 02 — Identity

Sources: Blueprint v10 (Anti-Impersonation & Device Trust), v12 §1, v13 §1 (C7), v11 §16.6.

## Keys

- Every principal has **its own Ed25519 key pair**. There are no shared secrets, no key shared by a whole household or company (v7 §10), and no global master key (C7).
- **Key id** (`kid`) = the first 16 bytes of `SHA-256(public_key_32_bytes)`.
- Signatures use the COSE algorithm `Ed25519` (-19), see spec 07. The algorithm is explicit on the wire, so there is a path to a new suite or PQC (v7 §13) without changing semantics.

## Key layers of a domain (v10 §10)

| Key | Role | Where (v0.1) |
|---|---|---|
| Domain authority key | Signs the domain's capability tokens | `keys/domain-authority.key` on the node; SHOULD move into a TPM / secure element (v5 §8) |
| Node service key (`service:node`) | Signs audit checkpoints, replies and execution orders | `keys/service-node.key` |
| Principal key (person/ai/service/device) | Signs requests, intents and approvals | On the principal's own device. `chitala init` puts them all in one directory, for single-machine trials only. |

The token-signing key (authority) is separate from the node key, so compromising one service does not hand over the whole domain (v10 §10 "service keys separate Authority/Broker/Update").

## Key files

One hex line holding the 32-byte Ed25519 seed, file mode `0600`. File name: `<kind>-<local>.key` (`person-alice.key`). Existing files are never overwritten.

## Identity registry

- A principal = `(id, public_key, roles, security_state, serves)`.
- Both `id` and `kid` are unique within the domain; enrolling a duplicate is an error.
- `domain:*` and `resource:*` cannot be enrolled as principals.
- **Roles** match `[a-z][a-z0-9_-]{0,63}`. The roles `owner` and `admin` are reserved for `person:*` (C1, C11): an AI never becomes owner or administrator of a domain.
- Roles only mean something through policy (spec 06). For non-human principals a role creates **no** ambient authority (policies `C12-*`).
- **Agency** (`serves`): the people a non-human principal acts for. It is declared at enrollment and never claimed per request. Every served principal must be an enrolled person; persons serve only themselves (spec 15).

## Test keys

`test_seed(label) = SHA-256("chitala-test-vector:" || label)` derives deterministic seeds for test vectors shared between implementations. It MUST NOT be used outside tests.

## Not in v0.1 (room has been left)

- Enrollment through `DISCOVER → … → ISSUE CREDENTIAL → JOIN` (v4 §5) and FIDO FDO-style onboarding (v10 §4). v0.1 enrolls through a config file the owner writes.
- Attestation (RATS/EAT, v10 §5).

Manager authentication in the other direction (a client authenticating the node, v10 §2) is in place: every node reply is signed and bound to its request (spec 11).
