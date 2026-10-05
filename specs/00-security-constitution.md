# 00 — Security Constitution

Sources: Blueprint v13 §1 (C1–C10), extended from v8 §8, §14, §18 and v15 §12 (C11–C14).

## Invariant 1

> **AI produces Intent. Chitala produces Authority. Only the trusted execution boundary produces physical Commands.**

Invariant 1 comes before C1–C14 and before every feature (spec 15):

- An AI only sends signed intents. A CSME `command` from an AI is refused with `E_INTENT_REQUIRED`.
- The Authority Engine (spec 16) is the only place that creates a `Grant`.
- Safety (spec 17) can only refuse.
- A physical command (an `ExecOrder`) is minted only by the Trusted Execution Boundary (`chitala-boundary`, spec 19), from an unforgeable authority proof (`Grant` or `Authorized`, or a `RecoveryGrant` for a resource's declared safe state after a failed outcome, spec 22) and a `Clearance`, and signed with an order key no other code holds.

Tests: `mcp::the_broker_never_sends_commands`, `monitor::ai_commands_are_refused_intents_are_required`, `physical_authority_slice::*`, and the `node_request` fuzz target (no single request except the owner's ever unlocks the door).

## C1–C14

The constitution is a set of invariants that **no application or AI can bypass**. Each one must be enforced at least at one point *outside* the AI or application. For serious attack paths it must be enforced in two independent layers (v13: "prefer at least two independent layers of defence"). The table below is a contract: every row has a corresponding automated test (v13 §20: "the Security Constitution is turned into automated conformance tests").

| # | Invariant | Enforced in v0.1 by | Tests |
|---|---|---|---|
| C1 | No AI, app or device grants or amplifies its own authority. | `HUMAN_ONLY_ROLES` (an AI cannot be owner or admin); delegation `child ⊆ parent`; no self-delegation; no principal changes its own security state. | `identity::ai_cannot_be_owner`, `token::props::delegation_never_amplifies`, `node::delegation_cannot_amplify` |
| C2 | Device A does not control device B without a valid capability or delegation. | Non-person principals need a token (`E_TOKEN_MISSING`); policy `C12-device-needs-token`. | `policy::default_policy_matrix` |
| C3 | Same LAN, same vendor or same cloud creates no trust. | Every request is a signed message; the IPC transport (a Unix socket on hosted platforms) is only a transport (spec 11). | `monitor::garbage_and_unknown_keys`, `node::ipc_round_trip_over_a_unix_socket`, `node::client_refuses_an_impostor_node` |
| C4 | Untrusted content (text, images, audio, web, the output of other AIs) never becomes authority. | Authority lives only in signed tokens (CSME key 13, intent key 14). MCP tool arguments and an intent's `purpose` are data. Unknown parameters are refused. Another AI's request travels only as a signed `cause`, and the chain's authority is intersected. | `mcp::prompt_injection_is_just_data`, `case5_an_ai_cannot_get_another_ai_to_open_the_door` |
| C5 | A validly signed command can still be refused by the safety layer or by a local invariant. | Registry safety envelope (`E_SAFETY_ENVELOPE`). Independent safety layer `SAFE-1…8` (spec 17, `E_SAFETY`), run again after a human approves. Device refusal (`X_DEVICE_REFUSED`). A command that was accepted can still be found not to have worked: its outcome is checked against the resource's witness, and a broken promise stops the resource (spec 22). | `safety::*`, `safety_is_checked_again_when_the_human_answers`, `node::safety_and_the_device_both_refuse_unsafe_commands` |
| C6 | Administering devices ≠ reading the Personal Vault. | Reserved: the `admin` role is separate from `owner`; there is no Personal Vault in v0.1. | — |
| C7 | There is no universal master key. | Tokens are signed with the authority key **of each domain**. Every principal has its own key. There is no ecosystem-wide key. | `token::foreign_or_tampered_tokens_are_invalid`, `monitor::token_checks` |
| C8 | Compromising one AI, device, service or domain yields no authority in another trust domain. | Tokens are holder-bound and domain-bound. A target outside the domain gets `E_UNKNOWN_TARGET`. Containment is per principal. | `monitor::token_checks`, `mcp::probing_through_the_broker_quarantines_the_ai` |
| C9 | Safety-critical functions behave safely locally when the cloud, server or AI is lost. | The node is local-first, with no cloud dependency. Policy `C9-critical-needs-approval`. SC4/Q4 come after 1.0. | `policy::default_policy_matrix` |
| C10 | Security semantics stay stable when crypto, transport, database or AI change. | CSME versioning (`E_VERSION`), critical extensions (`E_CRITICAL_EXT`), explicit algorithm ids (`E_ALG`), a versioned registry. | `csme::version_and_extensions` |
| C11 | An AI does not modify the protections (policy, revocation, safety holds, execution leases, plans, security states, the approval queue) and is never the final authority for a high-risk action. A plan never carries an approval: a step that needs one pauses the plan and is asked on its own (spec 23). An owner's approval may cover the bounded terms of an execution lease (spec 21): at most 3 uses within 1 hour at high risk, and never critical actions or two-key resources. | AIs send no commands (`E_INTENT_REQUIRED`). Policies `C11-ai-no-domain-admin` and `C11-ai-no-high-risk(-effective)`. A constitution rule **in the Authority Engine's code**: an AI with risk ≥ high needs an owner's approval. | `monitor::policy_checks`, `authority::case4_…`, `physical_authority_slice::case4_…` |
| C12 | No AI has default authority to control another entity. | `E_TOKEN_MISSING` (Authority Engine, DELEGATION step) **and** `C12-ai-needs-token` (policy): two independent layers. An AI acts only for the people it is declared to serve (`E_ON_BEHALF_OF`). | `authority::case2_…`, `node::milestone_0_0_1_…` |
| C13 | Delegation never amplifies: `child_scope ⊆ parent_scope`, `child_expiry ≤ parent_expiry`, bounded depth. | `chitala-token` (depth ≤ 3; an attenuated token cannot be re-delegated). Revocation cascades to every child token. | `token::delegation_rules`, `token::depth_is_bounded`, `token::revocation_cascades_to_children` |
| C14 | No response ≠ consent. | An escalation expires with the intent's deadline, is audited, and never executes. An answer from someone not entitled to give it does not close the question. Each AI may have at most 3 questions waiting (against approval fatigue). | `case4_rejected_or_ignored_means_the_door_stays_shut`, `an_agent_cannot_flood_its_owner_with_questions` |

## Rules of interpretation

1. When an invariant and a feature conflict, the invariant wins and the feature must be redesigned.
2. New invariants may be added (C15, …). Changing the meaning of an invariant or removing one is a breaking change and needs a new spec version.
3. A domain policy (`policy/default.cedar`) may **add** `forbid` rules but must not remove the policies prefixed `C*-`. Removing them amounts to amending the constitution.
