# 34 — Trusted approval (design)

**Status:** a design (Project Lead, 2026-10-09), of which the first part, P1a, is built (*What P1a built*, below). It answers gap G-9 ([hazard H-GEN-018](../docs/safety/hazard-log.md)). It sits beside Safety Contract v0.1 (ROADMAP step 6), because what an approver is told about consequences and safe states comes from the contract. Everything not listed as built is not claimed.

It needs no wide change to the frozen core. An approval already binds to the digest of one intent (spec 16), and Safety already runs again when a person answers (specs 17, 19). What is missing is mostly in the interface, the policy and the contracts.

## The gap

Chitala decides who may approve, and binds an approval to exactly one intent. It does not say what the approver must be shown before signing.

Before P1a:
- `domain.list_approvals` returned the parameters redacted by the audit's rules;
- `chitala approve` printed one line with the AI's `purpose` and not the parameters, and signed in the same step;
- nothing bounded how often one person was asked;
- a refused request could be asked again at once, reworded.

P1a closed these four (*What P1a built*). What remains of the gap is listed there.

No concrete exploit path has been shown. The gap is a missing requirement.

An AI can still persuade a person in its own conversation, outside Chitala. Chitala does not control that. H-GEN-018 stays a residual risk even when this spec is built.

## Requirements

### 1. Canonical content

Chitala builds what the approver is shown from the signed intent and the contract, never from the requester's words:
- **who:** the actor, the person it acts for, the agents that relayed it;
- **what:** the resource and the action;
- **the terms:** every parameter the approval covers;
- **when:** when it would act, and until when the question stands;
- **the scope:** one action, or a lease (how many uses, for how long, within which envelope). These are two different kinds of consent, and they are shown as such;
- **the risk:** from the registry and the resource, never from the requester;
- **from the contract:** what the action does, its safe state if it fails, the evidence it requires.

**Nothing is guessed.** If the contract does not state a consequence, a duration of effect or a safe state on failure, the approver is shown that it is unknown. Chitala never presents its own guess as a fact. A high-risk action whose contract states no safe state on failure is refused by policy. It is not offered for approval blind.

**Display is not redaction.** The audit's redaction rules are for the log, and they are not a display rule. Nothing the decision needs is hidden from the approver. A parameter that must never be shown is a reason to refuse the approval path, not to hide it.

**Bound to what was shown.** The summary is built from two things:
- the intent, identified by its digest;
- what is in force for it, which shapes what the person is shown:
  - the capability's entry in the registry;
  - the policy;
  - the resource's profile or contract;
  - the resource's own configuration, on the resource and every resource it is in: the binding of the capability (its device and its `risk_floor`), the envelope, the safe state, the owners, and whether it needs two keys.

It is a function of those two, so binding both binds what the person was shown. The approval signs both: the intent's digest, as today, and a **context digest**. That digest covers the content of what is in force, or a revision that changes whenever the content changes. It never covers a version label alone: if a binding, a risk floor, an envelope, the owners or the quorum changed while a profile's version stayed the same, an approval bound to the label would carry another meaning.
- **When the person answers,** the node computes the context digest again. If anything it covers changed since the question was asked, the approval does not verify (`E_APPROVAL_INVALID`). The person is asked again, with a summary built from what is now in force.
- **For a lease,** a change of anything the digest covers ends its approval, and its next use needs a new one.
- **A change to the action itself** (a parameter, a lease term) makes a new intent with a new digest, so an approval given before it is void.

The context digest changes the approval's wire format (spec 15). It is part of this design, not built. Until it is built, an approval binds only the intent's digest. Authority and Safety still run again, on what is then in force, when the person answers (specs 16, 17).

**What the context digest must satisfy** (Project Lead, 2026-10-09). The approval wire format changes only once all of these are specified, with test vectors:
1. **One snapshot.** The context is read as one consistent snapshot of what is in force. It is never assembled from a policy at one revision and a resource at another, which would hash a state that never existed.
2. **Canonical bytes.** The encoding is defined to the byte: the order of sets and maps, the number types, absent optional fields, a domain-separation tag and a schema version.
3. **Shown from what was hashed.** The summary is rendered from the same snapshot that was hashed. A name or a term is never taken from another snapshot.
4. **Terms, defined.** The schema lists which fields are terms of the approval: those that shape how a person understands it, such as the names of the resource and the device, the identity of the bound device, and the contract's descriptions. Purely cosmetic fields are left out, by an explicit list.
5. **No live state.** Sensor state and evidence, which change all the time, are not part of the static context. They are checked again before the action. A condition on a particular state, if an approval needs one, is written as an explicit condition.
6. **A change before the action.** A change to what the digest covers after the person answered, but before the order is minted or sent, voids the approval, or has it judged again as this spec defines. It is checked then, not only when the person answers.
7. **A lease is not asked again on its own.** A lease whose approval was voided ends. Its holder asks for a new lease. A use of a lease never escalates, and never re-asks the person by itself.
8. **No downgrade.** An approval of the current format (v1) is never read as one of the new format (v2). A capability that requires its context bound refuses a v1 approval.
9. **Re-asking is budgeted.** A question asked again because its context changed counts against the approver's budget (5), so a context that keeps changing cannot ask without end.

### 2. Trusted sources

- Names of devices and resources, the risk and the safety conditions come from the managed configuration and the profiles. Owners set them, and the changes are audited.
- An AI cannot set the risk, and cannot declare an action safe.
- A name the requester controls is labelled as the requester's.

### 3. Against spoofing

- The AI's words (`purpose`, any free text) are shown apart, as secondary, and labelled with their source ("ai:assistant says: …"). They never appear as Chitala's own text.
- The following are removed or escaped before display:
  - control characters;
  - bidirectional overrides;
  - characters that imitate Chitala's own markers.

  The length is bounded.
- Chitala's own fields never carry requester text.

### 4. What no approval removes

- Safety's rules and the evidence a contract requires hold whatever a person approved (specs 17, 19).
- Without the required evidence, the action is refused, or the resource goes to its declared safe state.
- An approval never makes a capability safe that its contract does not declare safe.

### 5. Against fatigue

- **A budget per approver** over a time window, counting the questions from every requester. It is added to the limits per requester.
- **Duplicates merged:** the same request asked again while it is pending is one question. "The same" means the same actor, resource, action and terms. The `purpose` is not part of it.
- **No reworded retry:** after a rejection, the same request with new words is refused without asking anyone, for a cool-down the owner sets.
- **A spent budget refuses:** a request beyond the budget is refused and reported, never queued in silence.

### 6. Control after approval

- The person sees the authority in force: tokens, leases, pending requests and plans.
- They can cancel a pending request, and revoke a token, a lease or everything (`domain.revoke_all`), through the existing Authority operations.
- The interface keeps **"authority revoked"** apart from **"device stopped"**. A revocation stops what still needs its authority checked (spec 05, *Revocation*). It does not cancel an order already accepted beyond the gate, and it does not stop a motion already running. Stopping takes a stop (spec 30).

## What P1a built (2026-10-09)

| Requirement | Built | Tests |
|---|---|---|
| Every term shown, in full (1) | `domain.list_approvals` returns the parameters as they are. The audit's redaction is not used. A request with a parameter that looks secret is never put to a person: it is refused (`E_CONSTRAINT`). No device action of the registry has such a parameter | `an_approver_is_shown_every_term_in_full`, `no_device_action_takes_a_parameter_that_could_not_be_shown` |
| Chitala's terms first, the requester's words apart (1, 3) | `chitala approve` shows who asks, for whom, the action, every parameter, the scope (one action, or a lease with its uses, duration and envelope), the risk, the approvals needed, why, the time left and the digest. Only then come the requester's words, labelled as its own and not checked by Chitala | `every_term_comes_before_the_requester_s_words`, `a_lease_is_shown_as_a_lease` |
| Against spoofing (3) | Every string shown is escaped: control characters, bidirectional overrides and invisible characters appear as `\u{…}`. Long text says how much was left out | `text_cannot_hide_or_pass_for_chitala_s`, `long_text_says_how_much_was_left_out` |
| A confirmation before signing | Approving needs the first 8 characters of the digest shown, typed at the prompt or passed with `--confirm`. Without them, nothing is signed. Rejecting needs none | `only_the_digest_s_own_start_confirms` |
| A budget per approver (5) | At most 10 questions per approver per 15 minutes, from every requester together (trial values). A request beyond it is refused and reported, never queued in silence. Only approvers with a question left are asked; if fewer than its quorum have one, it is refused | `an_approver_s_budget_of_questions_is_kept_over_every_requester` |
| Duplicates merged (5) | The same request (actor, person, resource, action, terms; never the purpose) while one is waiting is refused, naming the one waiting | `the_same_request_is_one_question` |
| No reworded retry (5) | After a person refuses a request, the same request, however worded, is refused for 10 minutes (a trial value) | `a_refused_request_is_not_asked_again_however_it_is_worded` |

**Still open:**
- the context digest (P1b);
- consequences and safe states taken from contracts, which do not exist yet;
- an interface beyond the CLI;
- the budget, the waiting requests and the refusals live in memory, so a restart forgets them;
- tests of what people understand.

G-9 stays open.

## Order of work (Project Lead, 2026-10-09)

1. This spec, with H-GEN-018 and G-9.
2. **The CLI first:**
   - show every term before asking;
   - make `purpose` secondary and label it;
   - remove what could spoof Chitala's text;
   - confirm before signing.
3. The budget per approver, cancelling and revoking, on the existing Authority operations.
4. Tests:
   - of the code;
   - of what people understand: misleading AI text, repeated requests, a single approval against a lease.

## Tests to write

- For any intent, the summary shows every parameter and lease term that the digest covers.
- Requester text never appears in Chitala's own fields, and control characters never reach the display.
- A changed term voids an approval given before the change. So does any change between the question and the answer to what the context digest covers: the registry entry, the policy, the profile or contract, a binding, a `risk_floor`, an envelope, a safe state, the owners, two keys. A change to that content under an unchanged version label voids it too.
- A budget per approver; a duplicate is one question; a reworded request is refused during its cool-down.
- What a person sees after `revoke_all`: authority revoked, and the state of each device as observed. A revocation never implies a stop.
- With people: whether they tell a single approval from a lease, and whether misleading AI text changes what they approve.

## What this does not claim

- People do not become immune to persuasion. The aim is that what Chitala shows is true, complete and its own, and that no approval can carry an action past Safety.
- Nothing here is enforced until it is built and tested. Until then, G-9 stays open.
