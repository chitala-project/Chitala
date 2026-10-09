# Apps and services on Chitala (design proposal)

**Status:** a proposal, revised twice after the Project Lead's reviews of 2026-10-09. The Lead approved the architectural direction on conditions, and asked for this revision before any real function is built. The project owner asked for the work on 2026-10-09. Nothing here is built, and nothing is claimed.

## What is asked

Apps run on Chitala:
- they help people and AIs;
- they use devices;
- they use services that third parties offer, now and later: email, messaging, the internet, calendars.

Every one of them must be safe. A person stays in control of what each app can see, do and send.

## The principles

Chitala already holds an app to its rules: "no AI, app or device grants or amplifies its own authority" (Constitution C1), and non-person principals need a token (C2, C12). This design applies those rules to apps and services. It adds no second system of authority.

1. **An app is a principal of its own,** with its own key, never a person's.
   - It acts for a person (`on_behalf_of`), with rights that person delegated, and never with the person's own authority.
   - Its requests go through the same monitor, Authority and Safety as an AI's.
   - A manifest asks for rights; it grants none.
2. **No ambient authority.** An app reaches nothing except through capabilities that Chitala checks:
   - no device;
   - no data;
   - no other app;
   - no network;
   - no file outside its own.
3. **A service is a resource:** an email account, a messaging channel, an internet destination. Each has owners, capabilities, envelopes, risk, outcomes and an audit.
4. **Content is never authority.** An email, a message, a web page or an AI's answer grants and widens no right (C4).
   - That does not stop every prompt injection. Content can still lead an AI or an app to misuse a right it really holds. The defence is that every action it is led to stays within its rights, its export rights, its recipients, its risk and its approvals.
   - Hazard H-APP-004 keeps that residual risk.
5. **A command is not an outcome.** A connector tells apart:
   - an order it sent;
   - what the service accepted;
   - what happened in the end.

   An outcome that is unknown is never retried on its own.
6. **The protection exists before the function opens.** No phase opens a function before the protections it relies on are there: running code before its sandbox, sending before export control, a real package before its integrity is checked.

## Two roles of an app

| Role | What it does | How Chitala holds it |
|---|---|---|
| **Consumer** | uses devices, data and services, for a person | a principal that needs a token for every capability; intents only, never direct commands; approvals when the risk needs them; Safety for physical actions |
| **Provider** | offers capabilities of its own (`calendar.add_event`, `notes.write`) | the provider of a resource, in an adapter's role: it executes only verified orders for its resource. Its answers are evidence from an untrusted source, and data with labels (below), never authority |

Apps talk to each other only through Chitala: intents for asking, capabilities for providing. What passes between them carries the data's labels and the restrictions of their sources, not only an intersection of authority (spec 15).

## `app:` and what it must inherit

The Lead's answer: `app:` as a principal kind, for the long-term design. `service:` may serve a prototype, provided its mark of origin is kept by the trusted registry and grants nothing implicitly.

Adding a kind does not, by itself, bring every protection with it. Some protections hold for every principal that is not a person:
- the identity registry refuses `owner` and `admin` to every kind but `person`;
- Authority asks a person to approve a high-risk action by any principal that is not a person.

Others are written for AIs alone:
- the default policy's rules on `Chitala::AI`: C11, the domain operations, high-risk approval;
- the monitor's rule that an AI sends intents, never commands;
- spec 05's binding of the person represented, described for AIs.

**App conformance.** Before an app runs anything, these hold for `app:` and are tested:

| Property | Test to write |
|---|---|
| No human role, no implicit administration | an app enrolled as owner or admin is refused |
| `on_behalf_of` checked against the registered agency, and bound in the token | an app acting for a person outside its registered agency, or with a token bound to another person, is refused. Delegation along a valid chain stays allowed, so the test checks agency and the token's binding, not only who delegated directly |
| Intents only, no direct commands | an app's command is refused as an AI's is (`E_INTENT_REQUIRED`) |
| No administration or delegation API used to get around a limit | every domain operation of C11 is refused to an app |
| Approvals, leases, plans, revocation and relays keep their meaning | each spec's tests, run again with an app as the actor |
| The policy covers `Chitala::App` wherever it covers `Chitala::AI` | a policy check that fails when a rule names one and not the other. This only supports the tests above: names appearing together do not show that the semantics are the same. The tests of behaviour do |

## The pieces

### 1. Packages, manifests and installation
- **The approval binds the package.** Installing is approved by an owner or an admin, never an AI (C11), through a trusted approval (spec 34). The approval binds:
  - the package's hash;
  - the manifest;
  - the publisher;
  - the terms granted.

  This needs spec 34's cryptographic binding of terms (P1b), not only the approval CLI (P1a).
- **A signature proves origin, not safety.** The publisher's signature proves where the package came from and that it is intact. It proves nothing about the code.
- **Narrowing rights and changing code are two things.**
  - A narrowing of rights takes effect at once.
  - New code always goes through the update policy, even when its rights are the same or fewer, because an update can still change what the app does with its data, change a capability it provides, or drop a function that safety needs.
- **Anti-rollback, with a way back.** A version never goes back. Known good old code can be released again under a new, approved revision, so that nobody is stuck with a bad new one.
- **Revoking a publisher's key has a defined scope and response.** It stops new installs and updates by that key. Existing installs are flagged to their owners, who decide. A provider whose function matters for safety moves to its defined safe state, rather than being killed outright.
- **Distribution keeps four things apart** (the Lead's answer): the right to publish; an owner's trust in a publisher; installing a package; granting it rights. There is no key that the whole ecosystem must trust.

### 2. Isolation, the minimum first
- **The minimum sandbox comes with the first app** (S1).
  - Hosted: a separate process under its own user, no network, no file system beyond its own directory, no other program started, and one channel: Chitala's endpoint for apps.
  - Its escape tests are part of S1.
- **Hardening comes later** (S5b): stronger sandboxes, and apps in partitions of their own on Native once H0 has shown partitioning on the hardware.
- **Quotas** for each app: CPU, memory, storage, requests, and questions to people. The questions count against each approver's budget (spec 34).
- **The owner's control path is never an app's.** Apps are clients of the general path (P0). An app's load must not take away the control path's availability, within the declared model of load and faults, and within bounds that are measured and tested. Separate endpoints and quotas alone do not ensure that the CPU, storage, the dispatcher and the device keep serving it. Whether a device then reaches a safe state also depends on the path of execution and on device-local safety.

### 3. Authority for apps
- A person delegates to an app as to an AI: attenuated tokens, limited in time, revocable. An app never hands its rights on (C1, C13).
- Templates of permissions (software track, P7) present the common shapes. The decision stays on concrete capabilities.

### 4. Data and export

**Labels, not only a class.** A data class (`DC0`–`DC4`, spec 03) says how sensitive data is. It cannot decide an export on its own: a camera's clip and a health record may share a class, and the right to export the clip to someone is no right to send them the health record. A label carries:

| Attribute | Meaning |
|---|---|
| Class | how sensitive: `DC0`–`DC4` |
| Source | which resource it came from: which camera, which account, which record |
| Subject | whose data it is |
| Export restrictions | to whom, through which service, on which conditions |

**An export checks two rights.** Sending data out needs:
- the right to send through that service (`email.send`);
- the right to export every source in the data's labels to that destination (`camera.export_clip` to that recipient).

`email.send` never replaces `camera.export_clip`.

**Conservative first.** Everything an app outputs carries the set of labels of all it has been given. This refuses more than is needed. It is also easy to check, unlike any attempt to guess what a given output contains.

**Rules for labels:**
- **Only trusted components label.** An app never declares or lowers a label.
- **Labels follow the data** through other apps, connectors and AI services.
- **A summary, an encryption or a new format does not drop a label.**
- **The app's state is what counts, not a session.** An app's set of labels covers all the state it can still reach: its files, and the memory of its live process. Opening a new connection or session never clears it. Only destroying that state does, for example a fresh process with its storage wiped, and the trusted runtime records that it did.
- **Labels survive** a restart, an update and a restore. A label that cannot be established refuses the export.

**Every way out, declared.** Not having direct internet does not mean every way out is controlled. These are all exports, each to its own destination and each checked:
- data sent to another app;
- content sent to an AI model in the cloud: an export to that AI's provider, not an internal step of the app;
- the clipboard, shared files, notifications and what is shown on a screen;
- URLs, query strings, headers, paths and attachments of a network request;
- logs, crash reports and telemetry.

**What this claims.** The first mechanism protects the declared and controlled channels. It does not claim to close every side channel.

**What comes back is data.** A reply, a page or a message is untrusted content, labelled with its source by a trusted component.

**Every release is audited:** which app, which labels, to which destination, for whom, under which rights.

### 5. Services, connectors and credentials

**Who holds the credential decides what H-APP-006 really covers.** Withholding a token from the app protects against the app, not against the connector: a compromised connector that holds a full OAuth token can call the service directly. Two options are written down:

| Option | What it means | Status |
|---|---|---|
| **A. The connector is trusted** | the connector holds the credential and is in the deployment's TCB | **for a prototype with fake services only.** H-APP-006 then stays not technically controlled |
| **B. A separate enforcement point** | the connector only forwards. A separate enforcement point holds the credential, checks each order, and builds the request to the service itself | **the default for every real service**, as in [device-side enforcement](device-side-enforcement.md) |

Option B's enforcement point never offers "any HTTP request, with the token attached": that would be an oracle that uses the credential. It offers named operations, bounded by:
- account;
- recipients;
- the content bound in the order;
- the service's endpoints.

Until B is built and tested, H-APP-006 has a control in design only.

**B does not remove every risk.** The enforcement point that holds the credential becomes a trusted component in its turn, which must be protected and verified.

**A connector holding a real credential inside the TCB** is not allowed by declaring option A. It would be a deployment option of its own, written separately, with:
- its own assessment of risk;
- limits on the credential's rights;
- the assurance level accepted for it.

**Sending email, precisely:**
- **A single-use order protects execution at the gate.** It does not show that the service makes exactly one effect through every crash.
- **The connector keeps a durable record of each execution.** It turns off a library's hidden retries where they are unsafe. It uses the provider's idempotency key where there is one.
- **A timeout or a lost answer is `unknown`,** never a certain refusal. It is never retried on its own.
- **The order binds everything that is sent:** every recipient in To, Cc and Bcc, the attachments, the sending account, and a digest of the actual content.
- **Past use is not low risk.** That a recipient was used before does not make the next send low risk. The risk comes from the policy, the labels and the content's destination.
- **Sent is not delivered.** A delivery receipt or a reply is evidence, with its source.
- **The provider's limits** (rate, quota, terms) are declared, and kept below.

### 6. AI in apps
- Chitala still builds no AI model.
- An app may host an AI, or call one in the cloud. That AI is a principal of its own (`ai:`), with its own key and tokens, and the app is its broker, as the MCP broker is today.
- A call to an AI in the cloud is an export (4).

### 7. Revoking, precisely

Revoking an app, quarantining it or uninstalling it:
- **stops** every request and use that still needs its rights checked;
- **cancels** what is still pending and still in Chitala's hands;
- **does not ensure** that an order past the last check of authority is cancelled, even before the outside service has confirmed receiving it. What happens to it depends on the gate, the queues and the protocol in place: the same interval as for devices (`a_revocation_after_the_fence_does_not_reach_an_order_on_its_way`);
- **cannot cancel** an action that an outside service has already accepted;
- **cannot recall** data already sent;
- **does not stop** a motion already running. Stopping takes a stop (spec 05, *Revocation*).

### 8. What a person sees and controls
- For each app: its rights in force; what it read, with labels; what it sent, and where; what it asked; what it did.
- One action pauses or removes an app, and the interface says what that does and does not undo (7).
- The explanation of any action (software track).

## Hazards (proposed)

| Id | Hazard | Main controls | Residual |
|---|---|---|---|
| H-APP-001 | An app acts beyond what it was granted: ambient authority, a confused deputy | its own principal and key; tokens; app conformance; the minimum sandbox | escapes from the sandbox |
| H-APP-002 | Personal data leaves through any way out | no ambient egress; labels with sources; two rights to export; every way out declared; audit | side channels; misuse inside the app |
| H-APP-003 | A message or an email sent twice, or to the wrong recipient | single-use orders; a durable record in the connector; idempotency keys; unknown never retried; every recipient bound | a service that duplicates on its own |
| H-APP-004 | Content leads an AI or an app to misuse a right it holds (prompt injection) | content grants nothing (C4); export, recipients, risk and approvals still bound the action | a misuse within real rights |
| H-APP-005 | An update or a compromised publisher changes what an app does | the approval binds the package's hash; new code goes through the update policy; anti-rollback with a way back; publishers revocable with a defined scope | malicious code that a person approved |
| H-APP-006 | A component holding a service's credentials acts outside Chitala | option A: none technical, declared; option B: a separate enforcement point with named operations | until B is built: not technically controlled |
| H-APP-007 | An app exhausts resources, wears a person down, or degrades the owner's control | quotas; the approver's budget; apps never on the control path | depends on isolating resources (CPU, storage, the dispatcher), not yet shown |
| H-APP-008 | An app passes itself off as Chitala, another app or a person | Chitala's own terms in approvals; the requester's words labelled; app identities shown | depends on a trusted path to the person's interface, not yet shown |
| H-APP-009 | A payment, a contract or another act that commits someone | refused until a profile, a contract and an assurance exist for it. Reading and drafting may be considered apart | — |

These enter the hazard log once the design is accepted, with their gaps named.

## The Trusted Core: sized honestly

"Two small changes" was too quick.
- A principal kind is small as syntax, but large as semantics: the conformance table above.
- Labels that persist across restarts and updates, and export checks across every way out, may change a great deal of meaning: the decision path, the audit, the persisted state.

The split stays:
- the decision core: the principal kind, the labels' check at export;
- the trusted runtime: sandbox, quotas, the package loader, the manifest check, keeping each app's labels;
- the platform: users, isolation, Native partitions;
- outside the core: connectors, which are in the TCB under option A;
- data: manifests, templates.

The size of each core change is set in its own design, with its invariants, its limits on resources, its behaviour in a crash and its tests.

## Phases (revised)

| Phase | What | Depends on | Done when |
|---|---|---|---|
| S0 | This design, the hazards, a threat model | — | the Lead's review |
| S1 | **A prototype:** test apps, fake data and fake connectors only. `app:` with the conformance table. The minimum sandbox. Packages checked: hash, manifest, version, bound to the install approval. Tokens to apps, quotas, the control path out of reach | P1a; P0's control path; P1b for the approval's binding | the conformance tests pass; escape tests pass; an app does nothing beyond its tokens |
| S2 | The connector framework, on **fake** connectors | S1 | execute once; a durable execution record; unknown never retried; every recipient bound |
| S3 | **Minimum export control:** labels with sources, two rights to export, every way out declared, labels kept across restarts | S1, S2; P7's information authority | the adversarial tests below |
| S4 | Apps as providers; apps calling each other through intents, labels and source restrictions carried | S3 | a label never drops between apps |
| S5a | (folded into S1) the minimum sandbox | — | — |
| S5b | Hardened sandboxes; apps in partitions on Native | S1; H0 for Native | escapes tested; on Native, isolation shown on hardware, otherwise hardware-pending |
| S6a | (folded into S1) package integrity | — | — |
| S6b | Distribution at scale: publishers, owners' trust, a review policy | S1 | the four things kept apart; a revoked publisher handled with its defined scope |
| — | **Real email**, or any real service | S3, and option B (or a deployment option assessed on its own, see 5) | — |
| — | **Third-party apps with real data** | S1, S3, and the adversarial tests below | — |

**Adversarial tests required before any third-party app uses real data:**
- reading a file or the network outside the broker;
- reading data, then opening a new session to export it;
- passing data through another app;
- sending it to an AI in the cloud;
- an update that changes the code after the approval;
- a connector restarted between sending and recording the result;
- a revocation on both sides of the point of sending;
- an app's load degrading the owner's control path.

## Conditions on the implementation's design

This document is not a full specification. The design of each phase must meet these conditions (Project Lead, 2026-10-09):
- **Labels before delivery.** An app's set of labels is updated, durably, before the data is handed to the app. Otherwise a crash between the two leaves, after a restart, an app holding data its labels do not show: a way out nobody checks.
- **One snapshot per export.** An export is checked and sent on one consistent snapshot of the labels, the content and the recipients. It is never checked on one set of labels and then sent with content or recipients that changed since.
- **Bounded label sets.** A set of labels has limits on its resources. Beyond them, or when a source cannot be established, the export is refused. A label is never dropped to make room.
- **Behaviour, not names.** The tests of `app:` test protective behaviour. That `Chitala::AI` and `Chitala::App` appear together in the policy supports them, and proves nothing on its own.
- **Revoking a publisher grants no physical recovery.** Moving a provider to its safe state still needs a contract, Authority, Safety and the right evidence.
- **The eight adversarial tests are a minimum,** not a certificate of safety. The detailed designs add their own crash and concurrency cases.

## The Project Lead's answers (2026-10-09)

| Question | Answer |
|---|---|
| Where this sits | an S1 prototype after P1a and P0's control path. No real data and no real egress before the minimum protections |
| `app:` or `service:` | `app:` for the design, with checks of compatibility and the conformance table. `service:` only in a prototype, with its origin kept by the trusted registry |
| Direct network | forbidden to apps that Chitala manages. Every network request goes through a broker that checks rights and exports |
| Financial and legal acts | refused when they commit someone, until a profile, a contract and an assurance exist. Reading or drafting may be considered apart |
| Publishing apps | publishing, trusting a publisher, installing a package and granting rights are kept apart. No key that the whole ecosystem must trust |

## What this does not claim

- Chitala does not make an app's code safe. It bounds what the app can reach, and what leaves through the ways out it controls.
- Data an app received can still be misused inside the app.
- Conservative labels at the app's boundary are not tracking inside the app, and do not close side channels.
- A signature on a package proves its origin, not its safety.
- Nothing here holds until it is built and tested.
- The approval of this direction allows design and prototypes within the limits above. It does not let third-party apps use real data, or connectors send to real services.
