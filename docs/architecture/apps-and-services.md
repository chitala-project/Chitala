# Apps and services on Chitala (design proposal)

**Status:** a proposal for review, not a decision and not an implementation. The project owner asked for it on 2026-10-09. Nothing here is claimed as built. Where it sits in the plan is for the Project Lead to decide. It is written to fit the software track ([ROADMAP](../../ROADMAP.md)) and the direction ([direction.md](direction.md)), not to replace them.

## What is asked

Apps run on Chitala:
- they help people and AIs;
- they use devices;
- they use services that third parties offer, now and later: email, messaging, the internet, calendars, payments.

Every one of them must be safe. A person must stay in control of what each app can see, do and send.

## The principle: an app is a principal, not a privilege

Chitala already holds an app to its rules: "no AI, app or device grants or amplifies its own authority" (Constitution C1), and non-person principals need a token (C2, C12). This design applies those rules to apps and to services. It adds no second system of authority.

1. **An app is a principal of its own.**
   - It has its own key, never a person's.
   - It acts for a person (`on_behalf_of`), with rights that person delegated, and never with the person's own authority (the confused deputy).
   - Its requests go through the same monitor, Authority and Safety as an AI's.
2. **No ambient authority.** An app reaches nothing except through capabilities that Chitala checks:
   - no device;
   - no data;
   - no other app;
   - no network.

   An app that holds the network directly could send anywhere whatever it had read, and every control below would be decoration.
3. **A service is a resource.** An email account, a messaging channel and an internet destination are resources, with owners, capabilities, envelopes, risk, outcomes and audit. They are like a light or a door ("resources, not devices", direction.md).
4. **A service connector is an adapter.**
   - It holds the service's credentials: an SMTP password, an OAuth token, an API key.
   - It carries out only verified, single-use orders.
   - It stays outside the Trusted Core.
   - What gap G-8 says of devices holds here too: a connector that holds credentials can act outside Chitala's decision. The answer is the same design, [device-side enforcement](device-side-enforcement.md): the credential lives with the enforcement point, never with the app.
5. **Content from a service is untrusted** (C4). An email, a message or a web page is data, never authority. Words that say "the owner agreed" grant nothing. That is prompt injection, handled as spec 12 already handles it.

## Two roles of an app

| Role | What it does | How Chitala holds it |
|---|---|---|
| **Consumer** | uses devices, data and services, for a person | a principal that needs a token for every capability; intents, as an AI's; approvals when the risk needs them; Safety for physical actions |
| **Provider** | offers capabilities of its own (`calendar.add_event`, `notes.write`) that people, AIs and other apps may use | the provider of a resource, in an adapter's role: it executes only verified orders for its resource, and reports outcomes. Its answers are evidence from an untrusted source, never authority |

Apps talk to each other only through Chitala:
- **intents** for asking, with relays whose authority is the intersection of every link (spec 15);
- **capabilities** for providing.

Nothing passes from app to app directly.

## The pieces

### 1. Identity and packages
- **A signed package.** The publisher's key signs the app's package. A version never goes back: anti-rollback, as for profiles. A publisher's key can be revoked, and with it every version that key signed.
- **A manifest the node checks.** The manifest declares:
  - the capabilities the app will ask for, and on which resources;
  - the data it reads, with its class (`DC0`–`DC4`, spec 03);
  - the services it uses and the destinations it sends to;
  - whether it hosts an AI;
  - the assurance it needs.

  A manifest asks; it grants nothing.
- **Installing is a governed operation.** An owner or an admin installs an app, never an AI (C11). They approve the manifest's exact terms, through a trusted approval ([spec 34](../../specs/34-trusted-approval.md)). An update that widens anything is approved again. One that narrows applies at once.
- **Uninstalling takes everything away:** the app's tokens (`domain.revoke_all` for the app principal), its sessions, its pending requests, and its data release.

### 2. Isolation and resources
- **Hosted:**
  - each app is a separate process under its own user, sandboxed;
  - it has no network, and no file system beyond its own directory;
  - it has one channel: Chitala's endpoint for apps.
- **Native:** each app gets a partition of its own, with channels only to Chitala, once H0 has shown partitioning on the hardware.
- **Quotas** for each app: CPU, memory, storage, requests, and questions to people. A question an app asks counts against the approver's budget (spec 34), so an app cannot wear a person down.
- **Apps never reach the owner's control path.** They are clients of the general path. However much an app does, the owner can still stop a device, revoke and hold.

### 3. Authority for apps
- **Delegation.** A person delegates to an app as to an AI: attenuated tokens, limited in time, revocable. An app never hands its rights on (C1, C13).
- **Templates of permissions** (the software track, P7) present the common shapes: observe, propose, bounded operation, execute after approval. They are configuration. The decision stays on concrete capabilities.
- **Containment.** Quarantining an app (the security states of spec 03) fences its tokens, its sessions and its orders in flight (spec 19). It never takes away the owner's stop path.

### 4. Information and egress: the heart of the services question

Chitala controls release, not use (direction.md). An app with no network of its own can use what it read only through Chitala's egress capabilities, so egress is where use can be governed.
- **Reading is its own right**, data class by data class: `camera.view`, `health.read`, `messages.read`. Reading is never sending.
- **Sending is an action with consequences:**
  - `email.send`, `message.send`, `net.request`;
  - each has an envelope: recipients or domains allowed, size, attachments, rate;
  - each has a risk: sending to a recipient never used before is high; a payment is critical.
- **What an app has read follows it.** Each app session carries the highest data class it has been given. Sending to a destination needs a right to export that class there. For example, a clip from a camera reaches an email only with `camera.export_clip` to that recipient. Without it, Chitala refuses, or asks a person, as the policy says. This is coarse information-flow control at the app's boundary. It is not tracking inside the app, and it does not claim to be.
- **What comes back is data.** A reply, a page or a message is untrusted content (C4). Its data class is the one the policy gives the source.
- **Every release is audited:** which app, which data class, to which destination, for whom, under which right.

### 5. Service connectors
A connector keeps the contract every adapter keeps (spec 26):
- an order executes once;
- it is never sent again blindly;
- when the answer is lost, the fate is unknown. An email whose fate is unknown is not sent again, because a second email is a second action;
- a refusal is certain.

Further:
- **Sent is not delivered.** A command is not an outcome. A delivery receipt or a reply is evidence, with its source.
- **Credentials.** The connector alone holds the service's credentials, in private storage, used only to carry out verified orders: the device-side enforcement model. A connector that also hands out its tokens is an oracle, and is not allowed.
- **The provider's limits** (rate, quota, terms) are declared, and kept below.

### 6. AI in apps
- Chitala still builds no AI model (direction.md).
- An app may host an AI, or call one in the cloud. That AI is a principal of its own (`ai:`), with its own key and tokens, and the app is its broker, as the MCP broker is today (spec 12).
- An AI reaches devices, data and services through the same intents as any AI. It reaches an app's own features through the capabilities the app provides.

### 7. What a person sees and controls
- **For each app:**
  - its rights in force;
  - what it read;
  - what it sent, and where;
  - what it asked;
  - what it did.
- **One action** pauses or removes an app.
- **The explanation of any action** (the software track): who allowed it, its risk, the evidence and the rights it used, and whether its outcome is known.

## New hazards (proposed)

| Id | Hazard | Main controls |
|---|---|---|
| H-APP-001 | An app acts beyond what it was granted: ambient authority, a confused deputy | its own principal and key; tokens for every capability; no ambient network or file system |
| H-APP-002 | Personal data leaves through email, a message or the internet | no ambient egress; data classes that follow the session; export rights per destination; approvals; the audit of every release |
| H-APP-003 | A message or an email sent twice, or to the wrong recipient | single-use orders; unknown never resent; recipient envelopes; a new recipient is high risk |
| H-APP-004 | Content from a service becomes authority (prompt injection by email or web) | C4; content is data; approvals shown from Chitala's own terms (spec 34) |
| H-APP-005 | An app update, or a compromised publisher, widens rights silently | signed packages; anti-rollback; a widening update is approved again; publisher keys revocable |
| H-APP-006 | A connector that holds a service's credentials acts outside Chitala | the device-side enforcement model; credentials only in the connector; gap G-8's design |
| H-APP-007 | An app exhausts resources, or wears a person down with questions | quotas per app; the approver's budget; apps never on the control path |
| H-APP-008 | An app passes itself off as Chitala, another app or a person | Chitala's own terms in approvals; the requester's words labelled; app identities shown |
| H-APP-009 | A payment, a contract or another financial or legal act through a service | critical risk: refused by default; on top, approval by a person and the assurance the deployment must show |

These enter the hazard log only once the Project Lead accepts this design, with their gaps named.

## The Trusted Core

Following the software track's split (decision core, trusted runtime, platform, data):

| Piece | Where |
|---|---|
| An app as a principal kind | **the decision core, a small change.** Today's kinds are `person`, `ai`, `device`, `service`, `domain` and `resource`. `service` names Chitala's own components (`service:node`, `service:cli`). An app is untrusted code from a third party, and is better kept apart: `app:`. An alternative is `service:` with a mark of its origin. Lead's decision |
| Data classes on a release, and the export check at egress | **the decision core:** a predicate on Authority's path. General: every profile that reads or sends data needs it |
| The app runtime: sandbox, quotas, the package loader, the manifest check | **trusted runtime** |
| Process isolation, users, network namespaces, Native partitions | **the platform (PAL)** |
| Connectors | **outside the core**, in an adapter's place. In the TCB of the deployment once they hold credentials |
| Manifests, templates, the services' profiles | **data** |
| The interface: rights, release history, pause and remove | **outside the decision core.** It reads; the budget of questions is enforced by the runtime |

Each core change answers the three questions for a new primitive, and comes with its invariants, its limits on resources, its behaviour in a crash, and its tests.

## Phases (proposed)

| Phase | What | Depends on | Done when |
|---|---|---|---|
| S0 | This design, the hazards, a threat model for apps and services | — | the Project Lead's review |
| S1 | Apps as principals on Hosted: identity, the manifest's schema, installation through a trusted approval, tokens to apps, quotas at intake. No network for apps | P1a (approval CLI); the owner's control path (P0) | an app does nothing beyond its tokens; uninstalling takes everything; an app cannot reach the control path |
| S2 | The connector framework, and a first connector: sending email | S1; spec 26's conformance | execute once; unknown never resent; credentials only in the connector; envelopes; a new recipient asks a person |
| S3 | Information authority at egress: data classes on what is released, export rights per destination | S1, S2; P7 (information authority) | a clip never reaches an email without its export right; every release audited |
| S4 | Apps as providers, and apps calling each other through intents | S1 | a provider executes only verified orders; relays intersect authority |
| S5 | Hardened sandboxes on Hosted (separate users, a sandbox, no network); apps in partitions on Native | S1; H0 for Native | escapes tested; on Native, the partition's isolation shown on hardware, otherwise hardware-pending |
| S6 | Signed packages, publisher keys, updates without rollback, a review policy for distribution | P7 (signed profiles share the loader) | a widening update asks again; a revoked publisher's apps stop |

Each phase carries the software track's statuses: design, implemented, simulation-validated, hardware-pending.

## Decisions for the Project Lead

1. **Where this sits:** proposed, S1 after P1a, with S2 and S3 beside P7, and S5 on Native after H0.
2. **`app:` as a principal kind,** or `service:` with a mark of its origin.
3. **No ambient network for any app.** An alternative: a class of isolated apps with network access and no rights at all, to data or devices. It is weaker, because such an app could still mislead a person.
4. **Financial and legal acts** (payments, contracts): refused for now, as critical, until a profile and an assurance exist for them.
5. **Distribution:** who may publish, and how an owner decides to trust a publisher.

## What this does not claim

- An app's code is not made safe by Chitala. What Chitala bounds is what the app can reach, and what leaves through it.
- Data an app received can still be misused inside the app. Without ambient egress, it can leave only through capabilities that Chitala checks.
- Coarse information-flow control at the app's boundary is not tracking inside the app.
- Nothing here holds until it is built and tested.
