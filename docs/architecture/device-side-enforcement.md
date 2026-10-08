# Device-side enforcement (design note)

**Status:** a design note, not an implementation. The Project Lead asked for it on 2026-10-08, to answer gap G-8 ([hazard H-GEN-017](../safety/hazard-log.md)). Nothing here is claimed as built. The mechanism is implemented later, on this design and on the platform evidence of H0 ([spec 33](../../specs/33-hardware-qualification.md)).

## The gap

Chitala decides; a component carries the decision out. Today the components that carry decisions out also **hold the device's credentials**:
- the matter.js sidecar holds the keys of Chitala's Matter fabric, and is a full controller of every device on it (spec 27);
- the Home Assistant bridge holds an access token, with which it can call services on any device Home Assistant controls (spec 25).

If such a component is compromised, it can act with no Authority, no Safety and no audit. Other paths reach the same devices without passing through Chitala at all:
- Home Assistant's own automations, users and apps;
- a second Matter fabric;
- a vendor's cloud or app.

Chitala's DENY never reaches an action that does not pass through it.

What Chitala has does not close this. It protects other things:

| What exists | What it protects | What it does not |
|---|---|---|
| Signed, session-bound, single-use orders (spec 19); the adapter's order gate | the path **into** a component: no order executes twice or unsigned | what a component does with credentials it already holds |
| The sidecar's typed, allowlisted protocol (spec 27) | what the sidecar's **caller** can make it do | what the sidecar itself can do |
| Native partitioning (N1, [ADR 0002](../adr/0002-production-native-architecture.md)) | the **core's** memory and keys, from an adapter | the **device**, from that adapter |

**Protecting the core's memory is not protecting control of the device.**

## The model

```text
Chitala core ──signed order──▶ adapter (untrusted transport) ──▶ enforcement point ──▶ device
                                                                  holds the credentials
                                                                  verifies every order
                                                                  executes it, at most once
◀──────────────────────────── receipt, signed by the enforcement point ◀──┘
```

- **The adapter forwards.** It is untrusted transport, like N1's relay: it may drop, delay or corrupt, but it holds no authority over the device.
- **The enforcement point verifies and executes.** It is a trusted component, as close to the device as the deployment allows. It holds the device's credentials, and it uses them only to carry out an order it has verified.

Where it can sit, from strongest to weakest:
1. **The device's firmware** verifies Chitala's orders itself. This needs the maker's support.
2. **A hardened gateway** between the network and the device: a Matter controller, a bus master or a PLC gateway.
3. **A credential partition on a Native node.** A partition of its own under seL4 holds the keys and runs the controller stack. The adapter's partition only relays orders to it.

For Matter, the enforcement point is the controller itself. CASE sessions and every command need the fabric's operational key, so whatever holds the key must also run the controller. The sidecar then moves into the trusted side, and the adapter becomes its transport.

For Home Assistant, Home Assistant is the controller, and its own users and automations are peer paths to the devices. Chitala cannot be the only path there. A deployment that relies on Home Assistant cannot close G-8 for those devices; it can declare the peer paths and accept the assurance that follows.

## What the design must answer

1. **Signature.** The enforcement point verifies the boundary's signature on every order, with a key provisioned to it and pinned, not learned from the transport.
2. **Session.** Each order is bound to one session of the enforcement point, as spec 19 binds orders to an executor session today.
3. **No replay across a restart.** The enforcement point must never execute an order twice, including after it restarts.
   - **Either** it keeps the orders it has used in storage that survives a restart, with an anchor that cannot be rolled back;
   - **or** it opens a new session at every start, from its own admitted entropy, so that every order minted for an earlier session is refused.

   The second needs no storage, and is the default.
4. **Expiry.** An order carries a deadline that the enforcement point can judge without trusting the transport's clock. It measures from its own session start on a monotonic clock, or uses a trusted time source. A clock set back must not revive an order (spec 13, N6).
5. **Revocation.**
   - Revocation takes effect at the boundary, before an order is minted.
   - For an order already in flight, the order's short lifetime bounds the window.
   - Where that window is too long, the enforcement point refuses orders older than the latest authority epoch, which the boundary signs and the transport cannot hold back without the enforcement point noticing.
6. **Other control paths.** Each deployment must account for every path to each device it governs:
   - other fabrics and their access-control entries;
   - clouds;
   - apps;
   - automations;
   - local buttons.

   A path that remains is declared, and lowers what the deployment can claim (the assurance levels). Local physical controls, such as a manual override, are part of a device's safety, not a gap.
7. **Key custody is not enough on its own.** Moving the keys into a trusted partition helps only if that partition will not let the adapter use them to issue arbitrary commands. The enforcement point exposes one operation: *execute this verified order*. It never exposes "sign this", "open a session" or "send this command". Otherwise the partition becomes an oracle, and the adapter can use the keys without holding them.
8. **Receipts.** The enforcement point signs each receipt with its own key, bound to the order (spec 19). The receipt is the device side's evidence that the order was carried out, and that it was carried out once.
9. **Failure.** If the enforcement point cannot be reached, an order is *not sent* or its fate is *unknown*, as spec 19 already defines. The enforcement point fails closed: no verified order, no action.
10. **Attestation.** Whether an enforcement point is genuine is a question of attestation, which belongs with gap G-4 (spec 13, R5). Until there is attestation, a deployment states how its enforcement points were provisioned.

## What this does not claim

- **Time.** N1.6 measured an order's path, from the boundary through the channel and the adapter to a verified receipt, and a stop decided through the node. Neither shows that a physical device reaches its safe state in time. A deadline on the device's side belongs to the deadman spec (gap G-5) and to each profile's contract.
- **Safety on the device.** An enforcement point decides nothing about safety. It carries out what Authority and Safety allowed, and refuses anything else. A dangerous device still needs its own safe behaviour when Chitala or the network is gone (Constitution C5).

## Order

This note comes first. Then the spec text, once a first implementation is designed: most likely a credential partition for Matter on Native, after H0 has shown the partitioning on real hardware. Hosted deployments keep the deployment requirements of spec 27 until then, and G-8 stays open.
