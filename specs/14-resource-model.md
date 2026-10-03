# 14 — Resource Model

Sources: Blueprint v20 "Resource Model", v19 "the physical world under authority"; crate `chitala-resource`.

A **resource** is anything in the physical world a domain governs: a house, a room, a door, a lock, a light, a robot, a vehicle, or a kind nobody has built yet. Principals *act*; resources are *acted upon*. A device is the hardware bound to a resource that executes. An AI always talks about resources ("open the front door"), never about devices.

## One primitive for everything

| Facet | Field | Meaning |
|---|---|---|
| identity | `id` | `resource:<local>`, an `EntityId` of kind `resource`; stable when the thing moves |
| kind | `kind` | `site`, `space`, `door`, `window`, `gate`, `lock`, `light`, `switch`, `climate`, `sensor`, `camera`, `appliance`, `robot`, `vehicle`, or an extension `x-<vendor>.<kind>` |
| ownership | `owners` | the **people** with final authority; empty = inherited from the nearest ancestor that has owners |
| parent/child | `parent` | containment or part-of (site ⊃ room ⊃ door ⊃ lock); a tree |
| location | `zone`, `boundary` → `Location` | derived: site, nearest space, zone label, `interior`/`perimeter` |
| state reference | `state` (`StateRef`) | which device reports the state, and how old that state may be |
| capability binding | `bindings` (`CapabilityBinding`) | which capability is executed by which device, with an optional `risk_floor` |
| safety envelope | `envelope` (`ParamLimit`) | parameter limits tighter than the registry, per resource |

## Graph invariants (checked when the node starts)

1. Unique ids; the parent exists; no cycles; depth ≤ 8; ≤ 10 000 resources.
2. **Every resource has at least one effective owner who is a person** (`Unowned` otherwise): there is always a human with final authority.
3. Owners are `person:*` only.
4. `site` and `space` are containers: no bindings and no state. A capability on a whole room would be a group command, which comes later.
5. Bindings:
   - the capability is in the registry and targets devices;
   - the device is a `device:*` that supports the capability (checked against the node's device list);
   - each capability is bound at most once.
6. A `risk_floor` only **raises** the risk (it must be above the registry risk). Unlocking a front door may be `critical` in one particular house.
7. A resource with bound actions MUST have a `StateRef`: safety must know its state (spec 17, SAFE-3).
8. Envelopes only cover integer parameters of bound capabilities, within the registry's range.

## Rights follow the tree

- A capability token can grant a right on a resource **or on a container**: a right on `resource:living-room` covers everything inside it (`token.authorize` is tried on the resource and then on each ancestor).
- Delegation (`domain.delegate`) with a resource as target has three conditions:
  - the capability must be bound at the target or below it;
  - the holder must be able to use it everywhere the right reaches (possibly with a human's approval);
  - for a root grant, the issuer must be entitled to it everywhere the right reaches.
- Cedar sees a resource as a `Chitala::Resource` entity with all its ancestors as parents, so policies can say `resource in Chitala::Resource::"resource:living-room"` (spec 06).

## Configuration

`resources` in `chitala.json` (see `chitala init`). The sample home:

- `home` (site, owner `person:alice`)
  - `living-room` ⊃ `living-room-light`, `thermostat` (envelope 18–28 °C)
  - `bedroom` ⊃ `fan`
  - `entrance` (zone `entrance`) ⊃ `front-door` (perimeter, bound to `device:front-door`)
