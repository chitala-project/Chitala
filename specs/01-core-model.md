# 01 — Core Model

Sources: Blueprint §4 (primitives), v12 §9 (`Device_ID ≠ AI_ID`), v17 §2 (Person_ID, Device_ID, AI_ID, Service_ID, Domain_ID and Resource_ID are different principals/objects).

## Identifiers

### EntityId

```
entity-id = kind ":" local
kind      = "person" / "ai" / "device" / "service" / "domain" / "resource"
local     = [a-z0-9] *127( [a-z0-9] / "." / "_" / "-" )
```

Examples: `person:alice`, `ai:assistant`, `device:living-room-light`, `service:node`, `domain:home`, `resource:front-door`.

- The kinds are **distinct**. A robot is `device:robot-17` and the AIs running on it are `ai:vision-17a`, `ai:nav-17c`, … Each AI is its own principal, with its own key, its own rights, and is contained independently (v12 §9).
- `person`, `ai`, `service` and `device` are **principals**: they can sign requests. `domain` and `resource` are governed objects and never principals. A resource (door, room, robot, vehicle) is acted upon, and the device bound to it executes (spec 14).
- `local` is case-sensitive and only lowercase is accepted, so the same entity has exactly one spelling.
- Identity is **not** based on IP, MAC or serial numbers (v5 §19).

### CapabilityId

```
capability-id = first-segment 1*( "." segment )
first-segment = segment / vendor
segment       = [a-z] *( [a-z0-9_] )
vendor        = "x-" 1*[a-z0-9]
```

At most 128 characters, for example `light.turn_on`, `climate.set_target_temperature`, `x-acme.fan.set_speed`. There are no wildcards (`light.*`): rights are always explicit.

## Primitives in v0.1

| Primitive (Blueprint §4) | v0.1 |
|---|---|
| Entity | `EntityId` + `DeviceDescriptor`; governed things as `Resource` (spec 14) |
| Capability | `CapabilityDef` in the registry (spec 04) |
| Property | the Digital Twin's `reported` state (spec 10) |
| Action | a capability with `kind = action` |
| Event | an `Event` on the bus (spec 10) |
| Actor | a principal (`person`/`ai`/`service`/`device`) |
| Authority | tokens (spec 05) + policy (spec 06) + the Authority Engine (spec 16) |
| Delegation | `domain.delegate` (spec 11) |
| Context | the CSME `context_ref` (opaque, ≤ 128 characters); an intent's `context` (purpose, relayed cause) |
| Trust | `SecurityClass`, `SecurityState` (spec 03) |
| Intent | a signed intent (spec 15) — what an AI produces instead of a command |
| Goal | message type 4 is **reserved** |

## Payload

A v0.1 payload is a flat map `text → (bool | int64 | text)`:

- **No floats.** This avoids ambiguity in canonical encoding and when comparing against a safety envelope. Physical values are integers with the unit in the name (`brightness_pct`, `celsius`).
- **No nesting.** v0.1 does not need it, and it keeps the parser small.
- Parameter names are ≤ 64 characters, with at most 32 parameters. Text is ≤ 4096 bytes on the wire; the registry may set tighter limits.

## DeviceDescriptor (minimal Entity Manifest)

```json
{
  "id": "device:front-door",
  "name": "Front door lock",
  "adapter": "mock",
  "capabilities": ["device.read_state", "lock.lock", "lock.unlock"],
  "security_class": "SC3",
  "room": "entrance"
}
```

This is a subset of the Entity Manifest (§8, Appendix A.4). The Interface, AI, Lifecycle, Attestation and Privacy groups will be added as optional fields. Parsers MUST ignore unknown non-critical fields.
