# 04 — Capability Registry

Sources: Appendix A.1–A.2 (Universal Semantic Layer, Capability Registry), v4 §7 (versioning), v4 §17 (against fragmentation).

The registry is the **shared semantics**: AIs, automations and applications only need to understand the standard capabilities, not every vendor's API. The v0.1 core registry lives in [`registry/capabilities-v0.1.json`](registry/capabilities-v0.1.json) and is embedded verbatim in the binary.

## Format

```json
{
  "registry": "chitala-core",
  "registry_version": "0.1.0",
  "status": "provisional",
  "capabilities": [
    {
      "id": "light.set_brightness",
      "version": 1,
      "kind": "action",
      "risk": "low",
      "target": "device",
      "description": "Set the brightness in percent; 0 is equivalent to off.",
      "params": [ { "name": "brightness_pct", "type": "integer", "min": 0, "max": 100, "required": true } ]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `id` | `CapabilityId` (spec 01), unique within the registry |
| `version` | ≥ 1. A breaking change means a new version; the meaning of a released version never changes |
| `kind` | `action` (changes the world; sent as `command` or requested as an intent) or `query` (read-only) |
| `risk` | `RiskClass` (spec 03). A CSME sender MUST declare exactly this risk; anything else → `E_RISK_MISMATCH`. Intents declare no risk: Chitala computes it (spec 16) |
| `target` | `device` (default) or `domain`. Domain administration capabilities go through the same Reference Monitor |
| `params` | `integer {min,max}` · `boolean` · `text {max_len}`; `required` defaults to `true` |

## Safety envelope

The `min/max` bounds of an `integer` parameter **are** its default safety envelope (A.1 "Safety metadata"). A value outside them → `E_SAFETY_ENVELOPE`. A wrong type, a missing or an extra parameter → `E_PAYLOAD_INVALID`.

Validation is strict: undeclared parameters are refused, not ignored, because an extra field may be an attempt to smuggle instructions into the payload (v8 §6).

A resource may set a tighter envelope of its own (spec 14, enforced by `SAFE-5`), and a device can still refuse an allowed command through its own invariants (C5, spec 10).

## Core registry v0.1

| Capability | kind | risk | target |
|---|---|---|---|
| `device.read_state` | query | low | device |
| `light.turn_on`, `light.turn_off` | action | low | device |
| `light.set_brightness` (`brightness_pct` 0–100) | action | low | device |
| `switch.turn_on`, `switch.turn_off` | action | low | device |
| `climate.set_target_temperature` (`celsius` 16–30) | action | medium | device |
| `lock.lock` | action | medium | device |
| `lock.unlock` | action | **high** | device |
| `domain.list_devices` | query | low | domain |
| `domain.list_approvals` | query | low | domain |
| `domain.delegate` | action | medium | domain |
| `domain.revoke_token` | action | medium | domain |
| `domain.set_principal_state` | action | **high** | domain |

`domain.delegate` is only *medium* because delegation cannot amplify authority (C13): anyone can only hand on a subset of what they hold.

## Vendor extensions

The `x-<vendor>.` namespace is reserved for vendors (v4 §17). An extension SHOULD map to a standard capability where one exists. A capability missing from the node's registry → `E_UNKNOWN_CAPABILITY`: the node never "guesses" what an unknown capability means (v4 §19).

## Evolution

- Registry status: `experimental → provisional → stable → deprecated`.
- A deprecated id is never reused with a different meaning.
- Next steps of A.1: units, quality (accuracy/confidence), privacy class and test vectors for every capability.
