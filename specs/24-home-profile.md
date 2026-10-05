# 24 — Home Capability Profile v0.1

Sources: v0.3 roadmap step ① (Project Lead, 2026-10-05); Blueprint A.1 (*Universal Semantic Layer*: AIs and applications understand standard capabilities, not every vendor's API); v19 §8 (a capability declares its outcome); spec 04 (registry), spec 14 (resources), spec 22 (outcome verification). Normative file: [`profiles/home-v0.1.json`](profiles/home-v0.1.json). Code: `chitala-adapters::profile`, outside the Trusted Core.

## Why

v0.3 connects real devices through two independent backends: Home Assistant and Matter. Both must mean the same thing by "the lock is locked", or outcome verification (spec 22) compares the world against the wrong words.

The profile fixes, for the three device classes v0.3 starts with:

- what each one is;
- what it must be able to do;
- what it reports;
- how each backend executes and reports it.

The profile is shared semantics, and a backend is only an implementation of it.

> Home Assistant and Matter execute and observe. They never decide authority (`ROADMAP.md`, v0.3 principles). The profile says how they translate; Chitala's chain decides whether anything happens at all.

## Device classes

| Class | Resource kinds | Requires | May offer | Registry risk | Recommended |
|---|---|---|---|---|---|
| `light` | `light` | `light.turn_on`, `light.turn_off` | `light.set_brightness`, `device.read_state` | low | — |
| `plug` | `switch`, `appliance` | `switch.turn_on`, `switch.turn_off` | `device.read_state` | low | `risk_floor` medium on `switch.turn_on` for plugs that power heat or motors; safe state `switch.turn_off` |
| `lock` | `lock`, `door`, `gate` | `lock.lock`, `lock.unlock` | `device.read_state` | `lock.lock` medium, `lock.unlock` high | safe state `lock.lock` |

A device belongs to the class whose required capabilities it offers in full: a lock must unlock as well as lock.

The recommendations are guidance for a domain's configuration (spec 14, spec 22), not rules: the owners decide their risks.

## Normalised state

| Class | Key | Type | Meaning |
|---|---|---|---|
| light | `on` (**required**) | boolean | the light is on |
| light | `brightness_pct` | integer 0–100 | brightness, when the light reports it |
| plug | `on` (**required**) | boolean | the plug supplies power |
| lock | `locked` | boolean | the bolt is fully thrown; **absent** while the lock moves, is jammed, or cannot tell |
| lock | `moving` | boolean | the lock is locking, unlocking or opening |
| lock | `fault` | text ≤ 32 | why the lock cannot report locked or unlocked: `jammed`, `not_fully_locked` |
| lock | `open` | boolean | the latch is pulled back as well as the bolt |
| lock | `door_open` | boolean | the door itself is open (a door sensor) |

**What cannot be known is left out, never guessed.** This is the rule outcome verification depends on:

- **A lock that is still moving has no `locked` key.** An unlock that is still `unlocking` therefore never verifies early.
- **A lock that is jammed has no `locked` key either.** At its deadline its outcome is `diverged`, and the door goes into recovery (spec 22).
- **An unavailable device is an observation error, not a state.** Home Assistant's `unavailable` and `unknown`, or a Matter attribute that reports `null`, give no state. The outcome is then `unconfirmed`, never a false `diverged`.
- **An unknown value is refused.** A Home Assistant state or a Matter enumeration value the profile does not know is not mapped to anything.

Every state a backend returns for a class must conform: only the class's keys, with their types and ranges, and the required keys present. Outcomes are checked against the profile: every key an action's registry outcome expects (spec 22) is a state key of the class, of the same type.

## Home Assistant

| Class | Domain | Capability → service | State → normalised |
|---|---|---|---|
| light | `light` | `light.turn_on` → `turn_on`; `light.turn_off` → `turn_off`; `light.set_brightness` → `turn_on` with `brightness_pct` (0 turns the light off) | `on` → `on: true`; `off` → `on: false`; attribute `brightness` 0–255 → `brightness_pct` 0–100 |
| plug | `switch` | `switch.turn_on` → `turn_on`; `switch.turn_off` → `turn_off` | `on`, `off` as for lights |
| lock | `lock` | `lock.lock` → `lock`; `lock.unlock` → `unlock` | `locked` → `locked: true`; `unlocked` → `locked: false`; `locking`, `unlocking`, `opening` → `moving: true`; `open` → `locked: false, open: true`; `jammed` → `fault: jammed` |

`unavailable` and `unknown` are observation errors (`X_DEVICE_UNAVAILABLE`) for every class.

The Home Assistant adapter takes its mapping for these three classes from the profile and nowhere else. Climate entities keep a mapping of their own, outside profile v0.1.

## Matter

| Class | Device types | Capability → cluster command | Attribute → normalised |
|---|---|---|---|
| light | On/Off Light `0x0100`, Dimmable Light `0x0101` | On/Off `0x0006`: `On` `0x01`, `Off` `0x00` | On/Off `0x0006`/`OnOff` `0x0000` → `on`; Level Control `0x0008`/`CurrentLevel` `0x0000` 0–254 → `brightness_pct` |
| plug | On/Off Plug-in Unit `0x010A` | On/Off `0x0006`: `On` `0x01`, `Off` `0x00` | `0x0006`/`0x0000` → `on` |
| lock | Door Lock `0x000A` | Door Lock `0x0101`: `LockDoor` `0x00`*, `UnlockDoor` `0x01`* | Door Lock `0x0101`/`LockState` `0x0000`: 0 NotFullyLocked → `fault: not_fully_locked`; 1 Locked → `locked: true`; 2 Unlocked → `locked: false`; 3 Unlatched* → `locked: false, open: true` |

The Matter column is used by the direct Matter adapter (v0.3 step ⑤).

Confirmed against public references on 2026-10-05:

- the cluster ids;
- the On/Off commands and attribute;
- `CurrentLevel`;
- the device types;
- `LockState` values 0–2.

Marked * and `"provisional"` in the profile file: the Door Lock command ids and `LockState` 3 (Unlatched, added in Matter 1.4). They are confirmed or corrected against a Matter controller in step ⑤.

## Format

`profiles/home-v0.1.json`: `profile`, `profile_version`, `status`, `registry` and `classes`. Each class has:

- `class`, `description`, `resource_kinds`;
- `required`, `optional`;
- `state`: key → `type` (`boolean`, `integer`, `text`), `required`, `min`, `max`, `max_len`, `description`;
- `recommended`: `risk_floor`, `safe_state`;
- `home_assistant`: `domain`, `services` (capability → `service`, `data` with literals or `{"param": …}`), `states` (HA state → fragment), `attributes` (attribute → a linear `scale` onto a key);
- `matter`: `device_types`, `commands` (capability → `cluster`, `command`, `provisional`), `attributes` (each a `boolean` key, a `scale`, or `values` per enumeration value; `provisional_values`).

Unknown fields are refused.

The loader (`HomeProfile::from_json`) refuses a profile in which:

- a fragment uses a key the class does not declare, or the wrong type;
- a required capability lacks a Home Assistant service or a Matter command;
- a mapping names a capability the class does not have;
- two classes share a name or a Home Assistant domain.

`HomeProfile::check` then ties the profile to the registry.

## Tests

- `chitala-adapters::profile`:
  - the profile fits the core registry;
  - Home Assistant and Matter normalisation without guessing (moving, jammed, unavailable, null and unknown values);
  - service calls come from the profile;
  - the mock's virtual light, plug and lock report conforming states before and after every required action;
  - a broken profile is refused.
- `chitala-adapters::home_assistant`: the adapter's mapping and normalisation go through the profile. A lock that is `unlocking` reports no `locked`.
- The `ha_state` fuzz target: whatever Home Assistant returns, a state it yields is bounded and, for a profile entity, conforms to its class.

## Not in v0.1

- Other classes: covers, climate, sensors, cameras.
- Colour and colour temperature.
- Lock user codes.
- Door position from the lock's own sensor (Matter `DoorState`).
- Discovery of which entities or endpoints are which class: that is the production Home Assistant adapter (step ②).
