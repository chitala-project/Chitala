# 06 — Policy Engine

Sources: v9 "Authority Engine", v11 §15 (several people sharing devices), v13 §1 (Security Constitution), v5 §11 / v13 §4 (legacy devices).

Policies are written in [Cedar](https://www.cedarpolicy.com/), a language with formal semantics that can be analysed and lives apart from the code (v13 §18 "machine-testable invariants"). The Authority Engine (spec 16) uses this engine as one of its questions.

## Schema (generated from the registry)

```cedarschema
namespace Chitala {
  entity Role;
  entity Domain;
  entity Person  in [Role] { state: String };
  entity AI      in [Role] { state: String };
  entity Service in [Role] { state: String };
  entity Device  in [Role] { state: String, security_class: Long, room: String };
  entity Resource in [Resource] { kind: String, boundary: String, zone: String,
                                  security_class: Long, owners: Set<Person> };
  type RequestContext = { token_granted: Bool, human_approved: Bool, risk: Long };
  action "risk-low"; action "risk-medium"; action "risk-high"; action "risk-critical";
  action "light.turn_on" in ["risk-low"] appliesTo {
    principal: [Person, AI, Service, Device], resource: [Device, Resource], context: RequestContext };
  // … one action per capability, in exactly one risk group
}
```

- Entity UIDs use the `EntityId` as is: `Chitala::Person::"person:alice"`.
- `principal in Chitala::Role::"owner"` ⇔ the principal has the role `owner`.
- `context.token_granted`: the request carries a token that passed verification and authorization (spec 05).
- `context.human_approved`: a valid approval from an owner is present (spec 16). The Authority Engine evaluates Cedar with both `false` and `true`. If the result changes, the action needs a human → ESCALATE. Policies express "needs human approval" with `unless { context.human_approved }`.
- `context.risk` on a Resource is the **effective risk** (the registry risk raised by `risk_floor`). Role grants for Resources are based on it (`adult-resources-low-medium`, `guest-resources-low`, …).
- Resources have all their ancestors as parents, so `resource in Chitala::Resource::"resource:living-room"` holds for everything in the room.
  - `security_class` is that of the device bound for the requested capability.
  - `owners` are the effective owners (policy `resource-owner`).

## Loading and evaluation

1. Policies are **validated strictly** against the schema when loaded. Type errors or unknown actions mean the node does not start (`PolicyError::Validation`). A wrong policy must not "silently never match".
2. Every policy MUST have a unique `@id("...")`. The ids appear in the audit log and in denial reasons.
3. Templates are not supported yet.
4. **Fail closed.** Cedar skips policies that error during evaluation, so an erroring `forbid` would turn into an *allow*. Therefore any evaluation error → `E_POLICY_ERROR` (deny).
5. `forbid` always beats `permit`. If no `permit` matches → `E_POLICY_DENIED`.
6. The fingerprint (first 8 bytes of SHA-256 over the policy source) is written into every decision record (`policy_fp`).

## Default policy

See [`policy/default.cedar`](policy/default.cedar). Summary:

| @id | Kind | Content |
|---|---|---|
| `owner-all` | permit | the owner may do everything |
| `admin-domain`, `admin-devices-low-medium` | permit | admins administer the domain and low/medium devices |
| `adult-devices-low-medium`, `adult-delegate` | permit | adults: low/medium devices; delegate/revoke/list devices/list approvals |
| `child-devices-low`, `guest-devices-low` | permit | children, guests: low only |
| `resource-owner` | permit | the effective owners of a resource may do everything on it |
| `admin-…`, `adult-…`, `child-…`, `guest-resources-…` | permit | role grants on Resources by effective risk |
| `token-grant` | permit | a valid token is a specific grant |
| `C12-ai-needs-token`, `C12-service-needs-token`, `C12-device-needs-token` | forbid | no ambient authority for non-human principals |
| `C11-ai-no-domain-admin` | forbid | an AI does not delegate, revoke, change security states or read the approval queue |
| `C11-ai-no-high-risk`, `C11-ai-no-high-risk-effective` | forbid | an AI does high/critical actions only with a human's approval |
| `C9-critical-needs-approval(-effective)` | forbid | critical needs a separate approval |
| `child-no-high-risk(-effective)` | forbid | children do no high/critical actions, even with a token |
| `SC0-no-high-risk-target`, `SC0-no-high-risk-resource`, `SC0-principal-low-only` | forbid | legacy SC0 devices |

A domain can replace the policy with `policy_file` in its config. The rule: `forbid`s may be added; the `C*-` policies must not be removed (spec 00).

## Two independent layers

For the most important attack path of the Blueprint (an AI acting on its own) there are two layers. Every non-human principal without a token is refused (`E_TOKEN_MISSING`), **and** policy `C12-ai-needs-token` forbids the same thing. A bug in one layer does not open up authority.
