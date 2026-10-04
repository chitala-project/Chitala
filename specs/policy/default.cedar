// Chitala default domain policy v0.1 — spec `specs/06-policy.md`.
//
// The Cedar schema is generated from the Capability Registry (namespace Chitala):
//   principal: Chitala::Person | Chitala::AI | Chitala::Service | Chitala::Device
//   resource : Chitala::Device | Chitala::Domain | Chitala::Resource (spec §14; `in` = the parent/child tree)
//   action   : Chitala::Action::"<capability id>", member of group "risk-low|medium|high|critical"
//   context  : { token_granted: Bool, human_approved: Bool, risk: Long }
//
// Rules: every policy MUST have a unique @id; the ids are written to the audit log as the
// reasons for a decision. forbid always beats permit (Cedar semantics). A policy that errors
// during evaluation turns the whole decision into DENY (E_POLICY_ERROR) — fail closed.

// ───────────────────────── Grants (RBAC/ABAC) ─────────────────────────

@id("owner-all")
permit (principal in Chitala::Role::"owner", action, resource);

@id("admin-domain")
permit (principal in Chitala::Role::"admin", action, resource is Chitala::Domain);

@id("admin-devices-low-medium")
permit (
  principal in Chitala::Role::"admin",
  action in [Chitala::Action::"risk-low", Chitala::Action::"risk-medium"],
  resource is Chitala::Device
);

@id("adult-devices-low-medium")
permit (
  principal in Chitala::Role::"adult",
  action in [Chitala::Action::"risk-low", Chitala::Action::"risk-medium"],
  resource is Chitala::Device
);

// Adults may delegate what they hold (the node checks child ⊆ parent), revoke tokens they
// issued (or everything they hold or issued: domain.revoke_all for themselves), list the
// devices, and see the approvals waiting for them.
// Every person may end and see execution leases (spec 21); the node narrows this to the
// leases they use, approved, or that act for them. Owners and admins see and end all.
@id("person-leases")
permit (
  principal is Chitala::Person,
  action in [Chitala::Action::"domain.lease_revoke", Chitala::Action::"domain.list_leases"],
  resource is Chitala::Domain
);

@id("adult-delegate")
permit (
  principal in Chitala::Role::"adult",
  action in [
    Chitala::Action::"domain.delegate",
    Chitala::Action::"domain.revoke_token",
    Chitala::Action::"domain.revoke_all",
    Chitala::Action::"domain.list_devices",
    Chitala::Action::"domain.list_approvals"
  ],
  resource is Chitala::Domain
);

@id("child-devices-low")
permit (
  principal in Chitala::Role::"child",
  action in Chitala::Action::"risk-low",
  resource is Chitala::Device
);

@id("guest-devices-low")
permit (
  principal in Chitala::Role::"guest",
  action in Chitala::Action::"risk-low",
  resource is Chitala::Device
);

// ───────────── Resource grants (intent path, spec §15–16) ─────────────
// On a Resource, role grants follow the EFFECTIVE risk (context.risk = max(registry risk,
// the binding's risk_floor)), not the static action groups: a resource may raise the risk
// of a capability.

// The owners (effective owners of the resource or an ancestor) hold every right on it.
@id("resource-owner")
permit (principal is Chitala::Person, action, resource is Chitala::Resource)
when { resource.owners.contains(principal) };

@id("admin-resources-low-medium")
permit (principal in Chitala::Role::"admin", action, resource is Chitala::Resource)
when { context.risk <= 1 };

@id("adult-resources-low-medium")
permit (principal in Chitala::Role::"adult", action, resource is Chitala::Resource)
when { context.risk <= 1 };

@id("child-resources-low")
permit (principal in Chitala::Role::"child", action, resource is Chitala::Resource)
when { context.risk == 0 };

@id("guest-resources-low")
permit (principal in Chitala::Role::"guest", action, resource is Chitala::Resource)
when { context.risk == 0 };

// A valid capability token (accepted by the Biscuit authorizer) is a specific grant.
@id("token-grant")
permit (principal, action, resource)
when { context.token_granted };

// ──────────────────── Security Constitution (forbid) ────────────────────

// C12: no AI/Service/Device has default authority to control another entity;
// every action of a non-human principal needs a token.
@id("C12-ai-needs-token")
forbid (principal is Chitala::AI, action, resource)
unless { context.token_granted };

@id("C12-service-needs-token")
forbid (principal is Chitala::Service, action, resource)
unless { context.token_granted };

@id("C12-device-needs-token")
forbid (principal is Chitala::Device, action, resource)
unless { context.token_granted };

// C11: an AI does not modify the protections: it does not delegate, revoke (tokens or
// execution leases), place or lift safety holds, or change security states, and it does
// not look into the humans' approval queue or their leases. A hold stops protective
// actions too (a held door cannot be locked), so placing one is not harmless either.
@id("C11-ai-no-domain-admin")
forbid (
  principal is Chitala::AI,
  action in [
    Chitala::Action::"domain.delegate",
    Chitala::Action::"domain.revoke_token",
    Chitala::Action::"domain.revoke_all",
    Chitala::Action::"domain.safety_hold",
    Chitala::Action::"domain.safety_release",
    Chitala::Action::"domain.lease_revoke",
    Chitala::Action::"domain.list_leases",
    Chitala::Action::"domain.set_principal_state",
    Chitala::Action::"domain.list_approvals"
  ],
  resource
);

// v15 D4 / v8 §10: an AI is never the final authority for a high-risk action. On the intent
// path this turns into ESCALATE: the action proceeds only with an owner's signed approval
// (human_approved). On the direct command path an AI is refused anyway (E_INTENT_REQUIRED).
@id("C11-ai-no-high-risk")
forbid (
  principal is Chitala::AI,
  action in [Chitala::Action::"risk-high", Chitala::Action::"risk-critical"],
  resource
)
unless { context.human_approved };

// v8 §10: critical actions only through a separate approval / a certified controller.
@id("C9-critical-needs-approval")
forbid (principal, action in Chitala::Action::"risk-critical", resource)
unless { context.human_approved };

// v11 §15: children do not perform high-risk actions, not even when delegated.
@id("child-no-high-risk")
forbid (
  principal in Chitala::Role::"child",
  action in [Chitala::Action::"risk-high", Chitala::Action::"risk-critical"],
  resource
);

// v5 §11 / v13 §4: SC0 devices (legacy, unauthenticated command path) take no high-risk
// commands; an SC0 device acting as a principal may only perform low-risk actions.
@id("SC0-no-high-risk-target")
forbid (
  principal,
  action in [Chitala::Action::"risk-high", Chitala::Action::"risk-critical"],
  resource is Chitala::Device
)
when { resource.security_class == 0 };

@id("SC0-no-high-risk-resource")
forbid (principal, action, resource is Chitala::Resource)
when { resource.security_class == 0 && context.risk >= 2 };

// Effective-risk versions of C11/C9/child for Resources: a risk_floor can turn a "medium"
// capability into a "high" one at a specific resource.
@id("C11-ai-no-high-risk-effective")
forbid (principal is Chitala::AI, action, resource is Chitala::Resource)
when { context.risk >= 2 }
unless { context.human_approved };

@id("C9-critical-needs-approval-effective")
forbid (principal, action, resource is Chitala::Resource)
when { context.risk >= 3 }
unless { context.human_approved };

@id("child-no-high-risk-effective")
forbid (principal in Chitala::Role::"child", action, resource is Chitala::Resource)
when { context.risk >= 2 };

@id("SC0-principal-low-only")
forbid (principal is Chitala::Device, action, resource)
when { principal.security_class == 0 }
unless { action in Chitala::Action::"risk-low" };
