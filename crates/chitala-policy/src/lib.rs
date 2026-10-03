//! Domain policy (spec `specs/06-policy.md`) and the Authority Engine
//! (spec `specs/16-authority-engine.md`, module [`authority`]).
//!
//! The Cedar schema is generated from the capability registry, so every capability
//! is a Cedar action in exactly one risk group (`Chitala::Action::"risk-high"`...).
//! Policies are validated strictly against that schema at load time; a policy set
//! that does not type-check is rejected instead of silently never matching.
//!
//! Evaluation fails closed: if any policy errors during evaluation the request is
//! denied with an error, because Cedar skips erroring policies — an erroring
//! `forbid` would otherwise turn into an allow.

#![forbid(unsafe_code)]

pub mod authority;

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId as CedarEntityId, EntityTypeName, EntityUid, PolicyId,
    PolicySet, Request, RestrictedExpression, Schema, ValidationMode, Validator,
};
use chitala_model::{
    CapabilityId, CapabilityRegistry, EntityId, EntityKind, RiskClass, SecurityClass, SecurityState, TargetKind,
};
use sha2::{Digest, Sha256};

/// The default policy set shipped with v0.1 (Security Constitution included).
pub const DEFAULT_POLICIES: &str = include_str!("../../../specs/policy/default.cedar");

const PRINCIPAL_TYPES: &str = "Person, AI, Service, Device";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("schema error: {0}")]
    Schema(String),
    #[error("policy parse error: {0}")]
    Parse(String),
    #[error("policy validation failed: {0}")]
    Validation(String),
    #[error("policy {0} has no @id annotation")]
    MissingId(String),
    #[error("duplicate policy @id {0:?}")]
    DuplicateId(String),
    /// → `E_POLICY_ERROR`
    #[error("policy evaluation error: {0}")]
    Evaluation(String),
}

/// Cedar schema (human-readable format) for a capability registry.
pub fn schema_text(registry: &CapabilityRegistry) -> String {
    let mut s = String::new();
    s.push_str("namespace Chitala {\n");
    s.push_str("  entity Role;\n");
    s.push_str("  entity Domain;\n");
    s.push_str("  entity Person in [Role] { state: String };\n");
    s.push_str("  entity AI in [Role] { state: String };\n");
    s.push_str("  entity Service in [Role] { state: String };\n");
    s.push_str("  entity Device in [Role] { state: String, security_class: Long, room: String };\n");
    s.push_str(
        "  entity Resource in [Resource] { kind: String, boundary: String, zone: String, security_class: Long, owners: Set<Person> };\n",
    );
    s.push_str("  type RequestContext = { token_granted: Bool, human_approved: Bool, risk: Long };\n");
    for r in RiskClass::ALL {
        let _ = writeln!(s, "  action \"{}\";", r.cedar_group());
    }
    for def in registry.iter() {
        let resource = match def.target {
            TargetKind::Device => "Device, Resource",
            TargetKind::Domain => "Domain",
        };
        let _ = writeln!(
            s,
            "  action \"{}\" in [\"{}\"] appliesTo {{ principal: [{PRINCIPAL_TYPES}], resource: [{resource}], context: RequestContext }};",
            def.id,
            def.risk.cedar_group()
        );
    }
    s.push_str("}\n");
    s
}

/// Attributes of a device, whether it appears as principal or as resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAttrs {
    pub security_class: SecurityClass,
    pub room: Option<String>,
    pub state: SecurityState,
}

#[derive(Debug, Clone)]
pub struct PrincipalInfo<'a> {
    pub id: &'a EntityId,
    pub roles: &'a [String],
    pub state: SecurityState,
    /// Required for device principals; `None` is treated as an unknown SC0 device.
    pub device: Option<&'a DeviceAttrs>,
}

/// Attributes of a governed resource (spec §14) as Cedar sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAttrs {
    pub kind: String,
    pub boundary: String,
    pub zone: Option<String>,
    /// Security class of the device bound for the requested capability.
    pub security_class: SecurityClass,
    /// Effective owners (persons).
    pub owners: Vec<EntityId>,
    /// Every ancestor resource, so `resource in Chitala::Resource::"…"` holds
    /// for the whole lineage.
    pub ancestors: Vec<EntityId>,
}

#[derive(Debug, Clone)]
pub enum ResourceInfo<'a> {
    Device { id: &'a EntityId, attrs: &'a DeviceAttrs },
    Domain { id: &'a EntityId },
    Resource { id: &'a EntityId, attrs: &'a ResourceAttrs },
}

impl ResourceInfo<'_> {
    pub fn id(&self) -> &EntityId {
        match self {
            ResourceInfo::Device { id, .. } | ResourceInfo::Domain { id } | ResourceInfo::Resource { id, .. } => id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyContext {
    /// The request carried a token that verified and authorized this exact request.
    pub token_granted: bool,
    /// A human approval (A4) is attached. Always `false` in v0.1.
    pub human_approved: bool,
    pub risk: RiskClass,
}

#[derive(Debug, Clone)]
pub struct PolicyRequest<'a> {
    pub principal: PrincipalInfo<'a>,
    pub capability: &'a CapabilityId,
    pub resource: ResourceInfo<'a>,
    pub context: PolicyContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub allowed: bool,
    /// `@id`s of the policies that determined the decision (for a deny: the
    /// matching forbids, empty when nothing permitted).
    pub reasons: Vec<String>,
}

pub struct PolicyEngine {
    schema: Schema,
    policies: PolicySet,
    ids: HashMap<PolicyId, String>,
    fingerprint: String,
    authorizer: Authorizer,
}

fn type_name(name: &str) -> EntityTypeName {
    EntityTypeName::from_str(name).expect("static Cedar type names are valid")
}

fn uid(type_: &str, id: &str) -> EntityUid {
    EntityUid::from_type_name_and_id(type_name(type_), CedarEntityId::new(id))
}

fn kind_type(kind: EntityKind) -> &'static str {
    kind.cedar_type()
}

impl PolicyEngine {
    pub fn new(registry: &CapabilityRegistry, policies_src: &str) -> Result<Self, PolicyError> {
        let (schema, _warnings) =
            Schema::from_cedarschema_str(&schema_text(registry)).map_err(|e| PolicyError::Schema(e.to_string()))?;
        let policies = PolicySet::from_str(policies_src).map_err(|e| PolicyError::Parse(e.to_string()))?;

        let result = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        if !result.validation_passed() {
            let msgs: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
            return Err(PolicyError::Validation(msgs.join("; ")));
        }

        let mut ids = HashMap::new();
        let mut seen = HashSet::new();
        for p in policies.policies() {
            let Some(id) = p.annotation("id").filter(|s| !s.is_empty()) else {
                return Err(PolicyError::MissingId(p.id().to_string()));
            };
            if !seen.insert(id.to_string()) {
                return Err(PolicyError::DuplicateId(id.to_string()));
            }
            ids.insert(p.id().clone(), id.to_string());
        }
        if policies.templates().next().is_some() {
            return Err(PolicyError::Validation("policy templates are not supported in v0.1".into()));
        }

        let fingerprint = hex::encode(&Sha256::digest(policies_src.as_bytes())[..8]);
        Ok(Self { schema, policies, ids, fingerprint, authorizer: Authorizer::new() })
    }

    pub fn with_default_policies(registry: &CapabilityRegistry) -> Result<Self, PolicyError> {
        Self::new(registry, DEFAULT_POLICIES)
    }

    /// Short hash of the policy source; recorded in audit entries.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn policy_ids(&self) -> impl Iterator<Item = &str> {
        self.ids.values().map(String::as_str)
    }

    pub fn evaluate(&self, req: &PolicyRequest<'_>) -> Result<PolicyDecision, PolicyError> {
        let eval = |e: &dyn std::fmt::Display| PolicyError::Evaluation(e.to_string());

        let p = &req.principal;
        let principal_uid = uid(kind_type(p.id.kind()), &p.id.to_string());
        let parents: HashSet<EntityUid> = p.roles.iter().map(|r| uid("Chitala::Role", r)).collect();
        let mut entities: Vec<Entity> =
            p.roles.iter().map(|r| Entity::new_no_attrs(uid("Chitala::Role", r), HashSet::new())).collect();

        let device_attrs = |attrs: &DeviceAttrs, state: SecurityState| {
            HashMap::from([
                ("state".to_string(), RestrictedExpression::new_string(state.label().to_string())),
                ("security_class".to_string(), RestrictedExpression::new_long(attrs.security_class.code() as i64)),
                ("room".to_string(), RestrictedExpression::new_string(attrs.room.clone().unwrap_or_default())),
            ])
        };
        let unknown_device =
            DeviceAttrs { security_class: SecurityClass::Sc0, room: None, state: SecurityState::Trusted };

        let principal_attrs = if p.id.kind() == EntityKind::Device {
            device_attrs(p.device.unwrap_or(&unknown_device), p.state)
        } else {
            HashMap::from([("state".to_string(), RestrictedExpression::new_string(p.state.label().to_string()))])
        };
        entities.push(Entity::new(principal_uid.clone(), principal_attrs, parents).map_err(|e| eval(&e))?);

        let resource_uid = match &req.resource {
            ResourceInfo::Device { id, attrs } => {
                let ruid = uid("Chitala::Device", &id.to_string());
                // a device acting on itself is a single entity
                if ruid != principal_uid {
                    entities.push(
                        Entity::new(ruid.clone(), device_attrs(attrs, attrs.state), HashSet::new())
                            .map_err(|e| eval(&e))?,
                    );
                }
                ruid
            }
            ResourceInfo::Domain { id } => {
                let ruid = uid("Chitala::Domain", &id.to_string());
                entities.push(Entity::new_no_attrs(ruid.clone(), HashSet::new()));
                ruid
            }
            ResourceInfo::Resource { id, attrs } => {
                let ruid = uid("Chitala::Resource", &id.to_string());
                let owners = attrs
                    .owners
                    .iter()
                    .map(|o| RestrictedExpression::new_entity_uid(uid("Chitala::Person", &o.to_string())));
                let a = HashMap::from([
                    ("kind".to_string(), RestrictedExpression::new_string(attrs.kind.clone())),
                    ("boundary".to_string(), RestrictedExpression::new_string(attrs.boundary.clone())),
                    ("zone".to_string(), RestrictedExpression::new_string(attrs.zone.clone().unwrap_or_default())),
                    ("security_class".to_string(), RestrictedExpression::new_long(attrs.security_class.code() as i64)),
                    ("owners".to_string(), RestrictedExpression::new_set(owners)),
                ]);
                // ancestors are listed as direct parents: `in` needs no ancestor entities
                let parents = attrs.ancestors.iter().map(|a| uid("Chitala::Resource", &a.to_string())).collect();
                entities.push(Entity::new(ruid.clone(), a, parents).map_err(|e| eval(&e))?);
                ruid
            }
        };

        let entities = Entities::from_entities(entities, Some(&self.schema)).map_err(|e| eval(&e))?;
        let context = Context::from_pairs([
            ("token_granted".to_string(), RestrictedExpression::new_bool(req.context.token_granted)),
            ("human_approved".to_string(), RestrictedExpression::new_bool(req.context.human_approved)),
            ("risk".to_string(), RestrictedExpression::new_long(req.context.risk.code() as i64)),
        ])
        .map_err(|e| eval(&e))?;
        let request = Request::new(
            principal_uid,
            uid("Chitala::Action", req.capability.as_str()),
            resource_uid,
            context,
            Some(&self.schema),
        )
        .map_err(|e| eval(&e))?;

        let response = self.authorizer.is_authorized(&request, &self.policies, &entities);
        let errors: Vec<String> = response.diagnostics().errors().map(|e| e.to_string()).collect();
        if !errors.is_empty() {
            return Err(PolicyError::Evaluation(errors.join("; ")));
        }
        let mut reasons: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|pid| self.ids.get(pid).cloned().unwrap_or_else(|| pid.to_string()))
            .collect();
        reasons.sort();
        Ok(PolicyDecision { allowed: response.decision() == Decision::Allow, reasons })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> PolicyEngine {
        PolicyEngine::with_default_policies(&CapabilityRegistry::core_v0_1()).unwrap()
    }
    fn id(s: &str) -> EntityId {
        EntityId::parse(s).unwrap()
    }
    fn cap(s: &str) -> CapabilityId {
        CapabilityId::parse(s).unwrap()
    }

    struct Case {
        who: &'static str,
        roles: &'static [&'static str],
        capability: &'static str,
        target: &'static str,
        token: bool,
        sc: SecurityClass,
    }

    fn run(e: &PolicyEngine, c: &Case) -> PolicyDecision {
        let reg = CapabilityRegistry::core_v0_1();
        let capability = cap(c.capability);
        let def = reg.get(&capability).unwrap();
        let roles: Vec<String> = c.roles.iter().map(|r| r.to_string()).collect();
        let pid = id(c.who);
        let tid = id(c.target);
        let attrs =
            DeviceAttrs { security_class: c.sc, room: Some("living-room".into()), state: SecurityState::Trusted };
        let resource = match def.target {
            TargetKind::Device => ResourceInfo::Device { id: &tid, attrs: &attrs },
            TargetKind::Domain => ResourceInfo::Domain { id: &tid },
        };
        e.evaluate(&PolicyRequest {
            principal: PrincipalInfo { id: &pid, roles: &roles, state: SecurityState::Trusted, device: None },
            capability: &capability,
            resource,
            context: PolicyContext { token_granted: c.token, human_approved: false, risk: def.risk },
        })
        .unwrap()
    }

    const LIGHT: &str = "device:living-room-light";
    const DOOR: &str = "device:front-door";
    const HOME: &str = "domain:home";

    #[test]
    fn schema_covers_registry() {
        let reg = CapabilityRegistry::core_v0_1();
        let text = schema_text(&reg);
        for def in reg.iter() {
            assert!(text.contains(&format!("action \"{}\" in [\"{}\"]", def.id, def.risk.cedar_group())));
        }
    }

    #[test]
    fn default_policy_matrix() {
        let e = engine();
        let sc2 = SecurityClass::Sc2;
        let table: &[(Case, bool, &str)] = &[
            // owner can do everything on devices and the domain
            (
                Case {
                    who: "person:alice",
                    roles: &["owner"],
                    capability: "lock.unlock",
                    target: DOOR,
                    token: false,
                    sc: sc2,
                },
                true,
                "owner-all",
            ),
            (
                Case {
                    who: "person:alice",
                    roles: &["owner"],
                    capability: "domain.set_principal_state",
                    target: HOME,
                    token: false,
                    sc: sc2,
                },
                true,
                "owner-all",
            ),
            // adult: low/medium devices, not unlock; can delegate
            (
                Case {
                    who: "person:bob",
                    roles: &["adult"],
                    capability: "climate.set_target_temperature",
                    target: LIGHT,
                    token: false,
                    sc: sc2,
                },
                true,
                "adult-devices-low-medium",
            ),
            (
                Case {
                    who: "person:bob",
                    roles: &["adult"],
                    capability: "lock.unlock",
                    target: DOOR,
                    token: false,
                    sc: sc2,
                },
                false,
                "",
            ),
            (
                Case {
                    who: "person:bob",
                    roles: &["adult"],
                    capability: "domain.delegate",
                    target: HOME,
                    token: false,
                    sc: sc2,
                },
                true,
                "adult-delegate",
            ),
            (
                Case {
                    who: "person:bob",
                    roles: &["adult"],
                    capability: "domain.set_principal_state",
                    target: HOME,
                    token: false,
                    sc: sc2,
                },
                false,
                "",
            ),
            // a guest with a delegated unlock token (v12 §18 "mở cổng 30 phút")
            (
                Case {
                    who: "person:carol",
                    roles: &["guest"],
                    capability: "lock.unlock",
                    target: DOOR,
                    token: true,
                    sc: sc2,
                },
                true,
                "token-grant",
            ),
            // a child never unlocks, even with a token
            (
                Case {
                    who: "person:dan",
                    roles: &["child"],
                    capability: "lock.unlock",
                    target: DOOR,
                    token: true,
                    sc: sc2,
                },
                false,
                "child-no-high-risk",
            ),
            // AI: nothing without a token; low risk with token; never high risk or domain admin
            (
                Case {
                    who: "ai:assistant",
                    roles: &[],
                    capability: "light.turn_on",
                    target: LIGHT,
                    token: false,
                    sc: sc2,
                },
                false,
                "C12-ai-needs-token",
            ),
            (
                Case {
                    who: "ai:assistant",
                    roles: &[],
                    capability: "light.turn_on",
                    target: LIGHT,
                    token: true,
                    sc: sc2,
                },
                true,
                "token-grant",
            ),
            (
                Case { who: "ai:assistant", roles: &[], capability: "lock.unlock", target: DOOR, token: true, sc: sc2 },
                false,
                "C11-ai-no-high-risk",
            ),
            (
                Case {
                    who: "ai:assistant",
                    roles: &[],
                    capability: "domain.delegate",
                    target: HOME,
                    token: true,
                    sc: sc2,
                },
                false,
                "C11-ai-no-domain-admin",
            ),
            // roles held by an AI do not give ambient authority
            (
                Case {
                    who: "ai:assistant",
                    roles: &["adult"],
                    capability: "light.turn_on",
                    target: LIGHT,
                    token: false,
                    sc: sc2,
                },
                false,
                "C12-ai-needs-token",
            ),
            // legacy SC0 device: no high-risk command, even for the owner
            (
                Case {
                    who: "person:alice",
                    roles: &["owner"],
                    capability: "lock.unlock",
                    target: DOOR,
                    token: false,
                    sc: SecurityClass::Sc0,
                },
                false,
                "SC0-no-high-risk-target",
            ),
            // device principals need tokens; unknown devices are treated as SC0
            (
                Case {
                    who: "device:sensor-1",
                    roles: &[],
                    capability: "light.turn_on",
                    target: LIGHT,
                    token: true,
                    sc: sc2,
                },
                true,
                "token-grant",
            ),
            (
                Case {
                    who: "device:sensor-1",
                    roles: &[],
                    capability: "lock.lock",
                    target: DOOR,
                    token: true,
                    sc: sc2,
                },
                false,
                "SC0-principal-low-only",
            ),
            (
                Case {
                    who: "service:automation",
                    roles: &[],
                    capability: "light.turn_on",
                    target: LIGHT,
                    token: false,
                    sc: sc2,
                },
                false,
                "C12-service-needs-token",
            ),
        ];
        for (case, allowed, reason) in table {
            let d = run(&e, case);
            assert_eq!(d.allowed, *allowed, "{} {} {}: {:?}", case.who, case.capability, case.target, d.reasons);
            if !reason.is_empty() {
                assert!(
                    d.reasons.iter().any(|r| r == reason),
                    "{} {}: expected {reason}, got {:?}",
                    case.who,
                    case.capability,
                    d.reasons
                );
            }
        }
    }

    #[test]
    fn rejects_bad_policy_sets() {
        let reg = CapabilityRegistry::core_v0_1();
        // type error: unknown attribute
        let bad = r#"@id("x") permit(principal, action, resource) when { principal.nope == 1 };"#;
        assert!(matches!(PolicyEngine::new(&reg, bad), Err(PolicyError::Validation(_))));
        // unknown action
        let bad = r#"@id("x") permit(principal, action == Chitala::Action::"door.explode", resource);"#;
        assert!(matches!(PolicyEngine::new(&reg, bad), Err(PolicyError::Validation(_))));
        // missing and duplicate ids
        assert!(matches!(
            PolicyEngine::new(&reg, "permit(principal, action, resource);"),
            Err(PolicyError::MissingId(_))
        ));
        let dup = r#"@id("a") permit(principal, action, resource); @id("a") forbid(principal, action, resource);"#;
        assert!(matches!(PolicyEngine::new(&reg, dup), Err(PolicyError::DuplicateId(_))));
        assert!(matches!(PolicyEngine::new(&reg, "permit("), Err(PolicyError::Parse(_))));
    }

    #[test]
    fn fingerprint_tracks_source() {
        let reg = CapabilityRegistry::core_v0_1();
        let a = PolicyEngine::with_default_policies(&reg).unwrap();
        let b = PolicyEngine::new(&reg, &format!("{DEFAULT_POLICIES}\n// changed\n")).unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.fingerprint().len(), 16);
    }
}
