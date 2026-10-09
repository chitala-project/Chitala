//! Unified classification scales (spec `specs/03-classification.md`).
//!
//! Blueprint v18 had nine overlapping scales (two different S0–S4, D0–D5 vs R0–R5,
//! C0–C4 vs IFC labels, L1–L6 vs the security state machine...). v0.1 keeps one
//! scale per concept, each with a distinct prefix.

use std::fmt;

use serde::{Deserialize, Serialize};

macro_rules! coded_enum {
    // shown as on the wire
    ($(#[$m:meta])* $name:ident { $($variant:ident = $code:expr, $label:expr;)+ }) => {
        coded_enum!(@wire $(#[$m])* $name { $($variant = $code, $label;)+ });

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.label())
            }
        }
    };
    // shown apart from the wire: `label` stays the serialized form, `display` is what people read
    ($(#[$m:meta])* $name:ident display { $($variant:ident = $code:expr, $label:expr, $display:expr;)+ }) => {
        coded_enum!(@wire $(#[$m])* $name { $($variant = $code, $label;)+ });

        impl $name {
            pub fn display_label(self) -> &'static str {
                match self {
                    $($name::$variant => $display,)+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.display_label())
            }
        }
    };
    (@wire $(#[$m:meta])* $name:ident { $($variant:ident = $code:expr, $label:expr;)+ }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub enum $name {
            $(#[serde(rename = $label)] $variant = $code,)+
        }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant,)+];

            pub fn code(self) -> u8 {
                self as u8
            }

            pub fn from_code(code: u64) -> Option<Self> {
                match code {
                    $(c if c == $code => Some($name::$variant),)+
                    _ => None,
                }
            }

            /// The serialized form, on the wire and in JSON.
            pub fn label(self) -> &'static str {
                match self {
                    $($name::$variant => $label,)+
                }
            }
        }
    };
}

coded_enum! {
    /// Assurance of an entity (replaces v13 S0–S4; v4 "security profiles" became
    /// deployment profiles). SC4 is deferred until after 1.0.
    SecurityClass {
        Sc0 = 0, "SC0";
        Sc1 = 1, "SC1";
        Sc2 = 2, "SC2";
        Sc3 = 3, "SC3";
        Sc4 = 4, "SC4";
    }
}

coded_enum! {
    /// Risk of an action (replaces CSME `safetyClass`, v8 risk levels, capability-budget risk).
    RiskClass {
        Low = 0, "low";
        Medium = 1, "medium";
        High = 2, "high";
        Critical = 3, "critical";
    }
}

coded_enum! {
    /// Autonomy ladder (merges planning D0–D5 and remediation R0–R5). Shown as
    /// `AU0`…`AU5`, apart from the assurance a deployment offers (`A0`–`A3`) and
    /// from an entity's security class (`SC0`…`SC4`). Its serialized form stays
    /// `A0`…`A5`: changing it needs a version, aliases or a migration, and test
    /// vectors (spec 03).
    AutonomyLevel display {
        A0 = 0, "A0", "AU0";
        A1 = 1, "A1", "AU1";
        A2 = 2, "A2", "AU2";
        A3 = 3, "A3", "AU3";
        A4 = 4, "A4", "AU4";
        A5 = 5, "A5", "AU5";
    }
}

coded_enum! {
    /// Data classification (merges IFC labels and storage classes C0–C4).
    DataClass {
        Dc0 = 0, "DC0";
        Dc1 = 1, "DC1";
        Dc2 = 2, "DC2";
        Dc3 = 3, "DC3";
        Dc4 = 4, "DC4";
    }
}

coded_enum! {
    /// Communication criticality (unchanged from v4). Q4 is deferred until after 1.0.
    QosClass {
        Q0 = 0, "Q0";
        Q1 = 1, "Q1";
        Q2 = 2, "Q2";
        Q3 = 3, "Q3";
        Q4 = 4, "Q4";
    }
}

coded_enum! {
    /// Hardware profile (unchanged from v5). `HX` = self-described future hardware.
    HardwareProfile {
        H0 = 0, "H0";
        H1 = 1, "H1";
        H2 = 2, "H2";
        H3 = 3, "H3";
        H4 = 4, "H4";
        H5 = 5, "H5";
        Hx = 255, "HX";
    }
}

coded_enum! {
    /// The single, canonical security state machine of an entity (v11 §16.5 = v13 §11).
    SecurityState {
        Trusted = 0, "TRUSTED";
        Suspicious = 1, "SUSPICIOUS";
        Restricted = 2, "RESTRICTED";
        Quarantined = 3, "QUARANTINED";
        Recovery = 4, "RECOVERY";
        ReAttest = 5, "RE_ATTEST";
    }
}

coded_enum! {
    /// CSME message type (spec §07-csme key 9). Intent and Goal are reserved in v0.1.
    MessageType {
        Command = 1, "command";
        Event = 2, "event";
        Intent = 3, "intent";
        Goal = 4, "goal";
        Query = 5, "query";
        Response = 6, "response";
    }
}

impl RiskClass {
    /// Cedar action group that every action of this risk class belongs to.
    pub fn cedar_group(self) -> &'static str {
        match self {
            RiskClass::Low => "risk-low",
            RiskClass::Medium => "risk-medium",
            RiskClass::High => "risk-high",
            RiskClass::Critical => "risk-critical",
        }
    }

    /// Highest autonomy an AI principal may exercise for an action of this risk
    /// (classification matrix M1). Above this level a human or a certified
    /// controller is the final authority. A higher level is not more freedom
    /// for the AI: at high and critical risk it means a human (`AU4`) or a
    /// special authority (`AU5`) decides. No permission is ever derived from
    /// this number alone.
    pub fn max_ai_autonomy(self) -> AutonomyLevel {
        match self {
            RiskClass::Low => AutonomyLevel::A2,
            RiskClass::Medium => AutonomyLevel::A3,
            RiskClass::High => AutonomyLevel::A4,
            RiskClass::Critical => AutonomyLevel::A5,
        }
    }
}

impl SecurityClass {
    /// Minimum hardware profile for a claimed security class (matrix M2).
    pub fn min_hardware(self) -> HardwareProfile {
        match self {
            SecurityClass::Sc0 | SecurityClass::Sc1 => HardwareProfile::H0,
            SecurityClass::Sc2 => HardwareProfile::H1,
            SecurityClass::Sc3 => HardwareProfile::H2,
            SecurityClass::Sc4 => HardwareProfile::H2,
        }
    }

    /// Whether this class is implemented in the v0.x line.
    pub fn supported_in_v0(self) -> bool {
        self != SecurityClass::Sc4
    }
}

impl SecurityState {
    /// Highest action risk a principal in this state may exercise (matrix M3,
    /// v13 §11): SUSPICIOUS loses high-risk capabilities, RESTRICTED keeps only
    /// low-risk ones, QUARANTINED and the recovery states may not act at all.
    pub fn max_risk(self) -> Option<RiskClass> {
        match self {
            SecurityState::Trusted => Some(RiskClass::Critical),
            SecurityState::Suspicious => Some(RiskClass::Medium),
            SecurityState::Restricted => Some(RiskClass::Low),
            SecurityState::Quarantined | SecurityState::Recovery | SecurityState::ReAttest => None,
        }
    }

    /// Whether a principal in this state may issue requests at all.
    pub fn may_act(self) -> bool {
        self.max_risk().is_some()
    }

    /// Containment ordering: TRUSTED < SUSPICIOUS < RESTRICTED < QUARANTINED.
    /// The recovery states are not on this ladder.
    fn containment_rank(self) -> Option<u8> {
        match self {
            SecurityState::Trusted => Some(0),
            SecurityState::Suspicious => Some(1),
            SecurityState::Restricted => Some(2),
            SecurityState::Quarantined => Some(3),
            SecurityState::Recovery | SecurityState::ReAttest => None,
        }
    }

    /// Allowed transitions of the canonical state machine
    /// `TRUSTED → SUSPICIOUS → RESTRICTED → QUARANTINED → RECOVERY → RE_ATTEST → TRUSTED`:
    /// - escalation to a stricter containment state is always allowed (also skipping steps);
    /// - SUSPICIOUS/RESTRICTED may be cleared back to TRUSTED (false positive, human decision);
    /// - a QUARANTINED principal must go through RECOVERY and RE_ATTEST before it is
    ///   trusted again — a reboot or restore never re-trusts it (v11 §30);
    /// - any state may be escalated to QUARANTINED.
    pub fn can_transition(self, to: SecurityState) -> bool {
        use SecurityState::*;
        if self == to {
            return false;
        }
        match (self.containment_rank(), to.containment_rank()) {
            (Some(a), Some(b)) if b > a => return true,
            _ => {}
        }
        matches!(
            (self, to),
            (Suspicious | Restricted, Trusted)
                | (Quarantined, Recovery)
                | (Recovery, ReAttest)
                | (ReAttest, Trusted)
                | (Recovery | ReAttest, Quarantined)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for r in RiskClass::ALL {
            assert_eq!(RiskClass::from_code(r.code() as u64), Some(*r));
        }
        for s in SecurityState::ALL {
            assert_eq!(SecurityState::from_code(s.code() as u64), Some(*s));
        }
        assert_eq!(MessageType::from_code(0), None);
        assert_eq!(HardwareProfile::from_code(255), Some(HardwareProfile::Hx));
    }

    #[test]
    fn labels_are_distinct_prefixes() {
        assert_eq!(SecurityClass::Sc3.label(), "SC3");
        assert_eq!(DataClass::Dc2.label(), "DC2");
        assert_eq!(AutonomyLevel::A4.label(), "A4");
        assert_eq!(serde_json::to_string(&SecurityState::ReAttest).unwrap(), "\"RE_ATTEST\"");
        assert_eq!(serde_json::from_str::<RiskClass>("\"high\"").unwrap(), RiskClass::High);
    }

    #[test]
    fn security_state_machine() {
        use SecurityState::*;
        assert_eq!(Trusted.max_risk(), Some(RiskClass::Critical));
        assert_eq!(Restricted.max_risk(), Some(RiskClass::Low));
        assert!(!Quarantined.may_act());
        // escalation, including skipping steps
        assert!(Trusted.can_transition(Suspicious));
        assert!(Trusted.can_transition(Quarantined));
        assert!(ReAttest.can_transition(Quarantined));
        // no shortcut out of quarantine
        assert!(!Quarantined.can_transition(Trusted));
        assert!(!Quarantined.can_transition(Restricted));
        assert!(!Recovery.can_transition(Trusted));
        assert!(Quarantined.can_transition(Recovery));
        assert!(Recovery.can_transition(ReAttest));
        assert!(ReAttest.can_transition(Trusted));
        // de-escalation of soft states is a human decision but allowed
        assert!(Restricted.can_transition(Trusted));
        assert!(!Restricted.can_transition(Suspicious));
        assert!(!Trusted.can_transition(Trusted));
    }

    /// Autonomy is shown as `AU`, and serialized as before: the wire and JSON
    /// keep `A0`…`A5`, and an `AU` label is not accepted on the wire.
    #[test]
    fn autonomy_is_shown_apart_from_its_wire_form() {
        for (level, wire, shown) in [(AutonomyLevel::A0, "A0", "AU0"), (AutonomyLevel::A4, "A4", "AU4")] {
            assert_eq!(level.label(), wire);
            assert_eq!(level.display_label(), shown);
            assert_eq!(level.to_string(), shown);
            assert_eq!(serde_json::to_string(&level).unwrap(), format!("\"{wire}\""));
            assert_eq!(serde_json::from_str::<AutonomyLevel>(&format!("\"{wire}\"")).unwrap(), level);
            assert!(serde_json::from_str::<AutonomyLevel>(&format!("\"{shown}\"")).is_err());
        }
        // the other scales are shown as on the wire
        assert_eq!(SecurityClass::Sc3.to_string(), "SC3");
        assert_eq!(RiskClass::High.to_string(), "high");
    }

    #[test]
    fn autonomy_matrix() {
        assert_eq!(RiskClass::Low.max_ai_autonomy(), AutonomyLevel::A2);
        assert_eq!(RiskClass::High.max_ai_autonomy(), AutonomyLevel::A4);
        assert!(RiskClass::Low < RiskClass::Critical);
    }
}
