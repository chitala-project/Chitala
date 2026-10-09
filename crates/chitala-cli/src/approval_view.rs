//! What a person is shown before they sign an approval (spec 34, P1a).
//!
//! The terms come first, built by Chitala from what the node holds: who asks,
//! for whom, what, every parameter in full, the scope (one action or a lease),
//! the risk, the deadline and the digest the approval signs. The requester's
//! words come after, apart, labelled as theirs and not checked by Chitala.
//! Every string that reaches the screen is escaped: control characters,
//! bidirectional overrides and invisible characters are shown as escapes, so
//! that no text can pass for Chitala's own, or hide part of itself.

use serde_json::Value;

/// The longest requester text shown, in characters.
pub const MAX_SHOWN_CHARS: usize = 500;
/// How many characters of the digest a person types to approve.
pub const CONFIRM_CHARS: usize = 8;

/// Characters that can hide or reorder text: shown as escapes.
fn hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
        )
}

/// `text` as it may be shown: every hidden character escaped, at most
/// `max_chars` characters, and how many more there were.
pub fn sanitize(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let total = text.chars().count();
    for c in text.chars().take(max_chars) {
        if hidden(c) {
            out.push_str(&format!("\\u{{{:04X}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    if total > max_chars {
        out.push_str(&format!(" … [{} more characters]", total - max_chars));
    }
    out
}

fn shown(v: &Value) -> String {
    match v {
        Value::String(s) => format!("\"{}\"", sanitize(s, MAX_SHOWN_CHARS)),
        Value::Null => "—".into(),
        other => sanitize(&other.to_string(), MAX_SHOWN_CHARS),
    }
}

fn field(entry: &Value, key: &str) -> String {
    match &entry[key] {
        Value::String(s) => sanitize(s, MAX_SHOWN_CHARS),
        Value::Null => "?".into(),
        other => sanitize(&other.to_string(), MAX_SHOWN_CHARS),
    }
}

/// The first characters of the digest that a person types to approve.
pub fn confirm_code(digest: &str) -> String {
    digest.chars().take(CONFIRM_CHARS).collect()
}

/// Whether `typed` confirms `digest`: at least [`CONFIRM_CHARS`] characters,
/// all of them the digest's own start.
pub fn confirms(digest: &str, typed: &str) -> bool {
    let typed = typed.trim().to_ascii_lowercase();
    typed.len() >= CONFIRM_CHARS && digest.to_ascii_lowercase().starts_with(&typed)
}

/// The approval as a person reads it before signing. `now_ms` turns the
/// deadline into the time left.
pub fn render(entry: &Value, now_ms: u64) -> String {
    let mut lines = vec!["The terms Chitala will sign for you:".to_string()];
    let mut by = field(entry, "actor");
    let relays: Vec<String> = entry["relayed_from"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| sanitize(r.as_str().unwrap_or("?"), 128))
        .collect();
    if !relays.is_empty() {
        by.push_str(&format!(", relayed by {}", relays.join(", ")));
    }
    lines.push(format!("  requester:  {by}, for {}", field(entry, "on_behalf_of")));
    lines.push(format!("  action:     {} on {}", field(entry, "capability"), field(entry, "resource")));
    match entry["params"].as_object() {
        Some(p) if !p.is_empty() => {
            lines.push("  parameters:".into());
            for (k, v) in p {
                lines.push(format!("    {} = {}", sanitize(k, 128), shown(v)));
            }
        }
        _ => lines.push("  parameters: none".into()),
    }
    match entry["lease"].as_object() {
        Some(lease) => {
            let uses = lease.get("max_uses").and_then(Value::as_u64).unwrap_or(0);
            let minutes = lease.get("duration_ms").and_then(Value::as_u64).unwrap_or(0) / 60_000;
            lines.push(format!("  scope:      a LEASE: up to {uses} uses within {minutes} minutes, each judged again"));
            if let Some(env) = lease.get("envelope").and_then(Value::as_object) {
                for (k, r) in env {
                    lines.push(format!("    {} chosen within {}..{}", sanitize(k, 128), shown(&r[0]), shown(&r[1])));
                }
            }
        }
        None => lines.push("  scope:      this one action, once".into()),
    }
    let approved: Vec<String> = entry["approved_by"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| sanitize(a.as_str().unwrap_or("?"), 128))
        .collect();
    lines.push(format!(
        "  risk:       {}   approvals needed: {}{}",
        field(entry, "risk"),
        field(entry, "quorum"),
        if approved.is_empty() { String::new() } else { format!(" (approved so far: {})", approved.join(", ")) }
    ));
    let reasons: Vec<String> =
        entry["reasons"].as_array().into_iter().flatten().map(|r| sanitize(r.as_str().unwrap_or("?"), 200)).collect();
    if !reasons.is_empty() {
        lines.push(format!("  why asked:  {}", reasons.join("; ")));
    }
    if let Some(deadline) = entry["deadline_ms"].as_u64() {
        lines.push(format!("  answer within {} s", deadline.saturating_sub(now_ms) / 1000));
    }
    let digest = entry["digest"].as_str().unwrap_or("?");
    lines.push(format!("  digest:     {}", sanitize(digest, 64)));
    lines.push(String::new());
    match entry["purpose"].as_str() {
        Some(p) if !p.is_empty() => {
            lines.push(format!("What {} says (its own words, not checked by Chitala):", field(entry, "actor")));
            lines.push(format!("  {}", shown(&Value::String(p.to_string()))));
        }
        _ => lines.push(format!("{} gave no purpose.", field(entry, "actor"))),
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry() -> Value {
        json!({
            "intent": "00".repeat(16),
            "digest": "a1b2c3d4e5f6".to_string() + &"0".repeat(52),
            "actor": "ai:assistant",
            "on_behalf_of": "person:alice",
            "relayed_from": [],
            "resource": "resource:thermostat",
            "capability": "climate.set_target_temperature",
            "params": {"celsius": 22},
            "lease": null,
            "purpose": "it is cold",
            "risk": "high",
            "quorum": 1,
            "approved_by": [],
            "reasons": ["C-high-risk-ai"],
            "deadline_ms": 120_000,
        })
    }

    #[test]
    fn every_term_comes_before_the_requester_s_words() {
        let shown = render(&entry(), 60_000);
        let terms = shown.find("celsius = 22").expect("the parameter, in full");
        let words = shown.find("its own words, not checked by Chitala").expect("the requester's words, labelled");
        assert!(terms < words, "{shown}");
        assert!(shown.contains("this one action, once"), "{shown}");
        assert!(shown.contains("answer within 60 s"), "{shown}");
        assert!(shown.contains("approvals needed: 1"), "{shown}");
    }

    #[test]
    fn a_lease_is_shown_as_a_lease() {
        let mut e = entry();
        e["lease"] = json!({"max_uses": 3, "duration_ms": 3_600_000, "envelope": {"celsius": [20, 24]}});
        let shown = render(&e, 0);
        assert!(shown.contains("a LEASE: up to 3 uses within 60 minutes"), "{shown}");
        assert!(shown.contains("celsius chosen within 20..24"), "{shown}");
        assert!(!shown.contains("this one action"), "{shown}");
    }

    #[test]
    fn text_cannot_hide_or_pass_for_chitala_s() {
        let mut e = entry();
        // a right-to-left override, a newline that fakes a line of terms, an invisible space
        e["purpose"] = json!("ok\u{202E}evorppa\n  risk:       low\u{200B}");
        e["params"] = json!({"label": "a\u{0007}b"});
        let shown = render(&e, 0);
        assert!(shown.contains("\\u{202E}") && shown.contains("\\u{000A}") && shown.contains("\\u{200B}"), "{shown}");
        assert!(shown.contains("label = \"a\\u{0007}b\""), "{shown}");
        assert!(!shown.contains('\u{202E}') && !shown.contains('\u{200B}'), "{shown}");
        // the fake line of terms stays inside the requester's quoted words
        assert_eq!(shown.lines().filter(|l| l.starts_with("  risk:")).count(), 1, "{shown}");
    }

    #[test]
    fn long_text_says_how_much_was_left_out() {
        let s = sanitize(&"x".repeat(MAX_SHOWN_CHARS + 7), MAX_SHOWN_CHARS);
        assert!(s.ends_with("… [7 more characters]"), "{s}");
    }

    #[test]
    fn only_the_digest_s_own_start_confirms() {
        let digest = "a1b2c3d4e5f6";
        assert_eq!(confirm_code(digest), "a1b2c3d4");
        assert!(confirms(digest, "a1b2c3d4"));
        assert!(confirms(digest, " A1B2C3D4E5 "));
        assert!(!confirms(digest, "a1b2c3"), "too short");
        assert!(!confirms(digest, "a1b2c3d5"), "another digest");
        assert!(!confirms(digest, "yes"));
    }
}
