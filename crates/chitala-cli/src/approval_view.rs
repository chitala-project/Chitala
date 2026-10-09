//! What a person is shown before they sign an approval (spec 34, P1a).
//!
//! The terms come first, built from what the node holds: who asks, for whom,
//! what, every parameter, the scope (one action or a lease, with its exact
//! duration), the risk, the deadline and the digest the approval signs. Terms
//! are shown in full, never cut. A term too long to show here makes the view
//! incomplete, and an incomplete view cannot be approved. The requester's
//! words come after, apart, labelled as theirs and not checked by Chitala; only
//! they are shortened.
//!
//! Characters from a fixed list are shown as escapes, everywhere: Unicode
//! control characters, bidirectional marks and overrides, zero-width and
//! joining characters, separators of lines and paragraphs, the byte order mark
//! and a few invisible fillers. That list is not every character that could
//! mislead a reader: look-alike letters, for one, are shown as they are.
//!
//! A confirmation (the digest's first characters) stops signing by mistake.
//! It does not show that a person read or understood the terms: a script can
//! pass it.

use serde_json::Value;

/// The longest requester text shown, in characters. Only the requester's own
/// words are shortened; terms never are.
pub const MAX_WORDS_CHARS: usize = 500;
/// The longest term this view shows. A longer one makes the view incomplete,
/// and it cannot be approved from here.
pub const MAX_TERM_CHARS: usize = 4_096;
/// How many characters of the digest a person types to approve.
pub const CONFIRM_CHARS: usize = 8;

/// The fixed list of characters shown as escapes.
fn hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{3164}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF9}'..='\u{FFFB}'
        )
}

/// `text` with every character of the fixed list escaped.
pub fn escape(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if hidden(c) {
            out.push_str(&format!("\\u{{{:04X}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// The requester's words: escaped, at most `max_chars` characters, and how
/// many more there were.
pub fn words(text: &str, max_chars: usize) -> String {
    let total = text.chars().count();
    let mut out = escape(&text.chars().take(max_chars).collect::<String>());
    if total > max_chars {
        out.push_str(&format!(" … [{} more characters]", total - max_chars));
    }
    out
}

/// What the view shows, and whether it shows every term in full.
pub struct View {
    pub text: String,
    /// Every term is shown in full. When it is not, approving is refused.
    pub complete: bool,
}

/// Terms are shown in full, or not at all.
struct Terms {
    complete: bool,
}

impl Terms {
    fn show(&mut self, s: &str) -> String {
        if s.chars().count() > MAX_TERM_CHARS {
            self.complete = false;
            return format!("[a term of {} characters, too long to show here]", s.chars().count());
        }
        escape(s)
    }

    fn value(&mut self, v: &Value) -> String {
        match v {
            Value::String(s) => format!("\"{}\"", self.show(s)),
            Value::Null => "—".into(),
            other => self.show(&other.to_string()),
        }
    }

    fn field(&mut self, entry: &Value, key: &str) -> String {
        match &entry[key] {
            Value::String(s) => self.show(s),
            Value::Null => "?".into(),
            other => self.show(&other.to_string()),
        }
    }
}

/// A duration exactly as it is granted: whole minutes when it is whole
/// minutes, otherwise minutes and seconds with the milliseconds besides.
pub fn exact_duration(ms: u64) -> String {
    if ms.is_multiple_of(60_000) {
        return format!("{} minutes", ms / 60_000);
    }
    let (min, rest) = (ms / 60_000, ms % 60_000);
    let secs = if rest.is_multiple_of(1_000) {
        format!("{} s", rest / 1_000)
    } else {
        format!("{}.{:03} s", rest / 1_000, rest % 1_000)
    };
    format!("{min} min {secs} ({ms} ms)")
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

/// Whether an answer may be signed. A rejection always may. An approval needs
/// a complete view, and the digest's first characters.
pub fn check_confirmation(reject: bool, view: &View, digest: &str, typed: Option<&str>) -> Result<(), String> {
    if reject {
        return Ok(());
    }
    if !view.complete {
        return Err("a term cannot be shown in full here, so it cannot be approved here: nothing was signed".into());
    }
    let Some(typed) = typed else {
        return Err(format!(
            "approving needs a confirmation: read the terms above, then pass --confirm {}",
            confirm_code(digest)
        ));
    };
    if !confirms(digest, typed) {
        return Err("not confirmed: nothing was signed".into());
    }
    Ok(())
}

/// The approval as a person reads it before signing. `now_ms` turns the
/// deadline into the time left.
pub fn render(entry: &Value, now_ms: u64) -> View {
    let mut t = Terms { complete: true };
    let mut lines = vec!["The terms Chitala will sign for you:".to_string()];
    let mut by = t.field(entry, "actor");
    let relays: Vec<String> = entry["relayed_from"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| t.value(r).trim_matches('"').to_string())
        .collect();
    if !relays.is_empty() {
        by.push_str(&format!(", relayed by {}", relays.join(", ")));
    }
    lines.push(format!("  requester:  {by}, for {}", t.field(entry, "on_behalf_of")));
    lines.push(format!("  action:     {} on {}", t.field(entry, "capability"), t.field(entry, "resource")));
    match entry["params"].as_object() {
        Some(p) if !p.is_empty() => {
            lines.push("  parameters:".into());
            for (k, v) in p {
                lines.push(format!("    {} = {}", t.show(k), t.value(v)));
            }
        }
        _ => lines.push("  parameters: none".into()),
    }
    match entry["lease"].as_object() {
        Some(lease) => {
            let uses = lease.get("max_uses").and_then(Value::as_u64).unwrap_or(0);
            let duration = exact_duration(lease.get("duration_ms").and_then(Value::as_u64).unwrap_or(0));
            lines.push(format!("  scope:      a LEASE: up to {uses} uses within {duration}, each judged again"));
            if let Some(env) = lease.get("envelope").and_then(Value::as_object) {
                for (k, r) in env {
                    lines.push(format!("    {} chosen within {}..{}", t.show(k), t.value(&r[0]), t.value(&r[1])));
                }
            }
        }
        None => lines.push("  scope:      this one action, once".into()),
    }
    let approved: Vec<String> = entry["approved_by"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| t.value(a).trim_matches('"').to_string())
        .collect();
    lines.push(format!(
        "  risk:       {}   approvals needed: {}{}",
        t.field(entry, "risk"),
        t.field(entry, "quorum"),
        if approved.is_empty() { String::new() } else { format!(" (approved so far: {})", approved.join(", ")) }
    ));
    let reasons: Vec<String> =
        entry["reasons"].as_array().into_iter().flatten().map(|r| t.value(r).trim_matches('"').to_string()).collect();
    if !reasons.is_empty() {
        lines.push(format!("  why asked:  {}", reasons.join("; ")));
    }
    if let Some(deadline) = entry["deadline_ms"].as_u64() {
        lines.push(format!("  answer within {} s", deadline.saturating_sub(now_ms) / 1000));
    }
    lines.push(format!("  digest:     {}", t.field(entry, "digest")));
    if !t.complete {
        lines.push("  ! a term is too long to show here: this cannot be approved from this client".into());
    }
    lines.push(String::new());
    let actor = escape(entry["actor"].as_str().unwrap_or("?"));
    match entry["purpose"].as_str() {
        Some(p) if !p.is_empty() => {
            lines.push(format!("What {actor} says (its own words, not checked by Chitala):"));
            lines.push(format!("  \"{}\"", words(p, MAX_WORDS_CHARS)));
        }
        _ => lines.push(format!("{actor} gave no purpose.")),
    }
    View { text: lines.join("\n"), complete: t.complete }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DIGEST: &str = "a1b2c3d4e5f60000000000000000000000000000000000000000000000000000";

    fn entry() -> Value {
        json!({
            "intent": "00".repeat(16),
            "digest": DIGEST,
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
        let v = render(&entry(), 60_000);
        let terms = v.text.find("celsius = 22").expect("the parameter, in full");
        let words = v.text.find("its own words, not checked by Chitala").expect("the requester's words, labelled");
        assert!(terms < words, "{}", v.text);
        assert!(v.text.contains("this one action, once"), "{}", v.text);
        assert!(v.text.contains("answer within 60 s"), "{}", v.text);
        assert!(v.text.contains("approvals needed: 1"), "{}", v.text);
        assert!(v.text.contains(DIGEST), "the whole digest: {}", v.text);
        assert!(v.complete);
    }

    #[test]
    fn a_lease_is_shown_as_a_lease_with_its_exact_duration() {
        let mut e = entry();
        e["lease"] = json!({"max_uses": 3, "duration_ms": 3_600_000, "envelope": {"celsius": [20, 24]}});
        let v = render(&e, 0);
        assert!(v.text.contains("a LEASE: up to 3 uses within 60 minutes"), "{}", v.text);
        assert!(v.text.contains("celsius chosen within 20..24"), "{}", v.text);
        assert!(!v.text.contains("this one action"), "{}", v.text);
        // a duration that is not whole minutes is never rounded down
        e["lease"]["duration_ms"] = json!(119_000);
        let v = render(&e, 0);
        assert!(v.text.contains("within 1 min 59 s (119000 ms)"), "{}", v.text);
        e["lease"]["duration_ms"] = json!(119_500);
        assert!(render(&e, 0).text.contains("within 1 min 59.500 s (119500 ms)"));
    }

    #[test]
    fn a_long_parameter_is_shown_whole_and_only_the_words_are_shortened() {
        let mut e = entry();
        let long = format!("{}END", "x".repeat(1_000));
        e["params"] = json!({"label": long});
        e["purpose"] = json!(format!("{}TAIL", "y".repeat(MAX_WORDS_CHARS)));
        let v = render(&e, 0);
        assert!(v.text.contains("END\""), "the whole parameter: {}", &v.text[..200]);
        assert!(!v.text.contains("TAIL"), "the words are shortened");
        assert!(v.text.contains("[4 more characters]"));
        assert!(v.complete);
    }

    #[test]
    fn a_term_too_long_to_show_cannot_be_approved_here() {
        let mut e = entry();
        e["params"] = json!({"label": "x".repeat(MAX_TERM_CHARS + 1)});
        let v = render(&e, 0);
        assert!(!v.complete);
        assert!(v.text.contains("too long to show here"), "{}", v.text);
        let err = check_confirmation(false, &v, DIGEST, Some(&confirm_code(DIGEST))).unwrap_err();
        assert!(err.contains("cannot be approved here"), "{err}");
        assert!(check_confirmation(true, &v, DIGEST, None).is_ok(), "rejecting is always possible");
    }

    #[test]
    fn text_cannot_hide_or_pass_for_chitala_s() {
        let mut e = entry();
        // a right-to-left override, a newline that fakes a line of terms, an invisible space
        e["purpose"] = json!("ok\u{202E}evorppa\n  risk:       low\u{200B}");
        e["params"] = json!({"label": "a\u{0007}b\u{2028}c"});
        let v = render(&e, 0);
        for escaped in ["\\u{202E}", "\\u{000A}", "\\u{200B}", "\\u{0007}", "\\u{2028}"] {
            assert!(v.text.contains(escaped), "{escaped}: {}", v.text);
        }
        assert!(!v.text.contains('\u{202E}') && !v.text.contains('\u{200B}'), "{}", v.text);
        // the fake line of terms stays inside the requester's quoted words
        assert_eq!(v.text.lines().filter(|l| l.starts_with("  risk:")).count(), 1, "{}", v.text);
    }

    #[test]
    fn long_words_say_how_much_was_left_out() {
        let s = words(&"x".repeat(MAX_WORDS_CHARS + 7), MAX_WORDS_CHARS);
        assert!(s.ends_with("… [7 more characters]"), "{s}");
    }

    #[test]
    fn only_the_digest_s_own_start_confirms() {
        assert_eq!(confirm_code(DIGEST), "a1b2c3d4");
        assert!(confirms(DIGEST, "a1b2c3d4"));
        assert!(confirms(DIGEST, " A1B2C3D4E5 "));
        assert!(!confirms(DIGEST, "a1b2c3"), "too short");
        assert!(!confirms(DIGEST, "a1b2c3d5"), "another digest");
        assert!(!confirms(DIGEST, "yes"));
    }

    #[test]
    fn nothing_is_signed_without_a_confirmation() {
        let v = render(&entry(), 0);
        let err = check_confirmation(false, &v, DIGEST, None).unwrap_err();
        assert!(err.contains("--confirm a1b2c3d4"), "{err}");
        assert!(check_confirmation(false, &v, DIGEST, Some("deadbeef")).is_err());
        assert!(check_confirmation(false, &v, DIGEST, Some("a1b2c3d4")).is_ok());
        assert!(check_confirmation(true, &v, DIGEST, None).is_ok(), "a rejection needs none");
    }
}
