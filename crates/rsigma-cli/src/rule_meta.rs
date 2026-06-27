//! Shared rule-metadata extraction used by the detection-as-code `rule`
//! commands.
//!
//! `rule coverage` and `rule hygiene` both read ATT&CK technique/tactic tags
//! and the "is this rule tagged at all" signal off a rule's `tags`. Keeping the
//! extraction here means the two commands cannot drift on what "untagged"
//! means: the `untagged_rules` set coverage emits and the untagged signal
//! hygiene flags are computed by the same `classify_tags`.

/// MITRE ATT&CK enterprise tactic slugs, as the ATT&CK Navigator spells them
/// (hyphenated). These are the canonical form the report and layer emit.
const TACTICS: &[&str] = &[
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
];

/// Normalize and validate an ATT&CK technique ID: `T` + 4+ digits with an
/// optional `.` + sub-technique digits. Returns the uppercased ID or `None` if
/// it does not look like a technique.
pub(crate) fn normalize_technique(raw: &str) -> Option<String> {
    let up = raw.trim().to_ascii_uppercase();
    let body = up.strip_prefix('T')?;
    let (num, sub) = match body.split_once('.') {
        Some((n, s)) => (n, Some(s)),
        None => (body, None),
    };
    if num.len() < 4 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if let Some(s) = sub
        && (s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    Some(up)
}

/// The parent technique of a sub-technique (`T1059.001` -> `T1059`), or `None`
/// for a base technique.
pub(crate) fn parent_technique(id: &str) -> Option<&str> {
    id.split_once('.').map(|(parent, _)| parent)
}

/// Resolve an `attack.<tactic>` short name to its canonical Navigator slug.
///
/// Both spellings seen in the wild are accepted: the hyphenated form the
/// SigmaHQ corpus uses (`attack.privilege-escalation`) and the underscore form
/// the Sigma spec and pySigma use (`attack.privilege_escalation`). Unknown
/// short names (custom taxonomies, ATT&CK groups/software) return `None`.
fn tactic_slug(short: &str) -> Option<&'static str> {
    let normalized = short.replace('_', "-");
    TACTICS.iter().copied().find(|slug| *slug == normalized)
}

/// Extract `(techniques, tactic_slugs, has_attack_tag)` from a rule's tags.
pub(crate) fn classify_tags(tags: &[String]) -> (Vec<String>, Vec<String>, bool) {
    let mut techniques = Vec::new();
    let mut tactics = Vec::new();
    let mut has_attack = false;
    for tag in tags {
        let lower = tag.to_ascii_lowercase();
        let Some(rest) = lower.strip_prefix("attack.") else {
            continue;
        };
        has_attack = true;
        // Technique tags are `attack.t<digits>[.<digits>]`.
        if let Some(after_t) = rest.strip_prefix('t')
            && after_t.bytes().next().is_some_and(|b| b.is_ascii_digit())
        {
            if let Some(id) = normalize_technique(&format!("t{after_t}")) {
                techniques.push(id);
            }
            continue;
        }
        if let Some(slug) = tactic_slug(rest) {
            tactics.push(slug.to_string());
        }
        // Other `attack.*` namespaces (groups `g*`, software `s*`, …) count as
        // tagged but contribute no technique/tactic.
    }
    (techniques, tactics, has_attack)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_technique_accepts_and_rejects() {
        assert_eq!(normalize_technique("t1059").as_deref(), Some("T1059"));
        assert_eq!(
            normalize_technique("T1059.001").as_deref(),
            Some("T1059.001")
        );
        assert_eq!(normalize_technique("  t1003 ").as_deref(), Some("T1003"));
        assert_eq!(normalize_technique("TA0001"), None); // tactic id, not technique
        assert_eq!(normalize_technique("1059"), None); // no T prefix
        assert_eq!(normalize_technique("T10"), None); // too few digits
        assert_eq!(normalize_technique("T1059.xy"), None); // non-digit sub
    }

    #[test]
    fn classify_tags_splits_techniques_tactics_and_other() {
        let tags = vec![
            "attack.t1059".to_string(),
            "attack.t1059.001".to_string(),
            "attack.execution".to_string(),
            "attack.g0016".to_string(), // group: tagged but no technique/tactic
            "cve.2023.1234".to_string(),
        ];
        let (techs, tactics, has_attack) = classify_tags(&tags);
        assert_eq!(techs, vec!["T1059".to_string(), "T1059.001".to_string()]);
        assert_eq!(tactics, vec!["execution".to_string()]);
        assert!(has_attack);
    }

    #[test]
    fn classify_tags_accepts_hyphen_and_underscore_tactics() {
        // SigmaHQ uses the hyphenated form; the Sigma spec/pySigma use
        // underscores. Both normalize to the canonical Navigator slug.
        let (_, hyphen, _) = classify_tags(&["attack.privilege-escalation".to_string()]);
        let (_, underscore, _) = classify_tags(&["attack.privilege_escalation".to_string()]);
        assert_eq!(hyphen, vec!["privilege-escalation".to_string()]);
        assert_eq!(underscore, vec!["privilege-escalation".to_string()]);
        // A custom (non-ATT&CK) tactic tag is not mapped.
        let (_, custom, has_attack) = classify_tags(&["attack.stealth".to_string()]);
        assert!(custom.is_empty());
        assert!(has_attack);
    }

    #[test]
    fn no_attack_tag_is_untagged() {
        let (techs, tactics, has_attack) = classify_tags(&["cve.2023.1".to_string()]);
        assert!(techs.is_empty());
        assert!(tactics.is_empty());
        assert!(!has_attack);
    }
}
