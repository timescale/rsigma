//! ATT&CK tactic extraction from a rule's tags.
//!
//! The risk accumulator's distinct-tactic modifier counts the distinct ATT&CK
//! tactics an entity's contributing detections touch. Tactics are read from the
//! `attack.<tactic>` tags on each firing and normalized to the canonical
//! hyphenated Navigator slug, so `attack.privilege_escalation` (the Sigma spec
//! and pySigma spelling) and `attack.privilege-escalation` (the SigmaHQ corpus
//! spelling) collapse to one tactic.

/// MITRE ATT&CK enterprise tactic slugs, as the ATT&CK Navigator spells them
/// (hyphenated). This mirrors the CLI's `rule_meta` list so the risk layer and
/// the coverage/hygiene reports cannot drift on what counts as a tactic.
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

/// Resolve an `attack.<tactic>` short name to its canonical Navigator slug,
/// accepting both the hyphen and underscore spellings. Unknown short names
/// (techniques, ATT&CK groups/software, custom taxonomies) return `None`.
fn tactic_slug(short: &str) -> Option<&'static str> {
    let normalized = short.replace('_', "-");
    TACTICS.iter().copied().find(|slug| *slug == normalized)
}

/// Extract the distinct canonical ATT&CK tactic slugs named by a rule's tags,
/// in the order they first appear.
pub fn extract(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tag in tags {
        let lower = tag.to_ascii_lowercase();
        let Some(rest) = lower.strip_prefix("attack.") else {
            continue;
        };
        if let Some(slug) = tactic_slug(rest) {
            let slug = slug.to_string();
            if !out.contains(&slug) {
                out.push(slug);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_canonical_slugs() {
        let tags = vec![
            "attack.t1059".to_string(),
            "attack.execution".to_string(),
            "attack.privilege_escalation".to_string(),
            "attack.g0016".to_string(),
        ];
        assert_eq!(
            extract(&tags),
            vec!["execution".to_string(), "privilege-escalation".to_string()]
        );
    }

    #[test]
    fn deduplicates_across_spellings() {
        let tags = vec![
            "attack.privilege-escalation".to_string(),
            "attack.privilege_escalation".to_string(),
        ];
        assert_eq!(extract(&tags), vec!["privilege-escalation".to_string()]);
    }

    #[test]
    fn ignores_non_attack_and_unknown_tags() {
        let tags = vec!["cve.2023.1".to_string(), "attack.stealth".to_string()];
        assert!(extract(&tags).is_empty());
    }
}
