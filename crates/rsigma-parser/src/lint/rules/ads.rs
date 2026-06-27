//! ADS (Alerting and Detection Strategy) presence checks.
//!
//! These checks run on detection rules only, and only when an `ads:` block is
//! configured (see [`AdsConfig`](super::super::AdsConfig)). For a rule whose
//! `status` is in the configured enforce set, each required ADS section that is
//! absent produces an `ads_missing_*` finding pointed at its carrier field; a
//! present-but-blank `rsigma.ads.*` section produces `ads_empty_section`; and
//! an unrecognised `rsigma.ads.*` key produces `ads_unknown_section` with a safe
//! rename fix to the nearest known section. A per-rule `rsigma.ads.exempt: true`
//! opts the rule out entirely.

use yaml_serde::Value;

use crate::ads::{ADS_PREFIX, AdsCarrier, AdsSection, EXEMPT_KEY};

use super::super::{
    AdsConfig, FixPatch, LintRule, LintWarning, Severity, TYPO_MAX_EDIT_DISTANCE, closest_match,
    get_seq, get_str, key, safe_fix, warn,
};

/// Minimum non-whitespace length for a `rsigma.ads.*` section to count as
/// filled in (mirrors the `falsepositive_too_short` threshold).
const MIN_SECTION_LEN: usize = 2;

pub(crate) fn lint_ads(
    m: &yaml_serde::Mapping,
    config: &AdsConfig,
    extra_namespaces: &[String],
    warnings: &mut Vec<LintWarning>,
) {
    // Gate on status: ADS enforcement applies only to rules whose status is in
    // the configured enforce set.
    if !config.enforces_status(get_str(m, "status")) {
        return;
    }

    // Per-rule opt-out for intentionally undocumented rules.
    if matches!(ads_attr(m, EXEMPT_KEY), Some(v) if v.as_bool() == Some(true)) {
        return;
    }

    // ── missing required sections ────────────────────────────────────────
    for &section in AdsSection::all() {
        if !config.requires(section.id()) {
            continue;
        }
        if section_present(m, section, extra_namespaces) {
            continue;
        }
        let severity = config
            .severity
            .unwrap_or_else(|| default_missing_severity(section));
        warnings.push(warn(
            missing_rule(section),
            severity,
            format!(
                "rule is missing the ADS {} section (carried by '{}')",
                section.id(),
                section.carrier_field()
            ),
            missing_path(section),
        ));
    }

    // ── empty and unknown rsigma.ads.* keys ──────────────────────────────
    check_ads_keys(m, config, warnings);
}

/// Whether the section's content is present on the raw rule mapping.
fn section_present(
    m: &yaml_serde::Mapping,
    section: AdsSection,
    extra_namespaces: &[String],
) -> bool {
    match section {
        AdsSection::Goal => get_str(m, "description").is_some_and(|s| !s.trim().is_empty()),
        AdsSection::Categorization => has_categorization(m, extra_namespaces),
        AdsSection::FalsePositives => get_seq(m, "falsepositives").is_some_and(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str())
                .any(|s| !s.trim().is_empty())
        }),
        // Custom-attribute sections: present iff the key exists at all. A
        // present-but-blank value is left to the empty-section check.
        other => ads_attr(m, other.carrier_field()).is_some(),
    }
}

/// Whether the rule carries an ATT&CK categorization: an `attack.*` tag, or a
/// tag in any configured extra namespace.
fn has_categorization(m: &yaml_serde::Mapping, extra_namespaces: &[String]) -> bool {
    let Some(tags) = get_seq(m, "tags") else {
        return false;
    };
    tags.iter()
        .filter_map(|t| t.as_str())
        .filter_map(|t| t.split('.').next())
        .any(|ns| ns == "attack" || extra_namespaces.iter().any(|e| e == ns))
}

/// Flag present-but-blank known sections (`ads_empty_section`) and unknown
/// `rsigma.ads.*` keys (`ads_unknown_section`).
fn check_ads_keys(m: &yaml_serde::Mapping, config: &AdsConfig, warnings: &mut Vec<LintWarning>) {
    let mut seen: Vec<String> = Vec::new();
    for (key_str, value, path) in ads_keys(m) {
        if key_str == EXEMPT_KEY || !seen_first(&mut seen, &key_str) {
            continue;
        }
        match section_for_carrier(&key_str) {
            Some(section) => {
                if value_text_len(value) < MIN_SECTION_LEN {
                    let severity = config.severity.unwrap_or(Severity::Info);
                    warnings.push(warn(
                        LintRule::AdsEmptySection,
                        severity,
                        format!(
                            "ADS {} section ('{key_str}') is present but empty or too short",
                            section.id()
                        ),
                        path,
                    ));
                }
            }
            None => {
                let severity = config.severity.unwrap_or(Severity::Info);
                let w = if let Some(closest) = closest_ads_carrier(&key_str) {
                    let mut w = warn(
                        LintRule::AdsUnknownSection,
                        severity,
                        format!("unknown ADS section '{key_str}'; did you mean '{closest}'?"),
                        path.clone(),
                    );
                    w.fix = safe_fix(
                        format!("rename '{key_str}' to '{closest}'"),
                        vec![FixPatch::ReplaceKey {
                            path,
                            new_key: closest.to_string(),
                        }],
                    );
                    w
                } else {
                    warn(
                        LintRule::AdsUnknownSection,
                        severity,
                        format!("unknown ADS section '{key_str}'"),
                        path,
                    )
                };
                warnings.push(w);
            }
        }
    }
}

/// Record `key_str` as seen, returning `true` the first time it appears so a
/// key written in both `custom_attributes:` and at the top level is flagged once.
fn seen_first(seen: &mut Vec<String>, key_str: &str) -> bool {
    if seen.iter().any(|s| s == key_str) {
        false
    } else {
        seen.push(key_str.to_string());
        true
    }
}

/// Every `rsigma.ads.*` key on the rule, from both the nested
/// `custom_attributes:` map and top-level flat dotted keys, with its JSON-pointer
/// path.
fn ads_keys(m: &yaml_serde::Mapping) -> Vec<(String, &Value, String)> {
    let mut out = Vec::new();
    if let Some(ca) = m.get(key("custom_attributes")).and_then(|v| v.as_mapping()) {
        for (k, v) in ca {
            if let Some(ks) = k.as_str()
                && ks.starts_with(ADS_PREFIX)
            {
                out.push((ks.to_string(), v, format!("/custom_attributes/{ks}")));
            }
        }
    }
    for (k, v) in m {
        if let Some(ks) = k.as_str()
            && ks.starts_with(ADS_PREFIX)
        {
            out.push((ks.to_string(), v, format!("/{ks}")));
        }
    }
    out
}

/// Look up a `rsigma.ads.*` attribute, checking both the nested
/// `custom_attributes:` map and a top-level flat dotted key.
fn ads_attr<'a>(m: &'a yaml_serde::Mapping, dotted: &str) -> Option<&'a Value> {
    if let Some(ca) = m.get(key("custom_attributes")).and_then(|v| v.as_mapping()) {
        for (k, v) in ca {
            if k.as_str() == Some(dotted) {
                return Some(v);
            }
        }
    }
    for (k, v) in m {
        if k.as_str() == Some(dotted) {
            return Some(v);
        }
    }
    None
}

/// Total non-whitespace text length carried by a value (a scalar's trimmed
/// length, or the summed lengths of a sequence's scalar items).
fn value_text_len(v: &Value) -> usize {
    match v {
        Value::String(s) => s.trim().chars().count(),
        Value::Bool(_) | Value::Number(_) => 1,
        Value::Sequence(seq) => seq.iter().map(value_text_len).sum(),
        _ => 0,
    }
}

/// The ADS section whose carrier is this custom-attribute key, if any.
fn section_for_carrier(key_str: &str) -> Option<AdsSection> {
    AdsSection::all()
        .iter()
        .copied()
        .find(|s| matches!(s.carrier(), AdsCarrier::CustomAttribute(k) if k == key_str))
}

/// The nearest known custom-attribute carrier within the typo edit distance.
fn closest_ads_carrier(key_str: &str) -> Option<&'static str> {
    let candidates: Vec<&str> = AdsSection::all()
        .iter()
        .filter_map(|s| match s.carrier() {
            AdsCarrier::CustomAttribute(k) => Some(k),
            AdsCarrier::StandardField(_) => None,
        })
        .collect();
    closest_match(key_str, &candidates, TYPO_MAX_EDIT_DISTANCE)
}

/// The `ads_missing_*` rule for a section.
fn missing_rule(section: AdsSection) -> LintRule {
    match section {
        AdsSection::Goal => LintRule::AdsMissingGoal,
        AdsSection::Categorization => LintRule::AdsMissingCategorization,
        AdsSection::Strategy => LintRule::AdsMissingStrategy,
        AdsSection::TechnicalContext => LintRule::AdsMissingTechnicalContext,
        AdsSection::BlindSpots => LintRule::AdsMissingBlindSpots,
        AdsSection::FalsePositives => LintRule::AdsMissingFalsePositives,
        AdsSection::Validation => LintRule::AdsMissingValidation,
        AdsSection::Priority => LintRule::AdsMissingPriority,
        AdsSection::Response => LintRule::AdsMissingResponse,
    }
}

/// The default severity for a section's missing check (matches the catalogue).
fn default_missing_severity(section: AdsSection) -> Severity {
    match section {
        AdsSection::Priority => Severity::Info,
        _ => Severity::Warning,
    }
}

/// The JSON-pointer path a missing-section finding points at.
fn missing_path(section: AdsSection) -> String {
    match section.carrier() {
        AdsCarrier::StandardField(field) => format!("/{field}"),
        AdsCarrier::CustomAttribute(k) => format!("/custom_attributes/{k}"),
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{
        AdsConfig, LintRule, LintWarning, Severity, lint_yaml_str_with_config,
    };

    fn ads_config() -> AdsConfig {
        AdsConfig::default()
    }

    fn lint_with_ads(yaml: &str, config: AdsConfig) -> Vec<LintWarning> {
        let cfg = super::super::super::LintConfig {
            ads: Some(config),
            ..Default::default()
        };
        lint_yaml_str_with_config(yaml, &cfg)
    }

    fn has_rule(w: &[LintWarning], rule: LintRule) -> bool {
        w.iter().any(|x| x.rule == rule)
    }

    const BARE_STABLE: &str = r#"
title: Bare stable rule
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"#;

    const FULL_STABLE: &str = r#"
title: Whoami execution
description: Detects whoami execution, a common discovery step.
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: medium
falsepositives:
    - Legitimate administrators enumerating privileges
tags:
    - attack.execution
    - attack.t1059
custom_attributes:
    rsigma.ads.strategy: Watch for the whoami binary in process creation events.
    rsigma.ads.technical_context: Requires process_creation telemetry with CommandLine.
    rsigma.ads.blind_spots:
        - Renamed whoami binaries evade the image match.
    rsigma.ads.validation: Run `whoami` in a lab and confirm the rule fires.
    rsigma.ads.priority: Medium because discovery is mid-kill-chain.
    rsigma.ads.response:
        - Confirm the user and host.
"#;

    #[test]
    fn bare_stable_rule_flags_every_missing_section() {
        let w = lint_with_ads(BARE_STABLE, ads_config());
        for rule in [
            LintRule::AdsMissingGoal,
            LintRule::AdsMissingCategorization,
            LintRule::AdsMissingStrategy,
            LintRule::AdsMissingTechnicalContext,
            LintRule::AdsMissingBlindSpots,
            LintRule::AdsMissingFalsePositives,
            LintRule::AdsMissingValidation,
            LintRule::AdsMissingPriority,
            LintRule::AdsMissingResponse,
        ] {
            assert!(has_rule(&w, rule), "expected {rule}");
        }
    }

    #[test]
    fn fully_documented_rule_has_no_ads_findings() {
        let w = lint_with_ads(FULL_STABLE, ads_config());
        assert!(
            !w.iter().any(|x| x.rule.to_string().starts_with("ads_")),
            "unexpected ADS findings: {:?}",
            w.iter()
                .filter(|x| x.rule.to_string().starts_with("ads_"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn status_gating_skips_non_enforced_status() {
        // A test-status rule is out of the default [stable] enforce set.
        let yaml = BARE_STABLE.replace("status: stable", "status: test");
        let w = lint_with_ads(&yaml, ads_config());
        assert!(!w.iter().any(|x| x.rule.to_string().starts_with("ads_")));
    }

    #[test]
    fn enforce_status_can_widen() {
        let yaml = BARE_STABLE.replace("status: stable", "status: test");
        let cfg = AdsConfig {
            enforce_status: vec!["stable".to_string(), "test".to_string()],
            ..AdsConfig::default()
        };
        let w = lint_with_ads(&yaml, cfg);
        assert!(has_rule(&w, LintRule::AdsMissingStrategy));
    }

    #[test]
    fn reused_description_satisfies_goal() {
        let yaml = format!("{BARE_STABLE}description: A real description of the goal.\n");
        let w = lint_with_ads(&yaml, ads_config());
        assert!(!has_rule(&w, LintRule::AdsMissingGoal));
    }

    #[test]
    fn required_subset_only_flags_listed_sections() {
        let cfg = AdsConfig {
            required: vec!["validation".to_string(), "response".to_string()],
            ..AdsConfig::default()
        };
        let w = lint_with_ads(BARE_STABLE, cfg);
        assert!(has_rule(&w, LintRule::AdsMissingValidation));
        assert!(has_rule(&w, LintRule::AdsMissingResponse));
        assert!(!has_rule(&w, LintRule::AdsMissingStrategy));
    }

    #[test]
    fn severity_override_flips_all_findings() {
        let cfg = AdsConfig {
            severity: Some(Severity::Error),
            ..AdsConfig::default()
        };
        let w = lint_with_ads(BARE_STABLE, cfg);
        let strategy = w
            .iter()
            .find(|x| x.rule == LintRule::AdsMissingStrategy)
            .unwrap();
        assert_eq!(strategy.severity, Severity::Error);
        // Even the normally-Info priority check becomes Error.
        let priority = w
            .iter()
            .find(|x| x.rule == LintRule::AdsMissingPriority)
            .unwrap();
        assert_eq!(priority.severity, Severity::Error);
    }

    #[test]
    fn exempt_flag_skips_enforcement() {
        let yaml = format!("{BARE_STABLE}custom_attributes:\n    rsigma.ads.exempt: true\n");
        let w = lint_with_ads(&yaml, ads_config());
        assert!(!w.iter().any(|x| x.rule.to_string().starts_with("ads_")));
    }

    #[test]
    fn empty_section_flagged_not_missing() {
        let yaml = format!(
            "{BARE_STABLE}description: g\ntags: [attack.execution]\nfalsepositives: [none known]\ncustom_attributes:\n    rsigma.ads.strategy: \"\"\n    rsigma.ads.technical_context: ctx\n    rsigma.ads.blind_spots: [x]\n    rsigma.ads.validation: run it\n    rsigma.ads.priority: medium\n    rsigma.ads.response: [act]\n"
        );
        let w = lint_with_ads(&yaml, ads_config());
        assert!(has_rule(&w, LintRule::AdsEmptySection));
        // A blank strategy is "empty", not "missing".
        assert!(!has_rule(&w, LintRule::AdsMissingStrategy));
    }

    #[test]
    fn unknown_section_typo_gets_rename_fix() {
        let yaml = format!("{BARE_STABLE}custom_attributes:\n    rsigma.ads.validaiton: run it\n");
        let w = lint_with_ads(&yaml, ads_config());
        let unknown = w
            .iter()
            .find(|x| x.rule == LintRule::AdsUnknownSection)
            .expect("expected ads_unknown_section");
        let fix = unknown.fix.as_ref().expect("expected a rename fix");
        assert!(fix.title.contains("rsigma.ads.validation"));
    }

    #[test]
    fn ads_off_by_default_without_config() {
        // No `ads:` block: the plain (no-config) lint path emits no ADS findings.
        let w = super::super::super::lint_yaml_str(BARE_STABLE);
        assert!(!w.iter().any(|x| x.rule.to_string().starts_with("ads_")));
    }
}
