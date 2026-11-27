use rsigma_parser::{
    ConditionExpr, FilterRule, FilterRuleTarget, LogSource, SelectorPattern, SigmaCollection,
    SigmaRule,
};

/// Asymmetric containment check for filter-to-rule matching: every field the
/// filter specifies must be present and equal in the rule. Fields the filter
/// omits are treated as wildcards (match any rule). This means a filter with
/// only `product: windows` applies to rules that have `product: windows`
/// regardless of their category/service, but a filter with
/// `category: process_creation` does NOT apply to a rule that lacks a category.
pub(super) fn filter_logsource_contains(filter_ls: &LogSource, rule_ls: &LogSource) -> bool {
    fn field_matches(filter_field: &Option<String>, rule_field: &Option<String>) -> bool {
        match filter_field {
            None => true,
            Some(fv) => match rule_field {
                Some(rv) => fv.eq_ignore_ascii_case(rv),
                None => false,
            },
        }
    }

    field_matches(&filter_ls.category, &rule_ls.category)
        && field_matches(&filter_ls.product, &rule_ls.product)
        && field_matches(&filter_ls.service, &rule_ls.service)
}

/// Key under which a filter detection (or a selector pattern over filter
/// detections) is injected into the target rule.
///
/// Names starting with `_` go under `__filter_{counter}_h_` and all others
/// under `__filter_{counter}_v_`. Every injected key starts with `_`, so the
/// selector matcher would otherwise let any rewritten pattern see the filter's
/// `_` names; the split keeps `them` and patterns that do not start with `_`
/// away from them, as the Sigma specification requires.
pub(super) fn filter_detection_key(counter: usize, name: &str) -> String {
    let scope = if name.starts_with('_') { 'h' } else { 'v' };
    format!("__filter_{counter}_{scope}_{name}")
}

/// Rewrite all `Identifier` nodes and selector patterns in a condition
/// expression tree so they reference the namespaced detection keys injected
/// into the target rule (see [`filter_detection_key`]).
pub(super) fn rewrite_condition_identifiers(expr: &ConditionExpr, counter: usize) -> ConditionExpr {
    match expr {
        ConditionExpr::Identifier(name) => {
            ConditionExpr::Identifier(filter_detection_key(counter, name))
        }
        ConditionExpr::And(children) => ConditionExpr::And(
            children
                .iter()
                .map(|c| rewrite_condition_identifiers(c, counter))
                .collect(),
        ),
        ConditionExpr::Or(children) => ConditionExpr::Or(
            children
                .iter()
                .map(|c| rewrite_condition_identifiers(c, counter))
                .collect(),
        ),
        ConditionExpr::Not(child) => {
            ConditionExpr::Not(Box::new(rewrite_condition_identifiers(child, counter)))
        }
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let pattern = match pattern {
                SelectorPattern::Them => {
                    SelectorPattern::Pattern(filter_detection_key(counter, "*"))
                }
                SelectorPattern::Pattern(pattern) => {
                    SelectorPattern::Pattern(filter_detection_key(counter, pattern))
                }
            };
            ConditionExpr::Selector {
                quantifier: quantifier.clone(),
                pattern,
            }
        }
    }
}

/// The identity of a rule a filter may target.
pub(super) struct FilterTarget<'a> {
    pub id: Option<&'a str>,
    pub name: Option<&'a str>,
    pub title: &'a str,
    pub logsource: &'a LogSource,
}

/// References of `filter` that name some rule's `id` or `name`. Such a
/// reference never falls back to matching a title, so a title cannot capture
/// a reference that names another rule's stable identity.
pub(super) fn stable_references(
    filter: &FilterRule,
    identities: &[(Option<&str>, Option<&str>)],
) -> Vec<String> {
    match &filter.rules {
        FilterRuleTarget::Any => Vec::new(),
        FilterRuleTarget::Specific(refs) => refs
            .iter()
            .filter(|reference| {
                identities.iter().any(|(id, name)| {
                    *id == Some(reference.as_str()) || *name == Some(reference.as_str())
                })
            })
            .cloned()
            .collect(),
    }
}

/// Whether `filter` applies to `rule`: a reference matches its `id` or
/// `name` (or, deprecated, its title), and the filter's logsource, if any,
/// is contained in the rule's.
pub(super) fn filter_targets(
    filter: &FilterRule,
    stable_references: &[String],
    rule: &FilterTarget<'_>,
) -> bool {
    let referenced = match &filter.rules {
        FilterRuleTarget::Any => true,
        FilterRuleTarget::Specific(refs) => refs.iter().any(|reference| {
            let identity_match =
                rule.id == Some(reference.as_str()) || rule.name == Some(reference.as_str());
            let title_match = !stable_references.contains(reference)
                && !identity_match
                && rule.title == reference;
            if title_match {
                log::warn!(
                    "filter '{}' references rule '{}' by title; title references are \
                     deprecated, use the rule id or name",
                    filter.title,
                    reference
                );
            }
            identity_match || title_match
        }),
    };
    referenced
        && filter
            .logsource
            .as_ref()
            .is_none_or(|filter_ls| filter_logsource_contains(filter_ls, rule.logsource))
}

/// The filter's condition with its identifiers namespaced under `counter`,
/// or the AND of its detections when it has no condition.
pub(super) fn namespaced_filter_condition(filter: &FilterRule, counter: usize) -> ConditionExpr {
    if let Some(cond_expr) = filter.detection.conditions.first() {
        return rewrite_condition_identifiers(cond_expr, counter);
    }
    let mut names: Vec<&String> = filter.detection.named.keys().collect();
    names.sort();
    let mut ids: Vec<ConditionExpr> = names
        .into_iter()
        .map(|name| ConditionExpr::Identifier(filter_detection_key(counter, name)))
        .collect();
    match ids.len() {
        1 => ids.remove(0),
        _ => ConditionExpr::And(ids),
    }
}

/// Add `filter` to a rule `condition` as one more AND operand. A condition
/// that is already an AND takes it as a new child, so applying many filters to
/// one rule widens the AND instead of nesting it one level per filter.
pub(super) fn and_filter(condition: &mut ConditionExpr, filter: &ConditionExpr) {
    match condition {
        ConditionExpr::And(children) => children.push(filter.clone()),
        other => {
            let original = std::mem::replace(other, ConditionExpr::And(Vec::new()));
            *other = ConditionExpr::And(vec![original, filter.clone()]);
        }
    }
}

/// Merge every filter in `collection` into the detection rules it targets and
/// return the rules, in collection order.
///
/// This is how pySigma applies filters when a collection loads: each filter's
/// detections are added to the rule under namespaced identifiers and each rule
/// condition becomes `(condition) and (filter condition)`. Apply processing
/// pipelines to the returned rules afterwards, so field mappings reach the
/// filter's fields too. Filters target rules the same way
/// [`Engine::apply_filter`](crate::Engine::apply_filter) does.
pub fn apply_filters(collection: &SigmaCollection) -> Vec<SigmaRule> {
    let mut rules = collection.rules.clone();
    let mut filtered = vec![false; rules.len()];
    for (counter, filter) in collection.filters.iter().enumerate() {
        if filter.detection.named.is_empty() {
            continue;
        }
        let identities: Vec<_> = collection
            .rules
            .iter()
            .map(|r| (r.id.as_deref(), r.name.as_deref()))
            .collect();
        let stable = stable_references(filter, &identities);
        let condition = namespaced_filter_condition(filter, counter);
        for (rule, filtered) in rules.iter_mut().zip(&mut filtered) {
            let target = FilterTarget {
                id: rule.id.as_deref(),
                name: rule.name.as_deref(),
                title: &rule.title,
                logsource: &rule.logsource,
            };
            if !filter_targets(filter, &stable, &target) {
                continue;
            }
            for (name, detection) in &filter.detection.named {
                rule.detection
                    .named
                    .insert(filter_detection_key(counter, name), detection.clone());
            }
            for cond in &mut rule.detection.conditions {
                and_filter(cond, &condition);
            }
            *filtered = true;
        }
    }
    for (rule, _) in rules.iter_mut().zip(filtered).filter(|(_, f)| *f) {
        rule.detection.condition_strings = rule
            .detection
            .conditions
            .iter()
            .map(ToString::to_string)
            .collect();
    }
    rules
}

/// Conflict-based compatibility check for hot-path logsource pruning.
///
/// Returns `false` only when a dimension is set on BOTH the rule and the
/// event and the two values differ (case-insensitive). A dimension unset on
/// either side is a wildcard, so the rule is kept. The standard `product`,
/// `service`, and `category` dimensions are checked, plus any custom dimension
/// keys present on both sides (a rule custom key the event does not assert is a
/// wildcard, and vice versa). `definition` is ignored.
///
/// This is deliberately distinct from the subset [`logsource_matches`] (and
/// the filter-side [`filter_logsource_contains`]): subset semantics require
/// every dimension the rule names to be present and equal in the event, which
/// would drop a `product: windows, category: process_creation` rule for an
/// event tagged only `product: windows` (no category) and silently lose the
/// detection. Conflict-based semantics keep that rule (the event never
/// asserted a conflicting category) and skip only rules whose stated
/// dimension genuinely disagrees with the event.
pub(super) fn logsource_compatible(rule_ls: &LogSource, event_ls: &LogSource) -> bool {
    fn conflicts(rule_field: &Option<String>, event_field: &Option<String>) -> bool {
        match (rule_field, event_field) {
            (Some(r), Some(e)) => !r.eq_ignore_ascii_case(e),
            _ => false,
        }
    }

    // A custom dimension conflicts only when the same key is present on both
    // sides with differing values; keys on one side only are wildcards.
    let custom_conflict = rule_ls.custom.iter().any(|(key, rule_value)| {
        event_ls
            .custom
            .get(key)
            .is_some_and(|event_value| !rule_value.eq_ignore_ascii_case(event_value))
    });

    !(conflicts(&rule_ls.product, &event_ls.product)
        || conflicts(&rule_ls.service, &event_ls.service)
        || conflicts(&rule_ls.category, &event_ls.category)
        || custom_conflict)
}

/// Asymmetric check: every field specified in `rule_ls` must be present and
/// match in `event_ls`. Used for routing events to rules by logsource.
pub(super) fn logsource_matches(rule_ls: &LogSource, event_ls: &LogSource) -> bool {
    if let Some(ref cat) = rule_ls.category {
        match &event_ls.category {
            Some(ec) if ec.eq_ignore_ascii_case(cat) => {}
            _ => return false,
        }
    }
    if let Some(ref prod) = rule_ls.product {
        match &event_ls.product {
            Some(ep) if ep.eq_ignore_ascii_case(prod) => {}
            _ => return false,
        }
    }
    if let Some(ref svc) = rule_ls.service {
        match &event_ls.service {
            Some(es) if es.eq_ignore_ascii_case(svc) => {}
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::{Quantifier, SelectorPattern};
    use std::collections::HashMap;

    fn ls(product: Option<&str>, custom: &[(&str, &str)]) -> LogSource {
        LogSource {
            product: product.map(str::to_string),
            custom: custom
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
            ..LogSource::default()
        }
    }

    #[test]
    fn custom_dimension_conflict_prunes_only_on_disagreement() {
        // Same custom key, differing values -> conflict (skip).
        assert!(!logsource_compatible(
            &ls(None, &[("tenant", "acme")]),
            &ls(None, &[("tenant", "globex")]),
        ));
        // Same custom key, same value (case-insensitive) -> keep.
        assert!(logsource_compatible(
            &ls(None, &[("tenant", "ACME")]),
            &ls(None, &[("tenant", "acme")]),
        ));
        // Key only on the rule side -> wildcard, keep.
        assert!(logsource_compatible(
            &ls(None, &[("tenant", "acme")]),
            &ls(None, &[]),
        ));
        // Key only on the event side -> wildcard, keep.
        assert!(logsource_compatible(
            &ls(None, &[]),
            &ls(None, &[("tenant", "acme")]),
        ));
        // Standard-dimension conflict still prunes alongside custom.
        assert!(!logsource_compatible(
            &ls(Some("linux"), &[]),
            &ls(Some("windows"), &[("tenant", "acme")]),
        ));
    }

    #[test]
    fn selector_patterns_are_scoped_to_injected_filter_detections() {
        let expression = ConditionExpr::Selector {
            quantifier: Quantifier::Any,
            pattern: SelectorPattern::Pattern("selection_*".to_string()),
        };
        assert_eq!(
            rewrite_condition_identifiers(&expression, 3),
            ConditionExpr::Selector {
                quantifier: Quantifier::Any,
                pattern: SelectorPattern::Pattern("__filter_3_v_selection_*".to_string()),
            }
        );
    }

    #[test]
    fn them_is_scoped_to_injected_filter_detections() {
        let expression = ConditionExpr::Selector {
            quantifier: Quantifier::All,
            pattern: SelectorPattern::Them,
        };
        assert_eq!(
            rewrite_condition_identifiers(&expression, 2),
            ConditionExpr::Selector {
                quantifier: Quantifier::All,
                pattern: SelectorPattern::Pattern("__filter_2_v_*".to_string()),
            }
        );
    }

    #[test]
    fn apply_filters_merges_into_referenced_rules_only() {
        let collection = rsigma_parser::parse_sigma_yaml(
            r#"
title: Whoami
name: whoami
logsource: { category: process_creation }
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
---
title: Ping
logsource: { category: process_creation }
detection:
    selection:
        Image|endswith: '\ping.exe'
    condition: selection
---
title: Exclude admins
logsource: { category: process_creation }
filter:
    rules: [whoami]
    selection:
        User: admin
    condition: not selection
"#,
        )
        .unwrap();
        let rules = apply_filters(&collection);
        assert!(
            rules[0]
                .detection
                .named
                .contains_key("__filter_0_v_selection")
        );
        assert_eq!(
            rules[0].detection.condition_strings,
            ["(selection and not __filter_0_v_selection)"]
        );
        assert_eq!(rules[1].detection, collection.rules[1].detection);
    }

    #[test]
    fn underscore_names_and_patterns_use_the_hidden_namespace() {
        assert_eq!(filter_detection_key(1, "_helper"), "__filter_1_h__helper");
        assert_eq!(
            filter_detection_key(1, "selection"),
            "__filter_1_v_selection"
        );

        let hidden = SelectorPattern::Pattern(filter_detection_key(1, "_*"));
        assert!(hidden.matches_detection_name(&filter_detection_key(1, "_helper")));
        assert!(!hidden.matches_detection_name(&filter_detection_key(1, "selection")));

        let visible = SelectorPattern::Pattern(filter_detection_key(1, "*"));
        assert!(visible.matches_detection_name(&filter_detection_key(1, "selection")));
        assert!(!visible.matches_detection_name(&filter_detection_key(1, "_helper")));
    }
}
