use rsigma_parser::{ConditionExpr, LogSource};

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

/// Rewrite all `Identifier` nodes in a condition expression tree, prefixing
/// each name with `__filter_{counter}_` so it references the namespaced
/// detection keys injected into the target rule.
pub(super) fn rewrite_condition_identifiers(expr: &ConditionExpr, counter: usize) -> ConditionExpr {
    match expr {
        ConditionExpr::Identifier(name) => {
            ConditionExpr::Identifier(format!("__filter_{counter}_{name}"))
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
        ConditionExpr::Selector { .. } => expr.clone(),
    }
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
