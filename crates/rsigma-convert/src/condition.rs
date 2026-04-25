use std::collections::HashMap;

use rsigma_parser::*;

use crate::backend::Backend;
use crate::error::{ConvertError, Result};
use crate::state::ConversionState;

/// Recursively walk a `ConditionExpr` tree and convert each node into a query fragment.
pub fn convert_condition_expr(
    backend: &dyn Backend,
    expr: &ConditionExpr,
    detections: &HashMap<String, Detection>,
    state: &mut ConversionState,
) -> Result<String> {
    match expr {
        ConditionExpr::Identifier(name) => {
            let det = detections.get(name).ok_or_else(|| {
                ConvertError::RuleConversion(format!("detection '{name}' not found"))
            })?;
            backend.convert_detection(det, state)
        }

        ConditionExpr::And(exprs) => {
            let parts: Vec<String> = exprs
                .iter()
                .map(|e| convert_condition_expr(backend, e, detections, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_and(&parts)
        }

        ConditionExpr::Or(exprs) => {
            let parts: Vec<String> = exprs
                .iter()
                .map(|e| convert_condition_expr(backend, e, detections, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_or(&parts)
        }

        ConditionExpr::Not(inner) => {
            let part = convert_condition_expr(backend, inner, detections, state)?;
            backend.convert_condition_not(&part)
        }

        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let names: Vec<&String> = match pattern {
                SelectorPattern::Them => {
                    detections.keys().filter(|n| !n.starts_with('_')).collect()
                }
                SelectorPattern::Pattern(pat) => detections
                    .keys()
                    .filter(|n| pattern_matches(pat, n))
                    .collect(),
            };

            if names.is_empty() {
                return Err(ConvertError::RuleConversion(
                    "selector matched no detections".into(),
                ));
            }

            let parts: Vec<String> = names
                .iter()
                .map(|name| {
                    let det = detections.get(*name).unwrap();
                    backend.convert_detection(det, state)
                })
                .collect::<Result<Vec<_>>>()?;

            match quantifier {
                Quantifier::Any | Quantifier::Count(1) => backend.convert_condition_or(&parts),
                Quantifier::All => backend.convert_condition_and(&parts),
                Quantifier::Count(n) => Err(ConvertError::RuleConversion(format!(
                    "'{n} of' quantifier not supported in conversion"
                ))),
            }
        }
    }
}

/// Simple wildcard match on detection names (supports `*` glob at end, start, or middle).
fn pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return name.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return name.ends_with(suffix);
    }
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        return name.starts_with(prefix) && name.ends_with(suffix);
    }
    pattern == name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matches_star_suffix() {
        assert!(pattern_matches("selection_*", "selection_main"));
        assert!(pattern_matches("selection_*", "selection_"));
        assert!(!pattern_matches("selection_*", "filter_main"));
    }

    #[test]
    fn test_pattern_matches_star_prefix() {
        assert!(pattern_matches("*_main", "selection_main"));
        assert!(!pattern_matches("*_main", "selection_alt"));
    }

    #[test]
    fn test_pattern_matches_star_middle() {
        assert!(pattern_matches("sel*main", "selection_main"));
        assert!(!pattern_matches("sel*main", "filter_main"));
    }

    #[test]
    fn test_pattern_matches_exact() {
        assert!(pattern_matches("selection", "selection"));
        assert!(!pattern_matches("selection", "filter"));
    }

    #[test]
    fn test_pattern_matches_star_only() {
        assert!(pattern_matches("*", "anything"));
    }
}
