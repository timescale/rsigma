//! Condition expression parser using pest PEG grammar + Pratt parser.
//!
//! Parses Sigma condition strings like:
//! - `"selection and not filter"`
//! - `"1 of selection_* and not 1 of filter_*"`
//! - `"all of them"`
//! - `"selection_main and 1 of selection_dword_* and not 1 of filter_optional_*"`
//!
//! Reference: pySigma conditions.py (uses pyparsing infix_notation)

use pest::Parser;
use pest::iterators::Pair;
use pest::pratt_parser::{Assoc, Op, PrattParser};
use pest_derive::Parser;

use crate::ast::{ConditionExpr, Quantifier, SelectorPattern};
use crate::error::{Result, SigmaParserError};

// ---------------------------------------------------------------------------
// Pest parser (generated from sigma.pest grammar)
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[grammar = "src/sigma.pest"]
struct SigmaConditionParser;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a Sigma condition expression string into an AST.
///
/// # Examples
///
/// ```
/// use rsigma_parser::condition::parse_condition;
///
/// let expr = parse_condition("selection and not filter").unwrap();
/// println!("{expr}");
/// ```
pub fn parse_condition(input: &str) -> Result<ConditionExpr> {
    let pairs = SigmaConditionParser::parse(Rule::condition, input)
        .map_err(|e| SigmaParserError::Condition(e.to_string()))?;

    let pratt = PrattParser::new()
        .op(Op::infix(Rule::or_op, Assoc::Left))
        .op(Op::infix(Rule::and_op, Assoc::Left))
        .op(Op::prefix(Rule::not_op));

    // condition = { SOI ~ expr ~ EOI }
    let condition_pair = pairs
        .into_iter()
        .next()
        .ok_or_else(|| SigmaParserError::Condition("empty condition expression".into()))?;
    let expr_pair = condition_pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::expr)
        .ok_or_else(|| SigmaParserError::Condition("missing expr in condition".into()))?;

    parse_expr(expr_pair, &pratt)
}

// ---------------------------------------------------------------------------
// Internal parsing helpers
// ---------------------------------------------------------------------------

fn parse_expr(pair: Pair<'_, Rule>, pratt: &PrattParser<Rule>) -> Result<ConditionExpr> {
    // The Pratt parser closures cannot return Result, so we capture the first
    // error in a shared RefCell and propagate it after parsing completes.
    let error: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);

    let result = pratt
        .map_primary(|primary| match primary.as_rule() {
            Rule::ident => ConditionExpr::Identifier(primary.as_str().to_string()),
            Rule::selector => parse_selector(primary).unwrap_or_else(|e| {
                if error.borrow().is_none() {
                    *error.borrow_mut() = Some(e.to_string());
                }
                ConditionExpr::Identifier(String::new())
            }),
            Rule::expr => parse_expr(primary, pratt).unwrap_or_else(|e| {
                if error.borrow().is_none() {
                    *error.borrow_mut() = Some(e.to_string());
                }
                ConditionExpr::Identifier(String::new())
            }),
            other => {
                if error.borrow().is_none() {
                    *error.borrow_mut() = Some(format!("unexpected primary rule: {other:?}"));
                }
                ConditionExpr::Identifier(String::new())
            }
        })
        .map_prefix(|op, rhs| match op.as_rule() {
            Rule::not_op => ConditionExpr::Not(Box::new(rhs)),
            other => {
                if error.borrow().is_none() {
                    *error.borrow_mut() = Some(format!("unexpected prefix rule: {other:?}"));
                }
                rhs
            }
        })
        .map_infix(|lhs, op, rhs| match op.as_rule() {
            Rule::and_op => merge_binary(ConditionExpr::And, lhs, rhs),
            Rule::or_op => merge_binary(ConditionExpr::Or, lhs, rhs),
            other => {
                if error.borrow().is_none() {
                    *error.borrow_mut() = Some(format!("unexpected infix rule: {other:?}"));
                }
                lhs
            }
        })
        .parse(pair.into_inner());

    if let Some(msg) = error.into_inner() {
        return Err(SigmaParserError::Condition(msg));
    }

    Ok(result)
}

/// Flatten nested binary operators of the same kind.
/// `a AND (b AND c)` → `AND(a, b, c)` instead of `AND(a, AND(b, c))`.
fn merge_binary(
    ctor: fn(Vec<ConditionExpr>) -> ConditionExpr,
    lhs: ConditionExpr,
    rhs: ConditionExpr,
) -> ConditionExpr {
    // Check if the constructor matches by trying to merge same-type children.
    // We use a discriminant check approach.
    let is_same = |expr: &ConditionExpr| -> bool {
        matches!(
            (&ctor(vec![]), expr),
            (ConditionExpr::And(_), ConditionExpr::And(_))
                | (ConditionExpr::Or(_), ConditionExpr::Or(_))
        )
    };

    let mut args = Vec::new();

    if is_same(&lhs) {
        match lhs {
            ConditionExpr::And(children) | ConditionExpr::Or(children) => {
                args.extend(children);
            }
            _ => unreachable!(),
        }
    } else {
        args.push(lhs);
    }

    if is_same(&rhs) {
        match rhs {
            ConditionExpr::And(children) | ConditionExpr::Or(children) => {
                args.extend(children);
            }
            _ => unreachable!(),
        }
    } else {
        args.push(rhs);
    }

    ctor(args)
}

fn parse_selector(pair: Pair<'_, Rule>) -> Result<ConditionExpr> {
    // Iterate children, skipping the of_kw_inner pair (atomic rules can't be silent
    // in pest, so of_kw_inner leaks into the parse tree)
    let mut quantifier_pair = None;
    let mut target_pair = None;

    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::quantifier => quantifier_pair = Some(p),
            Rule::selector_target => target_pair = Some(p),
            _ => {} // skip of_kw_inner
        }
    }

    let quantifier = parse_quantifier(
        quantifier_pair
            .ok_or_else(|| SigmaParserError::Condition("selector missing quantifier".into()))?,
    )?;
    let pattern = parse_selector_target(
        target_pair.ok_or_else(|| SigmaParserError::Condition("selector missing target".into()))?,
    )?;

    Ok(ConditionExpr::Selector {
        quantifier,
        pattern,
    })
}

fn parse_quantifier(pair: Pair<'_, Rule>) -> Result<Quantifier> {
    let inner = pair
        .into_inner()
        .next()
        .ok_or_else(|| SigmaParserError::Condition("quantifier missing child".into()))?;
    match inner.as_rule() {
        Rule::all_kw => Ok(Quantifier::All),
        Rule::any_kw => Ok(Quantifier::Any),
        Rule::uint => {
            let n: u64 = inner.as_str().parse().map_err(|e| {
                SigmaParserError::Condition(format!("invalid quantifier number: {e}"))
            })?;
            if n == 1 {
                Ok(Quantifier::Any)
            } else {
                Ok(Quantifier::Count(n))
            }
        }
        other => Err(SigmaParserError::Condition(format!(
            "unexpected quantifier rule: {other:?}"
        ))),
    }
}

fn parse_selector_target(pair: Pair<'_, Rule>) -> Result<SelectorPattern> {
    let inner = pair
        .into_inner()
        .next()
        .ok_or_else(|| SigmaParserError::Condition("selector target missing child".into()))?;
    match inner.as_rule() {
        Rule::them_kw => Ok(SelectorPattern::Them),
        Rule::ident_pattern => Ok(SelectorPattern::Pattern(inner.as_str().to_string())),
        other => Err(SigmaParserError::Condition(format!(
            "unexpected selector target rule: {other:?}"
        ))),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_identifier() {
        let expr = parse_condition("selection").unwrap();
        assert_eq!(expr, ConditionExpr::Identifier("selection".to_string()));
    }

    #[test]
    fn test_and() {
        let expr = parse_condition("selection and filter").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::And(vec![
                ConditionExpr::Identifier("selection".to_string()),
                ConditionExpr::Identifier("filter".to_string()),
            ])
        );
    }

    #[test]
    fn test_or() {
        let expr = parse_condition("selection1 or selection2").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Or(vec![
                ConditionExpr::Identifier("selection1".to_string()),
                ConditionExpr::Identifier("selection2".to_string()),
            ])
        );
    }

    #[test]
    fn test_not() {
        let expr = parse_condition("not filter").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Not(Box::new(ConditionExpr::Identifier("filter".to_string())))
        );
    }

    #[test]
    fn test_and_not() {
        let expr = parse_condition("selection and not filter").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::And(vec![
                ConditionExpr::Identifier("selection".to_string()),
                ConditionExpr::Not(Box::new(ConditionExpr::Identifier("filter".to_string()))),
            ])
        );
    }

    #[test]
    fn test_precedence_not_and_or() {
        // "a or not b and c" should parse as "a or ((not b) and c)"
        let expr = parse_condition("a or not b and c").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Or(vec![
                ConditionExpr::Identifier("a".to_string()),
                ConditionExpr::And(vec![
                    ConditionExpr::Not(Box::new(ConditionExpr::Identifier("b".to_string()))),
                    ConditionExpr::Identifier("c".to_string()),
                ]),
            ])
        );
    }

    #[test]
    fn test_parentheses() {
        let expr = parse_condition("(a or b) and c").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::And(vec![
                ConditionExpr::Or(vec![
                    ConditionExpr::Identifier("a".to_string()),
                    ConditionExpr::Identifier("b".to_string()),
                ]),
                ConditionExpr::Identifier("c".to_string()),
            ])
        );
    }

    #[test]
    fn test_selector_1_of_pattern() {
        let expr = parse_condition("1 of selection_*").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Selector {
                quantifier: Quantifier::Any,
                pattern: SelectorPattern::Pattern("selection_*".to_string()),
            }
        );
    }

    #[test]
    fn test_selector_all_of_them() {
        let expr = parse_condition("all of them").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Selector {
                quantifier: Quantifier::All,
                pattern: SelectorPattern::Them,
            }
        );
    }

    #[test]
    fn test_selector_any_of() {
        let expr = parse_condition("any of selection*").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Selector {
                quantifier: Quantifier::Any,
                pattern: SelectorPattern::Pattern("selection*".to_string()),
            }
        );
    }

    #[test]
    fn test_complex_condition() {
        // Real-world: selection_main and 1 of selection_dword_* and not 1 of filter_optional_*
        let expr = parse_condition(
            "selection_main and 1 of selection_dword_* and not 1 of filter_optional_*",
        )
        .unwrap();
        assert_eq!(
            expr,
            ConditionExpr::And(vec![
                ConditionExpr::Identifier("selection_main".to_string()),
                ConditionExpr::Selector {
                    quantifier: Quantifier::Any,
                    pattern: SelectorPattern::Pattern("selection_dword_*".to_string()),
                },
                ConditionExpr::Not(Box::new(ConditionExpr::Selector {
                    quantifier: Quantifier::Any,
                    pattern: SelectorPattern::Pattern("filter_optional_*".to_string()),
                })),
            ])
        );
    }

    #[test]
    fn test_identifier_with_keyword_substring() {
        // "and_filter" should be parsed as an identifier, not "and" + "filter"
        let expr = parse_condition("selection_and_filter").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Identifier("selection_and_filter".to_string())
        );
    }

    #[test]
    fn test_identifier_with_hyphen() {
        let expr = parse_condition("my-selection and my-filter").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::And(vec![
                ConditionExpr::Identifier("my-selection".to_string()),
                ConditionExpr::Identifier("my-filter".to_string()),
            ])
        );
    }

    #[test]
    fn test_triple_and_flattened() {
        let expr = parse_condition("a and b and c").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::And(vec![
                ConditionExpr::Identifier("a".to_string()),
                ConditionExpr::Identifier("b".to_string()),
                ConditionExpr::Identifier("c".to_string()),
            ])
        );
    }

    #[test]
    fn test_triple_or_flattened() {
        let expr = parse_condition("a or b or c").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Or(vec![
                ConditionExpr::Identifier("a".to_string()),
                ConditionExpr::Identifier("b".to_string()),
                ConditionExpr::Identifier("c".to_string()),
            ])
        );
    }

    #[test]
    fn test_all_of_selection_and_not_filter() {
        let expr =
            parse_condition("all of selection_powershell_* or all of selection_wmic_*").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Or(vec![
                ConditionExpr::Selector {
                    quantifier: Quantifier::All,
                    pattern: SelectorPattern::Pattern("selection_powershell_*".to_string()),
                },
                ConditionExpr::Selector {
                    quantifier: Quantifier::All,
                    pattern: SelectorPattern::Pattern("selection_wmic_*".to_string()),
                },
            ])
        );
    }

    #[test]
    fn test_real_world_complex() {
        // From rules: selection_key and (all of selection_powershell_* or all of selection_wmic_*)
        let expr = parse_condition(
            "selection_key and (all of selection_powershell_* or all of selection_wmic_*)",
        )
        .unwrap();
        assert_eq!(
            expr,
            ConditionExpr::And(vec![
                ConditionExpr::Identifier("selection_key".to_string()),
                ConditionExpr::Or(vec![
                    ConditionExpr::Selector {
                        quantifier: Quantifier::All,
                        pattern: SelectorPattern::Pattern("selection_powershell_*".to_string()),
                    },
                    ConditionExpr::Selector {
                        quantifier: Quantifier::All,
                        pattern: SelectorPattern::Pattern("selection_wmic_*".to_string()),
                    },
                ]),
            ])
        );
    }

    #[test]
    fn test_1_of_them() {
        let expr = parse_condition("1 of them").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Selector {
                quantifier: Quantifier::Any,
                pattern: SelectorPattern::Them,
            }
        );
    }

    #[test]
    fn test_count_of() {
        let expr = parse_condition("3 of selection_*").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Selector {
                quantifier: Quantifier::Count(3),
                pattern: SelectorPattern::Pattern("selection_*".to_string()),
            }
        );
    }

    #[test]
    fn test_not_1_of_filter() {
        let expr = parse_condition("selection and not 1 of filter*").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::And(vec![
                ConditionExpr::Identifier("selection".to_string()),
                ConditionExpr::Not(Box::new(ConditionExpr::Selector {
                    quantifier: Quantifier::Any,
                    pattern: SelectorPattern::Pattern("filter*".to_string()),
                })),
            ])
        );
    }
}
