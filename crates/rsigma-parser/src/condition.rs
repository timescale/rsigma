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
use crate::error::{Result, SigmaParserError, SourceLocation};

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
    let pairs = SigmaConditionParser::parse(Rule::condition, input).map_err(|e| {
        let loc = extract_pest_location(&e);
        SigmaParserError::Condition(e.to_string(), loc)
    })?;

    let pratt = PrattParser::new()
        .op(Op::infix(Rule::or_op, Assoc::Left))
        .op(Op::infix(Rule::and_op, Assoc::Left))
        .op(Op::prefix(Rule::not_op));

    // condition = { SOI ~ expr ~ EOI }
    let condition_pair = pairs
        .into_iter()
        .next()
        .ok_or_else(|| SigmaParserError::Condition("empty condition expression".into(), None))?;
    let expr_pair = condition_pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::expr)
        .ok_or_else(|| SigmaParserError::Condition("missing expr in condition".into(), None))?;

    parse_expr(expr_pair, &pratt)
}

fn extract_pest_location(err: &pest::error::Error<Rule>) -> Option<SourceLocation> {
    match err.line_col {
        pest::error::LineColLocation::Pos((line, col)) => Some(SourceLocation {
            line: line as u32,
            col: col as u32,
        }),
        pest::error::LineColLocation::Span((line, col), _) => Some(SourceLocation {
            line: line as u32,
            col: col as u32,
        }),
    }
}

// ---------------------------------------------------------------------------
// Internal parsing helpers
// ---------------------------------------------------------------------------

/// An error collected during Pratt parsing, with optional position context.
struct PrattError {
    message: String,
    location: Option<SourceLocation>,
}

fn location_from_pair(pair: &Pair<'_, Rule>) -> Option<SourceLocation> {
    let (line, col) = pair.as_span().start_pos().line_col();
    Some(SourceLocation {
        line: line as u32,
        col: col as u32,
    })
}

fn parse_expr(pair: Pair<'_, Rule>, pratt: &PrattParser<Rule>) -> Result<ConditionExpr> {
    // The Pratt parser closures cannot return Result, so we collect all
    // errors in a shared RefCell and report them after parsing completes.
    let errors: std::cell::RefCell<Vec<PrattError>> = std::cell::RefCell::new(Vec::new());

    let result = pratt
        .map_primary(|primary| {
            let loc = location_from_pair(&primary);
            match primary.as_rule() {
                Rule::ident => ConditionExpr::Identifier(primary.as_str().to_string()),
                Rule::selector => parse_selector(primary).unwrap_or_else(|e| {
                    errors.borrow_mut().push(PrattError {
                        message: e.to_string(),
                        location: e.location().or(loc),
                    });
                    ConditionExpr::Identifier(String::new())
                }),
                Rule::expr => parse_expr(primary, pratt).unwrap_or_else(|e| {
                    errors.borrow_mut().push(PrattError {
                        message: e.to_string(),
                        location: e.location().or(loc),
                    });
                    ConditionExpr::Identifier(String::new())
                }),
                other => {
                    errors.borrow_mut().push(PrattError {
                        message: format!("unexpected primary rule: {other:?}"),
                        location: loc,
                    });
                    ConditionExpr::Identifier(String::new())
                }
            }
        })
        .map_prefix(|op, rhs| {
            let loc = location_from_pair(&op);
            match op.as_rule() {
                Rule::not_op => ConditionExpr::Not(Box::new(rhs)),
                other => {
                    errors.borrow_mut().push(PrattError {
                        message: format!("unexpected prefix rule: {other:?}"),
                        location: loc,
                    });
                    rhs
                }
            }
        })
        .map_infix(|lhs, op, rhs| {
            let loc = location_from_pair(&op);
            match op.as_rule() {
                Rule::and_op => merge_binary(ConditionExpr::And, lhs, rhs),
                Rule::or_op => merge_binary(ConditionExpr::Or, lhs, rhs),
                other => {
                    errors.borrow_mut().push(PrattError {
                        message: format!("unexpected infix rule: {other:?}"),
                        location: loc,
                    });
                    lhs
                }
            }
        })
        .parse(pair.into_inner());

    let collected = errors.into_inner();
    if !collected.is_empty() {
        let combined = collected
            .iter()
            .map(|e| match &e.location {
                Some(loc) => format!("at {loc}: {}", e.message),
                None => e.message.clone(),
            })
            .collect::<Vec<_>>()
            .join("; ");
        let first_loc = collected.iter().find_map(|e| e.location);
        return Err(SigmaParserError::Condition(combined, first_loc));
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
    // Flatten same-type children to avoid unnecessary nesting: And(And(a, b), c) → And(a, b, c)
    let is_and = matches!(ctor(vec![]), ConditionExpr::And(_));

    let mut args = Vec::new();
    for expr in [lhs, rhs] {
        match expr {
            ConditionExpr::And(children) if is_and => args.extend(children),
            ConditionExpr::Or(children) if !is_and => args.extend(children),
            other => args.push(other),
        }
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

    let quantifier =
        parse_quantifier(quantifier_pair.ok_or_else(|| {
            SigmaParserError::Condition("selector missing quantifier".into(), None)
        })?)?;
    let pattern = parse_selector_target(
        target_pair
            .ok_or_else(|| SigmaParserError::Condition("selector missing target".into(), None))?,
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
        .ok_or_else(|| SigmaParserError::Condition("quantifier missing child".into(), None))?;
    match inner.as_rule() {
        Rule::all_kw => Ok(Quantifier::All),
        Rule::any_kw => Ok(Quantifier::Any),
        Rule::uint => {
            let n: u64 = inner.as_str().parse().map_err(|e| {
                SigmaParserError::Condition(format!("invalid quantifier number: {e}"), None)
            })?;
            if n == 1 {
                Ok(Quantifier::Any)
            } else {
                Ok(Quantifier::Count(n))
            }
        }
        other => Err(SigmaParserError::Condition(
            format!("unexpected quantifier rule: {other:?}"),
            None,
        )),
    }
}

fn parse_selector_target(pair: Pair<'_, Rule>) -> Result<SelectorPattern> {
    let inner = pair
        .into_inner()
        .next()
        .ok_or_else(|| SigmaParserError::Condition("selector target missing child".into(), None))?;
    match inner.as_rule() {
        Rule::them_kw => Ok(SelectorPattern::Them),
        Rule::ident_pattern => Ok(SelectorPattern::Pattern(inner.as_str().to_string())),
        other => Err(SigmaParserError::Condition(
            format!("unexpected selector target rule: {other:?}"),
            None,
        )),
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

    // ── Multi-wildcard selector pattern tests ──────────────────────────────

    #[test]
    fn test_selector_multi_wildcard_pattern() {
        let expr = parse_condition("1 of selection_*_*").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Selector {
                quantifier: Quantifier::Any,
                pattern: SelectorPattern::Pattern("selection_*_*".to_string()),
            }
        );
    }

    #[test]
    fn test_selector_leading_wildcard_pattern() {
        let expr = parse_condition("all of *_selection_*").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Selector {
                quantifier: Quantifier::All,
                pattern: SelectorPattern::Pattern("*_selection_*".to_string()),
            }
        );
    }

    #[test]
    fn test_selector_bare_wildcard() {
        let expr = parse_condition("1 of *").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Selector {
                quantifier: Quantifier::Any,
                pattern: SelectorPattern::Pattern("*".to_string()),
            }
        );
    }

    #[test]
    fn test_selector_triple_wildcard_segment() {
        let expr = parse_condition("any of sel_*_*_*").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Selector {
                quantifier: Quantifier::Any,
                pattern: SelectorPattern::Pattern("sel_*_*_*".to_string()),
            }
        );
    }

    #[test]
    fn test_multi_wildcard_in_complex_condition() {
        let expr =
            parse_condition("selection_main and 1 of sel_*_* and not 1 of filter_*_*").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::And(vec![
                ConditionExpr::Identifier("selection_main".to_string()),
                ConditionExpr::Selector {
                    quantifier: Quantifier::Any,
                    pattern: SelectorPattern::Pattern("sel_*_*".to_string()),
                },
                ConditionExpr::Not(Box::new(ConditionExpr::Selector {
                    quantifier: Quantifier::Any,
                    pattern: SelectorPattern::Pattern("filter_*_*".to_string()),
                })),
            ])
        );
    }

    #[test]
    fn test_selector_wildcard_only_prefix() {
        let expr = parse_condition("all of *suffix").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::Selector {
                quantifier: Quantifier::All,
                pattern: SelectorPattern::Pattern("*suffix".to_string()),
            }
        );
    }

    // ── Malformed condition expression tests ─────────────────────────────

    #[test]
    fn test_empty_string_fails() {
        let err = parse_condition("").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_whitespace_only_fails() {
        let err = parse_condition("   ").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_trailing_operator_fails() {
        let err = parse_condition("selection and").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_leading_operator_fails() {
        let err = parse_condition("and selection").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_double_operator_fails() {
        let err = parse_condition("selection and and filter").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_unbalanced_open_paren_fails() {
        let err = parse_condition("(selection and filter").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_unbalanced_close_paren_fails() {
        let err = parse_condition("selection and filter)").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_empty_parens_fails() {
        let err = parse_condition("()").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_only_operator_fails() {
        let err = parse_condition("and").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_only_not_fails() {
        let err = parse_condition("not").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_or_alone_fails() {
        let err = parse_condition("or").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_incomplete_selector_missing_target_fails() {
        let err = parse_condition("1 of").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_of_without_quantifier_fails() {
        let err = parse_condition("of selection_*").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_pest_error_carries_location() {
        let err = parse_condition("selection and").unwrap_err();
        match &err {
            SigmaParserError::Condition(_, loc) => {
                assert!(
                    loc.is_some(),
                    "pest parse errors should carry source location"
                );
            }
            _ => panic!("Expected Condition error"),
        }
    }

    #[test]
    fn test_invalid_characters_fails() {
        let err = parse_condition("selection @ filter").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }

    #[test]
    fn test_nested_empty_parens_fails() {
        let err = parse_condition("selection and ()").unwrap_err();
        assert!(matches!(err, SigmaParserError::Condition(_, _)));
    }
}
