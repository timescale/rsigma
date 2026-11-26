//! IR-native detection/item dispatch for the `Backend` trait.
//!
//! Walks [`IrDetection`] / [`IrDetectionItem`] and calls the IR-native
//! `Backend` value leaves. Encoding modifiers are expanded into an OR of plain
//! string matches by
//! [`rsigma_ir::encoding::expand_encoded_detections`] before the walk. An `expand` value
//! with unresolved placeholders and timestamp parts have no backend rendering
//! and are rejected here. `|neq` lowers to an [`IrMatcher::Not`] around the
//! whole item and is rendered with [`Backend::convert_condition_not`].

use std::collections::HashMap;

use rsigma_ir::{
    IrCondition, IrDetection, IrDetectionItem, IrMatcher, IrNumber, IrStrOp, NumericLiteral,
};
use rsigma_parser::{Quantifier, SelectorPattern};

use crate::backend::{Backend, CompareOp, TokenType};
use crate::convert::field_has_positional_index;
use crate::error::{ConvertError, Result};
use crate::state::{ConversionState, ConvertResult};

/// A converted operand and the operator at its top level (`None` for an
/// atom).
///
/// The operator comes from the IR node shape rather than the rendered text,
/// as pySigma groups by condition tree node: a value list is an OR even when
/// a backend renders it as a single list clause.
pub(crate) struct Operand {
    pub(crate) expr: String,
    pub(crate) op: Option<TokenType>,
}

impl Operand {
    pub(crate) fn new(expr: String, op: Option<TokenType>) -> Self {
        Self { expr, op }
    }
}

fn group<B: Backend + ?Sized>(backend: &B, outer: TokenType, operand: Operand) -> Result<String> {
    match operand.op {
        Some(inner) if !operand.expr.is_empty() => {
            backend.convert_condition_group(&operand.expr, outer, inner)
        }
        _ => Ok(operand.expr),
    }
}

/// Join operands with AND (`all`) or OR, grouping each one first. A single
/// operand is passed through ungrouped.
pub(crate) fn join<B: Backend + ?Sized>(
    backend: &B,
    all: bool,
    operands: Vec<Operand>,
) -> Result<String> {
    let outer = if all { TokenType::AND } else { TokenType::OR };
    let parts = if operands.len() == 1 {
        operands.into_iter().map(|o| o.expr).collect()
    } else {
        operands
            .into_iter()
            .map(|o| group(backend, outer, o))
            .collect::<Result<Vec<_>>>()?
    };
    if all {
        backend.convert_condition_and(&parts)
    } else {
        backend.convert_condition_or(&parts)
    }
}

/// Negate an operand, grouping it first.
pub(crate) fn negate<B: Backend + ?Sized>(backend: &B, operand: Operand) -> Result<String> {
    let expr = group(backend, TokenType::NOT, operand)?;
    backend.convert_condition_not(&expr)
}

fn list_op<T>(
    items: &[T],
    op: TokenType,
    item_op: impl Fn(&T) -> Option<TokenType>,
) -> Option<TokenType> {
    match items {
        [] => None,
        [only] => item_op(only),
        _ => Some(op),
    }
}

/// Top-level operator of a converted matcher.
pub(crate) fn matcher_op(matcher: &IrMatcher) -> Option<TokenType> {
    match matcher {
        IrMatcher::AnyOf(ms) => list_op(ms, TokenType::OR, matcher_op),
        IrMatcher::AllOf(ms) => list_op(ms, TokenType::AND, matcher_op),
        IrMatcher::Not(_) => Some(TokenType::NOT),
        IrMatcher::Encoded {
            encodings,
            op,
            pattern,
            ..
        } => match rsigma_ir::encoding::expand_encoded(encodings, *op, pattern) {
            Ok(variants) if variants.len() > 1 => Some(TokenType::OR),
            _ => None,
        },
        _ => None,
    }
}

/// Top-level operator of a converted detection.
pub(crate) fn detection_op(det: &IrDetection) -> Option<TokenType> {
    match det {
        IrDetection::AllOf(items) => list_op(items, TokenType::AND, |it| matcher_op(&it.matcher)),
        IrDetection::AnyOf(dets) => list_op(dets, TokenType::OR, detection_op),
        IrDetection::And(dets) => list_op(dets, TokenType::AND, detection_op),
        IrDetection::Keywords(matcher) => matcher_op(matcher),
        IrDetection::ArrayMatch { .. } => None,
        IrDetection::Conditional { named, condition } => condition_op(condition, named),
    }
}

/// Top-level operator of a converted condition.
pub(crate) fn condition_op(
    cond: &IrCondition,
    detections: &HashMap<String, IrDetection>,
) -> Option<TokenType> {
    match cond {
        IrCondition::Detection(name) => detections.get(name).and_then(detection_op),
        IrCondition::And(exprs) => list_op(exprs, TokenType::AND, |e| condition_op(e, detections)),
        IrCondition::Or(exprs) => list_op(exprs, TokenType::OR, |e| condition_op(e, detections)),
        IrCondition::Not(_) => Some(TokenType::NOT),
        IrCondition::Selector {
            quantifier,
            pattern,
        } => {
            let op = if matches!(quantifier, Quantifier::All) {
                TokenType::AND
            } else {
                TokenType::OR
            };
            let names = selected_detections(detections, pattern);
            list_op(&names, op, |n| detections.get(*n).and_then(detection_op))
        }
    }
}

/// Detection names a selector matches, sorted for deterministic output.
pub(crate) fn selected_detections<'a>(
    detections: &'a HashMap<String, IrDetection>,
    pattern: &SelectorPattern,
) -> Vec<&'a String> {
    let mut names: Vec<&String> = detections
        .keys()
        .filter(|n| pattern.matches_detection_name(n))
        .collect();
    names.sort();
    names
}

/// Resolve a leaf `ConvertResult`: a direct query fragment, or a deferred part
/// queued in the state that contributes an empty placeholder.
fn resolve(res: ConvertResult, state: &mut ConversionState) -> Option<String> {
    match res {
        ConvertResult::Query(q) if !q.is_empty() => Some(q),
        ConvertResult::Query(_) => None,
        ConvertResult::Deferred(d) => {
            state.add_deferred(d);
            None
        }
    }
}

fn number(n: &IrNumber) -> Result<NumericLiteral> {
    match n {
        IrNumber::Literal(v) => Ok(*v),
        IrNumber::DynamicSourceRef { source_id, .. } => Err(ConvertError::UnsupportedValue(
            format!("unresolved dynamic source reference '{source_id}'"),
        )),
    }
}

/// Default IR detection dispatch.
pub fn default_convert_ir_detection<B: Backend + ?Sized>(
    backend: &B,
    det: &IrDetection,
    state: &mut ConversionState,
) -> Result<String> {
    match det {
        IrDetection::AllOf(items) => {
            let parts = items
                .iter()
                .map(|it| {
                    let expr = backend.convert_ir_detection_item(it, state)?;
                    Ok(Operand::new(expr, matcher_op(&it.matcher)))
                })
                .collect::<Result<Vec<_>>>()?;
            join(backend, true, parts)
        }
        IrDetection::AnyOf(dets) | IrDetection::And(dets) => {
            let parts = dets
                .iter()
                .map(|d| {
                    let expr = backend.convert_ir_detection(d, state)?;
                    Ok(Operand::new(expr, detection_op(d)))
                })
                .collect::<Result<Vec<_>>>()?;
            join(backend, matches!(det, IrDetection::And(_)), parts)
        }
        IrDetection::Keywords(matcher) => {
            let subs: Vec<&IrMatcher> = match matcher {
                IrMatcher::AnyOf(ms) => ms.iter().collect(),
                other => vec![other],
            };
            let parts: Vec<String> = subs
                .iter()
                .map(|m| convert_keyword(backend, m, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_or(&parts)
        }
        IrDetection::ArrayMatch {
            field,
            quantifier,
            body,
        } => backend.convert_ir_array_match(field, *quantifier, body, state),
        IrDetection::Conditional { named, condition } => {
            convert_block_condition(backend, condition, named, state)
        }
    }
}

/// A full-text term matches anywhere in the event, so only a value without an
/// explicit operator or with `contains` has a faithful keyword rendering.
fn convert_keyword<B: Backend + ?Sized>(
    backend: &B,
    matcher: &IrMatcher,
    state: &mut ConversionState,
) -> Result<String> {
    match matcher {
        IrMatcher::Str {
            op: IrStrOp::Exact | IrStrOp::Contains,
            pattern,
            case_insensitive: true,
        } => backend.convert_keyword_str(pattern, state),
        IrMatcher::Str {
            op: IrStrOp::Exact | IrStrOp::Contains,
            pattern,
            case_insensitive: false,
        } => backend.convert_keyword_str_cased(pattern, state),
        IrMatcher::NumericEq(n) => backend.convert_keyword_num(number(n)?, state),
        _ => Err(ConvertError::UnsupportedKeyword),
    }
}

/// Render the matcher of a field-less item as full-text terms, one per value,
/// joined by the item's value-list operator.
fn convert_keyword_item<B: Backend + ?Sized>(
    backend: &B,
    matcher: &IrMatcher,
    state: &mut ConversionState,
) -> Result<String> {
    match matcher {
        IrMatcher::AnyOf(ms) | IrMatcher::AllOf(ms) => {
            let parts = ms
                .iter()
                .map(|m| {
                    let expr = convert_keyword_item(backend, m, state)?;
                    Ok(Operand::new(expr, matcher_op(m)))
                })
                .collect::<Result<Vec<_>>>()?;
            join(backend, matches!(matcher, IrMatcher::AllOf(_)), parts)
        }
        IrMatcher::Not(inner) => {
            let expr = convert_keyword_item(backend, inner, state)?;
            negate(backend, Operand::new(expr, matcher_op(inner)))
        }
        other => convert_keyword(backend, other, state),
    }
}

/// Default IR detection-item dispatch.
pub fn default_convert_ir_detection_item<B: Backend + ?Sized>(
    backend: &B,
    item: &IrDetectionItem,
    state: &mut ConversionState,
) -> Result<String> {
    let Some(field) = item.field.as_deref() else {
        return convert_keyword_item(backend, &item.matcher, state);
    };

    // A positional array index (`field[N]`) must not silently emit a literal
    // field reference on backends that cannot lower element-N semantics.
    if field_has_positional_index(field) && !backend.supports_field_index() {
        return Err(ConvertError::UnsupportedArrayMatching);
    }

    match &item.matcher {
        IrMatcher::AnyOf(ms) => {
            let parts = convert_matcher_list(backend, field, ms, state)?;
            join_parts(backend, parts, false)
        }
        IrMatcher::AllOf(ms) => {
            let parts = convert_matcher_list(backend, field, ms, state)?;
            join_parts(backend, parts, true)
        }
        other => match convert_leaf(backend, field, other, state)? {
            Some(q) => Ok(q),
            None => Ok(String::new()),
        },
    }
}

fn convert_matcher_list<B: Backend + ?Sized>(
    backend: &B,
    field: &str,
    ms: &[IrMatcher],
    state: &mut ConversionState,
) -> Result<Vec<Operand>> {
    let mut parts = Vec::with_capacity(ms.len());
    for m in ms {
        if let Some(q) = convert_leaf(backend, field, m, state)? {
            parts.push(Operand::new(q, matcher_op(m)));
        }
    }
    Ok(parts)
}

fn join_parts<B: Backend + ?Sized>(
    backend: &B,
    mut parts: Vec<Operand>,
    all: bool,
) -> Result<String> {
    match parts.len() {
        0 => Ok(String::new()),
        1 => Ok(parts.remove(0).expr),
        _ => join(backend, all, parts),
    }
}

/// Convert a single leaf matcher against `field`, resolving deferred parts.
/// Returns `None` when the matcher produced only a deferred part (empty
/// placeholder), matching the parser-path contract.
fn convert_leaf<B: Backend + ?Sized>(
    backend: &B,
    field: &str,
    matcher: &IrMatcher,
    state: &mut ConversionState,
) -> Result<Option<String>> {
    match matcher {
        IrMatcher::Str {
            op,
            pattern,
            case_insensitive,
        } => {
            let res = backend.convert_field_str(field, *op, pattern, *case_insensitive, state)?;
            Ok(resolve(res, state))
        }
        IrMatcher::Regex {
            pattern,
            case_insensitive,
            multiline,
            dotall,
            cased,
        } => {
            let flags = crate::backend::RegexFlags {
                case_insensitive: *case_insensitive,
                multiline: *multiline,
                dotall: *dotall,
                cased: *cased,
            };
            let res = backend.convert_field_regex(field, pattern, flags, state)?;
            Ok(resolve(res, state))
        }
        IrMatcher::Cidr { network } => {
            let res = backend.convert_field_eq_cidr(field, network, state)?;
            Ok(resolve(res, state))
        }
        IrMatcher::NumericEq(n) => Ok(Some(backend.convert_field_eq_num(
            field,
            number(n)?,
            state,
        )?)),
        IrMatcher::NumericGt(n) => Ok(Some(backend.convert_field_compare_op(
            field,
            CompareOp::Gt,
            number(n)?,
            state,
        )?)),
        IrMatcher::NumericGte(n) => Ok(Some(backend.convert_field_compare_op(
            field,
            CompareOp::Gte,
            number(n)?,
            state,
        )?)),
        IrMatcher::NumericLt(n) => Ok(Some(backend.convert_field_compare_op(
            field,
            CompareOp::Lt,
            number(n)?,
            state,
        )?)),
        IrMatcher::NumericLte(n) => Ok(Some(backend.convert_field_compare_op(
            field,
            CompareOp::Lte,
            number(n)?,
            state,
        )?)),
        IrMatcher::Exists(expect) => Ok(Some(backend.convert_field_exists(field, *expect, state)?)),
        IrMatcher::Null => Ok(Some(backend.convert_field_eq_null(field, state)?)),
        IrMatcher::BoolEq(b) => Ok(Some(backend.convert_field_eq_bool(field, *b, state)?)),
        IrMatcher::FieldRef {
            field: rf,
            op,
            case_insensitive,
        } => {
            let res = backend.convert_field_ref(field, rf, *op, *case_insensitive, state)?;
            Ok(resolve(res, state))
        }
        IrMatcher::Encoded { .. } => Err(ConvertError::RuleConversion(
            "encoding modifiers must be expanded before conversion".into(),
        )),
        IrMatcher::Not(inner) => convert_not(backend, field, inner, state),
        IrMatcher::Expand { template, .. } => {
            let unresolved: Vec<&str> = template
                .iter()
                .filter_map(|part| match part {
                    rsigma_ir::IrExpandPart::Placeholder(name) => Some(name.as_str()),
                    rsigma_ir::IrExpandPart::Literal(_) => None,
                })
                .collect();
            Err(ConvertError::UnsupportedModifier(format!(
                "expand placeholder(s) {} not resolved by a pipeline; conversion \
                 cannot substitute event fields at match time",
                unresolved
                    .iter()
                    .map(|name| format!("%{name}%"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
        IrMatcher::TimestampPart { .. } => {
            Err(ConvertError::UnsupportedModifier("timestamp part".into()))
        }
        IrMatcher::AnyOf(ms) => {
            let parts = convert_matcher_list(backend, field, ms, state)?;
            Ok(Some(join_parts(backend, parts, false)?))
        }
        IrMatcher::AllOf(ms) => {
            let parts = convert_matcher_list(backend, field, ms, state)?;
            Ok(Some(join_parts(backend, parts, true)?))
        }
    }
}

/// Convert `|neq`, which negates the whole detection item.
///
/// Deferred parts are negated in place. They are ANDed onto the query, so
/// negating each part of an OR list is De Morgan's law; an `|all` list of
/// several deferred parts has no equivalent and is rejected.
fn convert_not<B: Backend + ?Sized>(
    backend: &B,
    field: &str,
    inner: &IrMatcher,
    state: &mut ConversionState,
) -> Result<Option<String>> {
    let deferred_before = state.deferred.len();
    let (expr, op) = match inner {
        IrMatcher::AnyOf(ms) | IrMatcher::AllOf(ms) => {
            let parts = convert_matcher_list(backend, field, ms, state)?;
            let op = match parts.as_slice() {
                [] => None,
                [only] => only.op,
                _ => matcher_op(inner),
            };
            let all = matches!(inner, IrMatcher::AllOf(_));
            let expr = if parts.is_empty() {
                None
            } else {
                Some(join_parts(backend, parts, all)?)
            };
            (expr, op)
        }
        other => (
            convert_leaf(backend, field, other, state)?,
            matcher_op(other),
        ),
    };

    let deferred = &mut state.deferred[deferred_before..];
    if !deferred.is_empty() {
        if expr.is_some() {
            return Err(ConvertError::UnsupportedModifier(
                "neq over a mix of inline and deferred expressions".into(),
            ));
        }
        if deferred.len() > 1 && matches!(inner, IrMatcher::AllOf(_)) {
            return Err(ConvertError::UnsupportedModifier(
                "neq over an |all list of deferred expressions".into(),
            ));
        }
        for part in deferred.iter_mut() {
            part.negate();
        }
        return Ok(None);
    }

    let Some(expr) = expr else {
        return Ok(None);
    };
    if contains_field_ref(inner) {
        let expr = group(backend, TokenType::NOT, Operand::new(expr, op))?;
        return Ok(Some(backend.convert_negated_field_ref(field, &expr)?));
    }
    Ok(Some(negate(backend, Operand::new(expr, op))?))
}

fn contains_field_ref(matcher: &IrMatcher) -> bool {
    match matcher {
        IrMatcher::FieldRef { .. } => true,
        IrMatcher::AnyOf(ms) | IrMatcher::AllOf(ms) => ms.iter().any(contains_field_ref),
        IrMatcher::Not(inner) => contains_field_ref(inner),
        _ => false,
    }
}

/// Lower an extended array block-body `condition` (`Conditional`) into a single
/// boolean expression over the named sub-selections.
pub fn convert_block_condition<B: Backend + ?Sized>(
    backend: &B,
    expr: &IrCondition,
    named: &HashMap<String, IrDetection>,
    state: &mut ConversionState,
) -> Result<String> {
    match expr {
        IrCondition::Detection(name) => {
            let det = named
                .get(name)
                .ok_or_else(|| ConvertError::InvalidIdentifier(name.clone()))?;
            backend.convert_ir_detection(det, state)
        }
        IrCondition::And(exprs) | IrCondition::Or(exprs) => {
            let parts = exprs
                .iter()
                .map(|e| {
                    let expr = convert_block_condition(backend, e, named, state)?;
                    Ok(Operand::new(expr, condition_op(e, named)))
                })
                .collect::<Result<Vec<_>>>()?;
            join(backend, matches!(expr, IrCondition::And(_)), parts)
        }
        IrCondition::Not(inner) => {
            let part = convert_block_condition(backend, inner, named, state)?;
            negate(backend, Operand::new(part, condition_op(inner, named)))
        }
        IrCondition::Selector {
            quantifier,
            pattern,
        } => {
            let all = match quantifier {
                Quantifier::Any => false,
                Quantifier::All => true,
                Quantifier::Count(_) => return Err(ConvertError::UnsupportedArrayMatching),
            };
            let parts = selected_detections(named, pattern)
                .into_iter()
                .map(|n| {
                    let det = &named[n];
                    let expr = backend.convert_ir_detection(det, state)?;
                    Ok(Operand::new(expr, detection_op(det)))
                })
                .collect::<Result<Vec<_>>>()?;
            join(backend, all, parts)
        }
    }
}
