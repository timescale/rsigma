//! IR-native detection/item dispatch for the `Backend` trait.
//!
//! Walks [`IrDetection`] / [`IrDetectionItem`] and calls the IR-native
//! `Backend` value leaves. Encoding transforms, `neq`, `expand`, and timestamp
//! parts have no faithful backend rendering and are rejected here, matching the
//! historical parser-path behavior.

use std::collections::HashMap;

use rsigma_ir::{IrCondition, IrDetection, IrDetectionItem, IrMatcher, IrNumber};
use rsigma_parser::Quantifier;

use crate::backend::{Backend, CompareOp};
use crate::convert::field_has_positional_index;
use crate::error::{ConvertError, Result};
use crate::state::{ConversionState, ConvertResult};

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

fn number(n: &IrNumber) -> Result<f64> {
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
            let parts: Vec<String> = items
                .iter()
                .map(|it| backend.convert_ir_detection_item(it, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_and(&parts)
        }
        IrDetection::AnyOf(dets) => {
            let parts: Vec<String> = dets
                .iter()
                .map(|d| backend.convert_ir_detection(d, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_or(&parts)
        }
        IrDetection::And(dets) => {
            let parts: Vec<String> = dets
                .iter()
                .map(|d| backend.convert_ir_detection(d, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_and(&parts)
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

fn convert_keyword<B: Backend + ?Sized>(
    backend: &B,
    matcher: &IrMatcher,
    state: &mut ConversionState,
) -> Result<String> {
    match matcher {
        IrMatcher::Str { pattern, .. } => backend.convert_keyword_str(pattern, state),
        IrMatcher::NumericEq(n) => backend.convert_keyword_num(number(n)?, state),
        _ => Err(ConvertError::UnsupportedKeyword),
    }
}

/// Default IR detection-item dispatch.
pub fn default_convert_ir_detection_item<B: Backend + ?Sized>(
    backend: &B,
    item: &IrDetectionItem,
    state: &mut ConversionState,
) -> Result<String> {
    let field = item
        .field
        .as_deref()
        .ok_or(ConvertError::MissingFieldName)?;

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
) -> Result<Vec<String>> {
    let mut parts = Vec::with_capacity(ms.len());
    for m in ms {
        if let Some(q) = convert_leaf(backend, field, m, state)? {
            parts.push(q);
        }
    }
    Ok(parts)
}

fn join_parts<B: Backend + ?Sized>(backend: &B, parts: Vec<String>, all: bool) -> Result<String> {
    if parts.is_empty() {
        return Ok(String::new());
    }
    if parts.len() == 1 {
        return Ok(parts.into_iter().next().unwrap());
    }
    if all {
        backend.convert_condition_and(&parts)
    } else {
        backend.convert_condition_or(&parts)
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
            let res = backend.convert_field_cidr(field, network, state)?;
            Ok(resolve(res, state))
        }
        IrMatcher::NumericEq(n) => Ok(Some(backend.convert_field_num(field, number(n)?, state)?)),
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
        IrMatcher::Null => Ok(Some(backend.convert_field_null(field, state)?)),
        IrMatcher::BoolEq(b) => Ok(Some(backend.convert_field_bool(field, *b, state)?)),
        IrMatcher::FieldRef { field: rf, .. } => {
            let res = backend.convert_field_ref(field, rf, state)?;
            Ok(resolve(res, state))
        }
        // Encoding transforms, negation, expand, and timestamp parts have no
        // faithful backend rendering; reject them (as the parser path did).
        IrMatcher::Encoded { .. } => Err(ConvertError::UnsupportedModifier(
            "value-transformation modifiers (base64/wide/utf16/windash) are not \
             expressible as a backend query"
                .into(),
        )),
        IrMatcher::Not(_) => Err(ConvertError::UnsupportedModifier("Neq".into())),
        IrMatcher::Expand { .. } => Err(ConvertError::UnsupportedModifier("Expand".into())),
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
        IrCondition::And(exprs) => {
            let parts = exprs
                .iter()
                .map(|e| {
                    let sql = convert_block_condition(backend, e, named, state)?;
                    Ok(if matches!(e, IrCondition::Or(_)) {
                        format!("({sql})")
                    } else {
                        sql
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_and(&parts)
        }
        IrCondition::Or(exprs) => {
            let parts = exprs
                .iter()
                .map(|e| convert_block_condition(backend, e, named, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_or(&parts)
        }
        IrCondition::Not(inner) => {
            let part = convert_block_condition(backend, inner, named, state)?;
            backend.convert_condition_not(&format!("({part})"))
        }
        IrCondition::Selector {
            quantifier,
            pattern,
        } => {
            let mut names: Vec<&String> = named
                .keys()
                .filter(|n| pattern.matches_detection_name(n))
                .collect();
            names.sort();
            let parts = names
                .iter()
                .map(|n| backend.convert_ir_detection(&named[*n], state))
                .collect::<Result<Vec<_>>>()?;
            match quantifier {
                Quantifier::Any => backend.convert_condition_or(&parts),
                Quantifier::All => backend.convert_condition_and(&parts),
                Quantifier::Count(_) => Err(ConvertError::UnsupportedArrayMatching),
            }
        }
    }
}
