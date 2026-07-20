//! Compile HIR (`IrRule`) into physical [`CompiledRule`] form.
//!
//! This is the second half of the IR-backed compile path:
//! `lower_rule` (rsigma-ir) → [`compile_to_compiled`] → matcher optimizer.

use std::collections::HashMap;
use std::sync::Arc;

use regex::Regex;
use rsigma_ir::{
    IrCondition, IrDetection, IrDetectionItem, IrExpandPart, IrMatcher, IrNumber, IrRule,
    IrTimePart, IrValue,
};
use rsigma_parser::ConditionExpr;

use crate::error::{EvalError, Result};
use crate::matcher::{CompiledMatcher, ExpandPart, TimePart};

use super::optimizer;
use super::{CompiledDetection, CompiledDetectionItem, CompiledRule};

/// Compile an [`IrRule`] into a physical [`CompiledRule`] ready for evaluation.
pub fn compile_to_compiled(ir: &IrRule) -> Result<CompiledRule> {
    let mut detections = HashMap::new();
    for (name, detection) in &ir.detections {
        detections.insert(name.clone(), compile_ir_detection(detection)?);
    }

    let conditions: Vec<ConditionExpr> = ir
        .conditions
        .iter()
        .map(ir_condition_to_expr)
        .collect();

    let include_event = ir
        .metadata
        .custom_attributes
        .get("rsigma.include_event")
        .and_then(|v| v.as_str())
        == Some("true");

    Ok(CompiledRule {
        title: ir.metadata.title.clone(),
        id: ir.metadata.id.clone(),
        level: ir.metadata.level,
        tags: ir.metadata.tags.clone(),
        logsource: ir.logsource.clone(),
        detections,
        conditions,
        include_event,
        custom_attributes: Arc::new(ir.metadata.custom_attributes.clone()),
    })
}

fn compile_ir_detection(detection: &IrDetection) -> Result<CompiledDetection> {
    match detection {
        IrDetection::AllOf(items) => {
            if items.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "AllOf detection must not be empty (vacuous truth)".into(),
                ));
            }
            let compiled: Result<Vec<_>> = items.iter().map(compile_ir_detection_item).collect();
            Ok(CompiledDetection::AllOf(compiled?))
        }
        IrDetection::AnyOf(dets) => {
            if dets.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "AnyOf detection must not be empty (would never match)".into(),
                ));
            }
            let compiled: Result<Vec<_>> = dets.iter().map(compile_ir_detection).collect();
            Ok(CompiledDetection::AnyOf(compiled?))
        }
        IrDetection::ArrayMatch {
            field,
            quantifier,
            body,
        } => Ok(CompiledDetection::ArrayMatch {
            field: field.clone(),
            quantifier: *quantifier,
            body: Box::new(compile_ir_detection(body)?),
        }),
        IrDetection::And(dets) => {
            if dets.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "And detection must not be empty".into(),
                ));
            }
            let compiled: Result<Vec<_>> = dets.iter().map(compile_ir_detection).collect();
            Ok(CompiledDetection::And(compiled?))
        }
        IrDetection::Conditional { named, condition } => {
            if named.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "Conditional detection must have at least one named sub-selection".into(),
                ));
            }
            let compiled: Result<HashMap<String, CompiledDetection>> = named
                .iter()
                .map(|(k, d)| Ok((k.clone(), compile_ir_detection(d)?)))
                .collect();
            Ok(CompiledDetection::Conditional {
                named: compiled?,
                condition: ir_condition_to_expr(condition),
            })
        }
        IrDetection::Keywords(matcher) => {
            let compiled = compile_ir_matcher(matcher)?;
            // Keywords are OR-semantics; apply AnyOf optimizer when present.
            let matcher = match compiled {
                CompiledMatcher::AnyOf(ms) => optimizer::optimize_any_of(ms),
                other => other,
            };
            Ok(CompiledDetection::Keywords(matcher))
        }
    }
}

fn compile_ir_detection_item(item: &IrDetectionItem) -> Result<CompiledDetectionItem> {
    let matcher = compile_ir_matcher(&item.matcher)?;
    let bloom_eligible = item.field.is_some()
        && crate::engine::bloom_index::is_positive_substring_matcher(&matcher);

    Ok(CompiledDetectionItem {
        field: item.field.clone(),
        matcher,
        exists: item.exists,
        bloom_eligible,
    })
}

fn compile_ir_matcher(matcher: &IrMatcher) -> Result<CompiledMatcher> {
    match matcher {
        IrMatcher::Exact {
            value,
            case_insensitive,
        } => Ok(CompiledMatcher::Exact {
            value: ir_value_literal(value)?,
            case_insensitive: *case_insensitive,
        }),
        IrMatcher::Contains {
            value,
            case_insensitive,
        } => Ok(CompiledMatcher::Contains {
            value: ir_value_literal(value)?,
            case_insensitive: *case_insensitive,
        }),
        IrMatcher::StartsWith {
            value,
            case_insensitive,
        } => Ok(CompiledMatcher::StartsWith {
            value: ir_value_literal(value)?,
            case_insensitive: *case_insensitive,
        }),
        IrMatcher::EndsWith {
            value,
            case_insensitive,
        } => Ok(CompiledMatcher::EndsWith {
            value: ir_value_literal(value)?,
            case_insensitive: *case_insensitive,
        }),
        IrMatcher::Regex { pattern } => {
            let pattern = ir_value_literal(pattern)?;
            let regex = Regex::new(&pattern).map_err(EvalError::InvalidRegex)?;
            Ok(CompiledMatcher::Regex(regex))
        }
        IrMatcher::Cidr { network } => {
            let cidr_str = ir_value_literal(network)?;
            let net: ipnet::IpNet = cidr_str.parse().map_err(EvalError::InvalidCidr)?;
            Ok(CompiledMatcher::Cidr(net))
        }
        IrMatcher::NumericEq(n) => Ok(CompiledMatcher::NumericEq(ir_number_literal(n)?)),
        IrMatcher::NumericGt(n) => Ok(CompiledMatcher::NumericGt(ir_number_literal(n)?)),
        IrMatcher::NumericGte(n) => Ok(CompiledMatcher::NumericGte(ir_number_literal(n)?)),
        IrMatcher::NumericLt(n) => Ok(CompiledMatcher::NumericLt(ir_number_literal(n)?)),
        IrMatcher::NumericLte(n) => Ok(CompiledMatcher::NumericLte(ir_number_literal(n)?)),
        IrMatcher::Exists(b) => Ok(CompiledMatcher::Exists(*b)),
        IrMatcher::FieldRef {
            field,
            case_insensitive,
        } => Ok(CompiledMatcher::FieldRef {
            field: field.clone(),
            case_insensitive: *case_insensitive,
        }),
        IrMatcher::Null => Ok(CompiledMatcher::Null),
        IrMatcher::BoolEq(b) => Ok(CompiledMatcher::BoolEq(*b)),
        IrMatcher::Expand {
            template,
            case_insensitive,
        } => Ok(CompiledMatcher::Expand {
            template: template.iter().map(ir_expand_part).collect(),
            case_insensitive: *case_insensitive,
        }),
        IrMatcher::TimestampPart { part, inner } => Ok(CompiledMatcher::TimestampPart {
            part: ir_time_part(*part),
            inner: Box::new(compile_ir_matcher(inner)?),
        }),
        IrMatcher::Not(inner) => Ok(CompiledMatcher::Not(Box::new(compile_ir_matcher(inner)?))),
        IrMatcher::AnyOf(ms) => {
            let compiled: Result<Vec<_>> = ms.iter().map(compile_ir_matcher).collect();
            Ok(optimizer::optimize_any_of(compiled?))
        }
        IrMatcher::AllOf(ms) => {
            let compiled: Result<Vec<_>> = ms.iter().map(compile_ir_matcher).collect();
            Ok(CompiledMatcher::AllOf(compiled?))
        }
    }
}

fn ir_condition_to_expr(cond: &IrCondition) -> ConditionExpr {
    match cond {
        IrCondition::Detection(name) => ConditionExpr::Identifier(name.clone()),
        IrCondition::And(exprs) => {
            ConditionExpr::And(exprs.iter().map(ir_condition_to_expr).collect())
        }
        IrCondition::Or(exprs) => {
            ConditionExpr::Or(exprs.iter().map(ir_condition_to_expr).collect())
        }
        IrCondition::Not(inner) => ConditionExpr::Not(Box::new(ir_condition_to_expr(inner))),
    }
}

fn ir_value_literal(value: &IrValue) -> Result<String> {
    match value {
        IrValue::Literal(s) => Ok(s.clone()),
        IrValue::DynamicSourceRef { source_id, .. } => Err(EvalError::IncompatibleValue(format!(
            "unresolved dynamic source reference '{source_id}' cannot be compiled; \
             specialize the IR first"
        ))),
    }
}

fn ir_number_literal(n: &IrNumber) -> Result<f64> {
    match n {
        IrNumber::Literal(v) => Ok(*v),
        IrNumber::DynamicSourceRef { source_id, .. } => Err(EvalError::IncompatibleValue(format!(
            "unresolved dynamic source reference '{source_id}' cannot be compiled; \
             specialize the IR first"
        ))),
    }
}

fn ir_expand_part(part: &IrExpandPart) -> ExpandPart {
    match part {
        IrExpandPart::Literal(s) => ExpandPart::Literal(s.clone()),
        IrExpandPart::Placeholder(s) => ExpandPart::Placeholder(s.clone()),
    }
}

fn ir_time_part(part: IrTimePart) -> TimePart {
    match part {
        IrTimePart::Minute => TimePart::Minute,
        IrTimePart::Hour => TimePart::Hour,
        IrTimePart::Day => TimePart::Day,
        IrTimePart::Week => TimePart::Week,
        IrTimePart::Month => TimePart::Month,
        IrTimePart::Year => TimePart::Year,
    }
}
