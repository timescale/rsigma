//! Convert [`IrCondition`] trees against a rule's [`IrDetection`] map.
//!
//! The whole rule is lowered to HIR once (`convert_rule_via_ir`); both the
//! detection bodies and the conditions are then walked from the IR. Quantified
//! selectors are resolved here against the IR detections, mirroring eval:
//! an empty match set is rejected, `any` / `1 of` become OR, `all of` becomes
//! AND, and `N of` (N > 1) is unsupported.

use std::collections::HashMap;

use rsigma_eval::pipeline::PipelineState;
use rsigma_ir::{IrCondition, IrDetection, IrRule};
use rsigma_parser::{Quantifier, SigmaRule};

use crate::backend::Backend;
use crate::error::{ConvertError, Result};
use crate::ir_convert::{Operand, condition_op, detection_op, join, negate, selected_detections};
use crate::state::ConversionState;

/// Walk an [`IrCondition`] and convert each node into a query fragment.
///
/// Selectors are resolved here against the rule's detections, mirroring the
/// parser condition walker: an empty match set is rejected, `any` / `1 of`
/// become OR, `all of` becomes AND, and `N of` (N > 1) is unsupported.
/// Compound operands are grouped through [`Backend::convert_condition_group`].
pub fn convert_ir_condition(
    backend: &dyn Backend,
    expr: &IrCondition,
    detections: &HashMap<String, IrDetection>,
    state: &mut ConversionState,
) -> Result<String> {
    match expr {
        IrCondition::Detection(name) => {
            let det = detections.get(name).ok_or_else(|| {
                ConvertError::RuleConversion(format!("detection '{name}' not found"))
            })?;
            backend.convert_ir_detection(det, state)
        }
        IrCondition::And(exprs) | IrCondition::Or(exprs) => {
            let parts = exprs
                .iter()
                .map(|e| {
                    let part = convert_ir_condition(backend, e, detections, state)?;
                    Ok(Operand::new(part, condition_op(e, detections)))
                })
                .collect::<Result<Vec<_>>>()?;
            join(backend, matches!(expr, IrCondition::And(_)), parts)
        }
        IrCondition::Not(inner) => {
            let part = convert_ir_condition(backend, inner, detections, state)?;
            negate(backend, Operand::new(part, condition_op(inner, detections)))
        }
        IrCondition::Selector {
            quantifier,
            pattern,
        } => {
            let names = selected_detections(detections, pattern);
            if names.is_empty() {
                return Err(ConvertError::RuleConversion(
                    "selector matched no detections".into(),
                ));
            }
            let all = match quantifier {
                Quantifier::Any => false,
                Quantifier::Count(n) if n.get() == 1 => false,
                Quantifier::All => true,
                Quantifier::Count(n) => {
                    return Err(ConvertError::RuleConversion(format!(
                        "'{n} of' quantifier not supported in conversion"
                    )));
                }
            };

            let parts = names
                .into_iter()
                .map(|name| {
                    let det = &detections[name];
                    let part = backend.convert_ir_detection(det, state)?;
                    Ok(Operand::new(part, detection_op(det)))
                })
                .collect::<Result<Vec<_>>>()?;
            join(backend, all, parts)
        }
    }
}

/// Map an IR lowering error to the closest `ConvertError`, preserving the
/// error kinds convert historically surfaced (invalid/unsupported modifiers,
/// incompatible values).
pub(crate) fn ir_err(e: rsigma_ir::IrError) -> ConvertError {
    use rsigma_ir::IrError;
    match e {
        IrError::InvalidModifiers(m) => ConvertError::UnsupportedModifier(m),
        IrError::IncompatibleValue(m) | IrError::ExpectedNumeric(m) => {
            ConvertError::UnsupportedValue(m)
        }
        other => ConvertError::RuleConversion(other.to_string()),
    }
}

/// Lower a rule to the IR that conversion walks, with encoding modifiers
/// expanded into plain matches on fields. Keywords keep them, since a
/// keyword term that is a base64 fragment renders differently.
pub(crate) fn lower_rule_for_conversion(rule: &SigmaRule) -> Result<IrRule> {
    let mut ir =
        rsigma_ir::lower_rule(rule, &rsigma_ir::LowerOptions::default()).map_err(ir_err)?;
    ir.detections
        .values_mut()
        .try_for_each(expand_field_encodings)
        .map_err(ir_err)?;
    Ok(ir)
}

fn expand_field_encodings(det: &mut IrDetection) -> std::result::Result<(), rsigma_ir::IrError> {
    match det {
        IrDetection::AllOf(items) => items
            .iter_mut()
            .filter(|item| item.field.is_some())
            .try_for_each(|item| rsigma_ir::encoding::expand_encoded_matcher(&mut item.matcher)),
        IrDetection::AnyOf(dets) | IrDetection::And(dets) => {
            dets.iter_mut().try_for_each(expand_field_encodings)
        }
        IrDetection::Keywords(_) => Ok(()),
        // A field-less item in an array body compares the array member.
        IrDetection::ArrayMatch { body, .. } => rsigma_ir::encoding::expand_encoded_detection(body),
        IrDetection::Conditional { named, .. } => {
            named.values_mut().try_for_each(expand_field_encodings)
        }
    }
}

/// Fresh state for converting one condition of a rule.
pub(crate) fn condition_state(
    pipeline_state: &PipelineState,
    output_format: &str,
) -> ConversionState {
    let mut state = ConversionState::new(pipeline_state.state.clone());
    state
        .processing_state
        .insert("_output_format".to_string(), output_format.into());
    state
}

/// Shared `Backend::convert_rule` implementation: lower the whole rule to HIR
/// and convert detections and conditions from the faithful IR.
pub fn convert_rule_via_ir(
    backend: &dyn Backend,
    rule: &SigmaRule,
    output_format: &str,
    pipeline_state: &PipelineState,
) -> Result<Vec<String>> {
    let ir = lower_rule_for_conversion(rule)?;
    convert_lowered_rule(backend, rule, &ir, output_format, pipeline_state)
}

/// Convert every condition of an already lowered rule.
pub(crate) fn convert_lowered_rule(
    backend: &dyn Backend,
    rule: &SigmaRule,
    ir: &IrRule,
    output_format: &str,
    pipeline_state: &PipelineState,
) -> Result<Vec<String>> {
    let mut queries = Vec::with_capacity(ir.conditions.len());
    for (idx, cond) in ir.conditions.iter().enumerate() {
        let mut state = condition_state(pipeline_state, output_format);
        let query = convert_ir_condition(backend, cond, &ir.detections, &mut state)?;
        let finished = backend.finish_query(rule, query, &state)?;
        let finalized = backend.finalize_query(rule, finished, idx, &state, output_format)?;
        queries.push(finalized);
    }
    Ok(queries)
}
