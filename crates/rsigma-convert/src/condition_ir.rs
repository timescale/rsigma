//! Convert selector-free [`IrCondition`] trees against parser AST detections.
//!
//! Detection bodies still use the existing `Backend::convert_detection` path;
//! conditions are taken from `lower_conditions` so convert no longer resolves
//! selectors itself.

use std::collections::HashMap;

use rsigma_eval::pipeline::PipelineState;
use rsigma_ir::{IrCondition, IrDetection};
use rsigma_parser::{Quantifier, SigmaRule};

use crate::backend::Backend;
use crate::error::{ConvertError, Result};
use crate::state::ConversionState;

/// Walk an [`IrCondition`] and convert each node into a query fragment.
///
/// Selectors are resolved here against the rule's detections, mirroring the
/// parser condition walker: an empty match set is rejected, `any` / `1 of`
/// become OR, `all of` becomes AND, and `N of` (N > 1) is unsupported.
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
        IrCondition::And(exprs) => {
            let parts: Vec<String> = exprs
                .iter()
                .map(|e| convert_ir_condition(backend, e, detections, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_and(&parts)
        }
        IrCondition::Or(exprs) => {
            let parts: Vec<String> = exprs
                .iter()
                .map(|e| convert_ir_condition(backend, e, detections, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_or(&parts)
        }
        IrCondition::Not(inner) => {
            let part = convert_ir_condition(backend, inner, detections, state)?;
            backend.convert_condition_not(&part)
        }
        IrCondition::Selector {
            quantifier,
            pattern,
        } => {
            let mut names: Vec<&String> = detections
                .keys()
                .filter(|n| pattern.matches_detection_name(n))
                .collect();
            if names.is_empty() {
                return Err(ConvertError::RuleConversion(
                    "selector matched no detections".into(),
                ));
            }
            // Deterministic output regardless of HashMap iteration order.
            names.sort();

            let parts: Vec<String> = names
                .iter()
                .map(|name| {
                    let det = detections.get(*name).ok_or_else(|| {
                        ConvertError::RuleConversion(format!(
                            "selector matched detection '{name}' but it disappeared before lookup"
                        ))
                    })?;
                    backend.convert_ir_detection(det, state)
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

/// Map an IR lowering error to the closest `ConvertError`, preserving the
/// error kinds convert historically surfaced (invalid/unsupported modifiers,
/// incompatible values).
fn ir_err(e: rsigma_ir::IrError) -> ConvertError {
    use rsigma_ir::IrError;
    match e {
        IrError::InvalidModifiers(m) => ConvertError::UnsupportedModifier(m),
        IrError::IncompatibleValue(m) | IrError::ExpectedNumeric(m) => {
            ConvertError::UnsupportedValue(m)
        }
        other => ConvertError::RuleConversion(other.to_string()),
    }
}

/// Shared `Backend::convert_rule` implementation: lower the whole rule to HIR
/// and convert detections and conditions from the faithful IR.
pub fn convert_rule_via_ir(
    backend: &dyn Backend,
    rule: &SigmaRule,
    output_format: &str,
    pipeline_state: &PipelineState,
) -> Result<Vec<String>> {
    let ir = rsigma_ir::lower_rule(rule, &rsigma_ir::LowerOptions::default()).map_err(ir_err)?;

    let mut queries = Vec::with_capacity(ir.conditions.len());
    for (idx, cond) in ir.conditions.iter().enumerate() {
        let mut state = ConversionState::new(pipeline_state.state.clone());
        state
            .processing_state
            .insert("_output_format".to_string(), output_format.into());
        let query = convert_ir_condition(backend, cond, &ir.detections, &mut state)?;
        let finished = backend.finish_query(rule, query, &state)?;
        let finalized = backend.finalize_query(rule, finished, idx, &state, output_format)?;
        queries.push(finalized);
    }
    Ok(queries)
}
