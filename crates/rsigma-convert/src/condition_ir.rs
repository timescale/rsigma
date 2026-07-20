//! Convert selector-free [`IrCondition`] trees against parser AST detections.
//!
//! Detection bodies still use the existing `Backend::convert_detection` path
//! (modifier dispatch via AST / `SurfaceSpec` comes later). Conditions are
//! taken from `lower_rule` so convert no longer re-resolves selectors.

use std::collections::HashMap;

use rsigma_eval::pipeline::PipelineState;
use rsigma_ir::IrCondition;
use rsigma_parser::{Detection, SigmaRule};

use crate::backend::Backend;
use crate::error::{ConvertError, Result};
use crate::state::ConversionState;

/// Walk an [`IrCondition`] and convert each node into a query fragment.
///
/// Empty `And` / `Or` (vacuous selector collapse) is rejected so convert keeps
/// today's "selector matched no detections" behavior, which differs from eval's
/// vacuous-true `all of` semantics.
pub fn convert_ir_condition(
    backend: &dyn Backend,
    expr: &IrCondition,
    detections: &HashMap<String, Detection>,
    state: &mut ConversionState,
) -> Result<String> {
    match expr {
        IrCondition::Detection(name) => {
            let det = detections.get(name).ok_or_else(|| {
                ConvertError::RuleConversion(format!("detection '{name}' not found"))
            })?;
            backend.convert_detection(det, state)
        }
        IrCondition::And(exprs) => {
            if exprs.is_empty() {
                return Err(ConvertError::RuleConversion(
                    "selector matched no detections".into(),
                ));
            }
            let parts: Vec<String> = exprs
                .iter()
                .map(|e| convert_ir_condition(backend, e, detections, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_and(&parts)
        }
        IrCondition::Or(exprs) => {
            if exprs.is_empty() {
                return Err(ConvertError::RuleConversion(
                    "selector matched no detections".into(),
                ));
            }
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
    }
}

/// Reject `N of` selectors with N > 1 before lowering.
///
/// IR lowers those into combinatorial `Or`/`And` trees; convert historically
/// rejected them, so fail early with the same class of error.
pub fn reject_unsupported_convert_selectors(expr: &rsigma_parser::ConditionExpr) -> Result<()> {
    use rsigma_parser::{ConditionExpr, Quantifier};
    match expr {
        ConditionExpr::Selector {
            quantifier: Quantifier::Count(n),
            ..
        } if *n != 1 => Err(ConvertError::RuleConversion(format!(
            "'{n} of' quantifier not supported in conversion"
        ))),
        ConditionExpr::And(exprs) | ConditionExpr::Or(exprs) => {
            for e in exprs {
                reject_unsupported_convert_selectors(e)?;
            }
            Ok(())
        }
        ConditionExpr::Not(inner) => reject_unsupported_convert_selectors(inner),
        _ => Ok(()),
    }
}

fn ir_error_to_convert(err: rsigma_ir::IrError) -> ConvertError {
    use rsigma_ir::IrError;
    match err {
        IrError::InvalidModifiers(msg) => ConvertError::UnsupportedModifier(msg),
        IrError::InvalidRegex(e) => ConvertError::UnsupportedModifier(e.to_string()),
        IrError::IncompatibleValue(msg) | IrError::ExpectedNumeric(msg) => {
            ConvertError::UnsupportedValue(msg)
        }
        IrError::InvalidCidr(e) => ConvertError::CidrParse(e.to_string()),
        other => ConvertError::RuleConversion(other.to_string()),
    }
}

/// Shared `Backend::convert_rule` implementation: lower conditions via IR, keep
/// detection conversion on the parser AST.
pub fn convert_rule_via_ir(
    backend: &dyn Backend,
    rule: &SigmaRule,
    output_format: &str,
    pipeline_state: &PipelineState,
) -> Result<Vec<String>> {
    for cond in &rule.detection.conditions {
        reject_unsupported_convert_selectors(cond)?;
    }
    let ir = rsigma_ir::lower_rule(rule, &rsigma_ir::LowerOptions::default())
        .map_err(ir_error_to_convert)?;

    let mut queries = Vec::with_capacity(ir.conditions.len());
    for (idx, cond) in ir.conditions.iter().enumerate() {
        let mut state = ConversionState::new(pipeline_state.state.clone());
        state
            .processing_state
            .insert("_output_format".to_string(), output_format.into());
        let query = convert_ir_condition(backend, cond, &rule.detection.named, &mut state)?;
        let finished = backend.finish_query(rule, query, &state)?;
        let finalized = backend.finalize_query(rule, finished, idx, &state, output_format)?;
        queries.push(finalized);
    }
    Ok(queries)
}
