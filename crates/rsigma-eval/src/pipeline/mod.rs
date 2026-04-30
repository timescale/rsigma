//! Processing pipeline system for transforming Sigma rules before evaluation.
//!
//! Pipelines are parsed from YAML and applied to `SigmaRule` AST nodes before
//! compilation, transforming field names, logsources, values, and detection
//! structure.
//!
//! # Architecture
//!
//! 1. Parse pipeline(s) from YAML
//! 2. Sort by priority (lower = first)
//! 3. For each rule: apply all pipeline transformations in order
//! 4. Compile the transformed rule
//! 5. Evaluate against events
//!
//! # Example
//!
//! ```rust
//! use rsigma_eval::pipeline::{Pipeline, parse_pipeline};
//!
//! let yaml = r#"
//! name: Sysmon Field Mapping
//! priority: 10
//! transformations:
//!   - id: sysmon_field_mapping
//!     type: field_name_mapping
//!     mapping:
//!       CommandLine: process.command_line
//!       ParentImage: process.parent.executable
//!     rule_conditions:
//!       - type: logsource
//!         product: windows
//! "#;
//!
//! let pipeline = parse_pipeline(yaml).unwrap();
//! assert_eq!(pipeline.name, "Sysmon Field Mapping");
//! ```

pub mod conditions;
pub mod finalizers;
mod parsing;
pub mod state;
pub mod transformations;

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use rsigma_parser::{CorrelationRule, SigmaCollection, SigmaRule};

use crate::error::{EvalError, Result};

pub use conditions::{
    DetectionItemCondition, FieldNameCondition, NamedRuleCondition, RuleCondition,
    eval_condition_expr,
};
pub use finalizers::Finalizer;
pub use parsing::{parse_pipeline, parse_pipeline_file};
pub use state::PipelineState;
pub use transformations::Transformation;

// =============================================================================
// Pipeline types
// =============================================================================

/// A processing pipeline consisting of ordered transformations with conditions.
#[derive(Debug, Clone)]
pub struct Pipeline {
    /// Pipeline name.
    pub name: String,
    /// Priority (lower runs first). Default: 0.
    pub priority: i32,
    /// Pipeline variables used for placeholder expansion.
    pub vars: HashMap<String, Vec<String>>,
    /// Ordered list of transformations with their conditions.
    pub transformations: Vec<TransformationItem>,
    /// Finalizers (stored for YAML compat; eval-mode ignores them).
    pub finalizers: Vec<Finalizer>,
}

/// A single transformation with its gating conditions.
#[derive(Debug, Clone)]
pub struct TransformationItem {
    /// Optional ID for tracking in pipeline state.
    pub id: Option<String>,
    /// The transformation to apply.
    pub transformation: Transformation,
    /// Rule-level conditions (all must match for the transformation to fire).
    pub rule_conditions: Vec<NamedRuleCondition>,
    /// Optional logical expression over condition IDs.
    pub rule_cond_expr: Option<String>,
    /// Detection-item-level conditions.
    pub detection_item_conditions: Vec<DetectionItemCondition>,
    /// Field-name-level conditions.
    pub field_name_conditions: Vec<FieldNameCondition>,
    /// If true, negate the field name conditions.
    pub field_name_cond_not: bool,
}

// =============================================================================
// Pipeline application
// =============================================================================

impl Pipeline {
    /// Apply this pipeline to a single `SigmaRule`, mutating it in place.
    pub fn apply(&self, rule: &mut SigmaRule, state: &mut PipelineState) -> Result<()> {
        state.reset_rule();

        for item in &self.transformations {
            // Check rule-level conditions
            if !self.check_rule_conditions(rule, state, item) {
                continue;
            }

            state.reset_detection_item();

            // Apply the transformation
            let applied = item.transformation.apply(
                rule,
                state,
                &item.detection_item_conditions,
                &item.field_name_conditions,
                item.field_name_cond_not,
            )?;

            // Track application in state
            if applied && let Some(ref id) = item.id {
                state.mark_applied(id);
            }
        }

        Ok(())
    }

    /// Apply this pipeline to all rules in a collection.
    ///
    /// Returns cloned, transformed rules (originals are not modified).
    pub fn apply_to_collection(&self, collection: &SigmaCollection) -> Result<Vec<SigmaRule>> {
        let mut state = PipelineState::new(self.vars.clone());
        let mut transformed = Vec::with_capacity(collection.rules.len());

        for rule in &collection.rules {
            let mut cloned = rule.clone();
            self.apply(&mut cloned, &mut state)?;
            transformed.push(cloned);
        }

        Ok(transformed)
    }

    fn check_rule_conditions(
        &self,
        rule: &SigmaRule,
        state: &PipelineState,
        item: &TransformationItem,
    ) -> bool {
        if item.rule_conditions.is_empty() {
            return true;
        }

        if let Some(ref expr) = item.rule_cond_expr {
            let mut results = HashMap::new();
            for (i, named) in item.rule_conditions.iter().enumerate() {
                let id = named.id.clone().unwrap_or_else(|| format!("cond_{i}"));
                results.insert(id, named.condition.matches_rule(rule, state));
            }
            return eval_condition_expr(expr, &results);
        }

        // Default: all conditions must match (AND)
        item.rule_conditions
            .iter()
            .all(|c| c.condition.matches_rule(rule, state))
    }

    /// Apply this pipeline to a correlation rule, mutating it in place.
    ///
    /// Only correlation-applicable transformations fire:
    /// - `FieldNameMapping` / `FieldNamePrefixMapping` — remap `group_by` and
    ///   `aliases` mapping values
    /// - `FieldNamePrefix` / `FieldNameSuffix` — modify `group_by` and alias values
    /// - `SetCustomAttribute` — set key-value on `custom_attributes`
    /// - `SetState` — update pipeline state
    /// - `RuleFailure` — error if conditions match
    ///
    /// Detection-specific transforms (value replacements, detection item
    /// manipulation, etc.) are silently skipped.
    pub fn apply_to_correlation(
        &self,
        corr: &mut CorrelationRule,
        state: &mut PipelineState,
    ) -> Result<()> {
        state.reset_rule();

        for item in &self.transformations {
            if !self.check_correlation_conditions(corr, state, item) {
                continue;
            }

            state.reset_detection_item();

            let applied = apply_correlation_transformation(corr, &item.transformation, state)?;

            if applied && let Some(ref id) = item.id {
                state.mark_applied(id);
            }
        }

        Ok(())
    }

    fn check_correlation_conditions(
        &self,
        corr: &CorrelationRule,
        state: &PipelineState,
        item: &TransformationItem,
    ) -> bool {
        if item.rule_conditions.is_empty() {
            return true;
        }

        if let Some(ref expr) = item.rule_cond_expr {
            let mut results = HashMap::new();
            for (i, named) in item.rule_conditions.iter().enumerate() {
                let id = named.id.clone().unwrap_or_else(|| format!("cond_{i}"));
                results.insert(id, named.condition.matches_correlation(corr, state));
            }
            return eval_condition_expr(expr, &results);
        }

        item.rule_conditions
            .iter()
            .all(|c| c.condition.matches_correlation(corr, state))
    }
}

/// Apply a single transformation to a correlation rule.
///
/// Returns `true` if the transformation was meaningfully applied.
fn apply_correlation_transformation(
    corr: &mut CorrelationRule,
    transformation: &Transformation,
    state: &mut PipelineState,
) -> Result<bool> {
    match transformation {
        Transformation::FieldNameMapping { mapping } => {
            // Match pySigma's FieldMappingTransformationBase.apply() for
            // correlation rules: group_by expands all alternatives, while
            // aliases and threshold field reject one-to-many mappings.
            let alias_names: std::collections::HashSet<String> =
                corr.aliases.iter().map(|a| a.alias.clone()).collect();

            // aliases: error if any mapping value has multiple alternatives
            for alias in &mut corr.aliases {
                for (rule_ref, field_name) in &mut alias.mapping {
                    if let Some(alts) = mapping.get(field_name.as_str())
                        && alts.len() > 1
                    {
                        return Err(EvalError::InvalidModifiers(format!(
                            "field_name_mapping one-to-many cannot be applied to \
                             correlation alias mapping (alias '{}', rule '{}', \
                             field '{}' maps to {} alternatives)",
                            alias.alias,
                            rule_ref,
                            field_name,
                            alts.len(),
                        )));
                    } else if let Some(alts) = mapping.get(field_name.as_str()) {
                        *field_name = alts[0].clone();
                    }
                }
            }

            // group_by: expand all alternatives (skip alias names)
            corr.group_by = corr
                .group_by
                .iter()
                .flat_map(|field_name| {
                    if alias_names.contains(field_name.as_str()) {
                        vec![field_name.clone()]
                    } else if let Some(alts) = mapping.get(field_name.as_str()) {
                        alts.clone()
                    } else {
                        vec![field_name.clone()]
                    }
                })
                .collect();

            // threshold field: error if multiple alternatives
            if let rsigma_parser::CorrelationCondition::Threshold { ref mut field, .. } =
                corr.condition
                && let Some(fields) = field.as_mut()
            {
                for f in fields.iter_mut() {
                    if let Some(alts) = mapping.get(f.as_str()) {
                        if alts.len() > 1 {
                            return Err(EvalError::InvalidModifiers(format!(
                                "field_name_mapping one-to-many cannot be applied to \
                                 correlation condition field reference ('{}' maps to \
                                 {} alternatives)",
                                f,
                                alts.len(),
                            )));
                        }
                        *f = alts[0].clone();
                    }
                }
            }

            Ok(true)
        }

        Transformation::FieldNamePrefixMapping { mapping } => {
            remap_correlation_fields(corr, |name| {
                for (prefix, replacement) in mapping {
                    if let Some(rest) = name.strip_prefix(prefix.as_str()) {
                        return Some(format!("{replacement}{rest}"));
                    }
                }
                None
            });
            Ok(true)
        }

        Transformation::FieldNamePrefix { prefix } => {
            remap_correlation_fields(corr, |name| Some(format!("{prefix}{name}")));
            Ok(true)
        }

        Transformation::FieldNameSuffix { suffix } => {
            remap_correlation_fields(corr, |name| Some(format!("{name}{suffix}")));
            Ok(true)
        }

        Transformation::SetCustomAttribute { attribute, value } => {
            corr.custom_attributes
                .insert(attribute.clone(), serde_yaml::Value::String(value.clone()));
            Ok(true)
        }

        Transformation::SetState { key, value } => {
            state.set_state(key.clone(), serde_json::Value::String(value.clone()));
            Ok(true)
        }

        Transformation::RuleFailure { message } => Err(EvalError::InvalidModifiers(format!(
            "Pipeline rule failure: {message} (correlation: {})",
            corr.title
        ))),

        // Detection-specific transforms are no-ops for correlations
        _ => Ok(false),
    }
}

/// Apply a field name mapping function to all field references in a correlation rule:
/// `group_by` entries, `aliases` mapping values, and the `condition` field.
fn remap_correlation_fields(corr: &mut CorrelationRule, mapper: impl Fn(&str) -> Option<String>) {
    for field in &mut corr.group_by {
        if let Some(new_name) = mapper(field) {
            *field = new_name;
        }
    }

    for alias in &mut corr.aliases {
        let remapped: HashMap<String, String> = alias
            .mapping
            .iter()
            .map(|(rule_ref, field_name)| {
                let new_name = mapper(field_name).unwrap_or_else(|| field_name.clone());
                (rule_ref.clone(), new_name)
            })
            .collect();
        alias.mapping = remapped;
    }

    if let rsigma_parser::CorrelationCondition::Threshold { ref mut field, .. } = corr.condition
        && let Some(fields) = field.as_mut()
    {
        for f in fields.iter_mut() {
            if let Some(new_name) = mapper(f) {
                *f = new_name;
            }
        }
    }
}

// =============================================================================
// Multi-pipeline support
// =============================================================================

/// Sort pipelines by priority (lower = first) and apply them in order.
pub fn merge_pipelines(pipelines: &mut [Pipeline]) {
    pipelines.sort_by_key(|p| p.priority);
}

/// Apply multiple pipelines to a rule in priority order.
///
/// Each pipeline gets its own `PipelineState`, but the state is carried across
/// transformations within a single pipeline.
pub fn apply_pipelines(pipelines: &[Pipeline], rule: &mut SigmaRule) -> Result<()> {
    for pipeline in pipelines {
        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline.apply(rule, &mut state)?;
    }
    Ok(())
}

/// Apply multiple pipelines to a rule, returning the merged [`PipelineState`].
///
/// Unlike [`apply_pipelines`], this function accumulates state from all pipelines
/// into a single `PipelineState` so that conversion backends can read values set
/// by `SetState` and `QueryExpressionPlaceholders` transformations.
pub fn apply_pipelines_with_state(
    pipelines: &[Pipeline],
    rule: &mut SigmaRule,
) -> Result<PipelineState> {
    let mut merged = PipelineState::default();
    for pipeline in pipelines {
        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline.apply(rule, &mut state)?;
        for (k, v) in state.state {
            merged.state.insert(k, v);
        }
        merged.applied_items.extend(state.applied_items);
        merged.vars.extend(state.vars);
    }
    Ok(merged)
}

/// Apply multiple pipelines to a correlation rule in priority order,
/// returning the merged pipeline state.
pub fn apply_pipelines_to_correlation(
    pipelines: &[Pipeline],
    corr: &mut CorrelationRule,
) -> Result<PipelineState> {
    let mut merged = PipelineState::default();
    for pipeline in pipelines {
        let mut state = PipelineState::new(pipeline.vars.clone());
        pipeline.apply_to_correlation(corr, &mut state)?;
        for (k, v) in state.state {
            merged.state.insert(k, v);
        }
        merged.applied_items.extend(state.applied_items);
        merged.vars.extend(state.vars);
    }
    Ok(merged)
}
