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

pub mod builtin;
pub mod conditions;
pub mod finalizers;
mod parsing;
pub mod sources;
pub mod state;
pub mod transformations;

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use rsigma_parser::{CorrelationRule, SigmaCollection, SigmaRule};

use crate::error::{EvalError, Result};

pub use conditions::{
    ConditionOp, ConditionSet, DetectionItemCondition, FieldNameCondition,
    NamedDetectionItemCondition, NamedFieldNameCondition, NamedRuleCondition, RuleCondition,
    StateOperator, ValueMatch, eval_condition_expr,
};
pub use finalizers::Finalizer;
pub use parsing::{
    parse_pipeline, parse_pipeline_file, parse_sources, parse_sources_dir, parse_sources_file,
    parse_transformation_items, validate_source_refs,
};
pub use state::PipelineState;
pub use transformations::{MAX_PLACEHOLDER_COMBINATIONS, Transformation};

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
    /// Template references (`${source.*}`) found during parsing.
    ///
    /// Source *declarations* live in standalone source files loaded via
    /// `--source` (see [`parse_sources_file`]); a pipeline only carries the
    /// references it makes to them.
    pub source_refs: Vec<sources::SourceRef>,
}

/// A single transformation with its gating conditions.
#[derive(Debug, Clone)]
pub struct TransformationItem {
    /// Optional ID for tracking in pipeline state.
    pub id: Option<String>,
    /// The transformation to apply.
    pub transformation: Transformation,
    /// Rule-level conditions and their linking behavior.
    pub rule_conditions: ConditionSet<RuleCondition>,
    /// Detection-item-level conditions.
    pub detection_item_conditions: ConditionSet<DetectionItemCondition>,
    /// Field-name-level conditions.
    pub field_name_conditions: ConditionSet<FieldNameCondition>,
}

// =============================================================================
// Pipeline application
// =============================================================================

impl Pipeline {
    /// Apply this pipeline to a single `SigmaRule`, mutating it in place.
    pub fn apply(&self, rule: &mut SigmaRule, state: &mut PipelineState) -> Result<()> {
        state.reset_rule();
        state.track_detection_items = uses_detection_item_applied(&self.transformations);

        for item in &self.transformations {
            if !self.check_rule_conditions(rule, state, item) {
                continue;
            }

            state.current_item_id = item.id.clone();
            let applied = item.apply_tracked(rule, state);
            state.current_item_id = None;

            if applied? && let Some(ref id) = item.id {
                state.mark_applied(id);
            }
        }

        Ok(())
    }

    /// Apply this pipeline to all rules in a collection.
    ///
    /// Returns cloned, transformed rules (originals are not modified).
    ///
    /// One `PipelineState` is shared by every rule, so `set_state` values and
    /// `applied_items` accumulate across the collection. For several pipelines
    /// at once, or for per-rule applied ids and state, use
    /// [`transform_collection`].
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
        item.rule_conditions.conditions.is_empty()
            || item
                .rule_conditions
                .matches(|condition| condition.matches_rule(rule, state))
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

        apply_correlation_items(corr, &self.transformations, state)
    }

    /// Returns `true` if this pipeline contains any `${source.*}` template
    /// references (and therefore depends on external dynamic sources).
    pub fn is_dynamic(&self) -> bool {
        !self.source_refs.is_empty()
    }

    /// Returns a slice of all source references found during parsing.
    pub fn dynamic_references(&self) -> &[sources::SourceRef] {
        &self.source_refs
    }
}

/// Whether any item, including nested ones, has a detection-item
/// `processing_item_applied` condition.
fn uses_detection_item_applied(items: &[TransformationItem]) -> bool {
    items.iter().any(|item| {
        item.detection_item_conditions
            .conditions
            .iter()
            .any(|named| {
                matches!(
                    named.condition,
                    DetectionItemCondition::ProcessingItemApplied { .. }
                )
            })
            || matches!(
                &item.transformation,
                Transformation::Nest { items } if uses_detection_item_applied(items)
            )
    })
}

fn apply_correlation_items(
    corr: &mut CorrelationRule,
    items: &[TransformationItem],
    state: &mut PipelineState,
) -> Result<()> {
    for item in items {
        let rule_ok = item.rule_conditions.conditions.is_empty()
            || item
                .rule_conditions
                .matches(|condition| condition.matches_correlation(corr, state));
        if !rule_ok {
            continue;
        }

        let outer_id = std::mem::replace(&mut state.current_item_id, item.id.clone());
        let applied = apply_correlation_transformation(
            corr,
            &item.transformation,
            state,
            &item.field_name_conditions,
        );
        state.current_item_id = outer_id;

        if applied? && let Some(ref id) = item.id {
            state.mark_applied(id);
        }
    }
    Ok(())
}

/// Apply a single transformation to a correlation rule.
///
/// Returns `true` if the transformation was meaningfully applied.
fn apply_correlation_transformation(
    corr: &mut CorrelationRule,
    transformation: &Transformation,
    state: &mut PipelineState,
    field_name_conditions: &ConditionSet<FieldNameCondition>,
) -> Result<bool> {
    match transformation {
        Transformation::FieldNameMapping { mapping } => {
            map_correlation_fields(corr, state, field_name_conditions, |name| {
                mapping.get(name).cloned()
            })?;
            Ok(true)
        }

        Transformation::FieldNamePrefixMapping { mapping } => {
            map_correlation_fields(corr, state, field_name_conditions, |name| {
                mapping.iter().find_map(|(prefix, replacement)| {
                    name.strip_prefix(prefix.as_str())
                        .map(|rest| vec![format!("{replacement}{rest}")])
                })
            })?;
            Ok(true)
        }

        Transformation::FieldNamePrefix { prefix } => {
            map_correlation_fields(corr, state, field_name_conditions, |name| {
                Some(vec![format!("{prefix}{name}")])
            })?;
            Ok(true)
        }

        Transformation::FieldNameSuffix { suffix } => {
            map_correlation_fields(corr, state, field_name_conditions, |name| {
                Some(vec![format!("{name}{suffix}")])
            })?;
            Ok(true)
        }

        Transformation::FieldNameTransform {
            transform_func,
            mapping,
        } => {
            map_correlation_fields(corr, state, field_name_conditions, |name| {
                Some(vec![mapping.get(name).cloned().unwrap_or_else(|| {
                    transformations::apply_named_string_fn(transform_func, name)
                })])
            })?;
            Ok(true)
        }

        Transformation::SetCustomAttribute { attribute, value } => {
            corr.custom_attributes
                .insert(attribute.clone(), yaml_serde::Value::String(value.clone()));
            Ok(true)
        }

        Transformation::SetState { key, value } => {
            state.set_state(key.clone(), value.clone());
            Ok(true)
        }

        Transformation::RuleFailure { message } => Err(EvalError::Pipeline(format!(
            "rule failure: {message} (correlation: {})",
            corr.title
        ))),

        Transformation::Nest { items } => {
            apply_correlation_items(corr, items, state)?;
            Ok(true)
        }

        // Detection-specific transforms are no-ops for correlations
        _ => Ok(false),
    }
}

/// Rename the field names of a correlation rule like pySigma's
/// `FieldMappingTransformationBase`: the `fields` list and `group_by` expand
/// one-to-many mappings (`group_by` entries naming an alias are kept), while
/// alias mappings and the threshold field reject them. Only names passing the
/// field-name conditions are renamed.
fn map_correlation_fields(
    corr: &mut CorrelationRule,
    state: &mut PipelineState,
    field_name_conditions: &ConditionSet<FieldNameCondition>,
    mapper: impl Fn(&str) -> Option<Vec<String>>,
) -> Result<()> {
    let mut renames = Vec::new();
    let current: &PipelineState = state;
    let rename = |name: &str| {
        mapper(name).filter(|names| {
            !names.is_empty()
                && field_name_conditions
                    .matches(|condition| condition.matches_field_name(name, current))
        })
    };

    corr.fields = transformations::rename_field_list(
        std::mem::take(&mut corr.fields),
        current,
        &[field_name_conditions],
        &mapper,
        &mut renames,
    );

    let alias_names: std::collections::HashSet<String> =
        corr.aliases.iter().map(|a| a.alias.clone()).collect();
    for alias in &mut corr.aliases {
        for (rule_ref, field_name) in &mut alias.mapping {
            let Some(names) = rename(field_name) else {
                continue;
            };
            if names.len() > 1 {
                return Err(EvalError::Pipeline(format!(
                    "field_name_mapping one-to-many cannot be applied to \
                     correlation alias mapping (alias '{}', rule '{}', \
                     field '{}' maps to {} alternatives)",
                    alias.alias,
                    rule_ref,
                    field_name,
                    names.len(),
                )));
            }
            let renamed = names[0].clone();
            renames.push((std::mem::replace(field_name, renamed), names));
        }
    }

    let mut group_by = Vec::with_capacity(corr.group_by.len());
    for field_name in std::mem::take(&mut corr.group_by) {
        if alias_names.contains(&field_name) {
            group_by.push(field_name);
            continue;
        }
        let Some(names) = rename(&field_name) else {
            group_by.push(field_name);
            continue;
        };
        if names.len() > 1 {
            log::warn!(
                "correlation '{}': group_by field '{}' has a one-to-many \
                 mapping ({} alternatives: {:?}); expanding all, so \
                 correlation grouping may be broader than intended",
                corr.title,
                field_name,
                names.len(),
                names,
            );
        }
        group_by.extend(names.iter().cloned());
        renames.push((field_name, names));
    }
    corr.group_by = group_by;

    if let rsigma_parser::CorrelationCondition::Threshold { ref mut field, .. } = corr.condition
        && let Some(fields) = field.as_mut()
    {
        for f in fields.iter_mut() {
            let Some(names) = rename(f) else {
                continue;
            };
            if names.len() > 1 {
                return Err(EvalError::Pipeline(format!(
                    "field_name_mapping one-to-many cannot be applied to \
                     correlation condition field reference ('{}' maps to \
                     {} alternatives)",
                    f,
                    names.len(),
                )));
            }
            let renamed = names[0].clone();
            renames.push((std::mem::replace(f, renamed), names));
        }
    }

    state.track_field_renames(renames);
    Ok(())
}

// =============================================================================
// Multi-pipeline support
// =============================================================================

/// Sort pipelines by priority in place, lower first.
///
/// Despite the name this only orders the slice; it neither combines the
/// pipelines nor applies them. Call it before [`apply_pipelines`] and friends,
/// which walk the slice as given. [`Engine::add_pipeline`](crate::Engine) sorts
/// on insert, so engine callers get this for free.
pub fn merge_pipelines(pipelines: &mut [Pipeline]) {
    pipelines.sort_by_key(|p| p.priority);
}

/// Apply multiple pipelines to a rule, in the order of the slice.
///
/// Ordering is the caller's: sort with [`merge_pipelines`] first if the
/// pipelines are meant to run by `priority`.
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
/// Runs the pipelines in slice order, like [`apply_pipelines`].
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

/// A rule after pipeline application, with the transformations that fired.
///
/// Returned by [`transform_rule`] and [`transform_collection`] for callers that
/// need to read the rewritten rule itself rather than evaluate it: a collector
/// deriving which log channels to subscribe to from the post-pipeline
/// `logsource`, a report showing the injected conditions, or a test asserting
/// that a mapping applied.
#[derive(Debug, Clone)]
pub struct TransformedRule {
    /// The rule after every pipeline ran.
    pub rule: SigmaRule,
    /// Ids of the transformations that fired, sorted. Transformations without
    /// an `id:` are not tracked, so this can be empty even though `rule`
    /// changed.
    pub applied_items: Vec<String>,
    /// The merged state the pipelines accumulated (see
    /// [`apply_pipelines_with_state`]).
    pub state: PipelineState,
}

/// Apply `pipelines` to a clone of `rule` and return the rewritten rule.
///
/// The input rule is left untouched. This is the inspection counterpart to
/// loading rules into an engine: the engine applies the same pipelines and then
/// keeps only the compiled form, so a caller that needs the rewritten Sigma AST
/// (injected conditions, renamed fields, a `change_logsource` rewrite) asks for
/// it here.
///
/// Pipelines run in slice order, like [`apply_pipelines`]. Sort with
/// [`merge_pipelines`] first to match what an [`Engine`](crate::Engine) does,
/// since it keeps its own pipelines sorted by `priority`.
///
/// Call this once per rule set load, not per event: it clones and re-transforms
/// the rule, exactly like the load path does. When only the rewritten logsource
/// matters, prefer reading it off the loaded compiled rules instead, which costs
/// nothing extra.
///
/// # Example
///
/// ```rust
/// use rsigma_eval::pipeline::{parse_pipeline, transform_rule};
/// use rsigma_parser::parse_sigma_yaml;
///
/// let pipeline = parse_pipeline(
///     r#"
/// name: sysmon routing
/// transformations:
///   - id: process_creation
///     type: add_condition
///     conditions:
///       EventID: 1
///     rule_conditions:
///       - type: logsource
///         category: process_creation
///   - id: sysmon_logsource
///     type: change_logsource
///     service: sysmon
///     rule_conditions:
///       - type: logsource
///         product: windows
/// "#,
/// )?;
///
/// let collection = parse_sigma_yaml(
///     r#"
/// title: Whoami
/// logsource:
///     product: windows
///     category: process_creation
/// detection:
///     selection:
///         CommandLine|contains: whoami
///     condition: selection
/// "#,
/// )?;
///
/// let transformed = transform_rule(&[pipeline], &collection.rules[0])?;
///
/// assert_eq!(transformed.rule.logsource.service.as_deref(), Some("sysmon"));
/// assert!(transformed.applied_items.contains(&"process_creation".to_string()));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn transform_rule(pipelines: &[Pipeline], rule: &SigmaRule) -> Result<TransformedRule> {
    let mut transformed = rule.clone();
    let state = apply_pipelines_with_state(pipelines, &mut transformed)?;
    let mut applied_items: Vec<String> = state.applied_items.iter().cloned().collect();
    applied_items.sort();
    Ok(TransformedRule {
        rule: transformed,
        applied_items,
        state,
    })
}

/// Apply `pipelines` to every detection rule in `collection`.
///
/// Per-rule equivalent of [`transform_rule`], in collection order. Correlation
/// and filter rules are not included; correlation rules transform through
/// [`apply_pipelines_to_correlation`].
///
/// Each rule is transformed with its own state, so `applied_items` and `state`
/// on each result describe that rule alone. This is the difference from
/// [`Pipeline::apply_to_collection`], which shares one state across the whole
/// collection and takes a single pipeline.
pub fn transform_collection(
    pipelines: &[Pipeline],
    collection: &SigmaCollection,
) -> Result<Vec<TransformedRule>> {
    collection
        .rules
        .iter()
        .map(|rule| transform_rule(pipelines, rule))
        .collect()
}

/// Apply multiple pipelines to a correlation rule in slice order, returning the
/// merged pipeline state.
///
/// As with [`apply_pipelines`], sort with [`merge_pipelines`] first to run them
/// by `priority`.
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
