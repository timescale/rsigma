//! Pipeline transformations that mutate `SigmaRule` AST nodes.
//!
//! All 26 pySigma transformation types are implemented as variants of the
//! [`Transformation`] enum. Each variant carries its configuration parameters
//! and is applied via the [`Transformation::apply`] method.

mod helpers;

pub use helpers::MAX_PLACEHOLDER_COMBINATIONS;
#[cfg(test)]
mod tests;

use std::collections::HashMap;

use regex::Regex;

use rsigma_parser::{SigmaRule, SigmaValue};

use super::conditions::{
    ConditionOp, ConditionSet, DetectionItemCondition, FieldNameCondition, NamedCondition,
};
use super::state::PipelineState;
use crate::error::{EvalError, Result};

pub(super) use helpers::{apply_named_string_fn, rename_field_list};

// =============================================================================
// Transformation enum
// =============================================================================

/// All supported pipeline transformation types.
#[derive(Debug, Clone)]
pub enum Transformation {
    /// Map field names via a lookup table.
    ///
    /// Supports pySigma-compatible one-to-many mapping: a single source name
    /// can map to a list of alternative field names. When more than one
    /// alternative is present, the matched detection item is replaced with
    /// an OR-conjunction (`AnyOf`) of items, one per alternative — preserving
    /// the rule's original AND structure across the rest of the items in the
    /// same selection via a Cartesian expansion.
    ///
    /// For correlation rules, `group_by` fields are expanded to include all
    /// alternatives (alias names are left untouched). `aliases` mapping values
    /// and threshold `field` reject one-to-many mappings with an error since
    /// those positions are inherently scalar.
    FieldNameMapping {
        mapping: HashMap<String, Vec<String>>,
    },

    /// Map field name prefixes.
    FieldNamePrefixMapping { mapping: HashMap<String, String> },

    /// Add a prefix to all matched field names.
    FieldNamePrefix { prefix: String },

    /// Add a suffix to all matched field names.
    FieldNameSuffix { suffix: String },

    /// Remove matching detection items.
    DropDetectionItem,

    /// Add field=value conditions to the rule's detection.
    ///
    /// Each value is a `Vec<SigmaValue>` to support list values (OR semantics).
    /// A single-element vec behaves identically to the old `SigmaValue` scalar.
    /// A multi-element vec creates a detection item with multiple values, which
    /// are OR-linked per Sigma semantics — matching pySigma's
    /// `AddConditionTransformation` behavior.
    AddCondition {
        conditions: HashMap<String, Vec<SigmaValue>>,
        /// Field-to-field equality conditions (`field` equals the value of
        /// another field). The value of each entry is a *field name*, not a
        /// literal, lowered through the `fieldref` modifier so backends
        /// render it as `field = other_field` rather than a string compare.
        /// Combined with `negated` this expresses inequalities such as the
        /// Fibratus `create_remote_thread` macro's `evt.pid != thread.pid`.
        field_refs: HashMap<String, String>,
        /// If true, negate the added conditions.
        negated: bool,
        /// If true, AND the added conditions *before* the existing
        /// detection (`new AND existing`) instead of after. Backends
        /// whose engines short-circuit left-to-right benefit from
        /// putting a cheap, highly selective discriminator (e.g. an
        /// event-name predicate) first.
        prepend: bool,
        /// Name of the added detection. A generated name is used when unset.
        name: Option<String>,
        /// Treat string values as templates in which `$category`, `$product`,
        /// and `$service` are replaced with the rule's logsource values.
        template: bool,
    },

    /// Replace logsource fields.
    ChangeLogsource {
        category: Option<String>,
        product: Option<String>,
        service: Option<String>,
    },

    /// Regex replacement in string values.
    ///
    /// When `skip_special` is true, replacement is applied only to the plain
    /// (non-wildcard) segments of `SigmaString`, preserving `*` and `?` wildcards.
    /// Mirrors pySigma's `ReplaceStringTransformation.skip_special`.
    ReplaceString {
        regex: String,
        replacement: String,
        skip_special: bool,
        /// With `skip_special`, interpret wildcards in the replacement result
        /// instead of keeping them as literal characters.
        interpret_special: bool,
    },

    /// Expand `%name%` placeholders with pipeline variables.
    ValuePlaceholders {
        /// Leave unknown placeholders for rsigma's runtime event-field
        /// substitution instead of rejecting the pipeline application.
        allow_unresolved: bool,
        /// Resolve only these placeholder names.
        include: Option<Vec<String>>,
        /// Resolve every placeholder except these names.
        exclude: Option<Vec<String>>,
    },

    /// Replace unresolved `%name%` placeholders with `*` wildcard.
    WildcardPlaceholders {
        /// Resolve only these placeholder names.
        include: Option<Vec<String>>,
        /// Resolve every placeholder except these names.
        exclude: Option<Vec<String>>,
    },

    /// Store expression template (no-op for eval, kept for YAML compat).
    QueryExpressionPlaceholders { expression: String },

    /// Set key-value in pipeline state.
    SetState {
        key: String,
        value: serde_json::Value,
    },

    /// Fail if rule conditions match.
    RuleFailure { message: String },

    /// Fail if detection item conditions match.
    DetectionItemFailure { message: String },

    /// Apply a named function to field names (lowercase, uppercase, etc.).
    /// In pySigma this takes a Python callable; we support named functions.
    FieldNameTransform {
        /// One of: "lower", "upper", "title", "snake_case"
        transform_func: String,
        /// Explicit overrides: field → new_name (applied instead of the function).
        mapping: HashMap<String, String>,
    },

    /// Decompose hash fields into per-algorithm fields.
    ///
    /// `Hashes: [SHA1=abc, MD5=def]` becomes `SHA1: abc` OR `MD5: def`
    /// (each name prefixed with `field_prefix`). A bare hash value gets its
    /// algorithm from its length (MD5, SHA1, SHA256, or SHA512).
    HashesFields {
        /// Accepted upper-case algorithm names (e.g. `["MD5", "SHA1"]`).
        valid_hash_algos: Vec<String>,
        /// Prefix for generated field names (e.g. `"File"` → `FileMD5`).
        field_prefix: String,
        /// If true, omit algo name from field (use just prefix).
        drop_algo_prefix: bool,
        /// Field names whose values are parsed (default `Hashes` and `Hash`).
        field_to_parse: Vec<String>,
    },

    /// Map string values via a lookup table.
    ///
    /// Supports one-to-many mapping: a single value can map to multiple
    /// alternatives (pySigma compat). When one-to-many is used, the detection
    /// item's values list is expanded in place.
    MapString {
        mapping: HashMap<String, Vec<String>>,
    },

    /// Set all values of matching detection items to a fixed value.
    SetValue { value: SigmaValue },

    /// Convert detection item values to a different type.
    /// Supported: "str", "int", "float", "bool".
    ConvertType { target_type: String },

    /// Convert plain string values to regex patterns.
    Regex,

    /// Add a field name to the rule's output `fields` list.
    AddField { field: String },

    /// Remove a field name from the rule's output `fields` list.
    RemoveField { field: String },

    /// Set (replace) the rule's output `fields` list.
    SetField { fields: Vec<String> },

    /// Set a custom attribute on the rule.
    ///
    /// Stores the key-value pair in `SigmaRule.custom_attributes` as a
    /// `yaml_serde::Value::String`. Backends / engines can read these to
    /// modify per-rule behavior (e.g. `rsigma.suppress`, `rsigma.action`).
    /// Mirrors pySigma's `SetCustomAttributeTransformation`.
    SetCustomAttribute { attribute: String, value: String },

    /// Apply a case transformation to string values.
    /// Supported: "lower", "upper", "snake_case".
    CaseTransformation { case_type: String },

    /// Nested sub-pipeline: apply a list of transformations as a group.
    /// The inner items share the same conditions as the outer item.
    Nest {
        items: Vec<super::TransformationItem>,
    },

    /// Unresolved dynamic include directive.
    ///
    /// Represents `include: "${source.name}"` in the pipeline YAML. This is a
    /// placeholder that will be expanded into actual transformations when
    /// dynamic sources are resolved (Phase 2). At evaluation time, it is a
    /// no-op.
    Include { template: String },
}

// =============================================================================
// Application logic
// =============================================================================

impl Transformation {
    /// Apply this transformation to a `SigmaRule`, mutating it in place.
    ///
    /// Returns `Ok(true)` if the transformation was applied, `Ok(false)` if skipped.
    pub fn apply(
        &self,
        rule: &mut SigmaRule,
        state: &mut PipelineState,
        detection_item_conditions: &[DetectionItemCondition],
        field_name_conditions: &[FieldNameCondition],
        field_name_cond_not: bool,
    ) -> Result<bool> {
        let detection_item_conditions = ConditionSet {
            conditions: detection_item_conditions
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, condition)| NamedCondition {
                    id: (index + 1).to_string(),
                    condition,
                })
                .collect(),
            ..ConditionSet::default()
        };
        let field_name_conditions = ConditionSet {
            conditions: field_name_conditions
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, condition)| NamedCondition {
                    id: (index + 1).to_string(),
                    condition,
                })
                .collect(),
            op: ConditionOp::And,
            negated: field_name_cond_not,
            expression: None,
        };
        self.apply_with_condition_sets(
            rule,
            state,
            &[&detection_item_conditions],
            &[&field_name_conditions],
        )
    }

    pub(super) fn apply_with_condition_sets(
        &self,
        rule: &mut SigmaRule,
        state: &mut PipelineState,
        detection_item_conditions: &[&ConditionSet<DetectionItemCondition>],
        field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    ) -> Result<bool> {
        match self {
            Transformation::FieldNameMapping { mapping } => {
                helpers::apply_field_name_transform(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    |name| mapping.get(name).cloned(),
                )?;
                Ok(true)
            }

            Transformation::FieldNamePrefixMapping { mapping } => {
                helpers::apply_field_name_transform(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    |name| {
                        for (prefix, replacement) in mapping {
                            if name.starts_with(prefix.as_str()) {
                                return Some(vec![format!(
                                    "{}{}",
                                    replacement,
                                    &name[prefix.len()..]
                                )]);
                            }
                        }
                        None
                    },
                )?;
                Ok(true)
            }

            Transformation::FieldNamePrefix { prefix } => {
                helpers::apply_field_name_transform(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    |name| Some(vec![format!("{prefix}{name}")]),
                )?;
                Ok(true)
            }

            Transformation::FieldNameSuffix { suffix } => {
                helpers::apply_field_name_transform(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    |name| Some(vec![format!("{name}{suffix}")]),
                )?;
                Ok(true)
            }

            Transformation::DropDetectionItem => {
                helpers::drop_detection_items(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                );
                Ok(true)
            }

            Transformation::AddCondition {
                conditions,
                field_refs,
                negated,
                prepend,
                name,
                template,
            } => {
                helpers::add_conditions(
                    rule,
                    &helpers::AddedCondition {
                        conditions,
                        field_refs,
                        negated: *negated,
                        prepend: *prepend,
                        name: name.as_deref(),
                        template: *template,
                    },
                )?;
                Ok(true)
            }

            Transformation::ChangeLogsource {
                category,
                product,
                service,
            } => {
                if let Some(cat) = category {
                    rule.logsource.category = Some(cat.clone());
                }
                if let Some(prod) = product {
                    rule.logsource.product = Some(prod.clone());
                }
                if let Some(svc) = service {
                    rule.logsource.service = Some(svc.clone());
                }
                Ok(true)
            }

            Transformation::ReplaceString {
                regex,
                replacement,
                skip_special,
                interpret_special,
            } => {
                let re = Regex::new(regex)
                    .map_err(|e| EvalError::Pipeline(format!("bad regex: {e}")))?;
                helpers::replace_strings_in_rule(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    &re,
                    &helpers::StringReplace {
                        replacement,
                        skip_special: *skip_special,
                        interpret_special: *interpret_special,
                    },
                );
                Ok(true)
            }

            Transformation::ValuePlaceholders {
                allow_unresolved,
                include,
                exclude,
            } => {
                helpers::expand_placeholders_in_rule(
                    rule,
                    &helpers::PlaceholderExpansion {
                        state,
                        wildcard: false,
                        allow_unresolved: *allow_unresolved,
                        include: include.as_deref(),
                        exclude: exclude.as_deref(),
                    },
                )?;
                Ok(true)
            }

            Transformation::WildcardPlaceholders { include, exclude } => {
                helpers::expand_placeholders_in_rule(
                    rule,
                    &helpers::PlaceholderExpansion {
                        state,
                        wildcard: true,
                        allow_unresolved: false,
                        include: include.as_deref(),
                        exclude: exclude.as_deref(),
                    },
                )?;
                Ok(true)
            }

            Transformation::QueryExpressionPlaceholders { expression } => {
                state.set_state(
                    "query_expression_template".to_string(),
                    serde_json::Value::String(expression.clone()),
                );
                Ok(true)
            }

            Transformation::SetState { key, value } => {
                state.set_state(key.clone(), value.clone());
                Ok(true)
            }

            Transformation::RuleFailure { message } => Err(EvalError::Pipeline(format!(
                "rule failure: {message} (rule: {})",
                rule.title
            ))),

            Transformation::DetectionItemFailure { message } => {
                let has_match = helpers::rule_has_matching_item(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                );
                if has_match {
                    Err(EvalError::Pipeline(format!(
                        "detection item failure: {message} (rule: {})",
                        rule.title
                    )))
                } else {
                    Ok(false)
                }
            }

            Transformation::FieldNameTransform {
                transform_func,
                mapping,
            } => {
                let func = transform_func.clone();
                let map = mapping.clone();
                helpers::apply_field_name_transform(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    |name| {
                        if let Some(mapped) = map.get(name) {
                            return Some(vec![mapped.clone()]);
                        }
                        Some(vec![helpers::apply_named_string_fn(&func, name)])
                    },
                )?;
                Ok(true)
            }

            Transformation::HashesFields {
                valid_hash_algos,
                field_prefix,
                drop_algo_prefix,
                field_to_parse,
            } => {
                helpers::decompose_hashes_field(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    &helpers::HashesFields {
                        valid_hash_algos,
                        field_prefix,
                        drop_algo_prefix: *drop_algo_prefix,
                        field_to_parse,
                    },
                )?;
                Ok(true)
            }

            Transformation::MapString { mapping } => {
                helpers::map_string_values(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    mapping,
                );
                Ok(true)
            }

            Transformation::SetValue { value } => {
                helpers::set_detection_item_values(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    value,
                );
                Ok(true)
            }

            Transformation::ConvertType { target_type } => {
                helpers::convert_detection_item_types(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    target_type,
                );
                Ok(true)
            }

            Transformation::Regex => {
                // No-op: marking that plain strings should be treated as regex.
                // In eval mode all matching goes through our compiled matchers,
                // so there is nothing to mutate. Kept for YAML compat.
                Ok(false)
            }

            Transformation::AddField { field } => {
                if !rule.fields.contains(field) {
                    rule.fields.push(field.clone());
                }
                Ok(true)
            }

            Transformation::RemoveField { field } => {
                rule.fields.retain(|f| f != field);
                Ok(true)
            }

            Transformation::SetField { fields } => {
                rule.fields = fields.clone();
                Ok(true)
            }

            Transformation::SetCustomAttribute { attribute, value } => {
                rule.custom_attributes
                    .insert(attribute.clone(), yaml_serde::Value::String(value.clone()));
                Ok(true)
            }

            Transformation::CaseTransformation { case_type } => {
                helpers::apply_case_transformation(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    case_type,
                );
                Ok(true)
            }

            Transformation::Nest { items } => {
                let outer_id = state.current_item_id.clone();
                for item in items {
                    let rule_ok = item.rule_conditions.conditions.is_empty()
                        || item
                            .rule_conditions
                            .matches(|condition| condition.matches_rule(rule, state));
                    if !rule_ok {
                        continue;
                    }
                    state.current_item_id = item.id.clone();
                    let applied = item.apply_tracked(rule, state);
                    state.current_item_id = outer_id.clone();
                    if applied? && let Some(ref id) = item.id {
                        state.mark_applied(id);
                    }
                }
                Ok(true)
            }

            Transformation::Include { .. } => Ok(false),
        }
    }
}

impl super::TransformationItem {
    /// Apply this item's transformation under its own detection-item and
    /// field-name conditions, recording the detection items it changes when
    /// the pipeline tracks them.
    pub(super) fn apply_tracked(
        &self,
        rule: &mut SigmaRule,
        state: &mut PipelineState,
    ) -> Result<bool> {
        let before = state
            .track_detection_items
            .then(|| rule.detection.named.clone());
        let applied = self.transformation.apply_with_condition_sets(
            rule,
            state,
            &[&self.detection_item_conditions],
            &[&self.field_name_conditions],
        )?;
        if let Some(before) = before {
            helpers::track_detection_item_changes(&before, &rule.detection.named, state);
        }
        Ok(applied)
    }
}
