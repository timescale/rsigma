use std::collections::HashMap;

use regex::Regex;

use rsigma_parser::{
    ConditionExpr, Detection, DetectionItem, FieldSpec, LogSource, Modifier, SigmaRule,
    SigmaString, SigmaValue, SpecialChar, StringPart,
};

use super::super::conditions::{ConditionSet, DetectionItemCondition, FieldNameCondition};
use super::super::state::PipelineState;
use crate::error::{EvalError, Result};

// =============================================================================
// Field name transformation helper
// =============================================================================

/// Max branches a single one-to-many field-name expansion can produce inside
/// one `AllOf`.
///
/// The Cartesian product of per-item alternative lists grows fast
/// (e.g. 10 items * 5 alternatives each = ~9.7M branches). pySigma
/// materializes expanded rules once for query generation, but rsigma
/// evaluates rules against live events, so a blown-up detection tree stays
/// in the hot path permanently. We reject expansions above this threshold at
/// load time instead of silently ballooning memory and CPU.
const MAX_FIELD_MAPPING_COMBINATIONS: usize = 4096;

/// Apply a field-name-rewriting closure to every detection in `rule`.
///
/// The closure returns `None` to leave a name untouched, `Some(vec)` to
/// rewrite it. A single-element `Some` renames the item in place. Multiple
/// alternatives expand the matched item into an OR over the alternatives;
/// the surrounding `AllOf` becomes an `AnyOf` of `AllOf`s via Cartesian
/// expansion (see `transform_detection_fields`).
///
/// The rule's `fields` list is renamed too. Renames of `fields` entries and
/// field reference targets are recorded for field-name
/// `processing_item_applied` conditions, as pySigma does.
pub(super) fn apply_field_name_transform<F>(
    rule: &mut SigmaRule,
    state: &mut PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    transform_fn: F,
) -> Result<()>
where
    F: Fn(&str) -> Option<Vec<String>>,
{
    let mut renames = Vec::new();
    rule.fields = rename_field_list(
        std::mem::take(&mut rule.fields),
        state,
        field_name_conditions,
        &transform_fn,
        &mut renames,
    );
    let rule_title = rule.title.clone();
    for detection in rule.detection.named.values_mut() {
        transform_detection_fields(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            &transform_fn,
            &rule_title,
            &mut renames,
        )?;
    }
    state.track_field_renames(renames);
    Ok(())
}

/// A field renamed from the first name to the second list.
pub(in crate::pipeline) type FieldRename = (String, Vec<String>);

/// Rename the entries of a rule's `fields` list that pass the field-name
/// conditions, expanding one-to-many mappings.
pub(in crate::pipeline) fn rename_field_list<F>(
    fields: Vec<String>,
    state: &PipelineState,
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    transform_fn: &F,
    renames: &mut Vec<FieldRename>,
) -> Vec<String>
where
    F: Fn(&str) -> Option<Vec<String>>,
{
    let mut renamed = Vec::with_capacity(fields.len());
    for field in fields {
        match transform_fn(&field) {
            Some(names)
                if !names.is_empty()
                    && field_conditions_match(&field, state, field_name_conditions) =>
            {
                renamed.extend(names.iter().cloned());
                renames.push((field, names));
            }
            _ => renamed.push(field),
        }
    }
    renamed
}

fn transform_detection_fields<F>(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    transform_fn: &F,
    rule_title: &str,
    renames: &mut Vec<FieldRename>,
) -> Result<()>
where
    F: Fn(&str) -> Option<Vec<String>>,
{
    match detection {
        Detection::AllOf(items) => {
            let detection_matches: Vec<bool> = items
                .iter()
                .map(|item| {
                    item_conditions_match(item, state, detection_conditions, field_name_conditions)
                })
                .collect();
            for (item, matches) in items.iter_mut().zip(&detection_matches) {
                if *matches {
                    transform_field_reference_values(
                        item,
                        state,
                        field_name_conditions,
                        transform_fn,
                        rule_title,
                        renames,
                    )?;
                }
            }

            // First pass (read-only): resolve each item's mapping result.
            // Store either a single rename or a multi-alternative expansion.
            enum Resolved {
                Unchanged,
                Renamed(String),
                Expanded(Vec<String>),
            }
            let resolved: Vec<Resolved> = items
                .iter()
                .zip(detection_matches)
                .map(
                    |(item, detection_matches)| match item.field.name.as_deref() {
                        Some(name)
                            if detection_matches
                                && field_conditions_match(name, state, field_name_conditions) =>
                        {
                            match transform_fn(name) {
                                Some(new_names) if new_names.len() > 1 => {
                                    Resolved::Expanded(new_names)
                                }
                                Some(mut new_names) if new_names.len() == 1 => {
                                    Resolved::Renamed(new_names.pop().unwrap())
                                }
                                _ => Resolved::Unchanged,
                            }
                        }
                        _ => Resolved::Unchanged,
                    },
                )
                .collect();

            let needs_expansion = resolved.iter().any(|r| matches!(r, Resolved::Expanded(_)));

            if !needs_expansion {
                // Fast path: apply 1:1 renames in-place, no cloning.
                for (item, res) in items.iter_mut().zip(resolved) {
                    if let Resolved::Renamed(new_name) = res {
                        item.field.name = Some(new_name);
                    }
                }
            } else {
                // Build per-item alternative lists for the Cartesian product.
                let alternatives: Vec<Vec<DetectionItem>> = items
                    .iter()
                    .zip(resolved)
                    .map(|(item, res)| match res {
                        Resolved::Expanded(names) => names
                            .into_iter()
                            .map(|new_name| {
                                let mut clone = item.clone();
                                clone.field.name = Some(new_name);
                                clone
                            })
                            .collect(),
                        Resolved::Renamed(name) => {
                            let mut clone = item.clone();
                            clone.field.name = Some(name);
                            vec![clone]
                        }
                        Resolved::Unchanged => vec![item.clone()],
                    })
                    .collect();

                let total = alternatives
                    .iter()
                    .map(Vec::len)
                    .fold(1usize, |acc, n| acc.saturating_mul(n));
                if total > MAX_FIELD_MAPPING_COMBINATIONS {
                    let sizes: Vec<usize> = alternatives.iter().map(Vec::len).collect();
                    return Err(EvalError::Pipeline(format!(
                        "field name mapping cartesian expansion would produce {total} \
                         branches, exceeding the limit of {MAX_FIELD_MAPPING_COMBINATIONS} \
                         (rule: {rule_title}, per-item alternative counts: {sizes:?}); \
                         reduce the number of one-to-many alternatives or split the AllOf"
                    )));
                }
                let combinations = cartesian_product(alternatives);
                *detection =
                    Detection::AnyOf(combinations.into_iter().map(Detection::AllOf).collect());
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                transform_detection_fields(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    transform_fn,
                    rule_title,
                    renames,
                )?;
            }
        }
        Detection::ArrayMatch { body, .. } => {
            transform_detection_fields(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
                transform_fn,
                rule_title,
                renames,
            )?;
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                transform_detection_fields(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    transform_fn,
                    rule_title,
                    renames,
                )?;
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                transform_detection_fields(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    transform_fn,
                    rule_title,
                    renames,
                )?;
            }
        }
        Detection::Keywords(_) => {}
    }
    Ok(())
}

fn transform_field_reference_values<F>(
    item: &mut DetectionItem,
    state: &PipelineState,
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    transform_fn: &F,
    rule_title: &str,
    renames: &mut Vec<FieldRename>,
) -> Result<()>
where
    F: Fn(&str) -> Option<Vec<String>>,
{
    if !item.field.modifiers.contains(&Modifier::FieldRef) {
        return Ok(());
    }

    let mut mapped_values = Vec::new();
    for value in item.values.drain(..) {
        let SigmaValue::String(field_ref) = &value else {
            mapped_values.push(value);
            continue;
        };
        let Some(field_name) = field_ref.as_plain() else {
            mapped_values.push(value);
            continue;
        };
        if !field_conditions_match(&field_name, state, field_name_conditions) {
            mapped_values.push(value);
            continue;
        }

        match transform_fn(&field_name) {
            Some(names) if !names.is_empty() => {
                if mapped_values.len().saturating_add(names.len()) > MAX_FIELD_MAPPING_COMBINATIONS
                {
                    return Err(EvalError::Pipeline(format!(
                        "field reference mapping would produce more than \
                         {MAX_FIELD_MAPPING_COMBINATIONS} values (rule: {rule_title})"
                    )));
                }
                mapped_values.extend(
                    names
                        .iter()
                        .map(|name| SigmaValue::String(SigmaString::new(name))),
                );
                renames.push((field_name, names));
            }
            _ => mapped_values.push(value),
        }
    }
    item.values = mapped_values;
    Ok(())
}

/// Build the Cartesian product of a sequence of alternative lists.
///
/// `[[a, b], [c]]` → `[[a, c], [b, c]]`.
/// Empty input yields a single empty combination so callers handle the edge
/// case uniformly.
fn cartesian_product<T: Clone>(input: Vec<Vec<T>>) -> Vec<Vec<T>> {
    let mut result: Vec<Vec<T>> = vec![Vec::new()];
    for group in input {
        let mut next = Vec::with_capacity(result.len() * group.len().max(1));
        for prefix in &result {
            for elem in &group {
                let mut combo = prefix.clone();
                combo.push(elem.clone());
                next.push(combo);
            }
        }
        result = next;
    }
    result
}

fn field_conditions_match(
    field_name: &str,
    state: &PipelineState,
    condition_sets: &[&ConditionSet<FieldNameCondition>],
) -> bool {
    condition_sets
        .iter()
        .all(|set| set.matches(|condition| condition.matches_field_name(field_name, state)))
}

// =============================================================================
// Drop detection items
// =============================================================================

pub(super) fn drop_detection_items(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
) {
    for detection in rule.detection.named.values_mut() {
        drop_from_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
        );
    }
}

fn drop_from_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
) {
    match detection {
        Detection::AllOf(items) => {
            items.retain(|item| {
                !item_conditions_match(item, state, detection_conditions, field_name_conditions)
            });
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                drop_from_detection(sub, state, detection_conditions, field_name_conditions);
            }
        }
        Detection::ArrayMatch { body, .. } => {
            drop_from_detection(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
            );
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                drop_from_detection(sub, state, detection_conditions, field_name_conditions);
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                drop_from_detection(sub, state, detection_conditions, field_name_conditions);
            }
        }
        Detection::Keywords(_) => {}
    }
}

fn detection_conditions_match(
    item: &DetectionItem,
    state: &PipelineState,
    condition_sets: &[&ConditionSet<DetectionItemCondition>],
) -> bool {
    condition_sets
        .iter()
        .all(|set| set.matches(|condition| condition.matches_item(item, state)))
}

// =============================================================================
// Add conditions
// =============================================================================

/// Parameters of an `add_condition` transformation.
pub(super) struct AddedCondition<'a> {
    pub(super) conditions: &'a HashMap<String, Vec<SigmaValue>>,
    pub(super) field_refs: &'a HashMap<String, String>,
    pub(super) negated: bool,
    pub(super) prepend: bool,
    pub(super) name: Option<&'a str>,
    pub(super) template: bool,
}

pub(super) fn add_conditions(rule: &mut SigmaRule, added: &AddedCondition<'_>) -> Result<()> {
    let logsource = rule.logsource.clone();
    let mut items: Vec<DetectionItem> = added
        .conditions
        .iter()
        .map(|(field, values)| DetectionItem {
            field: FieldSpec::new(Some(field.clone()), Vec::new()),
            values: if added.template {
                values
                    .iter()
                    .map(|value| match value {
                        SigmaValue::String(s) => SigmaValue::String(SigmaString::new(
                            &substitute_logsource_template(&s.original, &logsource),
                        )),
                        other => other.clone(),
                    })
                    .collect()
            } else {
                values.clone()
            },
        })
        .collect();

    // Field-to-field equalities lower through the `fieldref` modifier so the
    // value is treated as another field name (`field = other_field`), not a
    // string literal.
    items.extend(
        added
            .field_refs
            .iter()
            .map(|(field, target)| DetectionItem {
                field: FieldSpec::new(Some(field.clone()), vec![Modifier::FieldRef]),
                values: vec![SigmaValue::String(SigmaString::new(target))],
            }),
    );

    let det_name = match added.name {
        Some(name) if rule.detection.named.contains_key(name) => {
            return Err(EvalError::Pipeline(format!(
                "add_condition name '{name}' collides with an existing detection (rule: {})",
                rule.title
            )));
        }
        Some(name) => name.to_string(),
        None => format!("__pipeline_cond_{}", rule.detection.named.len()),
    };
    rule.detection
        .named
        .insert(det_name.clone(), Detection::AllOf(items));

    // Add to existing conditions: AND (or AND NOT if negated)
    let cond_ref = ConditionExpr::Identifier(det_name);
    let cond_expr = if added.negated {
        ConditionExpr::Not(Box::new(cond_ref))
    } else {
        cond_ref
    };

    rule.detection.conditions = rule
        .detection
        .conditions
        .iter()
        .map(|existing| {
            // `prepend` puts the added condition first (`new AND
            // existing`) so left-to-right short-circuiting engines
            // evaluate the cheap discriminator before the rule body;
            // the default appends (`existing AND new`).
            let parts = if added.prepend {
                vec![cond_expr.clone(), existing.clone()]
            } else {
                vec![existing.clone(), cond_expr.clone()]
            };
            ConditionExpr::And(parts)
        })
        .collect();
    Ok(())
}

/// Substitute `$category`, `$product`, and `$service` (or the `${name}`
/// form) with the logsource values, following Python's
/// `string.Template.safe_substitute`: `$$` is a literal `$`, and unknown
/// names, unset logsource values, and a bare `$` are left as written.
fn substitute_logsource_template(text: &str, logsource: &LogSource) -> String {
    fn is_ident_start(c: char) -> bool {
        c == '_' || c.is_ascii_alphabetic()
    }
    fn is_ident_continue(c: char) -> bool {
        c == '_' || c.is_ascii_alphanumeric()
    }
    let lookup = |name: &str| match name {
        "category" => logsource.category.as_deref(),
        "product" => logsource.product.as_deref(),
        "service" => logsource.service.as_deref(),
        _ => None,
    };

    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(stripped) = after.strip_prefix('$') {
            out.push('$');
            rest = stripped;
            continue;
        }
        let (name, consumed) = if let Some(braced) = after.strip_prefix('{') {
            match braced.find('}') {
                Some(end)
                    if braced[..end].starts_with(is_ident_start)
                        && braced[..end].chars().all(is_ident_continue) =>
                {
                    (&braced[..end], end + 2)
                }
                _ => ("", 0),
            }
        } else if after.starts_with(is_ident_start) {
            let end = after
                .find(|c: char| !is_ident_continue(c))
                .unwrap_or(after.len());
            (&after[..end], end)
        } else {
            ("", 0)
        };
        match lookup(name) {
            Some(value) if consumed > 0 => {
                out.push_str(value);
                rest = &after[consumed..];
            }
            _ => {
                out.push('$');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

// =============================================================================
// Replace strings
// =============================================================================

/// Parameters of a `replace_string` transformation.
pub(super) struct StringReplace<'a> {
    pub(super) replacement: &'a str,
    pub(super) skip_special: bool,
    pub(super) interpret_special: bool,
}

pub(super) fn replace_strings_in_rule(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    re: &Regex,
    replace: &StringReplace<'_>,
) {
    for detection in rule.detection.named.values_mut() {
        replace_strings_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            re,
            replace,
        );
    }
}

fn replace_strings_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    re: &Regex,
    replace: &StringReplace<'_>,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item_conditions_match(item, state, detection_conditions, field_name_conditions) {
                    replace_strings_in_values(&mut item.values, re, replace);
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                replace_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    re,
                    replace,
                );
            }
        }
        Detection::ArrayMatch { body, .. } => {
            replace_strings_in_detection(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
                re,
                replace,
            );
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                replace_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    re,
                    replace,
                );
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                replace_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    re,
                    replace,
                );
            }
        }
        Detection::Keywords(values) => {
            replace_strings_in_values(values, re, replace);
        }
    }
}

fn replace_strings_in_values(values: &mut [SigmaValue], re: &Regex, replace: &StringReplace<'_>) {
    for value in values.iter_mut() {
        if let SigmaValue::String(s) = value {
            if replace.skip_special {
                // Replace only in plain segments, preserving wildcards. With
                // `interpret_special`, wildcards produced by the replacement
                // become wildcards; otherwise they stay literal characters.
                let new_parts: Vec<StringPart> = s
                    .parts
                    .iter()
                    .flat_map(|part| match part {
                        StringPart::Plain(text) => {
                            let replaced = re.replace_all(text, replace.replacement);
                            if replace.interpret_special {
                                SigmaString::new(&replaced).parts
                            } else {
                                vec![StringPart::Plain(replaced.into_owned())]
                            }
                        }
                        special => vec![special.clone()],
                    })
                    .collect();
                let new_parts = merge_plain_parts(new_parts);
                if new_parts != s.parts {
                    let new_original = parts_to_original(&new_parts);
                    s.parts = new_parts;
                    s.original = new_original;
                }
            } else {
                let replaced = re.replace_all(&s.original, replace.replacement);
                if replaced != s.original {
                    *s = SigmaString::new(&replaced);
                }
            }
        }
    }
}

/// Join adjacent plain parts so a rebuilt string has the canonical shape.
fn merge_plain_parts(parts: Vec<StringPart>) -> Vec<StringPart> {
    let mut merged: Vec<StringPart> = Vec::with_capacity(parts.len());
    for part in parts {
        match (merged.last_mut(), part) {
            (Some(StringPart::Plain(last)), StringPart::Plain(text)) => last.push_str(&text),
            (_, StringPart::Plain(text)) if text.is_empty() => {}
            (_, part) => merged.push(part),
        }
    }
    merged
}

/// Reconstruct the `original` string from parts, re-escaping wildcards.
fn parts_to_original(parts: &[StringPart]) -> String {
    let mut out = String::new();
    for part in parts {
        match part {
            StringPart::Plain(text) => {
                for c in text.chars() {
                    if c == '*' || c == '?' || c == '\\' {
                        out.push('\\');
                    }
                    out.push(c);
                }
            }
            StringPart::Special(SpecialChar::WildcardMulti) => out.push('*'),
            StringPart::Special(SpecialChar::WildcardSingle) => out.push('?'),
        }
    }
    out
}

// =============================================================================
// Placeholder expansion
// =============================================================================

/// How a placeholder transformation resolves `%name%` placeholders.
pub(super) struct PlaceholderExpansion<'a> {
    pub(super) state: &'a PipelineState,
    /// Replace every handled placeholder with `*` instead of its variable.
    pub(super) wildcard: bool,
    /// Leave placeholders without a variable for runtime substitution.
    pub(super) allow_unresolved: bool,
    pub(super) include: Option<&'a [String]>,
    pub(super) exclude: Option<&'a [String]>,
}

impl PlaceholderExpansion<'_> {
    fn handles(&self, name: &str) -> bool {
        self.include
            .is_none_or(|names| names.iter().any(|n| n == name))
            && self
                .exclude
                .is_none_or(|names| !names.iter().any(|n| n == name))
            && (self.wildcard || !self.allow_unresolved || self.state.vars.contains_key(name))
    }
}

pub(super) fn expand_placeholders_in_rule(
    rule: &mut SigmaRule,
    expansion: &PlaceholderExpansion<'_>,
) -> Result<()> {
    let rule_title = rule.title.clone();
    for detection in rule.detection.named.values_mut() {
        expand_placeholders_in_detection(detection, expansion, &rule_title)?;
    }
    Ok(())
}

fn expand_placeholders_in_detection(
    detection: &mut Detection,
    expansion: &PlaceholderExpansion<'_>,
    rule_title: &str,
) -> Result<()> {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item.field.modifiers.contains(&Modifier::Expand) {
                    expand_placeholders_in_values(&mut item.values, expansion, rule_title)?;
                    // An authored empty list is a null check. A placeholder
                    // that expanded to no values must match nothing instead,
                    // or an empty feed would fire on events missing the field.
                    if item.values.is_empty() {
                        item.field.modifiers = vec![Modifier::Re];
                        item.values = vec![SigmaValue::from_raw_string("a^")];
                    }
                }
            }
        }
        Detection::AnyOf(subs) | Detection::And(subs) => {
            for sub in subs.iter_mut() {
                expand_placeholders_in_detection(sub, expansion, rule_title)?;
            }
        }
        Detection::ArrayMatch { body, .. } => {
            expand_placeholders_in_detection(body.as_mut(), expansion, rule_title)?;
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                expand_placeholders_in_detection(sub, expansion, rule_title)?;
            }
        }
        Detection::Keywords(_) => {}
    }
    Ok(())
}

fn expand_placeholders_in_values(
    values: &mut Vec<SigmaValue>,
    expansion: &PlaceholderExpansion<'_>,
    rule_title: &str,
) -> Result<()> {
    let mut expanded_values = Vec::new();
    for value in values.drain(..) {
        if let SigmaValue::String(ref s) = value
            && s.original.contains('%')
        {
            expanded_values.extend(expand_placeholder_string(
                &s.original,
                expansion,
                rule_title,
            )?);
            continue;
        }
        expanded_values.push(value);
    }
    *values = expanded_values;
    Ok(())
}

/// A piece of raw Sigma source text: literal text or a `%name%` placeholder.
enum Segment<'a> {
    Literal(&'a str),
    Placeholder(&'a str),
}

/// Split raw Sigma source text into literal text and placeholders.
///
/// A backslash escapes `*`, `?`, `%`, and itself, as in the `expand` modifier:
/// `\%` is a literal percent and `\\%name%` is a backslash followed by a
/// placeholder. A placeholder name is non-empty and has no `*`, `?`, or
/// backslash.
fn placeholder_segments(s: &str) -> Vec<Segment<'_>> {
    let mut segments = Vec::new();
    let mut literal_start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' if chars
                .peek()
                .is_some_and(|&(_, next)| matches!(next, '*' | '?' | '%' | '\\')) =>
            {
                chars.next();
            }
            '%' => {
                let rest = &s[i + 1..];
                if let Some(len) = rest.find(['%', '*', '?', '\\'])
                    && len > 0
                    && rest[len..].starts_with('%')
                {
                    if literal_start < i {
                        segments.push(Segment::Literal(&s[literal_start..i]));
                    }
                    segments.push(Segment::Placeholder(&rest[..len]));
                    literal_start = i + len + 2;
                    while chars.peek().is_some_and(|&(j, _)| j < literal_start) {
                        chars.next();
                    }
                }
            }
            _ => {}
        }
    }
    if literal_start < s.len() {
        segments.push(Segment::Literal(&s[literal_start..]));
    }
    segments
}

/// Escape every `%` in literal Sigma source text that is not already escaped,
/// so the `expand` modifier never reads it as a placeholder.
fn escape_bare_percent(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                out.push('\\');
                if let Some(&next) = chars.peek()
                    && matches!(next, '*' | '?' | '%' | '\\')
                {
                    out.push(next);
                    chars.next();
                }
            }
            '%' => out.push_str("\\%"),
            _ => out.push(c),
        }
    }
    out
}

pub const MAX_PLACEHOLDER_COMBINATIONS: usize = 4096;

/// Substitute the placeholders in the raw source text `s` that `expansion`
/// handles, producing the Cartesian product of multi-value variables.
///
/// Substituted text is never scanned for further placeholders, and literal
/// text keeps its escapes: every `%` that is not part of a placeholder, in the
/// literal text or in a variable value, is written as `\%`.
fn expand_placeholder_string(
    s: &str,
    expansion: &PlaceholderExpansion<'_>,
    rule_title: &str,
) -> Result<Vec<SigmaValue>> {
    let segments = placeholder_segments(s);

    let mut combinations = vec![String::new()];
    for segment in &segments {
        let replacements: Vec<String> = match segment {
            Segment::Literal(text) => {
                let text = escape_bare_percent(text);
                for combination in &mut combinations {
                    combination.push_str(&text);
                }
                continue;
            }
            Segment::Placeholder(name) if !expansion.handles(name) => {
                for combination in &mut combinations {
                    combination.push('%');
                    combination.push_str(name);
                    combination.push('%');
                }
                continue;
            }
            Segment::Placeholder(_) if expansion.wildcard => vec!["*".to_string()],
            Segment::Placeholder(name) => match expansion.state.vars.get(*name) {
                Some(values) => values.iter().map(|v| v.replace('%', "\\%")).collect(),
                None => {
                    return Err(EvalError::Pipeline(format!(
                        "placeholder replacement variable '{name}' is not defined \
                         (rule: {rule_title})"
                    )));
                }
            },
        };

        let total = combinations.len().saturating_mul(replacements.len());
        if total > MAX_PLACEHOLDER_COMBINATIONS {
            return Err(EvalError::Pipeline(format!(
                "placeholder expansion would produce {total} values, exceeding the limit of \
                 {MAX_PLACEHOLDER_COMBINATIONS} (rule: {rule_title})"
            )));
        }
        combinations = combinations
            .iter()
            .flat_map(|prefix| {
                replacements
                    .iter()
                    .map(move |replacement| format!("{prefix}{replacement}"))
            })
            .collect();
    }

    Ok(combinations
        .into_iter()
        .map(|value| SigmaValue::String(SigmaString::new(&value)))
        .collect())
}

// =============================================================================
// Named string function helper (for FieldNameTransform)
// =============================================================================

pub(in crate::pipeline) fn apply_named_string_fn(func: &str, s: &str) -> String {
    match func {
        "lower" | "lowercase" => s.to_lowercase(),
        "upper" | "uppercase" => s.to_uppercase(),
        "title" => s
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(|w| {
                let mut c = w.chars();
                match c.next() {
                    None => String::new(),
                    Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
                }
            })
            .collect::<Vec<_>>()
            .join("_"),
        "snake_case" => {
            let mut out = String::new();
            for (i, ch) in s.chars().enumerate() {
                if ch.is_uppercase() && i > 0 {
                    out.push('_');
                }
                out.push(ch.to_lowercase().next().unwrap_or(ch));
            }
            out
        }
        _ => s.to_string(),
    }
}

// =============================================================================
// Hashes field decomposition
// =============================================================================

/// Parameters of a `hashes_fields` transformation.
pub(super) struct HashesFields<'a> {
    pub(super) valid_hash_algos: &'a [String],
    pub(super) field_prefix: &'a str,
    pub(super) drop_algo_prefix: bool,
    pub(super) field_to_parse: &'a [String],
}

/// Replace each detection item on a `field_to_parse` field whose values are
/// all strings with an OR over per-algorithm fields, as pySigma's
/// `HashesFieldsDetectionItemTransformation` does. A value is `ALGO=hash`,
/// `ALGO|hash`, or a bare hash whose algorithm is inferred from its length.
pub(super) fn decompose_hashes_field(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    hashes: &HashesFields<'_>,
) -> Result<()> {
    let rule_title = rule.title.clone();
    for detection in rule.detection.named.values_mut() {
        decompose_hashes_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            hashes,
            &rule_title,
        )?;
    }
    Ok(())
}

fn decompose_hashes_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    hashes: &HashesFields<'_>,
    rule_title: &str,
) -> Result<()> {
    match detection {
        Detection::AllOf(items) => {
            let mut kept = Vec::with_capacity(items.len());
            let mut groups = Vec::new();
            for item in items.drain(..) {
                let parses = item
                    .field
                    .name
                    .as_ref()
                    .is_some_and(|name| hashes.field_to_parse.contains(name))
                    && item
                        .values
                        .iter()
                        .all(|v| matches!(v, SigmaValue::String(_)))
                    && !item.field.modifiers.contains(&Modifier::FieldRef)
                    && item_conditions_match(
                        &item,
                        state,
                        detection_conditions,
                        field_name_conditions,
                    );
                if parses {
                    groups.push(hash_value_group(&item, hashes, rule_title)?);
                } else {
                    kept.push(item);
                }
            }
            if groups.is_empty() {
                *items = kept;
            } else {
                let mut parts = Vec::with_capacity(groups.len() + 1);
                if !kept.is_empty() {
                    parts.push(Detection::AllOf(kept));
                }
                parts.extend(groups);
                *detection = match parts.len() {
                    1 => parts.pop().expect("one part"),
                    _ => Detection::And(parts),
                };
            }
        }
        Detection::AnyOf(subs) | Detection::And(subs) => {
            for sub in subs.iter_mut() {
                decompose_hashes_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    hashes,
                    rule_title,
                )?;
            }
        }
        Detection::ArrayMatch { body, .. } => {
            decompose_hashes_in_detection(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
                hashes,
                rule_title,
            )?;
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                decompose_hashes_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    hashes,
                    rule_title,
                )?;
            }
        }
        Detection::Keywords(_) => {}
    }
    Ok(())
}

/// The OR over per-algorithm fields that replaces one hashes detection item.
fn hash_value_group(
    item: &DetectionItem,
    hashes: &HashesFields<'_>,
    rule_title: &str,
) -> Result<Detection> {
    let mut by_field: Vec<(String, Vec<SigmaValue>)> = Vec::new();
    for value in &item.values {
        let SigmaValue::String(s) = value else {
            continue;
        };
        let plain = plain_text_with_wildcards(s);
        let parts: Vec<&str> = if plain.contains('|') {
            plain.split('|').collect()
        } else {
            plain.split('=').collect()
        };
        let (algo, hash) = if let [algo, hash] = parts.as_slice() {
            (
                algo.trim_start_matches('*').to_uppercase(),
                hash.trim_matches(['*', '?']),
            )
        } else {
            let hash = parts[0].trim_matches(['*', '?']);
            let algo = match hash.len() {
                32 => "MD5",
                40 => "SHA1",
                64 => "SHA256",
                128 => "SHA512",
                _ => "",
            };
            (algo.to_string(), hash)
        };
        if algo.is_empty() || !hashes.valid_hash_algos.contains(&algo) {
            continue;
        }
        let field = if hashes.drop_algo_prefix {
            hashes.field_prefix.to_string()
        } else {
            format!("{}{algo}", hashes.field_prefix)
        };
        if field.is_empty() {
            continue;
        }
        let hash = SigmaValue::String(SigmaString::new(hash));
        match by_field.iter_mut().find(|(name, _)| *name == field) {
            Some((_, values)) => values.push(hash),
            None => by_field.push((field, vec![hash])),
        }
    }
    if by_field.is_empty() {
        return Err(EvalError::Pipeline(format!(
            "no valid hash algorithm found in field '{}'; use one of: {} (rule: {rule_title})",
            item.field.name.as_deref().unwrap_or_default(),
            hashes.valid_hash_algos.join(", ")
        )));
    }
    Ok(Detection::AnyOf(
        by_field
            .into_iter()
            .map(|(field, values)| {
                Detection::AllOf(vec![DetectionItem {
                    field: FieldSpec::new(Some(field), Vec::new()),
                    values,
                }])
            })
            .collect(),
    ))
}

/// The text of a Sigma string with wildcards written as `*` and `?`.
fn plain_text_with_wildcards(s: &SigmaString) -> String {
    s.parts
        .iter()
        .map(|part| match part {
            StringPart::Plain(text) => text.as_str(),
            StringPart::Special(SpecialChar::WildcardMulti) => "*",
            StringPart::Special(SpecialChar::WildcardSingle) => "?",
        })
        .collect()
}

// =============================================================================
// Map string values
// =============================================================================

pub(super) fn map_string_values(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    mapping: &HashMap<String, Vec<String>>,
) {
    for detection in rule.detection.named.values_mut() {
        map_strings_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            mapping,
        );
    }
}

fn map_strings_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    mapping: &HashMap<String, Vec<String>>,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item_conditions_match(item, state, detection_conditions, field_name_conditions) {
                    map_string_expand_values(&mut item.values, mapping);
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                map_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    mapping,
                );
            }
        }
        Detection::ArrayMatch { body, .. } => {
            map_strings_in_detection(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
                mapping,
            );
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                map_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    mapping,
                );
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                map_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    mapping,
                );
            }
        }
        Detection::Keywords(values) => {
            map_string_expand_values(values, mapping);
        }
    }
}

/// Map string values with one-to-many support.
///
/// When a mapping entry has multiple replacements (e.g. `"foo": ["bar", "baz"]`),
/// the original value is replaced with the first alternative and additional
/// alternatives are appended to the values list. This expands the detection
/// item's value list, matching pySigma's `MapStringTransformation` behavior.
fn map_string_expand_values(values: &mut Vec<SigmaValue>, mapping: &HashMap<String, Vec<String>>) {
    let mut extra: Vec<(usize, Vec<SigmaValue>)> = Vec::new();

    for (i, val) in values.iter_mut().enumerate() {
        if let SigmaValue::String(s) = val {
            let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
            if let Some(replacements) = mapping.get(&plain) {
                if let Some(first) = replacements.first() {
                    *s = SigmaString::new(first);
                }
                if replacements.len() > 1 {
                    let extras: Vec<SigmaValue> = replacements[1..]
                        .iter()
                        .map(|r| SigmaValue::String(SigmaString::new(r)))
                        .collect();
                    extra.push((i, extras));
                }
            }
        }
    }

    // Insert extra values in reverse order so indices remain valid
    for (idx, extras) in extra.into_iter().rev() {
        for (j, v) in extras.into_iter().enumerate() {
            values.insert(idx + 1 + j, v);
        }
    }
}

// =============================================================================
// Set value
// =============================================================================

pub(super) fn set_detection_item_values(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    value: &SigmaValue,
) {
    for detection in rule.detection.named.values_mut() {
        set_values_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            value,
        );
    }
}

fn set_values_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    value: &SigmaValue,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item_conditions_match(item, state, detection_conditions, field_name_conditions) {
                    item.values = vec![value.clone()];
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                set_values_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    value,
                );
            }
        }
        Detection::ArrayMatch { body, .. } => {
            set_values_in_detection(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
                value,
            );
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                set_values_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    value,
                );
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                set_values_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    value,
                );
            }
        }
        Detection::Keywords(_) => {}
    }
}

// =============================================================================
// Convert type
// =============================================================================

pub(super) fn convert_detection_item_types(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    target_type: &str,
) {
    for detection in rule.detection.named.values_mut() {
        convert_types_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            target_type,
        );
    }
}

fn convert_types_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    target_type: &str,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item_conditions_match(item, state, detection_conditions, field_name_conditions) {
                    for val in item.values.iter_mut() {
                        *val = convert_value(val, target_type);
                    }
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                convert_types_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    target_type,
                );
            }
        }
        Detection::ArrayMatch { body, .. } => {
            convert_types_in_detection(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
                target_type,
            );
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                convert_types_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    target_type,
                );
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                convert_types_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    target_type,
                );
            }
        }
        Detection::Keywords(_) => {}
    }
}

fn convert_value(val: &SigmaValue, target: &str) -> SigmaValue {
    match target {
        "str" | "string" => match val {
            SigmaValue::String(_) => val.clone(),
            SigmaValue::Integer(n) => SigmaValue::String(SigmaString::new(&n.to_string())),
            SigmaValue::Float(f) => SigmaValue::String(SigmaString::new(&f.to_string())),
            SigmaValue::Bool(b) => SigmaValue::String(SigmaString::new(&b.to_string())),
            SigmaValue::Null => SigmaValue::String(SigmaString::new("null")),
        },
        "int" | "integer" => match val {
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                plain
                    .parse::<i64>()
                    .map(SigmaValue::Integer)
                    .unwrap_or_else(|_| val.clone())
            }
            SigmaValue::Float(f) => SigmaValue::Integer(*f as i64),
            SigmaValue::Bool(b) => SigmaValue::Integer(if *b { 1 } else { 0 }),
            _ => val.clone(),
        },
        "float" => match val {
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                plain
                    .parse::<f64>()
                    .map(SigmaValue::Float)
                    .unwrap_or_else(|_| val.clone())
            }
            SigmaValue::Integer(n) => SigmaValue::Float(*n as f64),
            SigmaValue::Bool(b) => SigmaValue::Float(if *b { 1.0 } else { 0.0 }),
            _ => val.clone(),
        },
        "bool" | "boolean" => match val {
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                match plain.to_lowercase().as_str() {
                    "true" | "1" | "yes" => SigmaValue::Bool(true),
                    "false" | "0" | "no" => SigmaValue::Bool(false),
                    _ => val.clone(),
                }
            }
            SigmaValue::Integer(n) => SigmaValue::Bool(*n != 0),
            SigmaValue::Float(f) => SigmaValue::Bool(*f != 0.0),
            _ => val.clone(),
        },
        _ => val.clone(),
    }
}

// =============================================================================
// Case transformation
// =============================================================================

pub(super) fn apply_case_transformation(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    case_type: &str,
) {
    for detection in rule.detection.named.values_mut() {
        apply_case_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            case_type,
        );
    }
}

fn apply_case_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
    case_type: &str,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if item_conditions_match(item, state, detection_conditions, field_name_conditions) {
                    for val in item.values.iter_mut() {
                        apply_case_to_value(val, case_type);
                    }
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                apply_case_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    case_type,
                );
            }
        }
        Detection::ArrayMatch { body, .. } => {
            apply_case_in_detection(
                body.as_mut(),
                state,
                detection_conditions,
                field_name_conditions,
                case_type,
            );
        }
        Detection::And(subs) => {
            for sub in subs.iter_mut() {
                apply_case_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    case_type,
                );
            }
        }
        Detection::Conditional { named, .. } => {
            for sub in named.values_mut() {
                apply_case_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    case_type,
                );
            }
        }
        Detection::Keywords(values) => {
            for val in values.iter_mut() {
                apply_case_to_value(val, case_type);
            }
        }
    }
}

fn apply_case_to_value(val: &mut SigmaValue, case_type: &str) {
    if let SigmaValue::String(s) = val {
        let transformed = match case_type {
            "lower" | "lowercase" => s.original.to_lowercase(),
            "upper" | "uppercase" => s.original.to_uppercase(),
            "snake_case" => apply_named_string_fn("snake_case", &s.original),
            _ => return,
        };
        if transformed != s.original {
            *s = SigmaString::new(&transformed);
        }
    }
}

// =============================================================================
// Shared helper: check if a detection item matches both sets of conditions
// =============================================================================

/// pySigma's `match_detection_item`: the detection-item conditions and the
/// field-name conditions evaluated over the item's field name or any of its
/// field reference targets, each set's negation applied to that result.
fn item_conditions_match(
    item: &DetectionItem,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
) -> bool {
    detection_conditions_match(item, state, detection_conditions)
        && field_name_conditions
            .iter()
            .all(|set| set.matches(|condition| condition.matches_detection_item(item, state)))
}

// =============================================================================
// Helper: check if rule has any item matching conditions
// =============================================================================

pub(super) fn rule_has_matching_item(
    rule: &SigmaRule,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
) -> bool {
    rule.detection.named.values().any(|detection| {
        detection_has_matching_item(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
        )
    })
}

fn detection_has_matching_item(
    detection: &Detection,
    state: &PipelineState,
    detection_conditions: &[&ConditionSet<DetectionItemCondition>],
    field_name_conditions: &[&ConditionSet<FieldNameCondition>],
) -> bool {
    let recurse = |sub: &Detection| {
        detection_has_matching_item(sub, state, detection_conditions, field_name_conditions)
    };
    match detection {
        Detection::AllOf(items) => items.iter().any(|item| {
            item_conditions_match(item, state, detection_conditions, field_name_conditions)
        }),
        Detection::AnyOf(subs) | Detection::And(subs) => subs.iter().any(recurse),
        Detection::ArrayMatch { body, .. } => recurse(body.as_ref()),
        Detection::Conditional { named, .. } => named.values().any(recurse),
        Detection::Keywords(_) => false,
    }
}

// =============================================================================
// Detection item change tracking
// =============================================================================

/// Record every detection item that the transformation item being applied
/// changed between `before` and `after`, for detection-item
/// `processing_item_applied` conditions. An item that kept its position takes
/// over the IDs of the item it replaced; an item with no counterpart (such as
/// a `hashes_fields` replacement) only carries the current ID. Detections the
/// transformation added are not tracked.
pub(in crate::pipeline) fn track_detection_item_changes(
    before: &HashMap<String, Detection>,
    after: &HashMap<String, Detection>,
    state: &mut PipelineState,
) {
    let mut changes = Vec::new();
    for (name, detection) in after {
        if let Some(previous) = before.get(name) {
            diff_detection(previous, detection, &mut changes);
        }
    }
    let id = state.current_item_id.clone();
    for (previous, current) in changes {
        state.track_detection_item_change(previous, current, id.as_deref());
    }
}

fn diff_detection<'a>(
    before: &'a Detection,
    after: &'a Detection,
    changes: &mut Vec<(Option<&'a DetectionItem>, &'a DetectionItem)>,
) {
    match (before, after) {
        (Detection::AllOf(old), Detection::AllOf(new)) if old.len() == new.len() => {
            diff_items(old, new, changes);
        }
        (Detection::AllOf(old), Detection::AnyOf(branches))
            if branches.iter().all(
                |branch| matches!(branch, Detection::AllOf(new) if new.len() == old.len()),
            ) =>
        {
            for branch in branches {
                if let Detection::AllOf(new) = branch {
                    diff_items(old, new, changes);
                }
            }
        }
        (Detection::AnyOf(old), Detection::AnyOf(new))
        | (Detection::And(old), Detection::And(new))
            if old.len() == new.len() =>
        {
            for (old, new) in old.iter().zip(new) {
                diff_detection(old, new, changes);
            }
        }
        (Detection::ArrayMatch { body: old, .. }, Detection::ArrayMatch { body: new, .. }) => {
            diff_detection(old, new, changes);
        }
        (Detection::Conditional { named: old, .. }, Detection::Conditional { named: new, .. }) => {
            for (name, new) in new {
                if let Some(old) = old.get(name) {
                    diff_detection(old, new, changes);
                }
            }
        }
        _ => {
            let mut old_items = Vec::new();
            collect_items(before, &mut old_items);
            let mut new_items = Vec::new();
            collect_items(after, &mut new_items);
            for item in new_items {
                if !old_items.contains(&item) {
                    changes.push((None, item));
                }
            }
        }
    }
}

fn diff_items<'a>(
    old: &'a [DetectionItem],
    new: &'a [DetectionItem],
    changes: &mut Vec<(Option<&'a DetectionItem>, &'a DetectionItem)>,
) {
    for (old, new) in old.iter().zip(new) {
        if old != new {
            changes.push((Some(old), new));
        }
    }
}

fn collect_items<'a>(detection: &'a Detection, items: &mut Vec<&'a DetectionItem>) {
    match detection {
        Detection::AllOf(all) => items.extend(all),
        Detection::AnyOf(subs) | Detection::And(subs) => {
            for sub in subs {
                collect_items(sub, items);
            }
        }
        Detection::ArrayMatch { body, .. } => collect_items(body, items),
        Detection::Conditional { named, .. } => {
            for sub in named.values() {
                collect_items(sub, items);
            }
        }
        Detection::Keywords(_) => {}
    }
}
