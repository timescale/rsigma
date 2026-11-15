//! Emit a parsed Sigma rule back to canonical Sigma YAML.
//!
//! This is the inverse of [`parse_sigma_yaml`](crate::parse_sigma_yaml): it
//! turns a [`SigmaRule`] (or a [`SigmaCollection`] of detection rules) back
//! into standard Sigma YAML. Parsing then emitting then parsing again yields an
//! equal AST for the detection-rule shapes the parser produces (field matching
//! with modifiers, value lists, keyword blocks, `field[any]`/`field[all]` array
//! blocks, boolean and quantified conditions, and all standard metadata).
//!
//! The emitter is deterministic: mapping-shaped collections (named detections,
//! logsource custom fields, custom attributes) are emitted in sorted key order,
//! so the same rule always produces byte-identical YAML. Detection value order
//! and condition order are preserved as-is.
//!
//! Value scalars are rendered in Sigma's canonical quoting: a string stays
//! plain only when YAML would read it back as exactly that string, and literal
//! `*`, `?`, and `\` are escaped so a re-parse reproduces the same
//! [`SigmaString`] wildcard structure.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use crate::ast::{
    ArrayQuantifier, ConditionExpr, ConditionOperator, CorrelationCondition, CorrelationRule,
    Detection, DetectionItem, Detections, FieldAlias, FilterRule, FilterRuleTarget, LogSource,
    Modifier, Related, RelationType, SigmaCollection, SigmaRule, Status, WindowMode,
};
use crate::style::{KeyCtx, Lead, RSIGMA_ORDER, STEP, ScalarCtx, encode_key, push_scalar};
use crate::value::{SigmaString, SigmaValue, SpecialChar, StringPart};

/// Emit a single detection [`SigmaRule`] as canonical Sigma YAML.
///
/// The output always ends with a trailing newline and re-parses to an equal
/// [`SigmaRule`].
pub fn emit_rule_yaml(rule: &SigmaRule) -> String {
    let mut out = String::new();

    push_scalar(
        &mut out,
        "",
        Lead::Key("title"),
        &rule.title,
        ScalarCtx::Prose,
    );
    if let Some(id) = &rule.id {
        push_scalar(&mut out, "", Lead::Key("id"), id, ScalarCtx::Value);
    }
    if let Some(name) = &rule.name {
        push_scalar(&mut out, "", Lead::Key("name"), name, ScalarCtx::Value);
    }
    if let Some(status) = &rule.status {
        push_line(&mut out, "status", status_str(*status));
    }
    if let Some(description) = &rule.description {
        push_scalar(
            &mut out,
            "",
            Lead::Key("description"),
            description,
            ScalarCtx::Prose,
        );
    }
    emit_string_list(&mut out, "references", &rule.references, ScalarCtx::Prose);
    if let Some(author) = &rule.author {
        push_scalar(&mut out, "", Lead::Key("author"), author, ScalarCtx::Prose);
    }
    if let Some(date) = &rule.date {
        push_scalar(&mut out, "", Lead::Key("date"), date, ScalarCtx::Value);
    }
    if let Some(modified) = &rule.modified {
        push_scalar(
            &mut out,
            "",
            Lead::Key("modified"),
            modified,
            ScalarCtx::Value,
        );
    }
    emit_related(&mut out, &rule.related);
    emit_string_list(&mut out, "tags", &rule.tags, ScalarCtx::Prose);
    if let Some(version) = rule.sigma_version {
        push_line(&mut out, "sigma-version", &version.to_string());
    }
    emit_logsource(&mut out, &rule.logsource);
    emit_detection(&mut out, &rule.detection);
    emit_string_list(&mut out, "fields", &rule.fields, ScalarCtx::Prose);
    emit_string_list(
        &mut out,
        "falsepositives",
        &rule.falsepositives,
        ScalarCtx::Prose,
    );
    if let Some(level) = &rule.level {
        push_line(&mut out, "level", level.as_str());
    }
    emit_string_list(&mut out, "scope", &rule.scope, ScalarCtx::Prose);
    if let Some(license) = &rule.license {
        push_scalar(
            &mut out,
            "",
            Lead::Key("license"),
            license,
            ScalarCtx::Prose,
        );
    }
    if let Some(taxonomy) = &rule.taxonomy {
        push_scalar(
            &mut out,
            "",
            Lead::Key("taxonomy"),
            taxonomy,
            ScalarCtx::Value,
        );
    }
    emit_custom_attributes(&mut out, &rule.custom_attributes);

    out
}

/// Emit a single [`CorrelationRule`] as canonical Sigma YAML.
///
/// The output always ends with a trailing newline and re-parses to an equal
/// [`CorrelationRule`]. Correlation bodies are emitted in the key order the
/// parser accepts, `window` only when it is not the default sliding mode, and
/// `generate` only when true.
///
/// ```rust
/// use rsigma_parser::{emit_correlation_yaml, parse_sigma_yaml};
///
/// let yaml = r#"
/// title: Burst of failed logins
/// correlation:
///     type: event_count
///     rules:
///         - failed_login
///     group-by:
///         - User
///     timespan: 5m
///     condition:
///         gte: 10
/// "#;
/// let collection = parse_sigma_yaml(yaml).unwrap();
/// let emitted = emit_correlation_yaml(&collection.correlations[0]);
/// assert!(emitted.contains("type: event_count"));
/// assert!(emitted.contains("gte: 10"));
/// ```
pub fn emit_correlation_yaml(rule: &CorrelationRule) -> String {
    let mut out = String::new();

    push_scalar(
        &mut out,
        "",
        Lead::Key("title"),
        &rule.title,
        ScalarCtx::Prose,
    );
    if let Some(id) = &rule.id {
        push_scalar(&mut out, "", Lead::Key("id"), id, ScalarCtx::Value);
    }
    if let Some(name) = &rule.name {
        push_scalar(&mut out, "", Lead::Key("name"), name, ScalarCtx::Value);
    }
    if let Some(status) = &rule.status {
        push_line(&mut out, "status", status_str(*status));
    }
    if let Some(description) = &rule.description {
        push_scalar(
            &mut out,
            "",
            Lead::Key("description"),
            description,
            ScalarCtx::Prose,
        );
    }
    emit_string_list(&mut out, "references", &rule.references, ScalarCtx::Prose);
    if let Some(author) = &rule.author {
        push_scalar(&mut out, "", Lead::Key("author"), author, ScalarCtx::Prose);
    }
    if let Some(date) = &rule.date {
        push_scalar(&mut out, "", Lead::Key("date"), date, ScalarCtx::Value);
    }
    if let Some(modified) = &rule.modified {
        push_scalar(
            &mut out,
            "",
            Lead::Key("modified"),
            modified,
            ScalarCtx::Value,
        );
    }
    emit_related(&mut out, &rule.related);
    emit_string_list(&mut out, "tags", &rule.tags, ScalarCtx::Prose);
    if let Some(version) = rule.sigma_version {
        push_line(&mut out, "sigma-version", &version.to_string());
    }

    let _ = writeln!(out, "correlation:");
    push_line(&mut out, "    type", rule.correlation_type.as_str());
    emit_string_list_at(&mut out, "    rules", &rule.rules, ScalarCtx::Value);
    emit_string_list_at(&mut out, "    group-by", &rule.group_by, ScalarCtx::Value);
    push_line(&mut out, "    timespan", &rule.timespan.to_string());
    if rule.window != WindowMode::Sliding {
        push_line(&mut out, "    window", rule.window.as_str());
    }
    if let Some(gap) = &rule.gap {
        push_line(&mut out, "    gap", &gap.to_string());
    }
    emit_correlation_condition(&mut out, "    ", &rule.condition);
    emit_correlation_aliases(&mut out, &rule.aliases);
    if rule.generate {
        push_line(&mut out, "    generate", "true");
    }

    emit_string_list(&mut out, "fields", &rule.fields, ScalarCtx::Prose);
    emit_string_list(
        &mut out,
        "falsepositives",
        &rule.falsepositives,
        ScalarCtx::Prose,
    );
    if let Some(level) = &rule.level {
        push_line(&mut out, "level", level.as_str());
    }
    emit_string_list(&mut out, "scope", &rule.scope, ScalarCtx::Prose);
    if let Some(license) = &rule.license {
        push_scalar(
            &mut out,
            "",
            Lead::Key("license"),
            license,
            ScalarCtx::Prose,
        );
    }
    if let Some(taxonomy) = &rule.taxonomy {
        push_scalar(
            &mut out,
            "",
            Lead::Key("taxonomy"),
            taxonomy,
            ScalarCtx::Value,
        );
    }
    emit_custom_attributes(&mut out, &rule.custom_attributes);

    out
}

/// Emit a single [`FilterRule`] as canonical Sigma YAML.
///
/// The output always ends with a trailing newline and re-parses to an equal
/// [`FilterRule`]. The `filter:` block carries the detection items and
/// condition; `rules` is omitted when the filter applies to every rule.
///
/// ```rust
/// use rsigma_parser::{emit_filter_yaml, parse_sigma_yaml};
///
/// let yaml = r#"
/// title: Drop system accounts
/// logsource:
///     product: windows
/// filter:
///     rules:
///         - failed_login
///     selection:
///         User|endswith: '$'
///     condition: selection
/// "#;
/// let collection = parse_sigma_yaml(yaml).unwrap();
/// let emitted = emit_filter_yaml(&collection.filters[0]);
/// assert!(emitted.contains("filter:"));
/// assert!(emitted.contains("User|endswith"));
/// ```
pub fn emit_filter_yaml(rule: &FilterRule) -> String {
    let mut out = String::new();

    push_scalar(
        &mut out,
        "",
        Lead::Key("title"),
        &rule.title,
        ScalarCtx::Prose,
    );
    if let Some(id) = &rule.id {
        push_scalar(&mut out, "", Lead::Key("id"), id, ScalarCtx::Value);
    }
    if let Some(name) = &rule.name {
        push_scalar(&mut out, "", Lead::Key("name"), name, ScalarCtx::Value);
    }
    if let Some(status) = &rule.status {
        push_line(&mut out, "status", status_str(*status));
    }
    if let Some(description) = &rule.description {
        push_scalar(
            &mut out,
            "",
            Lead::Key("description"),
            description,
            ScalarCtx::Prose,
        );
    }
    emit_string_list(&mut out, "references", &rule.references, ScalarCtx::Prose);
    if let Some(author) = &rule.author {
        push_scalar(&mut out, "", Lead::Key("author"), author, ScalarCtx::Prose);
    }
    if let Some(date) = &rule.date {
        push_scalar(&mut out, "", Lead::Key("date"), date, ScalarCtx::Value);
    }
    if let Some(modified) = &rule.modified {
        push_scalar(
            &mut out,
            "",
            Lead::Key("modified"),
            modified,
            ScalarCtx::Value,
        );
    }
    emit_related(&mut out, &rule.related);
    emit_string_list(&mut out, "tags", &rule.tags, ScalarCtx::Prose);
    if let Some(version) = rule.sigma_version {
        push_line(&mut out, "sigma-version", &version.to_string());
    }
    match &rule.logsource {
        Some(logsource) => emit_logsource(&mut out, logsource),
        None => {
            let _ = writeln!(out, "logsource: {{}}");
        }
    }

    let _ = writeln!(out, "filter:");
    if let FilterRuleTarget::Specific(targets) = &rule.rules {
        emit_string_list_at(&mut out, "    rules", targets, ScalarCtx::Value);
    }
    for (name, det) in sorted_named(&rule.detection.named) {
        emit_named_detection(&mut out, name, det, "    ");
    }
    emit_timeframe(&mut out, "    ", &rule.detection);
    emit_condition_at(&mut out, "    ", &rule.detection.conditions);

    emit_string_list(&mut out, "fields", &rule.fields, ScalarCtx::Prose);
    emit_string_list(
        &mut out,
        "falsepositives",
        &rule.falsepositives,
        ScalarCtx::Prose,
    );
    if let Some(level) = &rule.level {
        push_line(&mut out, "level", level.as_str());
    }
    emit_string_list(&mut out, "scope", &rule.scope, ScalarCtx::Prose);
    if let Some(license) = &rule.license {
        push_scalar(
            &mut out,
            "",
            Lead::Key("license"),
            license,
            ScalarCtx::Prose,
        );
    }
    if let Some(taxonomy) = &rule.taxonomy {
        push_scalar(
            &mut out,
            "",
            Lead::Key("taxonomy"),
            taxonomy,
            ScalarCtx::Value,
        );
    }
    emit_custom_attributes(&mut out, &rule.custom_attributes);

    out
}

/// Emit every detection rule in a collection, separated by `---` documents.
///
/// Correlation and filter documents are not part of the reverse-conversion
/// surface and are skipped; only [`SigmaCollection::rules`] are emitted.
pub fn emit_collection_yaml(collection: &SigmaCollection) -> String {
    collection
        .rules
        .iter()
        .map(emit_rule_yaml)
        .collect::<Vec<_>>()
        .join("---\n")
}

// =============================================================================
// Metadata sections
// =============================================================================

fn push_line(out: &mut String, key: &str, value: &str) {
    let _ = writeln!(out, "{key}: {value}");
}

fn emit_string_list(out: &mut String, key: &str, items: &[String], ctx: ScalarCtx) {
    emit_string_list_at(out, key, items, ctx);
}

/// Emit a list whose key may carry leading indentation (for nested blocks).
fn emit_string_list_at(out: &mut String, key: &str, items: &[String], ctx: ScalarCtx) {
    if items.is_empty() {
        return;
    }
    let _ = writeln!(out, "{key}:");
    let indent = format!("{}{STEP}", leading_whitespace(key));
    for item in items {
        push_scalar(out, &indent, Lead::Dash, item, ctx);
    }
}

fn leading_whitespace(s: &str) -> &str {
    &s[..s.len() - s.trim_start().len()]
}

fn emit_related(out: &mut String, related: &[Related]) {
    if related.is_empty() {
        return;
    }
    let _ = writeln!(out, "related:");
    for entry in related {
        push_scalar(
            out,
            &format!("{STEP}- "),
            Lead::Key("id"),
            &entry.id,
            ScalarCtx::Value,
        );
        let _ = writeln!(out, "{STEP}  type: {}", relation_str(entry.relation_type));
    }
}

fn emit_logsource(out: &mut String, logsource: &LogSource) {
    // An empty `logsource:` key parses as null, which the parser reports as
    // not being a mapping; an explicit empty mapping gets the clearer error
    // that no log source field is set.
    if logsource.category.is_none()
        && logsource.product.is_none()
        && logsource.service.is_none()
        && logsource.definition.is_none()
        && logsource.custom.is_empty()
    {
        let _ = writeln!(out, "logsource: {{}}");
        return;
    }
    let _ = writeln!(out, "logsource:");
    if let Some(category) = &logsource.category {
        push_scalar(out, STEP, Lead::Key("category"), category, ScalarCtx::Value);
    }
    if let Some(product) = &logsource.product {
        push_scalar(out, STEP, Lead::Key("product"), product, ScalarCtx::Value);
    }
    if let Some(service) = &logsource.service {
        push_scalar(out, STEP, Lead::Key("service"), service, ScalarCtx::Value);
    }
    if let Some(definition) = &logsource.definition {
        push_scalar(
            out,
            STEP,
            Lead::Key("definition"),
            definition,
            ScalarCtx::Prose,
        );
    }
    for (key, value) in sorted(&logsource.custom) {
        push_scalar(
            out,
            STEP,
            Lead::Key(&encode_key(key, KeyCtx::Key)),
            value,
            ScalarCtx::Value,
        );
    }
}

fn emit_custom_attributes(out: &mut String, attrs: &HashMap<String, yaml_serde::Value>) {
    let mut keys: Vec<&str> = attrs.keys().map(String::as_str).collect();
    let mut ordered: Vec<&str> = RSIGMA_ORDER
        .iter()
        .copied()
        .filter(|key| attrs.contains_key(*key))
        .collect();
    keys.sort_unstable();
    ordered.extend(keys.into_iter().filter(|key| !RSIGMA_ORDER.contains(key)));
    for key in ordered {
        let value = &attrs[key];
        emit_yaml_value(out, &encode_key(key, KeyCtx::Key), value, "");
    }
}

// =============================================================================
// Detection section
// =============================================================================

fn emit_detection(out: &mut String, detection: &Detections) {
    let _ = writeln!(out, "detection:");
    for (name, det) in sorted_named(&detection.named) {
        emit_named_detection(out, name, det, STEP);
    }
    emit_timeframe(out, STEP, detection);
    emit_condition(out, &detection.conditions);
}

fn emit_timeframe(out: &mut String, indent: &str, detection: &Detections) {
    if let Some(timeframe) = &detection.timeframe {
        push_scalar(
            out,
            indent,
            Lead::Key("timeframe"),
            timeframe,
            ScalarCtx::Value,
        );
    }
}

fn emit_condition(out: &mut String, conditions: &[ConditionExpr]) {
    emit_condition_at(out, STEP, conditions);
}

fn emit_condition_at(out: &mut String, indent: &str, conditions: &[ConditionExpr]) {
    match conditions {
        [] => {}
        [single] => {
            push_scalar(
                out,
                indent,
                Lead::Key("condition"),
                &condition_source(single),
                ScalarCtx::Condition,
            );
        }
        many => {
            let _ = writeln!(out, "{indent}condition:");
            let nested = deeper(indent);
            for cond in many {
                push_scalar(
                    out,
                    &nested,
                    Lead::Dash,
                    &condition_source(cond),
                    ScalarCtx::Condition,
                );
            }
        }
    }
}

/// Render a condition expression as a Sigma condition string, without the
/// redundant outer parentheses [`ConditionExpr`]'s `Display` adds around a
/// top-level `and`/`or`.
fn condition_source(expr: &ConditionExpr) -> String {
    match expr {
        ConditionExpr::And(parts) => parts
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(" and "),
        ConditionExpr::Or(parts) => parts
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(" or "),
        other => other.to_string(),
    }
}

/// Emit a correlation `condition:` block at `indent` (including the key).
fn emit_correlation_condition(out: &mut String, indent: &str, condition: &CorrelationCondition) {
    match condition {
        CorrelationCondition::Threshold {
            predicates,
            field,
            percentile,
        } => {
            let _ = writeln!(out, "{indent}condition:");
            let nested = deeper(indent);
            let mut ordered: Vec<&(ConditionOperator, u64)> = predicates.iter().collect();
            ordered.sort_by_key(|(op, _)| operator_rank(*op));
            for (op, value) in ordered {
                push_line(
                    out,
                    &format!("{nested}{}", operator_str(*op)),
                    &value.to_string(),
                );
            }
            if let Some(field) = field {
                match field.as_slice() {
                    [single] => {
                        push_scalar(out, &nested, Lead::Key("field"), single, ScalarCtx::Value)
                    }
                    many => {
                        emit_string_list_at(out, &format!("{nested}field"), many, ScalarCtx::Value)
                    }
                }
            }
            if let Some(percentile) = percentile {
                push_line(out, &format!("{nested}percentile"), &percentile.to_string());
            }
        }
        CorrelationCondition::Extended(expr) => {
            push_scalar(
                out,
                indent,
                Lead::Key("condition"),
                &condition_source(expr),
                ScalarCtx::Condition,
            );
        }
    }
}

/// Emit the `aliases:` mapping of a correlation, with sorted per-rule keys.
fn emit_correlation_aliases(out: &mut String, aliases: &[FieldAlias]) {
    if aliases.is_empty() {
        return;
    }
    let _ = writeln!(out, "{STEP}aliases:");
    for alias in aliases {
        let _ = writeln!(
            out,
            "{STEP}{STEP}{}:",
            encode_key(&alias.alias, KeyCtx::Key)
        );
        let mut mapping: Vec<(&String, &String)> = alias.mapping.iter().collect();
        mapping.sort_by(|a, b| a.0.cmp(b.0));
        for (rule, field) in mapping {
            push_scalar(
                out,
                &format!("{STEP}{STEP}{STEP}"),
                Lead::Key(&encode_key(rule, KeyCtx::Key)),
                field,
                ScalarCtx::Value,
            );
        }
    }
}

fn emit_named_detection(out: &mut String, name: &str, det: &Detection, indent: &str) {
    let _ = writeln!(out, "{indent}{}:", encode_key(name, KeyCtx::Key));
    emit_detection_value(out, det, &deeper(indent));
}

/// Emit the body of a detection at `indent` (a mapping of items, a YAML list,
/// or a keyword list depending on the detection shape).
fn emit_detection_value(out: &mut String, det: &Detection, indent: &str) {
    match det {
        Detection::AnyOf(subs) => {
            for sub in subs {
                emit_list_item(out, sub, indent);
            }
        }
        Detection::Keywords(values) => {
            for value in values {
                push_value(out, indent, Lead::Dash, value, false, false);
            }
        }
        map_shaped => emit_map_entries(out, map_shaped, indent),
    }
}

/// Emit the `key: value` entries of a mapping-shaped detection.
fn emit_map_entries(out: &mut String, det: &Detection, indent: &str) {
    match det {
        Detection::AllOf(items) => {
            for item in items {
                emit_item(out, item, indent);
            }
        }
        Detection::And(subs) => {
            for sub in subs {
                emit_map_entries(out, sub, indent);
            }
        }
        Detection::ArrayMatch {
            field,
            quantifier,
            body,
        } => {
            let key = format!("{}[{}]", field, array_str(*quantifier));
            let _ = writeln!(out, "{indent}{}:", encode_key(&key, KeyCtx::FieldKey));
            emit_detection_value(out, body, &deeper(indent));
        }
        Detection::Conditional { named, condition } => {
            for (name, sub) in sorted_named(named) {
                emit_named_detection(out, name, sub, indent);
            }
            push_scalar(
                out,
                indent,
                Lead::Key("condition"),
                &condition_source(condition),
                ScalarCtx::Condition,
            );
        }
        // List-shaped detections cannot appear as bare map entries; render them
        // under a synthetic block so nothing is silently dropped.
        Detection::AnyOf(_) | Detection::Keywords(_) => {
            emit_detection_value(out, det, indent);
        }
    }
}

/// Emit one YAML list item (`- ...`) for an `AnyOf` sub-detection.
fn emit_list_item(out: &mut String, det: &Detection, indent: &str) {
    let mut buf = String::new();
    emit_detection_value(&mut buf, det, "");
    for (i, line) in buf.lines().enumerate() {
        if i == 0 {
            let _ = writeln!(out, "{indent}- {line}");
        } else {
            let _ = writeln!(out, "{indent}  {line}");
        }
    }
}

/// Emit a single detection item (`field|mods: value` or a value list).
fn emit_item(out: &mut String, item: &DetectionItem, indent: &str) {
    let base = item.field.name.as_deref().unwrap_or(".");
    let key = field_key(base, &item.field.modifiers);
    // `re`, `cidr`, and `fieldref` values are raw strings (the parser reads them
    // without wildcard interpretation), so they must be emitted verbatim rather
    // than wildcard-escaped, or a regex like `ab.*c` would gain a stray `\`.
    let raw = item
        .field
        .modifiers
        .iter()
        .any(|m| matches!(m, Modifier::Re | Modifier::Cidr | Modifier::FieldRef));
    let expand = item.field.modifiers.contains(&Modifier::Expand);
    match item.values.as_slice() {
        [single] => {
            push_value(out, indent, Lead::Key(&key), single, raw, expand);
        }
        values => {
            let _ = writeln!(out, "{indent}{key}:");
            for value in values {
                push_value(out, &deeper(indent), Lead::Dash, value, raw, expand);
            }
        }
    }
}

/// Write a [`SigmaValue`]: strings go through [`push_scalar`] in the value
/// context, while non-string scalars are copied verbatim.
fn push_value(
    out: &mut String,
    indent: &str,
    lead: Lead<'_>,
    value: &SigmaValue,
    raw: bool,
    expand: bool,
) {
    match value {
        SigmaValue::String(s) => {
            let source = if expand {
                s.original.clone()
            } else if raw {
                s.as_plain().unwrap_or_else(|| s.original.clone())
            } else {
                sigma_string_source(s)
            };
            push_scalar(out, indent, lead, &source, ScalarCtx::Value);
        }
        other => {
            let token = match other {
                SigmaValue::Integer(n) => n.to_string(),
                SigmaValue::Float(f) => float_token(*f),
                SigmaValue::Bool(b) => b.to_string(),
                SigmaValue::Null => "null".to_string(),
                SigmaValue::String(_) => unreachable!("string handled above"),
            };
            let prefix = match lead {
                Lead::Key(key) => format!("{indent}{key}:"),
                Lead::Dash => format!("{indent}-"),
            };
            let _ = writeln!(out, "{prefix} {token}");
        }
    }
}

// =============================================================================
// yaml_serde value emission (custom attributes)
// =============================================================================

fn emit_yaml_value(out: &mut String, key: &str, value: &yaml_serde::Value, indent: &str) {
    match value {
        yaml_serde::Value::Mapping(map) if !map.is_empty() => {
            let _ = writeln!(out, "{indent}{key}:");
            for (k, v) in map {
                let child_key = yaml_key(k);
                emit_yaml_value(out, &child_key, v, &deeper(indent));
            }
        }
        yaml_serde::Value::Mapping(_) => {
            let _ = writeln!(out, "{indent}{key}: {{}}");
        }
        yaml_serde::Value::Sequence(seq) if !seq.is_empty() => {
            let _ = writeln!(out, "{indent}{key}:");
            for v in seq {
                emit_yaml_seq_item(out, v, &deeper(indent));
            }
        }
        yaml_serde::Value::Sequence(_) => {
            let _ = writeln!(out, "{indent}{key}: []");
        }
        yaml_serde::Value::String(s) => {
            push_scalar(out, indent, Lead::Key(key), s, ScalarCtx::Value);
        }
        scalar => {
            let _ = writeln!(out, "{indent}{key}: {}", yaml_scalar(scalar));
        }
    }
}

/// Emit one YAML sequence item, including nested mappings and sequences.
fn emit_yaml_seq_item(out: &mut String, value: &yaml_serde::Value, indent: &str) {
    match value {
        yaml_serde::Value::Mapping(map) if !map.is_empty() => {
            let mut buf = String::new();
            for (k, v) in map {
                let child_key = yaml_key(k);
                emit_yaml_value(&mut buf, &child_key, v, "");
            }
            for (i, line) in buf.lines().enumerate() {
                if i == 0 {
                    let _ = writeln!(out, "{indent}- {line}");
                } else {
                    let _ = writeln!(out, "{indent}  {line}");
                }
            }
        }
        yaml_serde::Value::Mapping(_) => {
            let _ = writeln!(out, "{indent}- {{}}");
        }
        yaml_serde::Value::Sequence(seq) if !seq.is_empty() => {
            let _ = writeln!(out, "{indent}-");
            for v in seq {
                emit_yaml_seq_item(out, v, &deeper(indent));
            }
        }
        yaml_serde::Value::Sequence(_) => {
            let _ = writeln!(out, "{indent}- []");
        }
        yaml_serde::Value::String(s) => {
            push_scalar(out, indent, Lead::Dash, s, ScalarCtx::Value);
        }
        scalar => {
            let _ = writeln!(out, "{indent}- {}", yaml_scalar(scalar));
        }
    }
}

fn yaml_key(value: &yaml_serde::Value) -> String {
    match value {
        yaml_serde::Value::String(s) => encode_key(s, KeyCtx::Key),
        other => yaml_scalar(other),
    }
}

fn yaml_scalar(value: &yaml_serde::Value) -> String {
    match value {
        yaml_serde::Value::Null => "null".to_string(),
        yaml_serde::Value::Bool(b) => b.to_string(),
        yaml_serde::Value::Number(n) if n.is_f64() => float_token(n.as_f64().unwrap_or_default()),
        yaml_serde::Value::Number(n) => n.to_string(),
        yaml_serde::Value::String(s) => encode_key(s, KeyCtx::Key),
        // Nested collections are handled by emit_yaml_value; an inline fallback
        // keeps the emitter total for unexpected placements.
        other => format!("{other:?}"),
    }
}

// =============================================================================
// Scalars, keys, and value tokens
// =============================================================================

/// Format a float so it re-parses as a float (never collapses `3.0` to `3`).
fn float_token(f: f64) -> String {
    if f.is_nan() {
        return ".nan".to_string();
    }
    if f == f64::INFINITY {
        return ".inf".to_string();
    }
    if f == f64::NEG_INFINITY {
        return "-.inf".to_string();
    }
    let s = f.to_string();
    if s.contains(['.', 'e', 'E']) {
        s
    } else {
        format!("{s}.0")
    }
}

/// Reconstruct the Sigma source text of a [`SigmaString`], escaping literal
/// wildcard and backslash characters so the value round-trips through the
/// parser unchanged.
fn sigma_string_source(value: &SigmaString) -> String {
    let mut out = String::with_capacity(value.original.len());
    for part in &value.parts {
        match part {
            StringPart::Plain(text) => push_escaped_literal(&mut out, text),
            StringPart::Special(SpecialChar::WildcardMulti) => out.push('*'),
            StringPart::Special(SpecialChar::WildcardSingle) => out.push('?'),
        }
    }
    out
}

/// Escape a literal segment: `*`/`?` always gain a backslash; a run of
/// backslashes is doubled only when it would otherwise bind to a following
/// wildcard or end the value (keeping plain Windows paths readable).
fn push_escaped_literal(out: &mut String, text: &str) {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => out.push_str("\\*"),
            '?' => out.push_str("\\?"),
            '\\' => {
                let mut j = i;
                while j < chars.len() && chars[j] == '\\' {
                    j += 1;
                }
                let run = j - i;
                let next = chars.get(j);
                let must_escape = run > 1 || matches!(next, Some('*') | Some('?') | None);
                for _ in 0..run {
                    out.push_str(if must_escape { "\\\\" } else { "\\" });
                }
                i = j;
                continue;
            }
            other => out.push(other),
        }
        i += 1;
    }
}

/// Build a detection key from a field name and its ordered modifiers.
fn field_key(field: &str, modifiers: &[Modifier]) -> String {
    let mut key = String::new();
    key.push_str(field);
    for modifier in modifiers {
        key.push('|');
        key.push_str(modifier_str(*modifier));
    }
    encode_key(&key, KeyCtx::FieldKey)
}

pub(crate) fn modifier_str(modifier: Modifier) -> &'static str {
    match modifier {
        Modifier::Contains => "contains",
        Modifier::StartsWith => "startswith",
        Modifier::EndsWith => "endswith",
        Modifier::All => "all",
        Modifier::Base64 => "base64",
        Modifier::Base64Offset => "base64offset",
        Modifier::Wide => "wide",
        Modifier::Utf16be => "utf16be",
        Modifier::Utf16 => "utf16",
        Modifier::WindAsh => "windash",
        Modifier::Re => "re",
        Modifier::Cidr => "cidr",
        Modifier::Cased => "cased",
        Modifier::Exists => "exists",
        Modifier::Expand => "expand",
        Modifier::FieldRef => "fieldref",
        Modifier::Gt => "gt",
        Modifier::Gte => "gte",
        Modifier::Lt => "lt",
        Modifier::Lte => "lte",
        Modifier::Neq => "neq",
        Modifier::IgnoreCase => "i",
        Modifier::Multiline => "m",
        Modifier::DotAll => "s",
        Modifier::Minute => "minute",
        Modifier::Hour => "hour",
        Modifier::Day => "day",
        Modifier::Week => "week",
        Modifier::Month => "month",
        Modifier::Year => "year",
    }
}

fn status_str(status: Status) -> &'static str {
    match status {
        Status::Stable => "stable",
        Status::Test => "test",
        Status::Experimental => "experimental",
        Status::Deprecated => "deprecated",
        Status::Unsupported => "unsupported",
    }
}

fn operator_str(op: ConditionOperator) -> &'static str {
    match op {
        ConditionOperator::Lt => "lt",
        ConditionOperator::Lte => "lte",
        ConditionOperator::Gt => "gt",
        ConditionOperator::Gte => "gte",
        ConditionOperator::Eq => "eq",
        ConditionOperator::Neq => "neq",
    }
}

fn operator_rank(op: ConditionOperator) -> u8 {
    match op {
        ConditionOperator::Lt => 0,
        ConditionOperator::Lte => 1,
        ConditionOperator::Gt => 2,
        ConditionOperator::Gte => 3,
        ConditionOperator::Eq => 4,
        ConditionOperator::Neq => 5,
    }
}

fn relation_str(relation: RelationType) -> &'static str {
    match relation {
        RelationType::Correlation => "correlation",
        RelationType::Derived => "derived",
        RelationType::Obsolete => "obsolete",
        RelationType::Merged => "merged",
        RelationType::Renamed => "renamed",
        RelationType::Similar => "similar",
    }
}

fn array_str(quantifier: ArrayQuantifier) -> &'static str {
    match quantifier {
        ArrayQuantifier::Any => "any",
        ArrayQuantifier::All => "all",
        ArrayQuantifier::AllOrEmpty => "all_or_empty",
        ArrayQuantifier::None => "none",
    }
}

// =============================================================================
// Small helpers
// =============================================================================

fn deeper(indent: &str) -> String {
    format!("{indent}{STEP}")
}

fn sorted(map: &std::collections::HashMap<String, String>) -> Vec<(&str, &str)> {
    let mut entries: Vec<(&str, &str)> =
        map.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    entries
}

fn sorted_named(map: &std::collections::HashMap<String, Detection>) -> Vec<(&str, &Detection)> {
    let mut entries: BTreeMap<&str, &Detection> = BTreeMap::new();
    for (k, v) in map {
        entries.insert(k.as_str(), v);
    }
    entries.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_sigma_yaml;

    /// Assert the emitter is a stable canonical form: `emit(parse(x))` re-parses
    /// to one rule and re-emits to a byte-identical string. This is the correct
    /// round-trip criterion; it does not depend on the raw source spelling a
    /// [`SigmaString`] preserves in its `original` field.
    fn assert_round_trips(yaml: &str) -> String {
        let first = parse_sigma_yaml(yaml).expect("input parses");
        assert_eq!(first.rules.len(), 1, "expected one input rule");
        let emitted = emit_rule_yaml(&first.rules[0]);

        let reparsed = parse_sigma_yaml(&emitted)
            .unwrap_or_else(|e| panic!("emitted YAML must re-parse: {e}\n---\n{emitted}"));
        assert_eq!(
            reparsed.rules.len(),
            1,
            "expected one rule, got:\n{emitted}"
        );

        let reemitted = emit_rule_yaml(&reparsed.rules[0]);
        assert_eq!(emitted, reemitted, "emit is not idempotent:\n{emitted}");
        emitted
    }

    #[test]
    fn round_trips_minimal_rule() {
        assert_round_trips(
            "title: Whoami\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    selection:\n        CommandLine|contains: whoami\n    condition: selection\nlevel: medium\n",
        );
    }

    #[test]
    fn round_trips_modifiers_and_value_lists() {
        assert_round_trips(
            "title: Modifiers\nlogsource:\n    product: windows\ndetection:\n    selection:\n        Image|endswith:\n            - '\\\\cmd.exe'\n            - '\\\\powershell.exe'\n        CommandLine|contains|all:\n            - foo\n            - bar\n        Field|re: 'ab.*c'\n        Port|gt: 1024\n        User|cased: Admin\n    filter:\n        Image|startswith: 'C:\\\\Windows\\\\'\n    condition: selection and not filter\nlevel: high\n",
        );
    }

    #[test]
    fn round_trips_keywords_and_anyof() {
        assert_round_trips(
            "title: Keywords\nlogsource:\n    product: linux\ndetection:\n    keywords:\n        - mimikatz\n        - sekurlsa\n    selection:\n        - EventID: 1\n        - EventID: 4688\n    condition: keywords and selection\n",
        );
    }

    #[test]
    fn round_trips_metadata_and_selector_condition() {
        assert_round_trips(
            "title: Full Metadata\nid: 11111111-2222-3333-4444-555555555555\nstatus: experimental\ndescription: A single line description.\nreferences:\n    - https://example.com/a\nauthor: Jane Doe\ndate: 2026-01-01\ntags:\n    - attack.execution\n    - attack.t1059\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    selection_a:\n        Image|endswith: '\\\\a.exe'\n    selection_b:\n        Image|endswith: '\\\\b.exe'\n    condition: 1 of selection_*\nfalsepositives:\n    - Legitimate admin use\nlevel: low\n",
        );
    }

    #[test]
    fn escapes_wildcards_in_literal_values() {
        // A literal asterisk in the value must survive as a literal, not a wildcard.
        let yaml = "title: Escapes\nlogsource:\n    product: test\ndetection:\n    selection:\n        Field: 'a\\*b'\n    condition: selection\n";
        let emitted = assert_round_trips(yaml);
        assert!(
            emitted.contains(r"a\*b"),
            "expected escaped glob, got:\n{emitted}"
        );
    }

    #[test]
    fn empty_logsource_emits_a_mapping_the_parser_rejects() {
        let mut rule = parse_sigma_yaml(
            "title: No Logsource\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n",
        )
        .unwrap()
        .rules
        .remove(0);
        rule.logsource = LogSource::default();
        let emitted = emit_rule_yaml(&rule);
        assert!(emitted.contains("logsource: {}"), "{emitted}");
        let errors = parse_sigma_yaml(&emitted).unwrap().diagnostics;
        assert!(
            errors[0]
                .message
                .contains("at least one of category, product, or service"),
            "{errors:?}"
        );
    }

    #[test]
    fn round_trips_detection_exemplars() {
        let emitted = assert_round_trips(
            "title: Whoami\nid: 11111111-2222-3333-4444-555555555555\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    selection:\n        CommandLine|contains: whoami\n    condition: selection\ncustom_attributes:\n    rsigma.exemplars:\n        - name: whoami fires\n          expect: match\n          event:\n              CommandLine: whoami /all\n        - name: benign hostname\n          expect: no-match\n          event:\n              CommandLine: hostname\n",
        );
        assert!(
            emitted.contains("rsigma.exemplars:"),
            "expected exemplars in emit:\n{emitted}"
        );
        assert!(
            emitted.contains("whoami fires"),
            "expected exemplar name:\n{emitted}"
        );
        let reparsed = parse_sigma_yaml(&emitted).unwrap();
        let attrs = &reparsed.rules[0].custom_attributes;
        let list = crate::exemplar::exemplars_from_attrs(
            attrs,
            crate::exemplar::ExemplarRuleKind::Detection,
        )
        .expect("emitted exemplars re-parse");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].expect, crate::exemplar::Expect::Match);
        assert_eq!(list[1].expect, crate::exemplar::Expect::NoMatch);
    }

    #[test]
    fn emit_preserves_correlation_shaped_exemplar_sequence() {
        let emitted = assert_round_trips(
            "title: Burst host\nlogsource:\n    category: auth\ndetection:\n    selection:\n        EventType: login\n    condition: selection\ncustom_attributes:\n    rsigma.exemplars:\n        - name: burst\n          expect: match\n          event:\n              EventType: login\n              User: alice\n",
        );
        assert!(emitted.contains("User:"), "{emitted}");
    }

    #[test]
    fn round_trips_array_object_scope_block() {
        assert_round_trips(
            "title: Array\nsigma-version: 3\nlogsource:\n    category: test\ndetection:\n    selection:\n        connections[any]:\n            protocol: TCP\n            port: 445\n    condition: selection\n",
        );
    }

    #[test]
    fn quotes_strings_that_yaml_would_read_as_another_type() {
        assert_round_trips(
            "title: 'True'\nid: '123'\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: '0x1F'\n        Other: '1_000'\n        Third: '1:30'\n    condition: selection\n",
        );
    }

    #[test]
    fn emits_reference_urls_plain() {
        let emitted = assert_round_trips(
            "title: URL\nreferences:\n    - https://example.com/a?b=c\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n",
        );
        assert!(
            emitted.contains("- https://example.com/a?b=c\n"),
            "expected a plain URL:\n{emitted}"
        );
    }

    #[test]
    fn emits_multi_line_values_as_literal_blocks() {
        let emitted = assert_round_trips(
            "title: Multiline\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: |-\n            first line\n            second line\n    condition: selection\n",
        );
        assert!(emitted.contains("Field: |-"), "{emitted}");
    }

    #[test]
    fn quotes_a_field_name_with_a_space_as_one_key() {
        let emitted = assert_round_trips(
            "title: Space\nlogsource:\n    category: test\ndetection:\n    selection:\n        'Product Name|contains': thing\n    condition: selection\n",
        );
        assert!(
            emitted.contains("'Product Name|contains': thing"),
            "{emitted}"
        );
    }

    #[test]
    fn emits_empty_custom_attribute_collections() {
        let emitted = assert_round_trips(
            "title: Empty\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\nempty_map: {}\nempty_seq: []\n",
        );
        assert!(emitted.contains("empty_map: {}"), "{emitted}");
        assert!(emitted.contains("empty_seq: []"), "{emitted}");
    }

    #[test]
    fn quotes_a_condition_that_would_read_as_another_type() {
        let emitted = assert_round_trips(
            "title: Condition\nlogsource:\n    category: test\ndetection:\n    '1e3':\n        Field: value\n    condition: '1e3'\n",
        );
        assert!(emitted.contains("condition: '1e3'"), "{emitted}");
    }

    #[test]
    fn emits_root_keys_in_canonical_order() {
        let yaml = "\
zzz: last
title: Order
aaa: first
id: 11111111-2222-3333-4444-555555555555
name: order
status: experimental
description: Order test.
references:
    - https://example.com
author: Jane Doe
date: 2026-01-01
modified: 2026-02-01
related:
    - id: 22222222-3333-4444-5555-666666666666
      type: derived
tags:
    - attack.execution
sigma-version: 3
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Field: value
    condition: selection
fields:
    - Field
falsepositives:
    - None known
level: medium
scope:
    - endpoint
license: MIT
taxonomy: attack
rsigma.exemplars:
    - name: example
      expect: match
      event:
          Field: value
rsigma.suppress:
    - reason: noisy
";
        let rule = parse_sigma_yaml(yaml)
            .expect("input parses")
            .rules
            .remove(0);
        let emitted = emit_rule_yaml(&rule);
        let root_keys: Vec<&str> = emitted
            .lines()
            .filter(|line| !line.starts_with(' ') && line.contains(':'))
            .map(|line| line.split(':').next().unwrap_or_default())
            .collect();
        let expected = [
            "title",
            "id",
            "name",
            "status",
            "description",
            "references",
            "author",
            "date",
            "modified",
            "related",
            "tags",
            "sigma-version",
            "logsource",
            "detection",
            "fields",
            "falsepositives",
            "level",
            "scope",
            "license",
            "taxonomy",
            "rsigma.suppress",
            "rsigma.exemplars",
            "aaa",
            "zzz",
        ];
        assert_eq!(root_keys, expected, "{emitted}");
    }

    fn assert_correlation_round_trips(yaml: &str) -> String {
        let first = parse_sigma_yaml(yaml).expect("input parses");
        assert_eq!(first.correlations.len(), 1, "expected one correlation");
        let emitted = emit_correlation_yaml(&first.correlations[0]);
        let reparsed = parse_sigma_yaml(&emitted)
            .unwrap_or_else(|e| panic!("emitted YAML must re-parse: {e}\n---\n{emitted}"));
        assert_eq!(reparsed.correlations.len(), 1, "{emitted}");
        assert_eq!(first.correlations[0], reparsed.correlations[0]);
        assert_eq!(emitted, emit_correlation_yaml(&reparsed.correlations[0]));
        emitted
    }

    fn assert_filter_round_trips(yaml: &str) -> String {
        let first = parse_sigma_yaml(yaml).expect("input parses");
        assert_eq!(first.filters.len(), 1, "expected one filter");
        let emitted = emit_filter_yaml(&first.filters[0]);
        let reparsed = parse_sigma_yaml(&emitted)
            .unwrap_or_else(|e| panic!("emitted YAML must re-parse: {e}\n---\n{emitted}"));
        assert_eq!(reparsed.filters.len(), 1, "{emitted}");
        assert_eq!(first.filters[0], reparsed.filters[0]);
        assert_eq!(emitted, emit_filter_yaml(&reparsed.filters[0]));
        emitted
    }

    #[test]
    fn round_trips_event_count_session_gap_aliases() {
        let emitted = assert_correlation_round_trips(
            "title: Session burst\nid: 11111111-2222-3333-4444-555555555555\ndescription: Too many logins.\ntags:\n    - attack.credential_access\ncorrelation:\n    type: event_count\n    rules:\n        - failed_login\n        - failed_ssh\n    group-by:\n        - User\n    timespan: 1h\n    window: session\n    gap: 5m\n    condition:\n        gte: 10\n    aliases:\n        user:\n            failed_login: User\n            failed_ssh: Username\n    generate: true\nlevel: high\n",
        );
        assert!(emitted.contains("window: session"), "{emitted}");
        assert!(emitted.contains("gap: 5m"), "{emitted}");
        assert!(emitted.contains("generate: true"), "{emitted}");
        assert!(emitted.contains("failed_login: User"), "{emitted}");
    }

    #[test]
    fn round_trips_value_count_range_and_field() {
        let emitted = assert_correlation_round_trips(
            "title: Port scan\ncorrelation:\n    type: value_count\n    rules:\n        - connection\n    group-by:\n        - SourceIp\n    timespan: 5m\n    condition:\n        gt: 100\n        lte: 200\n        field:\n            - DestPort\n",
        );
        assert!(emitted.contains("gt: 100"), "{emitted}");
        assert!(emitted.contains("lte: 200"), "{emitted}");
        assert!(emitted.contains("DestPort"), "{emitted}");
    }

    #[test]
    fn round_trips_value_percentile() {
        assert_correlation_round_trips(
            "title: Slow tail\ncorrelation:\n    type: value_percentile\n    rules:\n        - latency\n    group-by:\n        - Service\n    timespan: 10m\n    condition:\n        gte: 95\n        field: LatencyMs\n        percentile: 99\n",
        );
    }

    #[test]
    fn round_trips_value_sum_avg_median() {
        assert_correlation_round_trips(
            "title: Sum\ncorrelation:\n    type: value_sum\n    rules:\n        - transfer\n    group-by:\n        - User\n    timespan: 1h\n    condition:\n        gte: 1000\n        field: Bytes\n",
        );
        assert_correlation_round_trips(
            "title: Avg\ncorrelation:\n    type: value_avg\n    rules:\n        - transfer\n    group-by:\n        - User\n    timespan: 1h\n    condition:\n        gte: 1000\n        field: Bytes\n",
        );
        assert_correlation_round_trips(
            "title: Median\ncorrelation:\n    type: value_median\n    rules:\n        - transfer\n    group-by:\n        - User\n    timespan: 1h\n    condition:\n        gte: 1000\n        field: Bytes\n",
        );
    }

    #[test]
    fn round_trips_temporal_extended_and_ordered() {
        assert_correlation_round_trips(
            "title: Login then process\ncorrelation:\n    type: temporal\n    rules:\n        - login\n        - process_start\n    group-by:\n        - User\n    timespan: 10m\n    condition: login and process_start\n",
        );
        assert_correlation_round_trips(
            "title: Ordered\ncorrelation:\n    type: temporal_ordered\n    rules:\n        - login\n        - process_start\n    group-by:\n        - User\n    timespan: 10m\n    condition: login and process_start\n",
        );
    }

    #[test]
    fn round_trips_tumbling_window() {
        assert_correlation_round_trips(
            "title: Tumbling\ncorrelation:\n    type: event_count\n    rules:\n        - login\n    group-by:\n        - User\n    timespan: 1h\n    window: tumbling\n    condition:\n        gte: 5\n",
        );
    }

    #[test]
    fn round_trips_filter_any() {
        let emitted = assert_filter_round_trips(
            "title: Drop system accounts\nlogsource:\n    product: windows\n    category: process_creation\nfilter:\n    selection:\n        User|endswith: '$'\n    condition: selection\n",
        );
        assert!(!emitted.contains("rules:"), "{emitted}");
    }

    #[test]
    fn round_trips_filter_specific_logsource() {
        let emitted = assert_filter_round_trips(
            "title: Drop admin whoami\nid: 22222222-3333-4444-5555-666666666666\nlogsource:\n    product: windows\n    service: security\nfilter:\n    rules:\n        - 11111111-2222-3333-4444-555555555555\n        - whoami_rule\n    selection:\n        Image|endswith: '\\whoami.exe'\n    filter_main_system:\n        User: SYSTEM\n    condition: selection and not filter_main_system\n",
        );
        assert!(emitted.contains("rules:"), "{emitted}");
        assert!(emitted.contains("whoami_rule"), "{emitted}");
        assert!(emitted.contains("filter_main_system"), "{emitted}");
    }

    #[test]
    fn round_trips_a_detection_timeframe() {
        let emitted = assert_round_trips(
            "title: Burst\nlogsource:\n    product: windows\ndetection:\n    selection:\n        EventID: 4625\n    condition: selection\n    timeframe: 5m\n",
        );
        assert!(emitted.contains("    timeframe: 5m\n"), "{emitted}");
    }

    #[test]
    fn round_trips_a_filter_timeframe() {
        let emitted = assert_filter_round_trips(
            "title: Drop bursts\nlogsource:\n    product: windows\nfilter:\n    selection:\n        User: SYSTEM\n    condition: selection\n    timeframe: 5m\n",
        );
        assert!(emitted.contains("    timeframe: 5m\n"), "{emitted}");
    }
}
