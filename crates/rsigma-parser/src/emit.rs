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
//! Value scalars are rendered in Sigma's single-quote convention, with literal
//! `*`, `?`, and `\` escaped so a re-parse reproduces the same
//! [`SigmaString`] wildcard structure.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::ast::{
    ArrayQuantifier, ConditionExpr, Detection, DetectionItem, Detections, LogSource, Modifier,
    Related, RelationType, SigmaCollection, SigmaRule, Status,
};
use crate::value::{SigmaString, SigmaValue, SpecialChar, StringPart};

/// One indentation level (four spaces, matching the SigmaHQ house style).
const STEP: &str = "    ";

/// Emit a single detection [`SigmaRule`] as canonical Sigma YAML.
///
/// The output always ends with a trailing newline and re-parses to an equal
/// [`SigmaRule`].
pub fn emit_rule_yaml(rule: &SigmaRule) -> String {
    let mut out = String::new();

    push_line(&mut out, "title", &scalar_prose(&rule.title));
    if let Some(id) = &rule.id {
        push_line(&mut out, "id", &scalar(id));
    }
    if let Some(name) = &rule.name {
        push_line(&mut out, "name", &scalar(name));
    }
    if let Some(status) = &rule.status {
        push_line(&mut out, "status", status_str(*status));
    }
    if let Some(description) = &rule.description {
        emit_scalar_field(&mut out, "description", description, "");
    }
    emit_string_list(&mut out, "references", &rule.references);
    if let Some(author) = &rule.author {
        emit_scalar_field(&mut out, "author", author, "");
    }
    if let Some(date) = &rule.date {
        push_line(&mut out, "date", &scalar(date));
    }
    if let Some(modified) = &rule.modified {
        push_line(&mut out, "modified", &scalar(modified));
    }
    emit_related(&mut out, &rule.related);
    emit_string_list(&mut out, "tags", &rule.tags);
    if let Some(version) = rule.sigma_version {
        push_line(&mut out, "sigma-version", &version.to_string());
    }
    emit_logsource(&mut out, &rule.logsource);
    emit_detection(&mut out, &rule.detection);
    emit_string_list(&mut out, "fields", &rule.fields);
    emit_string_list(&mut out, "falsepositives", &rule.falsepositives);
    if let Some(level) = &rule.level {
        push_line(&mut out, "level", level.as_str());
    }
    emit_string_list(&mut out, "scope", &rule.scope);
    if let Some(license) = &rule.license {
        emit_scalar_field(&mut out, "license", license, "");
    }
    if let Some(taxonomy) = &rule.taxonomy {
        push_line(&mut out, "taxonomy", &scalar(taxonomy));
    }
    emit_custom_attributes(&mut out, rule);

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

fn emit_scalar_field(out: &mut String, key: &str, value: &str, indent: &str) {
    if value.contains('\n') {
        let _ = writeln!(out, "{indent}{key}: |-");
        for line in value.split('\n') {
            let _ = writeln!(out, "{indent}{STEP}{line}");
        }
    } else {
        let _ = writeln!(out, "{indent}{key}: {}", scalar_prose(value));
    }
}

fn emit_string_list(out: &mut String, key: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    let _ = writeln!(out, "{key}:");
    for item in items {
        let _ = writeln!(out, "{STEP}- {}", scalar_prose(item));
    }
}

fn emit_related(out: &mut String, related: &[Related]) {
    if related.is_empty() {
        return;
    }
    let _ = writeln!(out, "related:");
    for entry in related {
        let _ = writeln!(out, "{STEP}- id: {}", scalar(&entry.id));
        let _ = writeln!(out, "{STEP}  type: {}", relation_str(entry.relation_type));
    }
}

fn emit_logsource(out: &mut String, logsource: &LogSource) {
    // An empty `logsource:` key parses as null, which the parser rejects (it
    // must be a mapping); emit an explicit empty mapping instead.
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
        let _ = writeln!(out, "{STEP}category: {}", scalar(category));
    }
    if let Some(product) = &logsource.product {
        let _ = writeln!(out, "{STEP}product: {}", scalar(product));
    }
    if let Some(service) = &logsource.service {
        let _ = writeln!(out, "{STEP}service: {}", scalar(service));
    }
    if let Some(definition) = &logsource.definition {
        emit_scalar_field(out, "definition", definition, STEP);
    }
    for (key, value) in sorted(&logsource.custom) {
        let _ = writeln!(out, "{STEP}{}: {}", key_token(key), scalar(value));
    }
}

fn emit_custom_attributes(out: &mut String, rule: &SigmaRule) {
    let mut keys: Vec<&String> = rule.custom_attributes.keys().collect();
    keys.sort();
    for key in keys {
        let value = &rule.custom_attributes[key];
        emit_yaml_value(out, &key_token(key), value, "");
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
    emit_condition(out, &detection.conditions);
}

fn emit_condition(out: &mut String, conditions: &[ConditionExpr]) {
    match conditions {
        [] => {}
        [single] => {
            let _ = writeln!(out, "{STEP}condition: {}", condition_source(single));
        }
        many => {
            let _ = writeln!(out, "{STEP}condition:");
            for cond in many {
                let _ = writeln!(out, "{STEP}{STEP}- {}", condition_source(cond));
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

fn emit_named_detection(out: &mut String, name: &str, det: &Detection, indent: &str) {
    let _ = writeln!(out, "{indent}{}:", key_token(name));
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
                let _ = writeln!(out, "{indent}- {}", value_token(value));
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
            let _ = writeln!(
                out,
                "{indent}{}[{}]:",
                field_token(field),
                array_str(*quantifier)
            );
            emit_detection_value(out, body, &deeper(indent));
        }
        Detection::Conditional { named, condition } => {
            for (name, sub) in sorted_named(named) {
                emit_named_detection(out, name, sub, indent);
            }
            let _ = writeln!(out, "{indent}condition: {}", condition_source(condition));
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
    match item.values.as_slice() {
        [single] => {
            let _ = writeln!(out, "{indent}{key}: {}", value_token_ctx(single, raw));
        }
        values => {
            let _ = writeln!(out, "{indent}{key}:");
            for value in values {
                let _ = writeln!(out, "{indent}{STEP}- {}", value_token_ctx(value, raw));
            }
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
                let child_key = k.as_str().map(key_token).unwrap_or_else(|| "?".to_string());
                emit_yaml_value(out, &child_key, v, &deeper(indent));
            }
        }
        yaml_serde::Value::Sequence(seq) if !seq.is_empty() => {
            let _ = writeln!(out, "{indent}{key}:");
            for v in seq {
                emit_yaml_seq_item(out, v, &deeper(indent));
            }
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
                let child_key = k.as_str().map(key_token).unwrap_or_else(|| "?".to_string());
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
        yaml_serde::Value::Sequence(seq) if !seq.is_empty() => {
            let _ = writeln!(out, "{indent}-");
            for v in seq {
                emit_yaml_seq_item(out, v, &deeper(indent));
            }
        }
        scalar => {
            let _ = writeln!(out, "{indent}- {}", yaml_scalar(scalar));
        }
    }
}

fn yaml_scalar(value: &yaml_serde::Value) -> String {
    match value {
        yaml_serde::Value::Null => "null".to_string(),
        yaml_serde::Value::Bool(b) => b.to_string(),
        yaml_serde::Value::Number(n) => n.to_string(),
        yaml_serde::Value::String(s) => scalar(s),
        // Nested collections are handled by emit_yaml_value; an inline fallback
        // keeps the emitter total for unexpected placements.
        other => scalar(&format!("{other:?}")),
    }
}

// =============================================================================
// Scalars, keys, and value tokens
// =============================================================================

/// Render a [`SigmaValue`] as a YAML token.
fn value_token(value: &SigmaValue) -> String {
    value_token_ctx(value, false)
}

/// Render a [`SigmaValue`] as a YAML token. When `raw` is set the string is a
/// raw value (a regex, CIDR, or field reference) and is emitted verbatim rather
/// than with Sigma wildcard escaping.
fn value_token_ctx(value: &SigmaValue, raw: bool) -> String {
    match value {
        SigmaValue::String(s) if raw => scalar(&s.as_plain().unwrap_or_else(|| s.original.clone())),
        SigmaValue::String(s) => scalar(&sigma_string_source(s)),
        SigmaValue::Integer(n) => n.to_string(),
        SigmaValue::Float(f) => float_token(*f),
        SigmaValue::Bool(b) => b.to_string(),
        SigmaValue::Null => "null".to_string(),
    }
}

/// Format a float so it re-parses as a float (never collapses `3.0` to `3`).
fn float_token(f: f64) -> String {
    let s = f.to_string();
    if s.contains(['.', 'e', 'E']) || s.contains("inf") || s.contains("NaN") {
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

/// Quote a value scalar in Sigma's single-quote convention unless it is a
/// bare-safe token.
fn scalar(s: &str) -> String {
    if is_bare_safe(s) {
        s.to_string()
    } else {
        quote(s)
    }
}

/// Looser quoting for prose scalars (title, description, author): plain YAML
/// permits internal spaces, so common values stay unquoted.
fn scalar_prose(s: &str) -> String {
    let bare = !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && !s.ends_with(' ')
        && !s.contains(": ")
        && !s.contains(" #")
        && !s.contains('\n')
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.' | ',' | '(' | ')' | '/')
        });
    if bare { s.to_string() } else { quote(s) }
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn is_bare_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'))
        && !s.starts_with('-')
        && s.parse::<f64>().is_err()
        && !matches!(
            s.to_ascii_lowercase().as_str(),
            "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "~"
        )
}

/// A mapping key (metadata key, custom-attribute key, or logsource custom
/// field). Quoted only when it contains characters unsafe in a plain key.
fn key_token(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if safe { s.to_string() } else { quote(s) }
}

/// A detection field name used inside a key (bare identifiers, dotted paths,
/// and array/index markers pass through; anything else is quoted).
fn field_token(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '[' | ']' | '@')
        });
    if safe { s.to_string() } else { quote(s) }
}

/// Build a detection key from a field name and its ordered modifiers.
fn field_key(field: &str, modifiers: &[Modifier]) -> String {
    let mut key = String::new();
    for (i, part) in field.split('|').enumerate() {
        if i > 0 {
            key.push('|');
        }
        key.push_str(&field_token(part));
    }
    for modifier in modifiers {
        key.push('|');
        key.push_str(modifier_str(*modifier));
    }
    key
}

fn modifier_str(modifier: Modifier) -> &'static str {
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
    fn empty_logsource_emits_a_mapping_that_reparses() {
        let emitted = assert_round_trips(
            "title: No Logsource\nlogsource: {}\ndetection:\n    selection:\n        Field: value\n    condition: selection\n",
        );
        assert!(emitted.contains("logsource: {}"), "{emitted}");
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
}
