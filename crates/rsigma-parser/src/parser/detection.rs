use std::collections::HashMap;

use yaml_serde::Value;

use crate::ast::*;
use crate::condition::parse_condition;
use crate::error::{Result, SigmaParserError};
use crate::fieldpath::{ends_with_unescaped, escape_brackets, first_unescaped};
use crate::value::SigmaValue;

use super::{
    collect_custom_attributes, get_str, get_str_list, parse_enum_with_warn, parse_logsource,
    parse_related, parse_sigma_version, val_key,
};

// =============================================================================
// Detection Rule Parsing
// =============================================================================

/// Parse a detection rule from a YAML value.
///
/// `warnings` receives non-fatal issues that would otherwise be
/// silently swallowed (invalid `status` / `level` values, malformed
/// `related:` entries). The parser still returns `Ok(rule)` for
/// these so a single typo does not invalidate the whole document.
///
/// Reference: pySigma rule.py SigmaRule.from_yaml / from_dict
pub(super) fn parse_detection_rule(value: &Value, warnings: &mut Vec<String>) -> Result<SigmaRule> {
    let m = value
        .as_mapping()
        .ok_or_else(|| SigmaParserError::InvalidRule("Expected a YAML mapping".into()))?;

    let title = get_str(m, "title")
        .ok_or_else(|| SigmaParserError::MissingField("title".into()))?
        .to_string();

    let sigma_version = parse_sigma_version(m, warnings);

    let detection_val = m
        .get(val_key("detection"))
        .ok_or_else(|| SigmaParserError::MissingField("detection".into()))?;
    let detection = parse_detections(
        detection_val,
        crate::version::array_matching_enabled(sigma_version),
    )?;

    let logsource = m
        .get(val_key("logsource"))
        .map(parse_logsource)
        .transpose()?
        .unwrap_or_default();

    // Custom attributes: merge arbitrary top-level keys and the entries of the
    // dedicated `custom_attributes:` mapping. Entries in `custom_attributes:`
    // win over a top-level key of the same name (last-write-wins).
    // Mirrors pySigma's `SigmaRule.custom_attributes` dict.
    let standard_rule_keys: &[&str] = &[
        "title",
        "sigma-version",
        "id",
        "related",
        "name",
        "taxonomy",
        "status",
        "description",
        "license",
        "author",
        "references",
        "date",
        "modified",
        "logsource",
        "detection",
        "fields",
        "falsepositives",
        "level",
        "tags",
        "scope",
        "custom_attributes",
    ];
    let custom_attributes = collect_custom_attributes(m, standard_rule_keys);

    Ok(SigmaRule {
        title,
        logsource,
        detection,
        sigma_version,
        id: get_str(m, "id").map(|s| s.to_string()),
        name: get_str(m, "name").map(|s| s.to_string()),
        related: parse_related(m.get(val_key("related")), warnings),
        taxonomy: get_str(m, "taxonomy").map(|s| s.to_string()),
        status: parse_enum_with_warn(get_str(m, "status"), "status", warnings),
        description: get_str(m, "description").map(|s| s.to_string()),
        license: get_str(m, "license").map(|s| s.to_string()),
        author: get_str(m, "author").map(|s| s.to_string()),
        references: get_str_list(m, "references"),
        date: get_str(m, "date").map(|s| s.to_string()),
        modified: get_str(m, "modified").map(|s| s.to_string()),
        fields: get_str_list(m, "fields"),
        falsepositives: get_str_list(m, "falsepositives"),
        level: parse_enum_with_warn(get_str(m, "level"), "level", warnings),
        tags: get_str_list(m, "tags"),
        scope: get_str_list(m, "scope"),
        custom_attributes,
    })
}

// =============================================================================
// Detection Section Parsing
// =============================================================================

/// Parse the `detection:` section of a rule.
///
/// The detection section contains:
/// - `condition`: string or list of strings
/// - `timeframe`: optional duration string
/// - Everything else: named detection identifiers
///
/// Reference: pySigma rule/detection.py SigmaDetections.from_dict
pub(super) fn parse_detections(value: &Value, array_matching: bool) -> Result<Detections> {
    let m = value.as_mapping().ok_or_else(|| {
        SigmaParserError::InvalidDetection("Detection section must be a mapping".into())
    })?;

    // Extract condition (required)
    let condition_val = m
        .get(val_key("condition"))
        .ok_or_else(|| SigmaParserError::MissingField("condition".into()))?;

    let condition_strings = match condition_val {
        Value::String(s) => vec![s.clone()],
        Value::Sequence(seq) => {
            let mut strings = Vec::with_capacity(seq.len());
            for v in seq {
                match v.as_str() {
                    Some(s) => strings.push(s.to_string()),
                    None => {
                        return Err(SigmaParserError::InvalidDetection(format!(
                            "condition list items must be strings, got: {v:?}"
                        )));
                    }
                }
            }
            strings
        }
        _ => {
            return Err(SigmaParserError::InvalidDetection(
                "condition must be a string or list of strings".into(),
            ));
        }
    };

    // Parse each condition string
    let conditions: Vec<ConditionExpr> = condition_strings
        .iter()
        .map(|s| parse_condition(s))
        .collect::<Result<Vec<_>>>()?;

    // Extract optional timeframe
    let timeframe = get_str(m, "timeframe").map(|s| s.to_string());

    // Parse all named detections (everything except condition and timeframe)
    let mut named = HashMap::new();
    for (key, val) in m {
        let key_str = key.as_str().unwrap_or("");
        if key_str == "condition" || key_str == "timeframe" {
            continue;
        }
        named.insert(key_str.to_string(), parse_detection(val, array_matching)?);
    }

    Ok(Detections {
        named,
        conditions,
        condition_strings,
        timeframe,
    })
}

/// Parse a single named detection definition.
///
/// A detection can be:
/// 1. A mapping (key-value pairs, AND-linked)
/// 2. A list of plain values (keyword detection)
/// 3. A list of mappings (OR-linked sub-detections)
///
/// Reference: pySigma rule/detection.py SigmaDetection.from_definition
fn parse_detection(value: &Value, array_matching: bool) -> Result<Detection> {
    match value {
        Value::Mapping(m) => {
            // Case 1: key-value mapping → AND-linked detection items.
            //
            // Keys without an `any`/`all` selector become plain detection items
            // exactly as before (a positional `[N]` index stays in the field
            // path). Keys carrying an `any`/`all` selector desugar into
            // `Detection::ArrayMatch` object-scope blocks. A map with no blocks
            // stays an `AllOf`; a single block becomes that block; a mix
            // becomes an `And`.
            let mut items: Vec<DetectionItem> = Vec::new();
            let mut blocks: Vec<Detection> = Vec::new();
            for (k, v) in m.iter() {
                match parse_map_entry(k.as_str().unwrap_or(""), v, array_matching)? {
                    ParsedEntry::Item(item) => items.push(item),
                    ParsedEntry::Block(block) => blocks.push(block),
                }
            }
            Ok(combine_entries(items, blocks))
        }
        Value::Sequence(seq) => {
            // Check if all items are plain values (strings/numbers/etc.)
            let all_plain = seq.iter().all(|v| !v.is_mapping() && !v.is_sequence());
            if all_plain {
                // Case 2: list of plain values → keyword detection
                let values = seq.iter().map(SigmaValue::from_yaml).collect();
                Ok(Detection::Keywords(values))
            } else {
                // Case 3: list of mappings → OR-linked sub-detections
                let subs: Vec<Detection> = seq
                    .iter()
                    .map(|v| parse_detection(v, array_matching))
                    .collect::<Result<Vec<_>>>()?;
                Ok(Detection::AnyOf(subs))
            }
        }
        // Plain value → single keyword
        _ => Ok(Detection::Keywords(vec![SigmaValue::from_yaml(value)])),
    }
}

/// Parse a single detection item from a key-value pair.
///
/// The key contains the field name and optional modifiers separated by `|`:
/// - `EventType` → field="EventType", no modifiers
/// - `TargetObject|endswith` → field="TargetObject", modifiers=[EndsWith]
/// - `Destination|contains|all` → field="Destination", modifiers=[Contains, All]
///
/// Reference: pySigma rule/detection.py SigmaDetectionItem.from_mapping
fn parse_detection_item(key: &str, value: &Value) -> Result<DetectionItem> {
    let field = parse_field_spec(key)?;

    let values = match value {
        Value::Sequence(seq) => seq.iter().map(|v| to_sigma_value(v, &field)).collect(),
        _ => vec![to_sigma_value(value, &field)],
    };

    Ok(DetectionItem { field, values })
}

// =============================================================================
// Array matching: object-scope quantifier blocks + positional indexing
// =============================================================================
//
// Proposed Sigma array-matching extension (sigma-specification Discussion #106,
// rsigma #158). A detection key whose field path carries an `any`/`all`
// selector desugars into a `Detection::ArrayMatch`:
//
//   connections[any]:            ArrayMatch { field: "connections", quantifier: Any,
//     protocol: "TCP"      ==>       body: AllOf([protocol == "TCP", ip cidr ...]) }
//     ip|cidr: "10.0.0.0/8"
//
//   connections[any].ip: "x" ==> ArrayMatch { field: "connections", quantifier: Any,
//                                              body: AllOf([ip == "x"]) }
//
// A positional `[N]` index is NOT a quantifier: it stays in the field-path
// string (`args[0]`, `connections[0].ip`) and is resolved by the evaluator and
// converters. Keys with no `any`/`all` selector parse exactly as before.

/// A parsed field-path segment: a name plus an optional array selector. At most
/// one of `index` / `quantifier` is set (a segment carries one `[...]`).
struct PathSegment {
    name: String,
    /// Positional `[N]` index, possibly negative (`[-1]` is the last element).
    /// Stays in the literal field path.
    index: Option<i64>,
    /// `[any]`/`[all]` quantifier (a desugaring point for object-scope blocks).
    quantifier: Option<ArrayQuantifier>,
}

impl PathSegment {
    /// Render this segment as part of a literal field path, re-appending a
    /// positional `[N]` marker (but not the `any`/`all` quantifier, which is
    /// consumed when a block is opened).
    fn path_str(&self) -> String {
        match self.index {
            Some(i) => format!("{}[{i}]", self.name),
            None => self.name.clone(),
        }
    }
}

/// The result of parsing one mapping entry: either a plain detection item or an
/// array object-scope block.
enum ParsedEntry {
    Item(DetectionItem),
    Block(Detection),
}

/// Combine the items and blocks parsed from a YAML mapping into a detection: an
/// `AllOf` when there are no blocks, the single block alone, or an `And` of the
/// plain items plus each block.
fn combine_entries(items: Vec<DetectionItem>, blocks: Vec<Detection>) -> Detection {
    if blocks.is_empty() {
        Detection::AllOf(items)
    } else if items.is_empty() && blocks.len() == 1 {
        blocks.into_iter().next().expect("len checked")
    } else {
        let mut parts: Vec<Detection> = Vec::new();
        if !items.is_empty() {
            parts.push(Detection::AllOf(items));
        }
        parts.extend(blocks);
        Detection::And(parts)
    }
}

/// Parse one `key: value` mapping entry, desugaring `any`/`all` array
/// quantifiers and indexed object-scope blocks.
fn parse_map_entry(key: &str, value: &Value, array_matching: bool) -> Result<ParsedEntry> {
    // Split the field path from the trailing modifier chain (`field|mod1|mod2`).
    let (field_part, modifier_part) = match key.split_once('|') {
        Some((f, m)) => (f, Some(m)),
        None => (key, None),
    };

    // Empty field part (keyword-style key or bare modifiers): defer to the
    // existing field-spec parser, which already handles these cases.
    if field_part.is_empty() {
        return Ok(ParsedEntry::Item(parse_detection_item(key, value)?));
    }

    // Below the array-matching spec version, a trailing `[...]` is not a
    // selector: brackets are literal field-name characters. Escape any
    // unescaped bracket so the escape-aware field resolver (evaluator and
    // converters) reads the name literally, and keep the entry a plain item.
    if !array_matching {
        let escaped = escape_brackets(field_part);
        let plain_key = match modifier_part {
            Some(m) => format!("{escaped}|{m}"),
            None => escaped.into_owned(),
        };
        return Ok(ParsedEntry::Item(parse_detection_item(&plain_key, value)?));
    }

    let segments = parse_field_path(field_part)?;
    match segments.iter().position(|s| s.quantifier.is_some()) {
        Some(idx) => {
            let quantifier = segments[idx]
                .quantifier
                .expect("position found a quantifier");
            // The array lives at the path up to and including the quantified
            // segment (positional `[N]` markers before it are preserved).
            let array_field = segments[..=idx]
                .iter()
                .map(PathSegment::path_str)
                .collect::<Vec<_>>()
                .join(".");
            let body =
                build_block_body(&segments[idx + 1..], modifier_part, value, array_matching)?;
            Ok(ParsedEntry::Block(Detection::ArrayMatch {
                field: array_field,
                quantifier,
                body: Box::new(body),
            }))
        }
        // No `any`/`all` selector. A map value on an indexed key opens a block
        // scoped to that one element; otherwise it is a plain item whose field
        // path keeps any positional `[N]` markers.
        None => {
            let has_index = segments.iter().any(|s| s.index.is_some());
            if value.is_mapping() && has_index {
                let prefix = reconstruct_key(&segments, None);
                Ok(ParsedEntry::Block(parse_block_with_prefix(
                    &prefix,
                    value,
                    array_matching,
                )?))
            } else {
                Ok(ParsedEntry::Item(parse_detection_item(key, value)?))
            }
        }
    }
}

/// Build the nested detection that an array block evaluates per member.
fn build_block_body(
    remaining: &[PathSegment],
    modifier_part: Option<&str>,
    value: &Value,
    array_matching: bool,
) -> Result<Detection> {
    if remaining.is_empty() {
        // The quantifier was on the final path segment.
        match value {
            // `field[any]: { sub-map }` → object-scope block over member fields.
            Value::Mapping(m) => {
                if modifier_part.is_some() {
                    return Err(SigmaParserError::InvalidFieldSpec(
                        "value modifiers cannot be applied to an array object-scope block; \
                         move the modifier onto a field inside the block"
                            .into(),
                    ));
                }
                // A `condition:` key opens the extended (nested-detection) body:
                // named element-scoped sub-selections combined with and/or/not.
                // Without it, the body is the basic conjunction map.
                if m.iter().any(|(k, _)| k.as_str() == Some("condition")) {
                    parse_extended_block_body(value, array_matching)
                } else {
                    parse_detection(value, array_matching)
                }
            }
            // `field[all]: value` (or a list) → match the array member itself.
            // Represented as a body item with no field name.
            _ => {
                let modifiers = parse_modifiers(modifier_part)?;
                let field = FieldSpec::new(None, modifiers);
                let values = match value {
                    Value::Sequence(seq) => seq.iter().map(|v| to_sigma_value(v, &field)).collect(),
                    _ => vec![to_sigma_value(value, &field)],
                };
                Ok(Detection::AllOf(vec![DetectionItem { field, values }]))
            }
        }
    } else if value.is_mapping() {
        // A map value after more path segments: the element's sub-object must
        // satisfy the block. Expand it under the remaining path prefix.
        let prefix = reconstruct_key(remaining, None);
        parse_block_with_prefix(&prefix, value, array_matching)
    } else {
        // A selector in the middle of the path with a scalar/list leaf: recurse
        // on the remainder so further selectors and the leaf predicate desugar.
        let remaining_key = reconstruct_key(remaining, modifier_part);
        match parse_map_entry(&remaining_key, value, array_matching)? {
            ParsedEntry::Item(item) => Ok(Detection::AllOf(vec![item])),
            ParsedEntry::Block(block) => Ok(block),
        }
    }
}

/// Parse the **extended** object-scope block body: named element-scoped
/// sub-selections plus a `condition:` combining them with `and`/`or`/`not`,
/// evaluated against a single array member (the recursive "mini-event" form).
fn parse_extended_block_body(value: &Value, array_matching: bool) -> Result<Detection> {
    let m = value.as_mapping().ok_or_else(|| {
        SigmaParserError::InvalidDetection("extended array block body must be a mapping".into())
    })?;
    let mut named: HashMap<String, Detection> = HashMap::new();
    let mut condition: Option<ConditionExpr> = None;
    for (k, v) in m.iter() {
        let key = k.as_str().ok_or_else(|| {
            SigmaParserError::InvalidDetection("non-string key in array block body".into())
        })?;
        if key == "condition" {
            condition = Some(parse_block_condition(v)?);
        } else {
            named.insert(key.to_string(), parse_detection(v, array_matching)?);
        }
    }
    let condition = condition.ok_or_else(|| {
        SigmaParserError::InvalidDetection("extended array block requires a 'condition'".into())
    })?;
    if named.is_empty() {
        return Err(SigmaParserError::InvalidDetection(
            "extended array block has a 'condition' but no named sub-selections".into(),
        ));
    }
    Ok(Detection::Conditional { named, condition })
}

/// Parse the `condition:` value inside an extended array block: a single
/// expression string, or a list of strings combined with OR.
fn parse_block_condition(value: &Value) -> Result<ConditionExpr> {
    match value {
        Value::String(s) => parse_condition(s),
        Value::Sequence(seq) => {
            let exprs = seq
                .iter()
                .map(|x| {
                    let s = x.as_str().ok_or_else(|| {
                        SigmaParserError::InvalidDetection(
                            "array block 'condition' list items must be strings".into(),
                        )
                    })?;
                    parse_condition(s)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(ConditionExpr::Or(exprs))
        }
        _ => Err(SigmaParserError::InvalidDetection(
            "array block 'condition' must be a string or list of strings".into(),
        )),
    }
}

/// Parse a YAML mapping as a detection, prefixing every key with `prefix.` so
/// the entries are scoped to an indexed element or a nested object.
fn parse_block_with_prefix(prefix: &str, value: &Value, array_matching: bool) -> Result<Detection> {
    let m = value.as_mapping().ok_or_else(|| {
        SigmaParserError::InvalidDetection("array block body must be a mapping".into())
    })?;
    let mut items: Vec<DetectionItem> = Vec::new();
    let mut blocks: Vec<Detection> = Vec::new();
    for (k, v) in m.iter() {
        let sub = k.as_str().unwrap_or("");
        let key = format!("{prefix}.{sub}");
        match parse_map_entry(&key, v, array_matching)? {
            ParsedEntry::Item(item) => items.push(item),
            ParsedEntry::Block(block) => blocks.push(block),
        }
    }
    Ok(combine_entries(items, blocks))
}

/// Split a field path into dot-separated segments, recognizing the array
/// selectors `[any]`, `[all]`, `[all_or_empty]`, `[none]`, and positional `[N]`
/// (negative allowed) on the tail of a segment.
///
/// Only a well-formed quantifier or `name[<integer>]` is treated as a selector.
/// Any other bracket token is a parse error so typos surface instead of
/// silently matching a literal field name with brackets.
fn parse_field_path(field_part: &str) -> Result<Vec<PathSegment>> {
    let mut segments = Vec::new();
    for raw in field_part.split('.') {
        // Only an unescaped trailing `[...]` is a selector. An escaped bracket
        // (`\[` / `\]`) is a literal part of the field name and leaves the
        // segment plain; it is unescaped when the field is resolved.
        if let Some(open) = first_unescaped(raw, b'[')
            && ends_with_unescaped(raw, b']')
        {
            let name = &raw[..open];
            let token = &raw[open + 1..raw.len() - 1];
            if name.is_empty() {
                return Err(SigmaParserError::InvalidFieldSpec(format!(
                    "array selector without a field name in '{field_part}'"
                )));
            }
            let (index, quantifier) = match token {
                "any" => (None, Some(ArrayQuantifier::Any)),
                "all" => (None, Some(ArrayQuantifier::All)),
                "all_or_empty" => (None, Some(ArrayQuantifier::AllOrEmpty)),
                "none" => (None, Some(ArrayQuantifier::None)),
                _ => match token.parse::<i64>() {
                    Ok(n) => (Some(n), None),
                    Err(_) => {
                        return Err(SigmaParserError::InvalidFieldSpec(format!(
                            "unknown array selector '[{token}]' in field '{field_part}'; \
                             only [any], [all], [all_or_empty], [none], and an integer index \
                             [N] (negative counts from the end) are supported; \
                             escape a literal bracket as \\[ or \\]"
                        )));
                    }
                },
            };
            segments.push(PathSegment {
                name: name.to_string(),
                index,
                quantifier,
            });
        } else {
            segments.push(PathSegment {
                name: raw.to_string(),
                index: None,
                quantifier: None,
            });
        }
    }
    Ok(segments)
}

/// Parse the pipe-separated modifier chain that follows the first `|` in a key.
fn parse_modifiers(modifier_part: Option<&str>) -> Result<Vec<Modifier>> {
    let mut modifiers = Vec::new();
    if let Some(part) = modifier_part {
        for mod_str in part.split('|') {
            if mod_str == "not" {
                return Err(SigmaParserError::NotIsNotAModifier);
            }
            let m = mod_str
                .parse::<Modifier>()
                .map_err(|_| SigmaParserError::UnknownModifier(mod_str.to_string()))?;
            modifiers.push(m);
        }
    }
    Ok(modifiers)
}

/// Rebuild a detection key string from path segments plus an optional modifier
/// chain, re-appending `[any]`/`[all]` and positional `[N]` markers.
fn reconstruct_key(segments: &[PathSegment], modifier_part: Option<&str>) -> String {
    let path = segments
        .iter()
        .map(|s| match s.quantifier {
            Some(q) => format!("{}[{q}]", s.name),
            None => s.path_str(),
        })
        .collect::<Vec<_>>()
        .join(".");
    match modifier_part {
        Some(m) => format!("{path}|{m}"),
        None => path,
    }
}

/// Convert a YAML value to a SigmaValue, respecting field modifiers.
///
/// When the `re` modifier is present, strings are treated as raw (no wildcard parsing).
fn to_sigma_value(v: &Value, field: &FieldSpec) -> SigmaValue {
    if field.has_modifier(Modifier::Re)
        && let Value::String(s) = v
    {
        return SigmaValue::from_raw_string(s);
    }
    SigmaValue::from_yaml(v)
}

/// Parse a field specification string like `"TargetObject|endswith"`.
///
/// Reference: pySigma rule/detection.py — `field, *modifier_ids = key.split("|")`
pub fn parse_field_spec(key: &str) -> Result<FieldSpec> {
    if key.is_empty() {
        return Ok(FieldSpec::new(None, Vec::new()));
    }

    let parts: Vec<&str> = key.split('|').collect();
    let field_name = parts[0];
    // A standalone `.` is the array-element reference inside an object-scope
    // block body (the current scalar member); it lowers to a field-less item,
    // which the evaluator matches against the member value itself. Outside a
    // block body it has no special meaning, but a literal field named `.` is
    // not a realistic event field, so the mapping is unconditional.
    let field = if field_name.is_empty() || field_name == "." {
        None
    } else {
        Some(field_name.to_string())
    };

    let mut modifiers = Vec::new();
    for &mod_str in &parts[1..] {
        // Sigma reserves `not` for condition expressions; it is not a value
        // modifier. Catch this idiom up front so the diagnostic explains
        // the workaround instead of just saying "unknown modifier".
        if mod_str == "not" {
            return Err(SigmaParserError::NotIsNotAModifier);
        }
        let m = mod_str
            .parse::<Modifier>()
            .map_err(|_| SigmaParserError::UnknownModifier(mod_str.to_string()))?;
        modifiers.push(m);
    }

    Ok(FieldSpec::new(field, modifiers))
}
