//! Encoding and value helpers ported from `rsigma-eval` compiler helpers.

use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use regex::Regex;
use rsigma_parser::SigmaValue;

use crate::error::IrError;

pub(super) type Result<T> = std::result::Result<T, IrError>;

/// Convert a `yaml_serde::Value` to a `serde_json::Value`.
pub(super) fn yaml_to_json(value: &yaml_serde::Value) -> serde_json::Value {
    match value {
        yaml_serde::Value::Null => serde_json::Value::Null,
        yaml_serde::Value::Bool(b) => serde_json::Value::Bool(*b),
        yaml_serde::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                serde_json::Value::Number(u.into())
            } else if let Some(f) = n.as_f64() {
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        }
        yaml_serde::Value::String(s) => serde_json::Value::String(s.clone()),
        yaml_serde::Value::Sequence(seq) => {
            serde_json::Value::Array(seq.iter().map(yaml_to_json).collect())
        }
        yaml_serde::Value::Mapping(map) => {
            let obj: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .filter_map(|(k, v)| Some((k.as_str()?.to_string(), yaml_to_json(v))))
                .collect();
            serde_json::Value::Object(obj)
        }
        yaml_serde::Value::Tagged(tagged) => yaml_to_json(&tagged.value),
    }
}

/// Convert a map of YAML values to a map of JSON values.
pub(super) fn yaml_to_json_map(
    map: &std::collections::HashMap<String, yaml_serde::Value>,
) -> std::collections::HashMap<String, serde_json::Value> {
    map.iter()
        .map(|(k, v)| (k.clone(), yaml_to_json(v)))
        .collect()
}

pub(super) fn value_to_plain_string(value: &SigmaValue) -> Result<String> {
    match value {
        SigmaValue::String(s) => Ok(s.as_plain().unwrap_or_else(|| s.original.clone())),
        SigmaValue::Integer(n) => Ok(n.to_string()),
        SigmaValue::Float(n) => Ok(n.to_string()),
        SigmaValue::Bool(b) => Ok(b.to_string()),
        SigmaValue::Null => Err(IrError::IncompatibleValue(
            "null value for string modifier".into(),
        )),
    }
}

pub(super) fn value_to_f64(value: &SigmaValue) -> Result<f64> {
    match value {
        SigmaValue::Integer(n) => Ok(*n as f64),
        SigmaValue::Float(n) => Ok(*n),
        SigmaValue::String(s) => {
            let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
            plain
                .parse::<f64>()
                .map_err(|_| IrError::ExpectedNumeric(plain))
        }
        _ => Err(IrError::ExpectedNumeric(format!("{value:?}"))),
    }
}

pub(super) fn sigma_string_to_bytes(s: &rsigma_parser::SigmaString) -> Vec<u8> {
    let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
    plain.into_bytes()
}

pub(super) fn to_utf16le_bytes(bytes: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(bytes);
    let mut wide = Vec::with_capacity(s.len() * 2);
    for c in s.chars() {
        let mut buf = [0u16; 2];
        let encoded = c.encode_utf16(&mut buf);
        for u in encoded {
            wide.extend_from_slice(&u.to_le_bytes());
        }
    }
    wide
}

pub(super) fn to_utf16be_bytes(bytes: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(bytes);
    let mut wide = Vec::with_capacity(s.len() * 2);
    for c in s.chars() {
        let mut buf = [0u16; 2];
        let encoded = c.encode_utf16(&mut buf);
        for u in encoded {
            wide.extend_from_slice(&u.to_be_bytes());
        }
    }
    wide
}

pub(super) fn to_utf16_bom_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![0xFF, 0xFE];
    result.extend_from_slice(&to_utf16le_bytes(bytes));
    result
}

pub(super) fn base64_offset_patterns(value: &[u8]) -> Vec<String> {
    let mut patterns = Vec::with_capacity(3);

    for offset in 0..3usize {
        let mut padded = vec![0u8; offset];
        padded.extend_from_slice(value);

        let encoded = BASE64_STANDARD.encode(&padded);
        let start = (offset * 4).div_ceil(3);
        let trimmed = encoded.trim_end_matches('=');
        let end = trimmed.len();

        if start < end {
            patterns.push(trimmed[start..end].to_string());
        }
    }

    patterns
}

pub(super) fn build_regex_pattern(
    pattern: &str,
    case_insensitive: bool,
    multiline: bool,
    dotall: bool,
) -> Result<String> {
    let mut flags = String::new();
    if case_insensitive {
        flags.push('i');
    }
    if multiline {
        flags.push('m');
    }
    if dotall {
        flags.push('s');
    }

    let full_pattern = if flags.is_empty() {
        pattern.to_string()
    } else {
        format!("(?{flags}){pattern}")
    };

    // Validate the pattern at lower time so invalid regex fails early.
    Regex::new(&full_pattern)?;
    Ok(full_pattern)
}

const WINDASH_CHARS: [char; 5] = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];
const MAX_WINDASH_DASHES: usize = 8;

pub(super) fn expand_windash(input: &str) -> Result<Vec<String>> {
    let dash_positions: Vec<usize> = input
        .char_indices()
        .filter(|(_, c)| *c == '-')
        .map(|(i, _)| i)
        .collect();

    if dash_positions.is_empty() {
        return Ok(vec![input.to_string()]);
    }

    let n = dash_positions.len();
    if n > MAX_WINDASH_DASHES {
        return Err(IrError::InvalidModifiers(format!(
            "windash modifier: value contains {n} dashes, max is {MAX_WINDASH_DASHES} \
             (would generate {} variants)",
            5u64.saturating_pow(n as u32)
        )));
    }

    let total = WINDASH_CHARS.len().pow(n as u32);
    let mut variants = Vec::with_capacity(total);

    for combo in 0..total {
        let mut variant = input.to_string();
        let mut idx = combo;
        for &pos in dash_positions.iter().rev() {
            let replacement = WINDASH_CHARS[idx % WINDASH_CHARS.len()];
            variant.replace_range(pos..pos + 1, &replacement.to_string());
            idx /= WINDASH_CHARS.len();
        }
        variants.push(variant);
    }

    Ok(variants)
}

/// Parse an expand template string like `C:\Users\%user%\AppData` into parts.
pub(super) fn parse_expand_template(s: &str) -> Vec<crate::IrExpandPart> {
    use crate::IrExpandPart;

    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_placeholder = false;
    let mut placeholder = String::new();

    for ch in s.chars() {
        if ch == '%' {
            if in_placeholder {
                if !placeholder.is_empty() {
                    parts.push(IrExpandPart::Placeholder(placeholder.clone()));
                    placeholder.clear();
                }
                in_placeholder = false;
            } else {
                if !current.is_empty() {
                    parts.push(IrExpandPart::Literal(current.clone()));
                    current.clear();
                }
                in_placeholder = true;
            }
        } else if in_placeholder {
            placeholder.push(ch);
        } else {
            current.push(ch);
        }
    }

    if in_placeholder && !placeholder.is_empty() {
        current.push('%');
        current.push_str(&placeholder);
    }

    if !current.is_empty() {
        parts.push(IrExpandPart::Literal(current));
    }

    parts
}

/// Build a regex pattern from Sigma string parts (wildcards → `.*` / `.`).
pub(super) fn sigma_parts_to_regex_pattern(
    parts: &[rsigma_parser::value::StringPart],
    case_insensitive: bool,
    contains: bool,
    startswith: bool,
    endswith: bool,
) -> String {
    use rsigma_parser::value::{SpecialChar, StringPart};

    let mut pattern = String::new();
    if case_insensitive {
        pattern.push_str("(?i)");
    }

    if !contains && !startswith {
        pattern.push('^');
    }

    for part in parts {
        match part {
            StringPart::Plain(text) => {
                pattern.push_str(&regex::escape(text));
            }
            StringPart::Special(SpecialChar::WildcardMulti) => {
                pattern.push_str(".*");
            }
            StringPart::Special(SpecialChar::WildcardSingle) => {
                pattern.push('.');
            }
        }
    }

    if !contains && !endswith {
        pattern.push('$');
    }

    pattern
}

/// Keywords wildcard path: contains-semantics regex anchored at both ends
/// after converting wildcards (same as eval `sigma_string_to_regex`).
pub(super) fn keywords_wildcard_pattern(
    parts: &[rsigma_parser::value::StringPart],
    case_insensitive: bool,
) -> String {
    use rsigma_parser::value::{SpecialChar, StringPart};

    let mut pattern = String::new();
    if case_insensitive {
        pattern.push_str("(?i)");
    }
    pattern.push('^');
    for part in parts {
        match part {
            StringPart::Plain(text) => pattern.push_str(&regex::escape(text)),
            StringPart::Special(SpecialChar::WildcardMulti) => pattern.push_str(".*"),
            StringPart::Special(SpecialChar::WildcardSingle) => pattern.push('.'),
        }
    }
    pattern.push('$');
    pattern
}
