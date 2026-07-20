//! Value-extraction helpers for lowering.
//!
//! Encoding, regex, and wildcard rendering deliberately live in the consumers
//! (eval's compile step and convert), not here: lowering stays purely
//! structural so the HIR round-trips faithfully.

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
