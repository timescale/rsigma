//! Expression-based data extraction for dynamic sources.
//!
//! Supports three extraction languages with dual syntax:
//! - Plain string: always jq (the common case)
//! - Structured object `{ expr, type }`: explicit language selection
//!
//! Supported types: `jq` (via jaq), `jsonpath` (via serde_json_path), `cel` (via cel-interpreter).

use rsigma_eval::pipeline::sources::ExtractExpr;

use super::{SourceError, SourceErrorKind};

/// Apply a typed extract expression to parsed source data.
pub fn apply_extract(
    data: &serde_json::Value,
    expr: &ExtractExpr,
) -> Result<serde_json::Value, SourceError> {
    match expr {
        ExtractExpr::Jq(e) => apply_jq(data, e),
        ExtractExpr::JsonPath(e) => apply_jsonpath(data, e),
        ExtractExpr::Cel(e) => apply_cel(data, e),
    }
}

/// Apply a jq expression using jaq.
///
/// Loads the jaq core natives (`+`, `length`, `keys`, …) and the
/// `jaq-std` library (`select`, `map`, `first`, `with_entries`, …) so
/// the supported filter surface matches real jq for the operator-facing
/// expressions documented in the dynamic-pipelines and enrichment
/// references.
fn apply_jq(data: &serde_json::Value, expr: &str) -> Result<serde_json::Value, SourceError> {
    use jaq_interpret::{Ctx, FilterT, RcIter, Val};

    let mut defs = jaq_interpret::ParseCtx::new(Vec::new());
    defs.insert_natives(jaq_core::core());
    defs.insert_defs(jaq_std::std());

    let (filter, errs) = jaq_parse::parse(expr, jaq_parse::main());

    if !errs.is_empty() || filter.is_none() {
        return Err(SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Extract(format!("invalid jq expression: {expr}")),
        });
    }

    let filter = defs.compile(filter.unwrap());
    if !defs.errs.is_empty() {
        return Err(SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Extract(format!(
                "jq compile errors ({} in: {expr})",
                defs.errs.len(),
            )),
        });
    }
    let inputs = RcIter::new(std::iter::empty());
    let val = Val::from(data.clone());

    let ctx = Ctx::new([], &inputs);
    let results: Vec<Val> = filter
        .run((ctx, val))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Extract(format!("jq execution error: {e}")),
        })?;

    match results.len() {
        0 => Ok(serde_json::Value::Null),
        1 => Ok(val_to_json(&results[0])),
        _ => {
            let arr: Vec<serde_json::Value> = results.iter().map(val_to_json).collect();
            Ok(serde_json::Value::Array(arr))
        }
    }
}

/// Apply a JSONPath expression using jsonpath-rust.
fn apply_jsonpath(data: &serde_json::Value, expr: &str) -> Result<serde_json::Value, SourceError> {
    use jsonpath_rust::JsonPath;

    let results = data.query(expr).map_err(|e| SourceError {
        source_id: String::new(),
        kind: SourceErrorKind::Extract(format!("invalid JSONPath expression: {e}")),
    })?;

    match results.len() {
        0 => Ok(serde_json::Value::Null),
        1 => Ok(results[0].clone()),
        _ => {
            let arr: Vec<serde_json::Value> = results.into_iter().cloned().collect();
            Ok(serde_json::Value::Array(arr))
        }
    }
}

/// Apply a CEL expression using the `cel` crate (cel-rust).
///
/// The resolved source data is bound as the CEL variable `data`.
fn apply_cel(data: &serde_json::Value, expr: &str) -> Result<serde_json::Value, SourceError> {
    use cel::{Context, Program};

    let program = Program::compile(expr).map_err(|e| SourceError {
        source_id: String::new(),
        kind: SourceErrorKind::Extract(format!("invalid CEL expression: {e}")),
    })?;

    let mut context = Context::default();
    let cel_value = json_to_cel(data);
    let _ = context.add_variable("data", cel_value);

    let result = program.execute(&context).map_err(|e| SourceError {
        source_id: String::new(),
        kind: SourceErrorKind::Extract(format!("CEL execution error: {e}")),
    })?;

    Ok(cel_to_json(&result))
}

/// Convert a serde_json::Value to a cel::Value.
fn json_to_cel(json: &serde_json::Value) -> cel::Value {
    match json {
        serde_json::Value::Null => cel::Value::Null,
        serde_json::Value::Bool(b) => (*b).into(),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into()
            } else if let Some(u) = n.as_u64() {
                u.into()
            } else if let Some(f) = n.as_f64() {
                f.into()
            } else {
                cel::Value::Null
            }
        }
        serde_json::Value::String(s) => s.as_str().into(),
        serde_json::Value::Array(arr) => {
            let items: Vec<cel::Value> = arr.iter().map(json_to_cel).collect();
            items.into()
        }
        serde_json::Value::Object(map) => {
            let cel_map: std::collections::HashMap<cel::objects::Key, cel::Value> = map
                .iter()
                .map(|(k, v)| (k.as_str().into(), json_to_cel(v)))
                .collect();
            cel_map.into()
        }
    }
}

/// Convert a cel::Value back to serde_json::Value.
fn cel_to_json(val: &cel::Value) -> serde_json::Value {
    match val {
        cel::Value::Null => serde_json::Value::Null,
        cel::Value::Bool(b) => serde_json::Value::Bool(*b),
        cel::Value::Int(i) => serde_json::json!(i),
        cel::Value::UInt(u) => serde_json::json!(u),
        cel::Value::Float(f) => serde_json::json!(f),
        cel::Value::String(s) => serde_json::Value::String(s.to_string()),
        cel::Value::List(list) => {
            let arr: Vec<serde_json::Value> = list.iter().map(cel_to_json).collect();
            serde_json::Value::Array(arr)
        }
        cel::Value::Map(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map.map.iter() {
                let key = match k {
                    cel::objects::Key::String(s) => s.to_string(),
                    cel::objects::Key::Int(i) => i.to_string(),
                    cel::objects::Key::Uint(u) => u.to_string(),
                    cel::objects::Key::Bool(b) => b.to_string(),
                };
                obj.insert(key, cel_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::String(format!("{val:?}")),
    }
}

/// Convert a jaq `Val` to a `serde_json::Value`.
fn val_to_json(val: &jaq_interpret::Val) -> serde_json::Value {
    match val {
        jaq_interpret::Val::Null => serde_json::Value::Null,
        jaq_interpret::Val::Bool(b) => serde_json::Value::Bool(*b),
        jaq_interpret::Val::Int(i) => serde_json::json!(i),
        jaq_interpret::Val::Float(f) => serde_json::json!(f),
        jaq_interpret::Val::Num(n) => {
            if let Ok(i) = n.parse::<i64>() {
                serde_json::json!(i)
            } else if let Ok(f) = n.parse::<f64>() {
                serde_json::json!(f)
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        jaq_interpret::Val::Str(s) => serde_json::Value::String(s.to_string()),
        jaq_interpret::Val::Arr(arr) => {
            serde_json::Value::Array(arr.iter().map(val_to_json).collect())
        }
        jaq_interpret::Val::Obj(obj) => {
            let map: serde_json::Map<String, serde_json::Value> = obj
                .iter()
                .map(|(k, v)| (k.to_string(), val_to_json(v)))
                .collect();
            serde_json::Value::Object(map)
        }
    }
}
