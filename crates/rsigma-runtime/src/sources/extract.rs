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
/// Loads the jaq core natives (`+`, `length`, `keys`, …), the
/// `jaq-std` library (`select`, `map`, `first`, `with_entries`, …),
/// and the `jaq-json` JSON-specific filters (`tojson`, `fromjson`,
/// `length`, …) so the supported filter surface matches real jq for
/// the operator-facing expressions documented in the dynamic-pipelines
/// and enrichment references.
fn apply_jq(data: &serde_json::Value, expr: &str) -> Result<serde_json::Value, SourceError> {
    use jaq_core::load::{Arena, File, Loader};
    use jaq_core::{Compiler, Ctx, Vars, data, unwrap_valr};
    use jaq_json::Val;

    let program = File {
        code: expr,
        path: (),
    };

    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());

    let arena = Arena::default();
    let modules = Loader::new(defs)
        .load(&arena, program)
        .map_err(|_| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Extract(format!("invalid jq expression: {expr}")),
        })?;

    let filter = Compiler::default()
        .with_funs(funs)
        .compile(modules)
        .map_err(|_| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Extract(format!("jq compile error in: {expr}")),
        })?;

    let input = json_to_val(data.clone());
    let ctx = Ctx::<data::JustLut<Val>>::new(&filter.lut, Vars::new([]));

    let mut results: Vec<Val> = Vec::new();
    for r in filter.id.run((ctx, input)).map(unwrap_valr) {
        let v = r.map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Extract(format!("jq execution error: {e}")),
        })?;
        results.push(v);
    }

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

/// Convert a `serde_json::Value` to a jaq `Val`.
fn json_to_val(v: serde_json::Value) -> jaq_json::Val {
    use jaq_core::ValT;
    use jaq_json::Val;

    match v {
        serde_json::Value::Null => Val::Null,
        serde_json::Value::Bool(b) => Val::Bool(b),
        serde_json::Value::Number(n) => Val::from_num(&n.to_string()).unwrap_or(Val::Null),
        serde_json::Value::String(s) => Val::from(s),
        serde_json::Value::Array(arr) => arr.into_iter().map(json_to_val).collect(),
        serde_json::Value::Object(obj) => Val::obj(
            obj.into_iter()
                .map(|(k, v)| (Val::from(k), json_to_val(v)))
                .collect(),
        ),
    }
}

/// Convert a jaq `Val` to a `serde_json::Value`.
///
/// Byte and text strings are decoded with lossy UTF-8 conversion. Non-string
/// object keys are stringified via their Display impl so they round-trip into
/// JSON keys.
fn val_to_json(val: &jaq_json::Val) -> serde_json::Value {
    use jaq_json::Val;
    use jaq_std::ValT;

    match val {
        Val::Null => serde_json::Value::Null,
        Val::Bool(b) => serde_json::Value::Bool(*b),
        Val::Num(_) => {
            if let Some(i) = val.as_isize() {
                serde_json::json!(i)
            } else if let Some(f) = val.as_f64() {
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or_else(|| serde_json::Value::String(val.to_string()))
            } else {
                serde_json::Value::String(val.to_string())
            }
        }
        Val::BStr(b) | Val::TStr(b) => {
            serde_json::Value::String(String::from_utf8_lossy(b).into_owned())
        }
        Val::Arr(arr) => serde_json::Value::Array(arr.iter().map(val_to_json).collect()),
        Val::Obj(obj) => {
            let mut map = serde_json::Map::new();
            for (k, v) in obj.iter() {
                let key = match k {
                    Val::BStr(b) | Val::TStr(b) => String::from_utf8_lossy(b).into_owned(),
                    _ => k.to_string(),
                };
                map.insert(key, val_to_json(v));
            }
            serde_json::Value::Object(map)
        }
    }
}
