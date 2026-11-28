//! JSONB field paths and array object-scope matching.
//!
//! A dotted field such as `process.args[0]` becomes a `->`/`->>` navigation
//! chain from the backend's JSONB column, and an array match such as
//! `connections[any]` becomes an `EXISTS` over `jsonb_array_elements` with the
//! body converted relative to the per-element alias.

#[cfg(test)]
mod tests;

use rsigma_ir::{IrDetection, IrDetectionItem};
use rsigma_parser::ArrayQuantifier;

use super::{PostgresBackend, is_field_key};
use crate::error::{ConvertError, Result};
use crate::state::ConversionState;

/// Processing-state key naming the scalar array element alias being
/// converted, whose values are text.
pub(super) const TEXT_ELEMENT_KEY: &str = "_text_array_element";

/// A JSONB field-path navigation op: an object key or a positional index
/// (possibly negative, counting from the end of the array).
#[derive(Debug, PartialEq)]
enum FieldOp {
    Key(String),
    Index(i64),
}

/// Return a fresh, query-unique sequence number for naming array-element
/// aliases (`__sigma_e0`, `__sigma_e1`, ...). Stored in the conversion state so
/// nested object-scope blocks never collide.
fn next_array_alias_seq(state: &mut ConversionState) -> u64 {
    let cur = state
        .processing_state
        .get("_array_alias_seq")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    state.processing_state.insert(
        "_array_alias_seq".to_string(),
        serde_json::Value::from(cur + 1),
    );
    cur
}

/// Build a JSONB navigation expression `base->'a'->0->'b'...`, supporting
/// dotted object keys and positional `[N]` indices. When `as_text` the
/// final hop uses `->>` (text); otherwise every hop uses `->` (jsonb),
/// which is what `jsonb_array_elements` needs.
pub(super) fn jsonb_path(base: &str, field: &str, as_text: bool) -> Result<String> {
    let ops = parse_field_ops(field)?;
    let last = ops.len() - 1;
    let mut expr = base.to_string();
    for (i, op) in ops.iter().enumerate() {
        let text = as_text && i == last;
        match op {
            FieldOp::Key(k) => {
                let escaped = k.replace('\'', "''");
                if text {
                    expr.push_str(&format!("->>'{escaped}'"));
                } else {
                    expr.push_str(&format!("->'{escaped}'"));
                }
            }
            FieldOp::Index(n) => {
                if text {
                    expr.push_str(&format!("->>{n}"));
                } else {
                    expr.push_str(&format!("->{n}"));
                }
            }
        }
    }
    Ok(expr)
}

/// Parse a JSONB field path into object-key and positional-index ops,
/// validating each key with [`is_field_key`].
fn parse_field_ops(field: &str) -> Result<Vec<FieldOp>> {
    let mut ops = Vec::new();
    for part in field.split('.') {
        if part.is_empty() {
            return Err(ConvertError::InvalidIdentifier(field.to_string()));
        }
        let bpos = part.find('[');
        let name = match bpos {
            Some(p) => &part[..p],
            None => part,
        };
        if !name.is_empty() {
            if !is_field_key(name) {
                return Err(ConvertError::InvalidIdentifier(name.to_string()));
            }
            ops.push(FieldOp::Key(name.to_string()));
        }
        if let Some(p) = bpos {
            let mut rem = &part[p..];
            while !rem.is_empty() {
                let rest = rem
                    .strip_prefix('[')
                    .ok_or_else(|| ConvertError::InvalidIdentifier(part.to_string()))?;
                let close = rest
                    .find(']')
                    .ok_or_else(|| ConvertError::InvalidIdentifier(part.to_string()))?;
                let n: i64 = rest[..close]
                    .parse()
                    .map_err(|_| ConvertError::InvalidIdentifier(part.to_string()))?;
                ops.push(FieldOp::Index(n));
                rem = &rest[close + 1..];
            }
        }
    }
    if ops.is_empty() {
        return Err(ConvertError::InvalidIdentifier(field.to_string()));
    }
    Ok(ops)
}

/// The items of an array body whose every item is field-less, which matches
/// each element of an array of scalars against the item's value.
fn scalar_self_body_ir(body: &IrDetection) -> Option<&[IrDetectionItem]> {
    if let IrDetection::AllOf(items) = body
        && !items.is_empty()
        && items.iter().all(|it| it.field.is_none())
    {
        return Some(items);
    }
    None
}

/// Whether an array body has a field-less item outside nested array matches.
fn has_fieldless_item(body: &IrDetection) -> bool {
    match body {
        IrDetection::AllOf(items) => items.iter().any(|it| it.field.is_none()),
        IrDetection::AnyOf(dets) | IrDetection::And(dets) => dets.iter().any(has_fieldless_item),
        IrDetection::Conditional { named, .. } => named.values().any(has_fieldless_item),
        IrDetection::Keywords(_) | IrDetection::ArrayMatch { .. } => false,
    }
}

impl PostgresBackend {
    /// Clone this backend with a different JSONB base column. Used to convert an
    /// array object-scope body relative to the per-element alias.
    fn with_json_field(&self, json_field: Option<String>) -> Self {
        PostgresBackend {
            config: self.config,
            table: self.table.clone(),
            timestamp_field: self.timestamp_field.clone(),
            json_field,
            schema: self.schema.clone(),
            database: self.database.clone(),
            timescaledb: self.timescaledb,
            correlation_method: self.correlation_method.clone(),
            session_gap_secs: self.session_gap_secs,
        }
    }

    /// Match `array_expr`, a JSONB array, against `body` under `quantifier`.
    /// A scalar body compares each element as text through
    /// `jsonb_array_elements_text`; an object body is converted through the
    /// IR-native detection dispatch with the element alias as its JSONB base.
    pub(super) fn array_exists_from_expr_ir(
        &self,
        array_expr: &str,
        quantifier: ArrayQuantifier,
        body: &IrDetection,
        state: &mut ConversionState,
    ) -> Result<String> {
        let seq = next_array_alias_seq(state);
        let alias = format!("__sigma_e{seq}");

        let (srf, body_sql) = if let Some(items) = scalar_self_body_ir(body) {
            let renamed = IrDetection::AllOf(
                items
                    .iter()
                    .map(|it| IrDetectionItem {
                        field: Some(alias.clone()),
                        matcher: it.matcher.clone(),
                        exists: it.exists,
                    })
                    .collect(),
            );
            let elem = self.with_json_field(None);
            let outer = state
                .processing_state
                .insert(TEXT_ELEMENT_KEY.to_string(), alias.clone().into());
            let body = crate::ir_convert::default_convert_ir_detection(&elem, &renamed, state);
            match outer {
                Some(v) => state
                    .processing_state
                    .insert(TEXT_ELEMENT_KEY.to_string(), v),
                None => state.processing_state.remove(TEXT_ELEMENT_KEY),
            };
            ("jsonb_array_elements_text", body?)
        } else {
            // A field-less item in an object body matches the element itself,
            // which the per-field SQL cannot express.
            if has_fieldless_item(body) {
                return Err(ConvertError::UnsupportedArrayMatching);
            }
            let elem = self.with_json_field(Some(alias.clone()));
            (
                "jsonb_array_elements",
                crate::ir_convert::default_convert_ir_detection(&elem, body, state)?,
            )
        };

        Ok(match quantifier {
            ArrayQuantifier::Any => format!(
                "(jsonb_typeof({array_expr}) = 'array' AND EXISTS \
                 (SELECT 1 FROM {srf}({array_expr}) AS {alias} WHERE {body_sql}))"
            ),
            ArrayQuantifier::All => format!(
                "(jsonb_typeof({array_expr}) = 'array' AND jsonb_array_length({array_expr}) > 0 \
                 AND NOT EXISTS \
                 (SELECT 1 FROM {srf}({array_expr}) AS {alias} WHERE ({body_sql}) IS NOT TRUE))"
            ),
            ArrayQuantifier::AllOrEmpty => format!(
                "(CASE WHEN jsonb_typeof({array_expr}) = 'array' \
                 THEN NOT EXISTS (SELECT 1 FROM {srf}({array_expr}) AS {alias} WHERE ({body_sql}) IS NOT TRUE) \
                 ELSE {array_expr} IS NULL OR jsonb_typeof({array_expr}) = 'null' END)"
            ),
            ArrayQuantifier::None => format!(
                "(CASE WHEN jsonb_typeof({array_expr}) = 'array' \
                 THEN NOT EXISTS (SELECT 1 FROM {srf}({array_expr}) AS {alias} WHERE {body_sql}) \
                 ELSE {array_expr} IS NULL OR jsonb_typeof({array_expr}) = 'null' END)"
            ),
        })
    }
}
