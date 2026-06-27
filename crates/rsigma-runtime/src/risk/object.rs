//! Risk-object (entity) extraction.
//!
//! Each firing detection names one or more risk objects, each a `{type, value}`
//! pair (`user`, `host`, `src_ip`, ...). An object is extracted by resolving a
//! field selector against the result; a selector that resolves to nothing
//! contributes no object, so there are no phantom entities. One detection can
//! raise risk on several objects at once, exactly the Splunk RBA model.

use rsigma_eval::EvaluationResult;
use serde::Serialize;

use crate::selector::Selector;

/// A typed selector that extracts one kind of risk object from a result.
#[derive(Debug, Clone)]
pub struct ObjectSelector {
    /// The risk-object type label, e.g. `user`, `host`, `src_ip`.
    pub object_type: String,
    /// The field selector resolving the entity value.
    pub selector: Selector,
}

/// A single extracted risk object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskObject {
    /// The risk-object type, e.g. `user`.
    #[serde(rename = "type")]
    pub object_type: String,
    /// The entity value, e.g. `alice`.
    pub value: String,
}

/// Resolve every configured object selector against a result, returning the
/// distinct risk objects it names (deduplicated on `(type, value)`, order
/// preserved). A selector resolving to a non-scalar or absent value is skipped.
pub fn extract(result: &EvaluationResult, selectors: &[ObjectSelector]) -> Vec<RiskObject> {
    let mut out: Vec<RiskObject> = Vec::new();
    for sel in selectors {
        let Some(value) = sel.selector.resolve(result) else {
            continue;
        };
        let Some(value) = scalar_to_string(&value) else {
            continue;
        };
        let object = RiskObject {
            object_type: sel.object_type.clone(),
            value,
        };
        if !out.contains(&object) {
            out.push(object);
        }
    }
    out
}

/// Stringify a scalar JSON value. Arrays, objects, and null yield `None`, so a
/// selector pointing at a structured field contributes no entity.
fn scalar_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::String(_) => None,
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::{DetectionBody, FieldMatch, ResultBody, RuleHeader};
    use rsigma_parser::Level;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn detection() -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "t".to_string(),
                rule_id: Some("r".to_string()),
                level: Some(Level::High),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: Some(
                    serde_json::json!({"user": "alice"})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![
                    FieldMatch::new("SourceIp", serde_json::json!("10.0.0.1")),
                    FieldMatch::new("SourceIp", serde_json::json!("10.0.0.1")),
                ],
                event: Some(serde_json::json!({"host": {"name": "dc01"}})),
            }),
        }
    }

    fn sel(object_type: &str, raw: &str) -> ObjectSelector {
        ObjectSelector {
            object_type: object_type.to_string(),
            selector: Selector::parse(raw).unwrap(),
        }
    }

    #[test]
    fn extracts_across_namespaces() {
        let objects = extract(
            &detection(),
            &[
                sel("src_ip", "match.SourceIp"),
                sel("host", "event.host.name"),
                sel("user", "enrichment.user"),
            ],
        );
        assert_eq!(
            objects,
            vec![
                RiskObject {
                    object_type: "src_ip".into(),
                    value: "10.0.0.1".into()
                },
                RiskObject {
                    object_type: "host".into(),
                    value: "dc01".into()
                },
                RiskObject {
                    object_type: "user".into(),
                    value: "alice".into()
                },
            ]
        );
    }

    #[test]
    fn missing_selector_contributes_nothing() {
        let objects = extract(&detection(), &[sel("user", "event.nope")]);
        assert!(objects.is_empty());
    }

    #[test]
    fn duplicate_objects_are_collapsed() {
        let objects = extract(
            &detection(),
            &[
                sel("src_ip", "match.SourceIp"),
                sel("src_ip", "match.SourceIp"),
            ],
        );
        assert_eq!(objects.len(), 1);
    }
}
