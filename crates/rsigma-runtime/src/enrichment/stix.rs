//! `StixEnricher`: query a local [`StixStore`](rstix::store::StixStore) and
//! inject matching STIX objects into detection/correlation enrichments.
//!
//! Requires the **`stix-enrich`** feature and a store opened by the daemon
//! (`--stix-store`, same layout as `rsigma taxii sync --store`).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rsigma_eval::EvaluationResult;
use rsigma_eval::pipeline::sources::ExtractExpr;
use rstix::core::{StixId, StixObjectKind};
use rstix::store::{QueryResult, StixQuery, StixStore};
use serde_json::Value;

use super::{
    EnrichError, EnrichErrorKind, Enricher, EnricherKind, OnError, Scope, inject_enrichment,
    template::render_template,
};
use crate::sources::extract::apply_extract;

/// Query parameters for a [`StixEnricher`].
#[derive(Clone, Debug)]
pub struct StixEnricherQuery {
    /// Template-expanded STIX id for a direct [`StixStore::get`] lookup.
    pub stix_id: Option<String>,
    /// Template-expanded substring passed to [`StixQuery::text_search`].
    pub text_search: Option<String>,
    /// When true, derive `text_search` from the first `attack.t*` technique tag
    /// on the firing rule (`attack.t1059.001` → `1059.001`).
    pub attack_technique: bool,
    /// Optional STIX type filter (for example `indicator`, `attack-pattern`).
    pub type_filter: Vec<StixObjectKind>,
    /// Maximum objects to return (default **1** when unset at construction).
    pub max_results: usize,
}

/// STIX store lookup enricher.
pub struct StixEnricher {
    id: String,
    kind: EnricherKind,
    inject_field: String,
    query: StixEnricherQuery,
    extract: Option<ExtractExpr>,
    default: Option<Value>,
    timeout: Duration,
    on_error: OnError,
    scope: Scope,
    store: Arc<dyn StixStore>,
}

impl StixEnricher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        kind: EnricherKind,
        inject_field: String,
        query: StixEnricherQuery,
        extract: Option<ExtractExpr>,
        default: Option<Value>,
        timeout: Duration,
        on_error: OnError,
        scope: Scope,
        store: Arc<dyn StixStore>,
    ) -> Self {
        Self {
            id,
            kind,
            inject_field,
            query,
            extract,
            default,
            timeout,
            on_error,
            scope,
            store,
        }
    }

    fn render_extract(&self, result: &EvaluationResult) -> Option<ExtractExpr> {
        let original = self.extract.as_ref()?;
        let (lang, raw) = match original {
            ExtractExpr::Jq(s) => ("jq", s),
            ExtractExpr::JsonPath(s) => ("jsonpath", s),
            ExtractExpr::Cel(s) => ("cel", s),
        };
        let rendered = render_template(raw, result);
        Some(match lang {
            "jq" => ExtractExpr::Jq(rendered),
            "jsonpath" => ExtractExpr::JsonPath(rendered),
            "cel" => ExtractExpr::Cel(rendered),
            _ => return None,
        })
    }

    fn attack_technique_search_term(tags: &[String]) -> Option<String> {
        tags.iter().find_map(|tag| {
            let rest = tag.strip_prefix("attack.t")?;
            rest.chars()
                .next()
                .filter(|c| c.is_ascii_digit())
                .map(|_| rest.to_ascii_lowercase())
        })
    }

    fn build_query(&self, result: &EvaluationResult) -> Result<StixQuery, EnrichError> {
        if let Some(template) = &self.query.stix_id {
            let rendered = render_template(template, result);
            if rendered.is_empty() {
                return Err(EnrichError {
                    enricher_id: self.id.clone(),
                    kind: EnrichErrorKind::Fetch("stix_id template rendered empty".into()),
                });
            }
            let id = StixId::parse(&rendered).map_err(|e| EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch(format!("invalid stix_id '{rendered}': {e}")),
            })?;
            return Ok(StixQuery::new()
                .id_filter(vec![id])
                .max_results(self.query.max_results));
        }

        let text_search = if self.query.attack_technique {
            Self::attack_technique_search_term(&result.header.tags).ok_or_else(|| EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch(
                    "attack_technique: no attack.t* technique tag on rule".into(),
                ),
            })?
        } else {
            let template = self.query.text_search.as_ref().ok_or_else(|| EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch(
                    "stix enricher requires stix_id, text_search, or attack_technique".into(),
                ),
            })?;
            let rendered = render_template(template, result);
            if rendered.is_empty() {
                return Err(EnrichError {
                    enricher_id: self.id.clone(),
                    kind: EnrichErrorKind::Fetch("text_search template rendered empty".into()),
                });
            }
            rendered
        };

        let mut query = StixQuery::new()
            .text_search(text_search)
            .max_results(self.query.max_results);
        if !self.query.type_filter.is_empty() {
            query = query.type_filter(self.query.type_filter.clone());
        }
        Ok(query)
    }

    fn query_store(&self, query: &StixQuery) -> Result<QueryResult, EnrichError> {
        self.store.query(query).map_err(|e| EnrichError {
            enricher_id: self.id.clone(),
            kind: EnrichErrorKind::Fetch(format!("stix store query failed: {e}")),
        })
    }

    fn objects_to_value(objects: &[rstix::model::stix_object::StixObject]) -> Value {
        let values: Vec<Value> = objects
            .iter()
            .filter_map(|obj| serde_json::to_value(obj).ok())
            .collect();
        Value::Array(values)
    }
}

#[async_trait]
impl Enricher for StixEnricher {
    fn kind(&self) -> EnricherKind {
        self.kind
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn inject_field(&self) -> &str {
        &self.inject_field
    }
    fn timeout(&self) -> Duration {
        self.timeout
    }
    fn scope(&self) -> &Scope {
        &self.scope
    }
    fn on_error(&self) -> OnError {
        self.on_error
    }

    async fn enrich(&self, result: &mut EvaluationResult) -> Result<(), EnrichError> {
        let query = self.build_query(result)?;
        let page = self.query_store(&query)?;
        if page.objects.is_empty() {
            if let Some(d) = &self.default {
                inject_enrichment(result, &self.inject_field, d.clone());
                return Ok(());
            }
            return Err(EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch("stix store query returned no objects".into()),
            });
        }

        let payload = Self::objects_to_value(&page.objects);
        let extracted = match self.render_extract(result) {
            None => payload,
            Some(expr) => apply_extract(&payload, &expr).map_err(|e| EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Extract(format!("{}", e.kind)),
            })?,
        };

        if extracted.is_null() {
            if let Some(d) = &self.default {
                inject_enrichment(result, &self.inject_field, d.clone());
                return Ok(());
            }
            return Err(EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch("stix extract returned null".into()),
            });
        }
        inject_enrichment(result, &self.inject_field, extracted);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use rsigma_eval::{DetectionBody, FieldMatch, ResultBody, RuleHeader};
    use rsigma_parser::Level;
    use rstix::store::MemoryStore;

    fn detection(tags: Vec<&str>, field: &str, value: &str) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "test".into(),
                rule_id: Some("rule-1".into()),
                tenant_id: None,
                level: Some(Level::High),
                tags: tags.into_iter().map(str::to_string).collect(),
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec!["sel".into()],
                matched_fields: vec![FieldMatch::new(field, Value::String(value.to_string()))],
                event: None,
            }),
        }
    }

    #[test]
    fn attack_technique_tag_maps_to_search_term() {
        assert_eq!(
            StixEnricher::attack_technique_search_term(&[
                "attack.execution".into(),
                "attack.t1059.001".into(),
            ]),
            Some("1059.001".into())
        );
        assert!(StixEnricher::attack_technique_search_term(&["attack.execution".into()]).is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn text_search_injects_matching_indicator() {
        let bundle = rstix::parse_bundle(include_str!(
            "../../../rstix/tests/fixtures/store/multi-indicators.json"
        ))
        .expect("parse");
        let store = Arc::new(MemoryStore::new());
        store.import_bundle(&bundle).expect("import");
        let enricher = StixEnricher::new(
            "hash_lookup".into(),
            EnricherKind::Detection,
            "stix_matches".into(),
            StixEnricherQuery {
                stix_id: None,
                text_search: Some("${detection.fields.Hash}".into()),
                attack_technique: false,
                type_filter: vec![StixObjectKind::from_type_str("indicator").unwrap()],
                max_results: 3,
            },
            None,
            None,
            Duration::from_secs(5),
            OnError::Skip,
            Scope::default(),
            store,
        );
        let mut result = detection(vec![], "Hash", "644bf17e482f443f763b0b7355b14372");
        enricher.enrich(&mut result).await.expect("enrich");
        let enrichments = result.header.enrichments.expect("enrichments");
        let matches = enrichments
            .get("stix_matches")
            .and_then(|v| v.as_array())
            .expect("array");
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0]["id"],
            "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
    }
}
