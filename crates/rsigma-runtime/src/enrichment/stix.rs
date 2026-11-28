//! `StixEnricher`: query a local [`StixStore`](rstix::store::StixStore) and
//! inject matching STIX objects into detection/correlation enrichments.
//!
//! Requires the **`stix-enrich`** feature and a store opened by the daemon
//! (`--stix-store`, same layout as `rsigma taxii sync --store`).

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use async_trait::async_trait;
use rsigma_eval::EvaluationResult;
use rsigma_eval::pipeline::sources::ExtractExpr;
use rstix::core::{StixId, StixObjectKind};
use rstix::store::{QueryResult, StixQuery, StixStore, TextMatch};
use serde_json::Value;
use tokio::sync::Semaphore;

use super::extract::EnricherExtract;
use super::{
    EnrichError, EnrichErrorKind, Enricher, EnricherKind, OnError, Scope, inject_enrichment,
    render_enricher_template,
};

/// Fewest characters a rendered `text_search` term may have, not counting
/// leading and trailing whitespace. Shorter terms match most of a store.
pub const MIN_TEXT_SEARCH_CHARS: usize = 3;

/// Store queries running on the blocking pool at once. A query that outlives
/// its enricher's timeout keeps its slot until it finishes, so slow queries
/// delay other STIX lookups (which then time out) rather than filling the
/// blocking pool the rest of the runtime uses.
static QUERY_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| {
    let cpus = std::thread::available_parallelism().map_or(4, |n| n.get());
    Arc::new(Semaphore::new(cpus.max(2) * 2))
});

/// Query parameters for a [`StixEnricher`].
#[derive(Clone, Debug)]
pub struct StixEnricherQuery {
    /// Template-expanded STIX id for a direct [`StixStore::get`] lookup.
    pub stix_id: Option<String>,
    /// Template-expanded term passed to [`StixQuery::text_search`]. A rendered
    /// term shorter than [`MIN_TEXT_SEARCH_CHARS`] fails the lookup.
    pub text_search: Option<String>,
    /// How the `text_search` or `attack_technique` term is compared with the
    /// store's indexed text.
    pub text_match: TextMatch,
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
    extract: Option<EnricherExtract>,
    default: Option<Value>,
    timeout: Duration,
    on_error: OnError,
    on_miss: OnError,
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
            extract: extract.map(|expr| EnricherExtract::new(&expr, true)),
            default,
            timeout,
            on_error,
            on_miss: on_error,
            scope,
            store,
        }
    }

    /// Set the policy applied when this enricher finds no data
    /// ([`EnrichErrorKind::Miss`]). Defaults to the `on_error` policy.
    pub fn with_on_miss(mut self, on_miss: OnError) -> Self {
        self.on_miss = on_miss;
        self
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
            let rendered = render_enricher_template(template, result);
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
            let rendered = render_enricher_template(template, result);
            if rendered.is_empty() {
                return Err(EnrichError {
                    enricher_id: self.id.clone(),
                    kind: EnrichErrorKind::Fetch("text_search template rendered empty".into()),
                });
            }
            if rendered.trim().chars().count() < MIN_TEXT_SEARCH_CHARS {
                return Err(EnrichError {
                    enricher_id: self.id.clone(),
                    kind: EnrichErrorKind::Fetch(format!(
                        "text_search template rendered '{rendered}', shorter than {MIN_TEXT_SEARCH_CHARS} characters"
                    )),
                });
            }
            rendered
        };

        let mut query = StixQuery::new()
            .text_search(text_search)
            .text_match(self.query.text_match)
            .max_results(self.query.max_results);
        if !self.query.type_filter.is_empty() {
            query = query.type_filter(self.query.type_filter.clone());
        }
        Ok(query)
    }

    /// Run the query on the blocking pool, bounded by the enricher timeout.
    async fn query_store(&self, query: StixQuery) -> Result<QueryResult, EnrichError> {
        let failed = |message: String| EnrichError {
            enricher_id: self.id.clone(),
            kind: EnrichErrorKind::Fetch(format!("stix store query failed: {message}")),
        };
        let store = Arc::clone(&self.store);
        let run = async {
            let permit = Arc::clone(&QUERY_SLOTS)
                .acquire_owned()
                .await
                .map_err(|e| failed(e.to_string()))?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                store.query(&query)
            })
            .await
            .map_err(|e| failed(e.to_string()))?
            .map_err(|e| failed(e.to_string()))
        };
        tokio::time::timeout(self.timeout, run)
            .await
            .map_err(|_| EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Timeout,
            })?
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
    fn on_miss(&self) -> OnError {
        self.on_miss
    }

    async fn enrich(&self, result: &mut EvaluationResult) -> Result<(), EnrichError> {
        let query = self.build_query(result)?;
        let page = self.query_store(query).await?;
        if page.objects.is_empty() {
            if let Some(d) = &self.default {
                inject_enrichment(result, &self.inject_field, d.clone());
                return Ok(());
            }
            return Err(EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Miss("stix store query returned no objects".into()),
            });
        }

        let payload = Self::objects_to_value(&page.objects);
        let extracted = match &self.extract {
            None => payload,
            Some(extract) => {
                extract
                    .apply(&self.id, payload, result, self.timeout)
                    .await?
            }
        };

        if extracted.is_null() {
            if let Some(d) = &self.default {
                inject_enrichment(result, &self.inject_field, d.clone());
                return Ok(());
            }
            return Err(EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Miss("stix extract returned null".into()),
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
    use rstix::model::Bundle;
    use rstix::model::stix_object::StixObject;
    use rstix::store::{ImportReport, MemoryStore, StoreError};

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
                text_match: TextMatch::Substring,
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

    fn enricher(
        store: Arc<dyn StixStore>,
        query: StixEnricherQuery,
        timeout: Duration,
    ) -> StixEnricher {
        StixEnricher::new(
            "lookup".into(),
            EnricherKind::Detection,
            "stix_matches".into(),
            query,
            None,
            None,
            timeout,
            OnError::Skip,
            Scope::default(),
            store,
        )
    }

    fn search(template: &str, text_match: TextMatch) -> StixEnricherQuery {
        StixEnricherQuery {
            stix_id: None,
            text_search: Some(template.into()),
            text_match,
            attack_technique: false,
            type_filter: Vec::new(),
            max_results: 10,
        }
    }

    fn ip_store() -> Arc<MemoryStore> {
        let objects: Vec<_> = ["10.0.0.1", "10.0.0.10"]
            .iter()
            .enumerate()
            .map(|(n, ip)| {
                rstix::parse_object(&format!(
                    r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-{n:012x}","created":"2024-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","pattern":"[ipv4-addr:value = '{ip}']","pattern_type":"stix","valid_from":"2024-01-01T00:00:00.000Z"}}"#
                ))
                .expect("indicator")
            })
            .collect();
        let store = Arc::new(MemoryStore::new());
        store.import_objects(&objects).expect("import");
        store
    }

    #[tokio::test]
    async fn short_rendered_term_is_rejected() {
        for value in ["a", " ab "] {
            let lookup = enricher(
                ip_store(),
                search("${detection.fields.Ip}", TextMatch::Substring),
                Duration::from_secs(5),
            );
            let mut result = detection(vec![], "Ip", value);
            let err = lookup.enrich(&mut result).await.unwrap_err();
            let EnrichErrorKind::Fetch(message) = &err.kind else {
                panic!("expected a fetch error, got {:?}", err.kind);
            };
            assert!(
                message.contains(&format!("shorter than {MIN_TEXT_SEARCH_CHARS} characters")),
                "{message}"
            );
        }
    }

    #[tokio::test]
    async fn token_match_does_not_match_inside_a_longer_value() {
        let matched = |text_match| async move {
            let lookup = enricher(
                ip_store(),
                search("${detection.fields.Ip}", text_match),
                Duration::from_secs(5),
            );
            let mut result = detection(vec![], "Ip", "10.0.0.1");
            lookup.enrich(&mut result).await.expect("enrich");
            result.header.enrichments.expect("enrichments")["stix_matches"]
                .as_array()
                .expect("array")
                .len()
        };
        assert_eq!(matched(TextMatch::Substring).await, 2);
        assert_eq!(matched(TextMatch::Token).await, 1);
    }

    /// A store whose queries block the calling thread.
    struct SlowStore(MemoryStore);

    impl StixStore for SlowStore {
        fn upsert(&self, obj: &StixObject) -> Result<(), StoreError> {
            self.0.upsert(obj)
        }
        fn get(&self, id: &StixId) -> Result<Option<StixObject>, StoreError> {
            self.0.get(id)
        }
        fn get_all_versions(&self, id: &StixId) -> Result<Vec<StixObject>, StoreError> {
            self.0.get_all_versions(id)
        }
        fn query(&self, q: &StixQuery) -> Result<QueryResult, StoreError> {
            std::thread::sleep(Duration::from_millis(500));
            self.0.query(q)
        }
        fn import_bundle(&self, bundle: &Bundle) -> Result<ImportReport, StoreError> {
            self.0.import_bundle(bundle)
        }
        fn import_objects(&self, objects: &[StixObject]) -> Result<ImportReport, StoreError> {
            self.0.import_objects(objects)
        }
        fn delete(&self, id: &StixId) -> Result<bool, StoreError> {
            self.0.delete(id)
        }
        fn export_bundle(&self, bundle_id: StixId) -> Result<Bundle, StoreError> {
            self.0.export_bundle(bundle_id)
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn slow_query_runs_off_the_runtime_and_times_out() {
        let lookup = enricher(
            Arc::new(SlowStore(MemoryStore::new())),
            search("${detection.fields.Ip}", TextMatch::Substring),
            Duration::from_millis(20),
        );
        let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ticker = tokio::spawn({
            let ticks = Arc::clone(&ticks);
            async move {
                loop {
                    ticks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            }
        });
        let mut result = detection(vec![], "Ip", "10.0.0.1");
        let err = lookup.enrich(&mut result).await.unwrap_err();
        ticker.abort();
        assert!(
            matches!(err.kind, EnrichErrorKind::Timeout),
            "{:?}",
            err.kind
        );
        assert!(
            ticks.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "the runtime kept running other tasks during the query"
        );
    }
}
