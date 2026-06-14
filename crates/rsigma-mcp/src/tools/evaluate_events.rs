//! The `evaluate_events` tool: evaluate JSON events against Sigma rules
//! (detections and correlations), with optional enrichment.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_eval::{CorrelationConfig, CorrelationEngine, Engine, EvaluationResult, JsonEvent};
use rsigma_runtime::{EnrichersFile, EnrichmentPipeline, build_enrichers, load_enrichers_file};
use serde_json::{Value, json};

use crate::input::resolve_path;

use super::RsigmaMcp;
use super::shared::{invalid, json_result, parse_match_detail, to_value};

/// Input for `evaluate_events`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct EvaluateInput {
    /// Inline Sigma YAML. Mutually exclusive with `path`.
    #[serde(default)]
    pub yaml: Option<String>,
    /// Path to a Sigma file or directory. Mutually exclusive with `yaml`.
    #[serde(default)]
    pub path: Option<String>,
    /// Inline events as a JSON array of objects. Mutually exclusive with `events_path`.
    #[serde(default)]
    pub events: Option<Vec<Value>>,
    /// Path to an NDJSON file of events. Mutually exclusive with `events`.
    #[serde(default)]
    pub events_path: Option<String>,
    /// Processing pipelines (builtin names or file paths).
    #[serde(default)]
    pub pipelines: Vec<String>,
    /// Match-detail verbosity: `off` (default), `summary`, or `full`.
    #[serde(default)]
    pub match_detail: Option<String>,
    /// Extra event field names to try for correlation timestamp extraction.
    #[serde(default)]
    pub timestamp_fields: Vec<String>,
    /// Inline enrichers config (YAML/JSON) applied to results before returning.
    /// Mutually exclusive with `enrichers_path`. `lookup` enrichers are not
    /// supported here (no dynamic-source cache); use the daemon for those.
    #[serde(default)]
    pub enrichers: Option<String>,
    /// Path to an enrichers config file. Mutually exclusive with `enrichers`.
    #[serde(default)]
    pub enrichers_path: Option<String>,
}

#[tool_router(router = evaluate_events_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Evaluate JSON events against Sigma rules (detections and correlations).
    #[tool(
        description = "Evaluate JSON events against Sigma rules and return matches. Detection-only rules use the stateless engine; collections with correlations use the stateful correlation engine. Rules via inline `yaml` or `path`; events via an inline `events` JSON array or an NDJSON `events_path`. Optional `pipelines` and `match_detail` (off/summary/full)."
    )]
    async fn evaluate_events(
        &self,
        Parameters(input): Parameters<EvaluateInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_evaluate_events(input).await?))
    }

    pub(crate) async fn run_evaluate_events(
        &self,
        input: EvaluateInput,
    ) -> Result<Value, McpError> {
        let collection = self.load_collection(input.yaml.as_deref(), input.path.as_deref())?;
        let pipelines = self.load_pipelines(&input.pipelines)?;
        let events = self.load_events(input.events, input.events_path.as_deref())?;
        let detail = parse_match_detail(input.match_detail.as_deref())?;
        let enrichment =
            self.build_enrichment(input.enrichers.as_deref(), input.enrichers_path.as_deref())?;

        let mut results: Vec<Value> = Vec::new();
        let mut detection_matches = 0usize;
        let mut correlation_matches = 0usize;

        let json_events: Vec<JsonEvent> = events.iter().map(JsonEvent::borrow).collect();
        let refs: Vec<&JsonEvent> = json_events.iter().collect();

        // Per-event result batches as owned `Vec<EvaluationResult>` so the
        // enrichment pipeline (which mutates and may drop results) can run
        // against each event's results while preserving the event index.
        let batches: Vec<Vec<EvaluationResult>> = if collection.correlations.is_empty() {
            let mut engine = Engine::new();
            engine.set_match_detail(detail);
            for p in &pipelines {
                engine.add_pipeline(p.clone());
            }
            engine
                .add_collection(&collection)
                .map_err(|e| invalid(format!("rule compile error: {e}")))?;
            engine.evaluate_batch(&refs)
        } else {
            let mut config = CorrelationConfig::default();
            if !input.timestamp_fields.is_empty() {
                let mut fields = input.timestamp_fields.clone();
                fields.extend(config.timestamp_fields);
                config.timestamp_fields = fields;
            }
            let mut engine = CorrelationEngine::new(config);
            engine.set_match_detail(detail);
            for p in &pipelines {
                engine.add_pipeline(p.clone());
            }
            engine
                .add_collection(&collection)
                .map_err(|e| invalid(format!("rule compile error: {e}")))?;
            engine
                .process_batch(&refs)
                .into_iter()
                .map(|pr| pr.to_vec())
                .collect()
        };

        for (idx, mut per_event) in batches.into_iter().enumerate() {
            if let Some(pipeline) = &enrichment {
                pipeline.run(&mut per_event).await;
            }
            for r in &per_event {
                if r.is_correlation() {
                    correlation_matches += 1;
                } else {
                    detection_matches += 1;
                }
                results.push(json!({ "event_index": idx, "result": to_value(r) }));
            }
        }

        Ok(json!({
            "ok": true,
            "summary": {
                "events_evaluated": events.len(),
                "detection_matches": detection_matches,
                "correlation_matches": correlation_matches,
                "enriched": enrichment.is_some(),
            },
            "results": results,
        }))
    }

    /// Build an optional [`EnrichmentPipeline`] from an inline config xor a path.
    /// `lookup` enrichers are unsupported here (no dynamic-source cache).
    fn build_enrichment(
        &self,
        enrichers: Option<&str>,
        enrichers_path: Option<&str>,
    ) -> Result<Option<EnrichmentPipeline>, McpError> {
        let file: Option<EnrichersFile> = match (enrichers, enrichers_path) {
            (Some(_), Some(_)) => {
                return Err(invalid(
                    "provide either `enrichers` or `enrichers_path`, not both",
                ));
            }
            (None, None) => None,
            (Some(text), None) => Some(
                yaml_serde::from_str(text)
                    .map_err(|e| invalid(format!("invalid enrichers config: {e}")))?,
            ),
            (None, Some(p)) => {
                let path = resolve_path(p, self.root());
                Some(load_enrichers_file(&path).map_err(|e| invalid(e.to_string()))?)
            }
        };

        match file {
            None => Ok(None),
            Some(file) => build_enrichers(file)
                .map(Some)
                .map_err(|e| invalid(format!("enrichers config error: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{GOLDEN_RULE, VALID_RULE, handler};

    #[tokio::test]
    async fn evaluate_events_detects_match() {
        let v = handler()
            .run_evaluate_events(EvaluateInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                events: Some(vec![json!({ "CommandLine": "cmd /c whoami" })]),
                events_path: None,
                pipelines: vec![],
                match_detail: Some("summary".to_string()),
                timestamp_fields: vec![],
                enrichers: None,
                enrichers_path: None,
            })
            .await
            .unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["summary"]["detection_matches"], 1);
        assert_eq!(v["results"][0]["event_index"], 0);
    }

    #[tokio::test]
    async fn evaluate_events_requires_events() {
        let err = handler()
            .run_evaluate_events(EvaluateInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                events: None,
                events_path: None,
                pipelines: vec![],
                match_detail: None,
                timestamp_fields: vec![],
                enrichers: None,
                enrichers_path: None,
            })
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("events"));
    }

    #[tokio::test]
    async fn evaluate_events_with_template_enricher() {
        let enrichers = r#"
enrichers:
  - id: runbook
    kind: detection
    type: template
    inject_field: runbook_url
    template: "https://wiki/${detection.rule.id}"
"#;
        let v = handler()
            .run_evaluate_events(EvaluateInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                events: Some(vec![json!({ "CommandLine": "cmd /c whoami" })]),
                events_path: None,
                pipelines: vec![],
                match_detail: None,
                timestamp_fields: vec![],
                enrichers: Some(enrichers.to_string()),
                enrichers_path: None,
            })
            .await
            .unwrap();
        assert_eq!(v["summary"]["enriched"], true);
        let enrichments = &v["results"][0]["result"]["enrichments"];
        assert_eq!(
            enrichments["runbook_url"],
            "https://wiki/8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a"
        );
    }

    #[tokio::test]
    async fn evaluate_events_invalid_enricher_config_errors() {
        let enrichers = r#"
enrichers:
  - id: bad
    kind: detection
    type: template
    inject_field: out
    template: "https://wiki/${correlation.rule.id}"
"#;
        let err = handler()
            .run_evaluate_events(EvaluateInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                events: Some(vec![json!({ "CommandLine": "cmd /c whoami" })]),
                events_path: None,
                pipelines: vec![],
                match_detail: None,
                timestamp_fields: vec![],
                enrichers: Some(enrichers.to_string()),
                enrichers_path: None,
            })
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("namespace"));
    }

    #[tokio::test]
    async fn golden_evaluate_events() {
        let v = handler()
            .run_evaluate_events(EvaluateInput {
                yaml: Some(GOLDEN_RULE.to_string()),
                path: None,
                events: Some(vec![
                    json!({ "CommandLine": "cmd /c whoami /priv" }),
                    json!({ "CommandLine": "ipconfig /all" }),
                ]),
                events_path: None,
                pipelines: vec![],
                match_detail: Some("summary".to_string()),
                timestamp_fields: vec![],
                enrichers: None,
                enrichers_path: None,
            })
            .await
            .unwrap();
        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!("evaluate_events", v);
        });
    }
}
