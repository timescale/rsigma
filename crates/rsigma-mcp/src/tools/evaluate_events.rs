//! The `evaluate_events` tool: evaluate JSON events against Sigma rules
//! (detections and correlations), with optional enrichment.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_eval::{CorrelationConfig, CorrelationEngine, Engine, EvaluationResult, JsonEvent};
use rsigma_runtime::{
    EnrichersFile, EnrichmentPipeline, build_enrichers, env_references, load_enrichers_file,
};
use serde_json::{Value, json};

use crate::input::resolve_confined_path;

use super::RsigmaMcp;
use super::shared::{invalid, json_result, parse_match_detail, to_value};

/// Enricher types `evaluate_events` builds in-process.
const MCP_ENRICHER_TYPES: &[&str] = &["template"];

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
    /// Emit matches for rules referenced by correlations, including
    /// correlations that feed another correlation.
    #[serde(default)]
    pub emit_detections: bool,
    /// Inline enrichers config (YAML/JSON) applied to results before returning.
    /// Mutually exclusive with `enrichers_path`. Only `template` enrichers with
    /// `${detection.*}` or `${correlation.*}` references are supported here;
    /// `${ENV_VAR}` references are refused. Use the daemon for `lookup`, `http`,
    /// `command`, and `stix`.
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
            let mut config = CorrelationConfig {
                emit_detections: input.emit_detections,
                ..Default::default()
            };
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
    /// Only the types in [`MCP_ENRICHER_TYPES`] are accepted.
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
                let path = resolve_confined_path(p, self.root())?;
                Some(load_enrichers_file(&path).map_err(|e| invalid(e.to_string()))?)
            }
        };

        // `command` and `http` would let any MCP caller run local programs or
        // reach internal network endpoints as the server process.
        if let Some(cfg) = file
            .iter()
            .flat_map(|f| &f.enrichers)
            .find(|cfg| !MCP_ENRICHER_TYPES.contains(&cfg.type_name.as_str()))
        {
            return Err(invalid(format!(
                "enricher '{}': type '{}' is not available over MCP (supported: {}); use the daemon for it",
                cfg.id,
                cfg.type_name,
                MCP_ENRICHER_TYPES.join(", ")
            )));
        }

        // `${ENV_VAR}` renders from the server's environment, which would hand
        // its secrets (API keys, tokens) back to the MCP caller in the result.
        for cfg in file.iter().flat_map(|f| &f.enrichers) {
            let names = cfg
                .template
                .as_deref()
                .map(env_references)
                .unwrap_or_default();
            if !names.is_empty() {
                let refs: Vec<String> = names.iter().map(|n| format!("${{{n}}}")).collect();
                return Err(invalid(format!(
                    "enricher '{}': environment variable references are not available over MCP (found {}); use ${{detection.*}} or ${{correlation.*}} references, or the daemon",
                    cfg.id,
                    refs.join(", ")
                )));
            }
        }

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
                emit_detections: false,
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
                emit_detections: false,
                enrichers: None,
                enrichers_path: None,
            })
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("events"));
    }

    #[tokio::test]
    async fn evaluate_events_suppresses_correlation_inputs_unless_requested() {
        let yaml = r#"
title: Base
name: base
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Count
correlation:
    type: event_count
    rules: [base]
    group-by: [Host]
    timespan: 1m
    condition:
        gte: 2
"#;
        let input = |emit_detections| EvaluateInput {
            yaml: Some(yaml.to_string()),
            path: None,
            events: Some(vec![
                json!({"EventID": 1, "Host": "h1", "timestamp": "2025-01-01T00:00:00Z"}),
                json!({"EventID": 1, "Host": "h1", "timestamp": "2025-01-01T00:00:01Z"}),
            ]),
            events_path: None,
            pipelines: vec![],
            match_detail: None,
            timestamp_fields: vec![],
            emit_detections,
            enrichers: None,
            enrichers_path: None,
        };

        let default = handler().run_evaluate_events(input(false)).await.unwrap();
        assert_eq!(default["summary"]["detection_matches"], 0);
        assert_eq!(default["summary"]["correlation_matches"], 1);

        let emitted = handler().run_evaluate_events(input(true)).await.unwrap();
        assert_eq!(emitted["summary"]["detection_matches"], 2);
        assert_eq!(emitted["summary"]["correlation_matches"], 1);
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
                emit_detections: false,
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
                emit_detections: false,
                enrichers: Some(enrichers.to_string()),
                enrichers_path: None,
            })
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("namespace"));
    }

    fn eval_with_enrichers(enrichers: &str) -> EvaluateInput {
        EvaluateInput {
            yaml: Some(VALID_RULE.to_string()),
            path: None,
            events: Some(vec![json!({ "CommandLine": "cmd /c whoami" })]),
            events_path: None,
            pipelines: vec![],
            match_detail: None,
            timestamp_fields: vec![],
            emit_detections: false,
            enrichers: Some(enrichers.to_string()),
            enrichers_path: None,
        }
    }

    #[tokio::test]
    async fn evaluate_events_rejects_command_enricher() {
        let enrichers = r#"
enrichers:
  - id: exec
    kind: detection
    type: command
    inject_field: out
    output: raw
    command: ["echo", "executed"]
"#;
        let err = handler()
            .run_evaluate_events(eval_with_enrichers(enrichers))
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("not available over MCP"));
    }

    #[tokio::test]
    async fn evaluate_events_rejects_http_enricher() {
        let enrichers = r#"
enrichers:
  - id: fetch
    kind: detection
    type: http
    inject_field: out
    url: "http://169.254.169.254/latest/meta-data/"
"#;
        let err = handler()
            .run_evaluate_events(eval_with_enrichers(enrichers))
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("not available over MCP"));
    }

    #[tokio::test]
    async fn evaluate_events_rejects_env_reference_in_template() {
        let enrichers = r#"
enrichers:
  - id: leak
    kind: detection
    type: template
    inject_field: out
    template: "${detection.rule.id}:${PATH}:${HOME}"
"#;
        let err = handler()
            .run_evaluate_events(eval_with_enrichers(enrichers))
            .await
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("environment variable references are not available over MCP"),
            "{msg}"
        );
        assert!(msg.contains("${PATH}, ${HOME}"), "{msg}");
    }

    #[tokio::test]
    async fn evaluate_events_rejects_env_reference_from_enrichers_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("enrichers.yaml"),
            r#"
enrichers:
  - id: leak
    kind: detection
    type: template
    inject_field: out
    template: "${HOME}"
"#,
        )
        .unwrap();
        let err = RsigmaMcp::new(Some(dir.path().to_path_buf()), Default::default(), false)
            .run_evaluate_events(EvaluateInput {
                enrichers: None,
                enrichers_path: Some("enrichers.yaml".to_string()),
                ..eval_with_enrichers("")
            })
            .await
            .unwrap_err();
        assert!(
            format!("{err:?}")
                .contains("environment variable references are not available over MCP")
        );
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
                emit_detections: false,
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
