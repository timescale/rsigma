//! The `evaluate_events` tool: evaluate JSON events against Sigma rules
//! (detections and correlations), with optional enrichment.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_eval::{
    CorrelationConfig, CorrelationEngine, Engine, EvaluationResult, JsonEvent, RuleFieldSet,
    RulesetEngines, RulesetUnit, UnitEngine,
};
use rsigma_runtime::{
    EnricherConfig, EnrichersFile, EnrichmentPipeline, build_enrichers, env_references,
    load_enrichers_file,
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
    /// Inline Sigma YAML. Mutually exclusive with `path` and `ruleset`.
    #[serde(default)]
    pub yaml: Option<String>,
    /// Path to a Sigma file or directory. Mutually exclusive with `yaml` and
    /// `ruleset`.
    #[serde(default)]
    pub path: Option<String>,
    /// Named ruleset from the server's rsigma.yaml. Mutually exclusive with
    /// `yaml`, `path`, and `rulesets`.
    #[serde(default)]
    pub ruleset: Option<String>,
    /// Several named rulesets evaluated side by side. Mutually exclusive with
    /// `yaml`, `path`, and `ruleset`. Names must be distinct and defined in the
    /// server's rsigma.yaml.
    #[serde(default)]
    pub rulesets: Option<Vec<String>>,
    /// Inline events as a JSON array of objects. Mutually exclusive with `events_path`.
    #[serde(default)]
    pub events: Option<Vec<Value>>,
    /// Path to an NDJSON file of events. Mutually exclusive with `events`.
    #[serde(default)]
    pub events_path: Option<String>,
    /// Processing pipelines (builtin names or file paths).
    /// When set, these replace the pipelines of a `ruleset`.
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
        description = "Evaluate JSON events against Sigma rules and return matches. Detection-only rules use the stateless engine; collections with correlations use the stateful correlation engine. Provide exactly one of inline `yaml`, a file/directory `path`, a named `ruleset`, or several `rulesets` from the server's configuration; events via an inline `events` JSON array or an NDJSON `events_path`. Optional `pipelines` and `match_detail` (off/summary/full)."
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
        let selected = usize::from(input.yaml.is_some())
            + usize::from(input.path.is_some())
            + usize::from(input.ruleset.is_some())
            + usize::from(input.rulesets.is_some());
        if selected != 1 {
            return Err(invalid(
                "provide exactly one of `yaml`, `path`, `ruleset`, or `rulesets`",
            ));
        }
        if let Some(names) = &input.rulesets {
            if names.is_empty() {
                return Err(invalid("`rulesets` must name at least one ruleset"));
            }
            let mut seen = std::collections::HashSet::new();
            if let Some(duplicate) = names.iter().find(|name| !seen.insert(name.as_str())) {
                return Err(invalid(format!("duplicate ruleset name '{duplicate}'")));
            }
            if names.len() > self.rulesets.len() {
                return Err(invalid(format!(
                    "`rulesets` names {} rulesets, but the server defines {}",
                    names.len(),
                    self.rulesets.len()
                )));
            }
        }

        let events = self.load_events(input.events, input.events_path.as_deref())?;
        let detail = parse_match_detail(input.match_detail.as_deref())?;
        let enrichment =
            self.build_enrichment(input.enrichers.as_deref(), input.enrichers_path.as_deref())?;

        let mut results: Vec<Value> = Vec::new();
        let mut detection_matches = 0usize;
        let mut correlation_matches = 0usize;
        let mut ruleset_matches: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let mut ruleset_summary: Option<Vec<Value>> = None;

        let json_events: Vec<JsonEvent> = events.iter().map(JsonEvent::borrow).collect();
        let refs: Vec<&JsonEvent> = json_events.iter().collect();

        let batches: Vec<Vec<EvaluationResult>> = if let Some(names) = &input.rulesets {
            let mut units = Vec::new();
            let mut stats = Vec::new();
            for name in names {
                let (collection, spec_pipelines) = self.resolve_ruleset(name)?;
                let pipeline_specs = if input.pipelines.is_empty() {
                    spec_pipelines
                } else {
                    input.pipelines.clone()
                };
                let pipelines = self.load_pipelines(&pipeline_specs)?;
                let field_set = RuleFieldSet::collect(&collection, &pipelines, true);
                let detection_rules = collection.rules.len();
                let correlation_rules = collection.correlations.len();
                let engine = if collection.correlations.is_empty() {
                    let mut engine = Engine::new();
                    engine.set_match_detail(detail);
                    for pipeline in &pipelines {
                        engine.add_pipeline(pipeline.clone());
                    }
                    engine
                        .add_collection(&collection)
                        .map_err(|e| invalid(format!("rule compile error: {e}")))?;
                    UnitEngine::Detection(Box::new(engine))
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
                    for pipeline in &pipelines {
                        engine.add_pipeline(pipeline.clone());
                    }
                    engine
                        .add_collection(&collection)
                        .map_err(|e| invalid(format!("rule compile error: {e}")))?;
                    UnitEngine::Correlation(Box::new(engine))
                };
                stats.push((name.clone(), detection_rules, correlation_rules));
                units.push(RulesetUnit {
                    name: std::sync::Arc::from(name.as_str()),
                    when_schemas: Vec::new(),
                    tenants: Vec::new(),
                    engine,
                    field_set,
                });
            }
            let mut engines = RulesetEngines::new(units, None)
                .map_err(|e| invalid(format!("ruleset setup error: {e}")))?;
            let batches = engines.process_batch(&refs);
            ruleset_summary = Some(
                stats
                    .into_iter()
                    .map(|(name, detection_rules, correlation_rules)| {
                        json!({
                            "name": name,
                            "detection_rules": detection_rules,
                            "correlation_rules": correlation_rules,
                            "matches": 0,
                        })
                    })
                    .collect(),
            );
            batches
        } else {
            let (collection, ruleset_pipelines) = self.load_collection(
                input.yaml.as_deref(),
                input.path.as_deref(),
                input.ruleset.as_deref(),
            )?;
            let pipeline_specs = if input.pipelines.is_empty() {
                ruleset_pipelines
            } else {
                input.pipelines
            };
            let pipelines = self.load_pipelines(&pipeline_specs)?;
            if collection.correlations.is_empty() {
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
            }
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
                if let Some(name) = &r.header.ruleset {
                    *ruleset_matches.entry(name.to_string()).or_default() += 1;
                }
                results.push(json!({ "event_index": idx, "result": to_value(r) }));
            }
        }

        let mut envelope = json!({
            "ok": true,
            "summary": {
                "events_evaluated": events.len(),
                "detection_matches": detection_matches,
                "correlation_matches": correlation_matches,
                "enriched": enrichment.is_some(),
            },
            "results": results,
        });
        if let Some(mut summary) = ruleset_summary {
            for entry in &mut summary {
                let name = entry["name"].as_str().unwrap_or_default();
                entry["matches"] = json!(ruleset_matches.get(name).copied().unwrap_or(0));
            }
            envelope["rulesets"] = json!(summary);
        }
        Ok(envelope)
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
            let mut seen = std::collections::HashSet::new();
            let names: Vec<String> = templated_fields(cfg)
                .flat_map(env_references)
                .filter(|n| seen.insert(n.clone()))
                .collect();
            if !names.is_empty() {
                let mut refs: Vec<String> = names
                    .iter()
                    .take(MAX_LISTED_ENV_REFS)
                    .map(|n| format!("${{{n}}}"))
                    .collect();
                if names.len() > MAX_LISTED_ENV_REFS {
                    refs.push(format!("and {} more", names.len() - MAX_LISTED_ENV_REFS));
                }
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

/// How many `${ENV_VAR}` names an error lists before summarizing the rest.
const MAX_LISTED_ENV_REFS: usize = 5;

/// Every string field of an enricher config that renders `${...}` references.
fn templated_fields(cfg: &EnricherConfig) -> impl Iterator<Item = &str> {
    [
        cfg.template.as_deref(),
        cfg.url.as_deref(),
        cfg.body.as_deref(),
        cfg.extract.as_deref(),
        cfg.stix_id.as_deref(),
        cfg.text_search.as_deref(),
        cfg.key.as_deref(),
    ]
    .into_iter()
    .flatten()
    .chain(cfg.headers.values().map(String::as_str))
    .chain(cfg.command.iter().map(String::as_str))
    .chain(cfg.env.values().map(String::as_str))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::tools::{GOLDEN_RULE, VALID_RULE, handler, ruleset_handler, ruleset_spec};

    #[tokio::test]
    async fn evaluate_events_detects_match() {
        let v = handler()
            .run_evaluate_events(EvaluateInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                ruleset: None,
                rulesets: None,
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
                ruleset: None,
                rulesets: None,
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
            ruleset: None,
            rulesets: None,
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
                ruleset: None,
                rulesets: None,
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
                ruleset: None,
                rulesets: None,
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
            ruleset: None,
            rulesets: None,
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
    async fn evaluate_events_checks_every_enricher_and_field() {
        let enrichers = r#"
enrichers:
  - id: clean
    kind: detection
    type: template
    inject_field: out
    template: "${detection.rule.id}"
  - id: leak
    kind: correlation
    type: template
    inject_field: out
    template: "${correlation.type}"
    headers:
      X-Leak: "${HOME}"
"#;
        let err = handler()
            .run_evaluate_events(eval_with_enrichers(enrichers))
            .await
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("enricher 'leak'"), "{msg}");
        assert!(msg.contains("${HOME}"), "{msg}");
    }

    #[tokio::test]
    async fn evaluate_events_caps_the_listed_env_references() {
        let template: String = (0..8).map(|i| format!("${{V{i}}}")).collect();
        let enrichers = format!(
            "enrichers:\n  - id: leak\n    kind: detection\n    type: template\n    inject_field: out\n    template: \"{template}\"\n"
        );
        let err = handler()
            .run_evaluate_events(eval_with_enrichers(&enrichers))
            .await
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("${V0}, ${V1}, ${V2}, ${V3}, ${V4}, and 3 more"),
            "{msg}"
        );
        assert!(!msg.contains("${V5}"), "{msg}");
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
    async fn evaluate_events_uses_ruleset_pipelines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rule.yml"), VALID_RULE).unwrap();
        let rulesets = BTreeMap::from([(
            "base".to_string(),
            ruleset_spec(dir.path(), &["rule.yml"], &["ecs_windows"]),
        )]);
        let value = ruleset_handler(Some(dir.path().to_path_buf()), rulesets)
            .run_evaluate_events(EvaluateInput {
                yaml: None,
                path: None,
                ruleset: Some("base".to_string()),
                rulesets: None,
                events: Some(vec![json!({ "process.command_line": "cmd /c whoami" })]),
                events_path: None,
                pipelines: vec![],
                match_detail: None,
                timestamp_fields: vec![],
                emit_detections: false,
                enrichers: None,
                enrichers_path: None,
            })
            .await
            .unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["summary"]["detection_matches"], 1);
    }

    #[tokio::test]
    async fn evaluate_events_rejects_ruleset_and_path() {
        let error = handler()
            .run_evaluate_events(EvaluateInput {
                yaml: None,
                path: Some("rule.yml".to_string()),
                ruleset: Some("base".to_string()),
                rulesets: None,
                events: Some(vec![json!({})]),
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
        assert!(format!("{error:?}").contains("exactly one"));
    }

    #[tokio::test]
    async fn golden_evaluate_events() {
        let v = handler()
            .run_evaluate_events(EvaluateInput {
                yaml: Some(GOLDEN_RULE.to_string()),
                path: None,
                ruleset: None,
                rulesets: None,
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

    #[tokio::test]
    async fn evaluate_events_explicit_pipelines_replace_the_ruleset_pipelines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rule.yml"), VALID_RULE).unwrap();
        std::fs::write(
            dir.path().join("noop.yml"),
            "name: noop\ntransformations: []\n",
        )
        .unwrap();
        let rulesets = BTreeMap::from([(
            "base".to_string(),
            ruleset_spec(dir.path(), &["rule.yml"], &["ecs_windows"]),
        )]);
        let value = ruleset_handler(Some(dir.path().to_path_buf()), rulesets)
            .run_evaluate_events(EvaluateInput {
                yaml: None,
                path: None,
                ruleset: Some("base".to_string()),
                rulesets: None,
                events: Some(vec![json!({ "CommandLine": "cmd /c whoami" })]),
                events_path: None,
                pipelines: vec![dir.path().join("noop.yml").display().to_string()],
                match_detail: None,
                timestamp_fields: vec![],
                emit_detections: false,
                enrichers: None,
                enrichers_path: None,
            })
            .await
            .unwrap();
        assert_eq!(value["ok"], true, "{value}");
        assert_eq!(value["summary"]["detection_matches"], 1, "{value}");
    }

    #[tokio::test]
    async fn evaluate_events_runs_several_rulesets() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rule.yml"), VALID_RULE).unwrap();
        let rulesets = BTreeMap::from([
            (
                "a".to_string(),
                ruleset_spec(dir.path(), &["rule.yml"], &[]),
            ),
            (
                "b".to_string(),
                ruleset_spec(dir.path(), &["rule.yml"], &[]),
            ),
        ]);
        let value = ruleset_handler(Some(dir.path().to_path_buf()), rulesets)
            .run_evaluate_events(EvaluateInput {
                yaml: None,
                path: None,
                ruleset: None,
                rulesets: Some(vec!["a".to_string(), "b".to_string()]),
                events: Some(vec![json!({ "CommandLine": "cmd /c whoami" })]),
                events_path: None,
                pipelines: vec![],
                match_detail: None,
                timestamp_fields: vec![],
                emit_detections: false,
                enrichers: None,
                enrichers_path: None,
            })
            .await
            .unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["summary"]["detection_matches"], 2);
        let results = value["results"].as_array().unwrap();
        assert_eq!(results[0]["result"]["ruleset"], "a");
        assert_eq!(results[1]["result"]["ruleset"], "b");
        let summary = value["rulesets"].as_array().unwrap();
        assert_eq!(summary[0]["name"], "a");
        assert_eq!(summary[0]["matches"], 1);
        assert_eq!(summary[1]["matches"], 1);
    }

    #[tokio::test]
    async fn evaluate_events_rejects_invalid_ruleset_lists() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rule.yml"), VALID_RULE).unwrap();
        let rulesets = BTreeMap::from([(
            "a".to_string(),
            ruleset_spec(dir.path(), &["rule.yml"], &[]),
        )]);
        let server = ruleset_handler(Some(dir.path().to_path_buf()), rulesets);
        let input = |names: Vec<&str>| EvaluateInput {
            yaml: None,
            path: None,
            ruleset: None,
            rulesets: Some(names.into_iter().map(str::to_string).collect()),
            events: Some(vec![json!({})]),
            events_path: None,
            pipelines: vec![],
            match_detail: None,
            timestamp_fields: vec![],
            emit_detections: false,
            enrichers: None,
            enrichers_path: None,
        };
        let cases = [
            (
                EvaluateInput {
                    yaml: Some(VALID_RULE.to_string()),
                    ..input(vec!["a"])
                },
                "exactly one",
            ),
            (
                EvaluateInput {
                    path: Some("rule.yml".to_string()),
                    ..input(vec!["a"])
                },
                "exactly one",
            ),
            (
                EvaluateInput {
                    ruleset: Some("a".to_string()),
                    ..input(vec!["a"])
                },
                "exactly one",
            ),
            (input(vec![]), "at least one ruleset"),
            (input(vec!["a", "a"]), "duplicate ruleset name 'a'"),
            (
                input(vec!["a", "b"]),
                "names 2 rulesets, but the server defines 1",
            ),
        ];
        for (input, expected) in cases {
            let error = server.run_evaluate_events(input).await.unwrap_err();
            assert!(
                error.message.contains(expected),
                "expected {expected:?}, got {:?}",
                error.message
            );
        }
    }

    #[tokio::test]
    async fn evaluate_events_rejects_an_unknown_ruleset_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rule.yml"), VALID_RULE).unwrap();
        let rulesets = BTreeMap::from([(
            "a".to_string(),
            ruleset_spec(dir.path(), &["rule.yml"], &[]),
        )]);
        let error = ruleset_handler(Some(dir.path().to_path_buf()), rulesets)
            .run_evaluate_events(EvaluateInput {
                yaml: None,
                path: None,
                ruleset: None,
                rulesets: Some(vec!["nope".to_string()]),
                events: Some(vec![json!({})]),
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
        assert!(format!("{error:?}").contains("unknown ruleset 'nope'"));
    }
}
