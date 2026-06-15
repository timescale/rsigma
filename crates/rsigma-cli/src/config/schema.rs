//! Deserializable, layer-friendly representation of `rsigma.yaml`.
//!
//! Every field is optional so that a config file may set only the keys it
//! cares about. Multiple files (system, user, project) are deserialized into
//! these `*Partial` structs and folded together with [`Merge`], where a
//! higher-precedence layer wins on a per-field basis.
//!
//! Secret-bearing daemon settings (NATS credentials/token/password/nkey, the
//! TLS key password) are deliberately absent: they stay env/flag-only so that
//! a version-controlled config file never carries secrets.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Fold a higher-precedence layer (`over`) onto a lower one (`self`).
pub(crate) trait Merge {
    /// Returns the merged value: `over` wins on every field it sets.
    fn merge(self, over: Self) -> Self;
}

/// Merge two optional sub-sections, recursing when both are present.
fn merge_opt<T: Merge>(base: Option<T>, over: Option<T>) -> Option<T> {
    match (base, over) {
        (Some(base), Some(over)) => Some(base.merge(over)),
        (base, over) => over.or(base),
    }
}

/// Top-level layered configuration. All sections optional.
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct RsigmaConfigPartial {
    /// Config schema version, reserved for future migrations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// Settings shared across all commands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global: Option<GlobalPartial>,
    /// `rsigma engine daemon` settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon: Option<DaemonPartial>,
    /// `rsigma engine eval` settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval: Option<EvalPartial>,
    /// `rsigma rule backtest` settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backtest: Option<BacktestPartial>,
    /// `rsigma mcp serve` settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpPartial>,
}

impl Merge for RsigmaConfigPartial {
    fn merge(self, over: Self) -> Self {
        Self {
            version: over.version.or(self.version),
            global: merge_opt(self.global, over.global),
            daemon: merge_opt(self.daemon, over.daemon),
            eval: merge_opt(self.eval, over.eval),
            backtest: merge_opt(self.backtest, over.backtest),
            mcp: merge_opt(self.mcp, over.mcp),
        }
    }
}

/// Cross-command settings.
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct GlobalPartial {
    /// Diagnostic log format on stderr: `text` or `json` (maps to `--log-format`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_format: Option<String>,
    /// Color policy: `auto`, `always`, `never` (maps to `--color`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Default structured output format: `json`, `ndjson`, `table`, `csv`,
    /// `tsv` (maps to `--output-format`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<String>,
}

impl Merge for GlobalPartial {
    fn merge(self, over: Self) -> Self {
        Self {
            log_format: over.log_format.or(self.log_format),
            color: over.color.or(self.color),
            output_format: over.output_format.or(self.output_format),
        }
    }
}

/// Daemon settings.
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct DaemonPartial {
    /// Path to a Sigma rule file or directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<PathBuf>,
    /// Builtin pipeline names or YAML file paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipelines: Option<Vec<PathBuf>>,
    /// External dynamic-source files or directories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<PathBuf>>,
    /// Post-evaluation enricher config file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrichers: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<ApiPartial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<InputPartial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<OutputPartial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<CorrelationPartial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StatePartial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<EnginePartial>,
    /// Non-secret NATS knobs. Ignored unless built with `daemon-nats`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nats: Option<NatsPartial>,
}

impl Merge for DaemonPartial {
    fn merge(self, over: Self) -> Self {
        Self {
            rules: over.rules.or(self.rules),
            pipelines: over.pipelines.or(self.pipelines),
            sources: over.sources.or(self.sources),
            enrichers: over.enrichers.or(self.enrichers),
            api: merge_opt(self.api, over.api),
            input: merge_opt(self.input, over.input),
            output: merge_opt(self.output, over.output),
            correlation: merge_opt(self.correlation, over.correlation),
            state: merge_opt(self.state, over.state),
            engine: merge_opt(self.engine, over.engine),
            nats: merge_opt(self.nats, over.nats),
        }
    }
}

/// API listener settings.
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct ApiPartial {
    /// Bind address for health, metrics, and the HTTP/OTLP API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    /// TLS settings. Ignored unless built with `daemon-tls`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsPartial>,
}

impl Merge for ApiPartial {
    fn merge(self, over: Self) -> Self {
        Self {
            addr: over.addr.or(self.addr),
            tls: merge_opt(self.tls, over.tls),
        }
    }
}

/// Server-side TLS settings (no key password; that stays env-only).
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct TlsPartial {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ca: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_plaintext: Option<bool>,
}

impl Merge for TlsPartial {
    fn merge(self, over: Self) -> Self {
        Self {
            cert: over.cert.or(self.cert),
            key: over.key.or(self.key),
            client_ca: over.client_ca.or(self.client_ca),
            min_version: over.min_version.or(self.min_version),
            allow_plaintext: over.allow_plaintext.or(self.allow_plaintext),
        }
    }
}

/// Event input settings.
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct InputPartial {
    /// Event source: `stdin`, `http`, `nats://host:port/subject`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Log format: `auto`, `json`, `syslog`, `plain`, `logfmt`, `cef`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Default timezone offset for RFC 3164 syslog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syslog_tz: Option<String>,
    /// Strip a leading UTF-8 BOM from RFC 5424 syslog messages (default true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syslog_strip_bom: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<usize>,
    /// jq filter to extract the event payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,
    /// JSONPath query to extract the event payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jsonpath: Option<String>,
}

impl Merge for InputPartial {
    fn merge(self, over: Self) -> Self {
        Self {
            source: over.source.or(self.source),
            format: over.format.or(self.format),
            syslog_tz: over.syslog_tz.or(self.syslog_tz),
            syslog_strip_bom: over.syslog_strip_bom.or(self.syslog_strip_bom),
            buffer_size: over.buffer_size.or(self.buffer_size),
            batch_size: over.batch_size.or(self.batch_size),
            jq: over.jq.or(self.jq),
            jsonpath: over.jsonpath.or(self.jsonpath),
        }
    }
}

/// Detection output settings.
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct OutputPartial {
    /// Detection sinks: `stdout`, `file://path`, `nats://host:port/subject`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sinks: Option<Vec<String>>,
    /// Dead-letter queue for events that fail processing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dlq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_event: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pretty: Option<bool>,
}

impl Merge for OutputPartial {
    fn merge(self, over: Self) -> Self {
        Self {
            sinks: over.sinks.or(self.sinks),
            dlq: over.dlq.or(self.dlq),
            drain_timeout: over.drain_timeout.or(self.drain_timeout),
            include_event: over.include_event.or(self.include_event),
            pretty: over.pretty.or(self.pretty),
        }
    }
}

/// Correlation settings.
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct CorrelationPartial {
    /// Suppression window for correlation alerts (e.g. `5m`, `1h`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppress: Option<String>,
    /// Action after a correlation fires: `alert` or `reset`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Correlation event inclusion: `none`, `full`, `refs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_events: Option<usize>,
    /// Hard cap on `(correlation, group-key)` state entries before
    /// stalest-first eviction (default 100,000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_state_entries: Option<usize>,
    /// Cap on retained entries within a single group's window state.
    /// Unset means unbounded (the historical behavior).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_group_entries: Option<usize>,
    /// Extra event field names for timestamp extraction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_fields: Option<Vec<String>>,
    /// Behavior when no timestamp is found: `wallclock` or `skip`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_fallback: Option<String>,
    /// Suppress detection output for correlation-only rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_detections: Option<bool>,
}

impl Merge for CorrelationPartial {
    fn merge(self, over: Self) -> Self {
        Self {
            suppress: over.suppress.or(self.suppress),
            action: over.action.or(self.action),
            event_mode: over.event_mode.or(self.event_mode),
            max_events: over.max_events.or(self.max_events),
            max_state_entries: over.max_state_entries.or(self.max_state_entries),
            max_group_entries: over.max_group_entries.or(self.max_group_entries),
            timestamp_fields: over.timestamp_fields.or(self.timestamp_fields),
            timestamp_fallback: over.timestamp_fallback.or(self.timestamp_fallback),
            no_detections: over.no_detections.or(self.no_detections),
        }
    }
}

/// Correlation state persistence settings.
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct StatePartial {
    /// SQLite database for persisting correlation state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub save_interval: Option<u64>,
}

impl Merge for StatePartial {
    fn merge(self, over: Self) -> Self {
        Self {
            db: over.db.or(self.db),
            save_interval: over.save_interval.or(self.save_interval),
        }
    }
}

/// Matching-engine tuning settings.
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct EnginePartial {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bloom_prefilter: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bloom_max_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observe_fields: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observe_fields_max_keys: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_remote_include: Option<bool>,
    /// Cross-rule Aho-Corasick pre-filter. Ignored unless built with `daachorse-index`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_rule_ac: Option<bool>,
    /// Match-detail verbosity for detection output: `off` (default),
    /// `summary`, or `full`. Controls how much per-field match information
    /// is attached to detection results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_detail: Option<String>,
    /// HTTP egress policy applied to dynamic-source and enrichment HTTP clients:
    /// `default` (block link-local + cloud metadata), `strict` (also block
    /// loopback + RFC1918 private), or `permissive` (allow everything).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_policy: Option<String>,
}

impl Merge for EnginePartial {
    fn merge(self, over: Self) -> Self {
        Self {
            bloom_prefilter: over.bloom_prefilter.or(self.bloom_prefilter),
            bloom_max_bytes: over.bloom_max_bytes.or(self.bloom_max_bytes),
            observe_fields: over.observe_fields.or(self.observe_fields),
            observe_fields_max_keys: over
                .observe_fields_max_keys
                .or(self.observe_fields_max_keys),
            allow_remote_include: over.allow_remote_include.or(self.allow_remote_include),
            cross_rule_ac: over.cross_rule_ac.or(self.cross_rule_ac),
            match_detail: over.match_detail.or(self.match_detail),
            egress_policy: over.egress_policy.or(self.egress_policy),
        }
    }
}

/// Non-secret NATS knobs. Secrets stay env-only.
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct NatsPartial {
    /// Shared durable consumer name for load balancing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer_group: Option<String>,
}

impl Merge for NatsPartial {
    fn merge(self, over: Self) -> Self {
        Self {
            consumer_group: over.consumer_group.or(self.consumer_group),
        }
    }
}

/// `eval` settings.
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct EvalPartial {
    /// Default rules path for `rsigma engine eval`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipelines: Option<Vec<PathBuf>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syslog_tz: Option<String>,
    /// Strip a leading UTF-8 BOM from RFC 5424 syslog messages (default true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syslog_strip_bom: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_on_detection: Option<bool>,
}

impl Merge for EvalPartial {
    fn merge(self, over: Self) -> Self {
        Self {
            rules: over.rules.or(self.rules),
            pipelines: over.pipelines.or(self.pipelines),
            input_format: over.input_format.or(self.input_format),
            syslog_tz: over.syslog_tz.or(self.syslog_tz),
            syslog_strip_bom: over.syslog_strip_bom.or(self.syslog_strip_bom),
            fail_on_detection: over.fail_on_detection.or(self.fail_on_detection),
        }
    }
}

/// `rsigma rule backtest` settings.
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct BacktestPartial {
    /// Default rules path for `rsigma rule backtest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<PathBuf>,
    /// Event corpus file(s) or directory(ies), walked recursively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus: Option<Vec<PathBuf>>,
    /// Expectations YAML file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expectations: Option<PathBuf>,
    /// Policy for unexpected fires: `fail`, `warn`, or `ignore`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unexpected: Option<String>,
    /// Builtin pipeline names or YAML file paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipelines: Option<Vec<PathBuf>>,
    /// Input log format for non-NDJSON corpus files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_format: Option<String>,
    /// Default timezone offset for RFC 3164 syslog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syslog_tz: Option<String>,
    /// Strip a leading UTF-8 BOM from RFC 5424 syslog messages (default true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syslog_strip_bom: Option<bool>,
}

impl Merge for BacktestPartial {
    fn merge(self, over: Self) -> Self {
        Self {
            rules: over.rules.or(self.rules),
            corpus: over.corpus.or(self.corpus),
            expectations: over.expectations.or(self.expectations),
            unexpected: over.unexpected.or(self.unexpected),
            pipelines: over.pipelines.or(self.pipelines),
            input_format: over.input_format.or(self.input_format),
            syslog_tz: over.syslog_tz.or(self.syslog_tz),
            syslog_strip_bom: over.syslog_strip_bom.or(self.syslog_strip_bom),
        }
    }
}

/// `mcp serve` settings. The auth token is deliberately absent: secrets stay
/// flag/env-only (`--auth-token` / `RSIGMA_MCP_AUTH_TOKEN`).
#[derive(Debug, Default, Clone, Deserialize, Serialize, JsonSchema)]
pub(crate) struct McpPartial {
    /// Bind address for the Streamable HTTP transport (maps to `--http`).
    /// Unset means stdio.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_addr: Option<String>,
    /// Lint config file applied by the `lint_rules` tool (maps to `--lint-config`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lint_config: Option<PathBuf>,
    /// Default root for relative path-based tool calls (maps to `--rules-dir`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_dir: Option<PathBuf>,
}

impl Merge for McpPartial {
    fn merge(self, over: Self) -> Self {
        Self {
            http_addr: over.http_addr.or(self.http_addr),
            lint_config: over.lint_config.or(self.lint_config),
            rules_dir: over.rules_dir.or(self.rules_dir),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_prefers_higher_layer_per_field() {
        let base = RsigmaConfigPartial {
            version: Some(1),
            daemon: Some(DaemonPartial {
                rules: Some(PathBuf::from("/etc/rsigma/rules")),
                api: Some(ApiPartial {
                    addr: Some("0.0.0.0:9090".into()),
                    tls: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let over = RsigmaConfigPartial {
            daemon: Some(DaemonPartial {
                // overrides addr but leaves rules untouched
                api: Some(ApiPartial {
                    addr: Some("127.0.0.1:8080".into()),
                    tls: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let merged = base.merge(over);
        let daemon = merged.daemon.expect("daemon section");
        assert_eq!(daemon.rules, Some(PathBuf::from("/etc/rsigma/rules")));
        assert_eq!(
            daemon.api.expect("api section").addr,
            Some("127.0.0.1:8080".into())
        );
        assert_eq!(merged.version, Some(1));
    }

    #[test]
    fn mcp_section_parses_and_merges() {
        let base: RsigmaConfigPartial = yaml_serde::from_str(
            "mcp:\n  http_addr: 127.0.0.1:9100\n  rules_dir: /etc/rsigma/rules\n",
        )
        .expect("parses mcp section");
        let over: RsigmaConfigPartial =
            yaml_serde::from_str("mcp:\n  rules_dir: /override/rules\n").expect("parses override");
        let merged = base.merge(over);
        let mcp = merged.mcp.expect("mcp section");
        // higher layer wins per-field; untouched fields are preserved
        assert_eq!(mcp.http_addr.as_deref(), Some("127.0.0.1:9100"));
        assert_eq!(mcp.rules_dir, Some(PathBuf::from("/override/rules")));
    }

    #[test]
    fn merge_keeps_base_when_over_is_none() {
        let base = RsigmaConfigPartial {
            global: Some(GlobalPartial {
                log_format: Some("json".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let merged = base.merge(RsigmaConfigPartial::default());
        assert_eq!(
            merged.global.expect("global").log_format,
            Some("json".into())
        );
    }
}
