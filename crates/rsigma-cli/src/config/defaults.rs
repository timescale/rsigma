//! The single source of truth for every config default.
//!
//! These constants and [`defaults_partial`] are the lowest layer of the
//! resolution stack. Once the daemon/eval flags are repointed at these
//! constants (in the command-wiring phase), there is exactly one place a
//! default is written, and a drift-guard test pins clap to these values.

use super::schema::{
    ApiPartial, CorrelationPartial, DaemonPartial, EnginePartial, EvalPartial, GlobalPartial,
    InputPartial, OutputPartial, RsigmaConfigPartial, StatePartial,
};

pub(crate) const CONFIG_VERSION: u32 = 1;
pub(crate) const LOG_FORMAT: &str = "text";
pub(crate) const API_ADDR: &str = "0.0.0.0:9090";
pub(crate) const INPUT_SOURCE: &str = "stdin";
pub(crate) const INPUT_FORMAT: &str = "auto";
pub(crate) const SYSLOG_TZ: &str = "+00:00";
pub(crate) const SYSLOG_STRIP_BOM: bool = true;
pub(crate) const BUFFER_SIZE: usize = 10_000;
pub(crate) const BATCH_SIZE: usize = 1;
pub(crate) const DRAIN_TIMEOUT: u64 = 5;
pub(crate) const CORRELATION_ACTION: &str = "alert";
pub(crate) const CORRELATION_EVENT_MODE: &str = "none";
pub(crate) const MAX_CORRELATION_EVENTS: usize = 10;
/// Default hard cap on `(correlation, group-key)` state entries. Must match
/// `CorrelationConfig::default().max_state_entries` in rsigma-eval; a
/// drift-guard test pins the two together.
pub(crate) const MAX_STATE_ENTRIES: usize = 100_000;
pub(crate) const TIMESTAMP_FALLBACK: &str = "wallclock";
pub(crate) const STATE_SAVE_INTERVAL: u64 = 30;
pub(crate) const OBSERVE_FIELDS_MAX_KEYS: usize = 10_000;
pub(crate) const STDOUT_SINK: &str = "stdout";
/// Default HTTP egress policy applied to dynamic-source and enrichment HTTP
/// clients. `default` blocks link-local and known cloud-metadata addresses
/// (the classic SSRF targets) while leaving loopback and RFC1918 private
/// addresses reachable so internal threat-intel APIs keep working.
pub(crate) const EGRESS_POLICY: &str = "default";
/// Default match-detail verbosity for detection output. `off` preserves the
/// historical `{ field, value }` wire shape.
pub(crate) const MATCH_DETAIL: &str = "off";
/// Default minimum TLS version for the daemon API listener. Only consumed by
/// the `--tls-min-version` flag, so it is gated on the same `daemon-tls`
/// feature to avoid a dead-code warning in builds without it.
#[cfg(feature = "daemon-tls")]
pub(crate) const TLS_MIN_VERSION: &str = "1.3";

/// A fully-populated partial holding every compiled default.
///
/// Fields that are genuinely required at runtime (e.g. `daemon.rules`) stay
/// `None`: they have no default and must be supplied by a file, env, or flag.
pub(crate) fn defaults_partial() -> RsigmaConfigPartial {
    RsigmaConfigPartial {
        version: Some(CONFIG_VERSION),
        global: Some(GlobalPartial {
            log_format: Some(LOG_FORMAT.to_string()),
            color: None,
            output_format: None,
        }),
        daemon: Some(DaemonPartial {
            rules: None,
            pipelines: Some(Vec::new()),
            sources: Some(Vec::new()),
            enrichers: None,
            api: Some(ApiPartial {
                addr: Some(API_ADDR.to_string()),
                tls: None,
            }),
            input: Some(InputPartial {
                source: Some(INPUT_SOURCE.to_string()),
                format: Some(INPUT_FORMAT.to_string()),
                syslog_tz: Some(SYSLOG_TZ.to_string()),
                syslog_strip_bom: Some(SYSLOG_STRIP_BOM),
                buffer_size: Some(BUFFER_SIZE),
                batch_size: Some(BATCH_SIZE),
                jq: None,
                jsonpath: None,
            }),
            output: Some(OutputPartial {
                sinks: Some(vec![STDOUT_SINK.to_string()]),
                dlq: None,
                drain_timeout: Some(DRAIN_TIMEOUT),
                include_event: Some(false),
                pretty: Some(false),
            }),
            correlation: Some(CorrelationPartial {
                suppress: None,
                action: Some(CORRELATION_ACTION.to_string()),
                event_mode: Some(CORRELATION_EVENT_MODE.to_string()),
                max_events: Some(MAX_CORRELATION_EVENTS),
                max_state_entries: Some(MAX_STATE_ENTRIES),
                max_group_entries: None,
                timestamp_fields: None,
                timestamp_fallback: Some(TIMESTAMP_FALLBACK.to_string()),
                no_detections: Some(false),
            }),
            state: Some(StatePartial {
                db: None,
                save_interval: Some(STATE_SAVE_INTERVAL),
            }),
            engine: Some(EnginePartial {
                bloom_prefilter: Some(false),
                bloom_max_bytes: None,
                observe_fields: Some(false),
                observe_fields_max_keys: Some(OBSERVE_FIELDS_MAX_KEYS),
                allow_remote_include: Some(false),
                cross_rule_ac: Some(false),
                match_detail: Some(MATCH_DETAIL.to_string()),
                egress_policy: Some(EGRESS_POLICY.to_string()),
            }),
            nats: None,
        }),
        eval: Some(EvalPartial {
            rules: None,
            pipelines: Some(Vec::new()),
            input_format: Some(INPUT_FORMAT.to_string()),
            syslog_tz: Some(SYSLOG_TZ.to_string()),
            syslog_strip_bom: Some(SYSLOG_STRIP_BOM),
            fail_on_detection: Some(false),
        }),
        // The `mcp` section has no compiled defaults: stdio is the default
        // transport, and the lint-config / rules-dir roots have no default.
        mcp: None,
    }
}
