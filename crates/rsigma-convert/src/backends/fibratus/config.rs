//! Runtime configuration for the Fibratus backend.
//!
//! Carries the knobs set by `rsigma backend convert -O <key>=<value>`
//! flags. Defaults are picked to produce output that matches the
//! upstream rules library style verbatim: no `action` block (Fibratus
//! generates an alert when the rule fires regardless), latest
//! `min-engine-version`, idiomatic macros on, full metadata copied.

use std::collections::HashMap;

/// Configurable knobs for the Fibratus backend.
#[derive(Debug, Clone)]
pub struct FibratusConfig {
    /// Actions appended to every rule envelope (`- name: <action>`).
    /// `None` omits the `action:` block entirely.
    pub action: Option<Vec<String>>,

    /// Value emitted in the `min-engine-version:` field of every rule.
    pub min_engine_version: String,

    /// Value emitted in the required `version:` field of every rule. This
    /// is the rule *content* version (a free-form string the upstream
    /// rules library writes as semver, e.g. `1.0.1`), distinct from
    /// `min-engine-version`. Sigma has no equivalent attribute, so it
    /// defaults to `1.0.0` and is overridable with `-O version=<value>`.
    /// The Fibratus loader rejects a rule that omits it.
    pub rule_version: String,

    /// Whether to rewrite recognized clauses in the generated filter
    /// expression into idiomatic Fibratus macros
    /// (`spawn_process`/`open_file`/...). Applied by `finalize_query` via the
    /// macro recognizer, which is a no-op on inputs that match no macros, so
    /// disabling it yields byte-equivalent output.
    pub use_macros: bool,

    /// Default logsource product to assume when a Sigma rule lacks
    /// `logsource.product`, used when matching the rule against the pipeline.
    pub default_logsource: String,

    /// Emit `description:` and `labels:` blocks. Disable to produce a
    /// minimal envelope (handy when the upstream loader has metadata
    /// from another source).
    pub emit_metadata: bool,

    /// Maximum number of repeated/distinct sequence slots generated when
    /// emulating `event_count` / `value_count`. Anything above this threshold
    /// returns `UnsupportedCorrelation` rather than ballooning the YAML.
    pub max_repeated_slots: u64,

    /// When converting `temporal` (any-order) correlation, emit
    /// `N!` permutation rules under the same group. Capped at
    /// `N <= 3` regardless of this flag.
    pub temporal_permute: bool,

    /// Force case-sensitive operators globally
    /// (`contains`/`startswith`/... instead of their `i`-prefixed
    /// cousins). Equivalent to setting `|cased` on every value.
    pub case_sensitive: bool,

    /// Correlation method selected via the `correlation_method` option
    /// (`sliding`/`session`), mirroring pySigma's `correlation_methods`.
    /// `None` falls back to each rule's own `window`. `tumbling` is not
    /// in the advertised list because Fibratus has no calendar-aligned
    /// bucket primitive and the corresponding window mode returns
    /// `UnsupportedCorrelation`.
    pub correlation_method: Option<String>,

    /// Default session gap in seconds, from the `gap` option (e.g.
    /// `gap=5m`). Used when a `session` window is requested via
    /// `correlation_method=session` and the rule does not declare its
    /// own `gap`. A rule's own `gap` always wins. Fibratus's `sequence`
    /// DSL has no native gap primitive, so the value is only used to
    /// derive the warning text the degraded-conversion path emits; the
    /// emitted query still relies on `maxspan` for the time-window cap.
    pub session_gap_secs: Option<u64>,
}

impl Default for FibratusConfig {
    fn default() -> Self {
        Self {
            action: None,
            min_engine_version: "3.0.0".to_string(),
            rule_version: "1.0.0".to_string(),
            use_macros: true,
            default_logsource: "windows".to_string(),
            emit_metadata: true,
            max_repeated_slots: 5,
            temporal_permute: false,
            case_sensitive: false,
            correlation_method: None,
            session_gap_secs: None,
        }
    }
}

impl FibratusConfig {
    /// Build a `FibratusConfig` from CLI-style `-O key=value` options.
    ///
    /// Unrecognized keys are silently ignored so forward-compatible
    /// flags can be added without breaking existing invocations
    /// (matches the convention `PostgresBackend::from_options` uses).
    pub fn from_options(options: &HashMap<String, String>) -> Self {
        let mut cfg = Self::default();
        if let Some(v) = options.get("action") {
            let actions: Vec<String> = v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            cfg.action = if actions.is_empty() {
                None
            } else {
                Some(actions)
            };
        }
        if let Some(v) = options.get("min_engine") {
            cfg.min_engine_version = v.clone();
        }
        if let Some(v) = options.get("version")
            && !v.trim().is_empty()
        {
            cfg.rule_version = v.clone();
        }
        if let Some(v) = options.get("use_macros") {
            cfg.use_macros = parse_bool(v).unwrap_or(true);
        }
        if let Some(v) = options.get("default_logsource") {
            cfg.default_logsource = v.clone();
        }
        if let Some(v) = options.get("emit_metadata") {
            cfg.emit_metadata = parse_bool(v).unwrap_or(true);
        }
        if let Some(v) = options.get("max_repeated_slots")
            && let Ok(n) = v.parse::<u64>()
        {
            cfg.max_repeated_slots = n;
        }
        if let Some(v) = options.get("temporal_permute") {
            cfg.temporal_permute = parse_bool(v).unwrap_or(false);
        }
        if let Some(v) = options.get("case_sensitive") {
            cfg.case_sensitive = parse_bool(v).unwrap_or(false);
        }
        if let Some(v) = options.get("correlation_method") {
            cfg.correlation_method = Some(v.clone());
        }
        if let Some(v) = options.get("gap") {
            // Invalid durations are ignored here for the same reason
            // PostgreSQL's `from_options` ignores them: the CLI
            // validates the format up front when the operator passes
            // -O gap=..., and per-rule `gap:` declarations are
            // validated by the parser.
            cfg.session_gap_secs = rsigma_parser::Timespan::parse(v).ok().map(|t| t.seconds);
        }
        cfg
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn defaults_match_documented_baseline() {
        let cfg = FibratusConfig::default();
        assert_eq!(cfg.action, None);
        assert_eq!(cfg.min_engine_version, "3.0.0");
        assert_eq!(cfg.rule_version, "1.0.0");
        assert!(cfg.use_macros);
        assert_eq!(cfg.default_logsource, "windows");
        assert!(cfg.emit_metadata);
        assert_eq!(cfg.max_repeated_slots, 5);
        assert!(!cfg.temporal_permute);
        assert!(!cfg.case_sensitive);
    }

    #[test]
    fn from_options_overrides_rule_version() {
        let cfg = FibratusConfig::from_options(&opts(&[("version", "2.3.1")]));
        assert_eq!(cfg.rule_version, "2.3.1");
        // An empty value keeps the required default rather than emitting a
        // blank `version:` the loader would reject.
        let cfg_empty = FibratusConfig::from_options(&opts(&[("version", "  ")]));
        assert_eq!(cfg_empty.rule_version, "1.0.0");
    }

    #[test]
    fn from_options_parses_actions() {
        let cfg = FibratusConfig::from_options(&opts(&[("action", "kill, isolate")]));
        assert_eq!(
            cfg.action,
            Some(vec!["kill".to_string(), "isolate".to_string()])
        );
    }

    #[test]
    fn from_options_empty_action_means_none() {
        let cfg = FibratusConfig::from_options(&opts(&[("action", ", ,")]));
        assert_eq!(cfg.action, None);
    }

    #[test]
    fn from_options_min_engine_and_macros() {
        let cfg = FibratusConfig::from_options(&opts(&[
            ("min_engine", "3.1.0"),
            ("use_macros", "false"),
        ]));
        assert_eq!(cfg.min_engine_version, "3.1.0");
        assert!(!cfg.use_macros);
    }

    #[test]
    fn from_options_ignores_unknown_keys() {
        let cfg = FibratusConfig::from_options(&opts(&[("unknown", "x")]));
        assert_eq!(cfg.min_engine_version, "3.0.0");
    }

    #[test]
    fn from_options_max_slots() {
        let cfg = FibratusConfig::from_options(&opts(&[("max_repeated_slots", "10")]));
        assert_eq!(cfg.max_repeated_slots, 10);
    }
}
