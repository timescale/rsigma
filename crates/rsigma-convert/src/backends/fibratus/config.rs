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

    /// Whether to walk the condition AST and rewrite recognized
    /// sub-trees into idiomatic Fibratus macros
    /// (`spawn_process`/`open_file`/...). Phase 3 wires the recognition;
    /// the knob is present from Phase 0 so output formats stay stable
    /// when the recognition pass lands.
    pub use_macros: bool,

    /// Default logsource product to assume when a Sigma rule lacks
    /// `logsource.product`. Used by Phase 2's pipeline matching.
    pub default_logsource: String,

    /// Emit `description:` and `labels:` blocks. Disable to produce a
    /// minimal envelope (handy when the upstream loader has metadata
    /// from another source).
    pub emit_metadata: bool,

    /// Maximum number of repeated/distinct sequence slots Phase 4 will
    /// generate when emulating `event_count` / `value_count`. Anything
    /// above this threshold returns `UnsupportedCorrelation` rather
    /// than ballooning the YAML.
    pub max_repeated_slots: u64,

    /// When converting `temporal` (any-order) correlation, emit
    /// `N!` permutation rules under the same group. Capped at
    /// `N <= 3` regardless of this flag.
    pub temporal_permute: bool,

    /// Force case-sensitive operators globally
    /// (`contains`/`startswith`/... instead of their `i`-prefixed
    /// cousins). Equivalent to setting `|cased` on every value.
    pub case_sensitive: bool,
}

impl Default for FibratusConfig {
    fn default() -> Self {
        Self {
            action: None,
            min_engine_version: "3.0.0".to_string(),
            use_macros: true,
            default_logsource: "windows".to_string(),
            emit_metadata: true,
            max_repeated_slots: 5,
            temporal_permute: false,
            case_sensitive: false,
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
        assert!(cfg.use_macros);
        assert_eq!(cfg.default_logsource, "windows");
        assert!(cfg.emit_metadata);
        assert_eq!(cfg.max_repeated_slots, 5);
        assert!(!cfg.temporal_permute);
        assert!(!cfg.case_sensitive);
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
