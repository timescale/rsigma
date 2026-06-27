//! Risk-score sourcing for a firing detection.
//!
//! A single integer score is resolved per result by a fixed precedence so an
//! operator can reason about it without reading code:
//!
//! 1. An explicit per-rule score: the `rsigma.risk_score` custom attribute
//!    (settable in a processing pipeline via `SetCustomAttribute`). A number or
//!    a numeric string wins outright.
//! 2. A `tag_scores` map, scoring by tag (exact or a `prefix.*` wildcard such as
//!    `attack.*`). When more than one entry matches, the `reducer` combines them
//!    (`sum` or `max`).
//! 3. A `level_scores` map, mapping the severity to a number.
//! 4. A `default_score` for everything else.

use std::collections::HashMap;

use rsigma_eval::EvaluationResult;
use rsigma_parser::Level;

/// The default custom-attribute key carrying an explicit per-rule score.
pub const DEFAULT_SCORE_ATTRIBUTE: &str = "rsigma.risk_score";

/// How multiple matching `tag_scores` entries combine into one score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Reducer {
    /// Add every matching tag score together (default).
    #[default]
    Sum,
    /// Take the highest matching tag score.
    Max,
}

/// A single `tag_scores` key: a literal tag or a `prefix.*` wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TagPattern {
    Exact(String),
    Prefix(String),
}

impl TagPattern {
    fn parse(raw: &str) -> Self {
        if let Some(prefix) = raw.strip_suffix(".*") {
            TagPattern::Prefix(format!("{prefix}."))
        } else {
            TagPattern::Exact(raw.to_string())
        }
    }

    fn matches(&self, tag: &str) -> bool {
        match self {
            TagPattern::Exact(t) => tag == t,
            TagPattern::Prefix(p) => tag.starts_with(p.as_str()),
        }
    }
}

/// Validated scoring configuration.
#[derive(Debug, Clone)]
pub struct ScoreConfig {
    /// Custom-attribute key holding an explicit per-rule score.
    attribute: String,
    /// Tag patterns and their scores, applied when no explicit score is set.
    tag_scores: Vec<(TagPattern, i64)>,
    /// How multiple matching tag scores combine.
    reducer: Reducer,
    /// Per-severity scores, applied when no tag score matches.
    level_scores: HashMap<Level, i64>,
    /// Fallback score when nothing else applies.
    default_score: i64,
}

impl ScoreConfig {
    /// Build a scoring config from raw parts.
    pub fn new(
        attribute: Option<String>,
        tag_scores: HashMap<String, i64>,
        reducer: Reducer,
        level_scores: HashMap<Level, i64>,
        default_score: i64,
    ) -> Self {
        let tag_scores = tag_scores
            .into_iter()
            .map(|(raw, score)| (TagPattern::parse(&raw), score))
            .collect();
        ScoreConfig {
            attribute: attribute.unwrap_or_else(|| DEFAULT_SCORE_ATTRIBUTE.to_string()),
            tag_scores,
            reducer,
            level_scores,
            default_score,
        }
    }

    /// Resolve the risk score for a result, following the documented precedence.
    pub fn resolve(&self, result: &EvaluationResult) -> i64 {
        if let Some(value) = result.header.custom_attributes.get(&self.attribute)
            && let Some(score) = value_as_i64(value)
        {
            return score;
        }

        let mut matched: Vec<i64> = Vec::new();
        for tag in &result.header.tags {
            for (pattern, score) in &self.tag_scores {
                if pattern.matches(tag) {
                    matched.push(*score);
                }
            }
        }
        if !matched.is_empty() {
            return match self.reducer {
                Reducer::Sum => matched.iter().sum(),
                Reducer::Max => matched.into_iter().max().unwrap_or(self.default_score),
            };
        }

        if let Some(level) = result.header.level
            && let Some(score) = self.level_scores.get(&level)
        {
            return *score;
        }

        self.default_score
    }
}

/// Coerce a JSON value into an integer score: a JSON number (rounded) or a
/// numeric string. Anything else yields `None` so the next precedence tier wins.
fn value_as_i64(value: &serde_json::Value) -> Option<i64> {
    match value {
        serde_json::Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.round() as i64)),
        serde_json::Value::String(s) => s
            .trim()
            .parse::<i64>()
            .ok()
            .or_else(|| s.trim().parse::<f64>().ok().map(|f| f.round() as i64)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::{DetectionBody, FieldMatch, ResultBody, RuleHeader};
    use std::sync::Arc;

    fn result(
        level: Option<Level>,
        tags: Vec<&str>,
        attrs: &[(&str, serde_json::Value)],
    ) -> EvaluationResult {
        let mut custom = HashMap::new();
        for (k, v) in attrs {
            custom.insert(k.to_string(), v.clone());
        }
        EvaluationResult {
            header: RuleHeader {
                rule_title: "t".to_string(),
                rule_id: Some("r".to_string()),
                level,
                tags: tags.into_iter().map(str::to_string).collect(),
                custom_attributes: Arc::new(custom),
                enrichments: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![FieldMatch::new("f", serde_json::json!("v"))],
                event: None,
            }),
        }
    }

    fn config() -> ScoreConfig {
        let mut tag_scores = HashMap::new();
        tag_scores.insert("attack.*".to_string(), 10);
        tag_scores.insert("crown-jewel".to_string(), 50);
        let mut level_scores = HashMap::new();
        level_scores.insert(Level::High, 40);
        level_scores.insert(Level::Critical, 80);
        ScoreConfig::new(None, tag_scores, Reducer::Sum, level_scores, 1)
    }

    #[test]
    fn explicit_attribute_wins() {
        let r = result(
            Some(Level::Critical),
            vec!["attack.t1059"],
            &[("rsigma.risk_score", serde_json::json!(99))],
        );
        assert_eq!(config().resolve(&r), 99);
    }

    #[test]
    fn explicit_attribute_accepts_string() {
        let r = result(
            None,
            vec![],
            &[("rsigma.risk_score", serde_json::json!("42"))],
        );
        assert_eq!(config().resolve(&r), 42);
    }

    #[test]
    fn tag_scores_sum_over_matches() {
        let r = result(
            Some(Level::Critical),
            vec!["attack.t1059", "crown-jewel"],
            &[],
        );
        // attack.* (10) + crown-jewel (50) = 60, beating the level score.
        assert_eq!(config().resolve(&r), 60);
    }

    #[test]
    fn tag_scores_max_reducer() {
        let mut tag_scores = HashMap::new();
        tag_scores.insert("attack.*".to_string(), 10);
        tag_scores.insert("crown-jewel".to_string(), 50);
        let cfg = ScoreConfig::new(None, tag_scores, Reducer::Max, HashMap::new(), 1);
        let r = result(None, vec!["attack.t1059", "crown-jewel"], &[]);
        assert_eq!(cfg.resolve(&r), 50);
    }

    #[test]
    fn falls_back_to_level_then_default() {
        let by_level = result(Some(Level::High), vec![], &[]);
        assert_eq!(config().resolve(&by_level), 40);
        let by_default = result(Some(Level::Low), vec![], &[]);
        assert_eq!(config().resolve(&by_default), 1);
    }
}
