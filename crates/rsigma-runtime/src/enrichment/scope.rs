//! Scope filtering for enrichers.
//!
//! Each enricher carries an optional [`Scope`] that decides, on a per-result
//! basis, whether the enricher should fire. Scope is applied **after** the
//! kind-vs-body filter and **before** [`Enricher::enrich`](super::Enricher::enrich)
//! runs, so an enricher pays no I/O cost for results it would have ignored
//! anyway.
//!
//! Three independent axes:
//!
//! - `rules`: rule-id exact match or rule-title glob (via [`globset`]).
//! - `tags`: tag-set intersection with prefix wildcard support
//!   (`attack.*` matches `attack.t1059.001`).
//! - `levels`: severity membership.
//!
//! All three axes are **AND-ed** when configured: an enricher fires only when
//! every populated axis matches. Empty axes are not filters (an empty
//! `tags: []` does not exclude every result; it means "no tag constraint").
//! No `scope.kinds` axis exists — the top-level `kind` field on the enricher
//! already gates which result-body variant it sees.

use globset::{Glob, GlobMatcher};
use rsigma_eval::EvaluationResult;
use rsigma_parser::Level;

/// Scope filter applied per result before [`Enricher::enrich`](super::Enricher::enrich).
///
/// Constructed once at config load and then read concurrently from the
/// pipeline driver, so all internal state is immutable after `Scope::new`.
#[derive(Debug, Default)]
pub struct Scope {
    rule_ids: Vec<String>,
    rule_title_globs: Vec<GlobMatcher>,
    tag_globs: Vec<TagPattern>,
    levels: Vec<Level>,
}

/// A single tag-pattern entry. Either a literal tag (case-sensitive
/// equality) or a prefix-wildcard pattern like `attack.*`.
#[derive(Debug)]
enum TagPattern {
    Exact(String),
    Prefix(String),
}

impl Scope {
    /// Build a scope from raw config values.
    ///
    /// `rules` mixes exact rule IDs (anything without glob metacharacters)
    /// and rule-title globs (anything containing `*`, `?`, or `[`).
    /// `tags` mixes exact tags and prefix-wildcard patterns ending in
    /// `.*` (e.g. `attack.*`). `levels` is a list of severity strings
    /// as understood by `<rsigma_parser::Level as FromStr>::from_str`.
    ///
    /// Returns an error if any glob fails to compile or any level string
    /// fails to parse, so the daemon refuses to start with a malformed
    /// scope rather than silently mismatching at runtime.
    pub fn new(rules: Vec<String>, tags: Vec<String>, levels: Vec<String>) -> Result<Self, String> {
        let mut rule_ids = Vec::new();
        let mut rule_title_globs = Vec::new();
        for r in rules {
            if has_glob_meta(&r) {
                let glob =
                    Glob::new(&r).map_err(|e| format!("invalid scope.rules glob '{r}': {e}"))?;
                rule_title_globs.push(glob.compile_matcher());
            } else {
                rule_ids.push(r);
            }
        }

        let mut tag_globs = Vec::new();
        for t in tags {
            if let Some(prefix) = t.strip_suffix(".*") {
                tag_globs.push(TagPattern::Prefix(prefix.to_string()));
            } else if t.ends_with('*') {
                // Bare `*` suffix without `.` separator is allowed too.
                let prefix = t.trim_end_matches('*').to_string();
                tag_globs.push(TagPattern::Prefix(prefix));
            } else {
                tag_globs.push(TagPattern::Exact(t));
            }
        }

        let mut parsed_levels = Vec::new();
        for l in levels {
            let lvl: Level = l
                .parse()
                .map_err(|_| format!("invalid scope.levels entry '{l}'"))?;
            parsed_levels.push(lvl);
        }

        Ok(Self {
            rule_ids,
            rule_title_globs,
            tag_globs,
            levels: parsed_levels,
        })
    }

    /// True when no axis is populated. The pipeline can fast-path past
    /// empty scopes without inspecting the result.
    pub fn is_unrestricted(&self) -> bool {
        self.rule_ids.is_empty()
            && self.rule_title_globs.is_empty()
            && self.tag_globs.is_empty()
            && self.levels.is_empty()
    }

    /// True when this scope admits the given result.
    ///
    /// Each populated axis must match; empty axes are skipped. An
    /// unrestricted scope ([`Scope::is_unrestricted`]) admits every result.
    pub fn matches(&self, result: &EvaluationResult) -> bool {
        if self.is_unrestricted() {
            return true;
        }

        if !self.rule_ids.is_empty() || !self.rule_title_globs.is_empty() {
            let by_id = result
                .header
                .rule_id
                .as_deref()
                .is_some_and(|id| self.rule_ids.iter().any(|r| r == id));
            let by_title = self
                .rule_title_globs
                .iter()
                .any(|g| g.is_match(&result.header.rule_title));
            if !(by_id || by_title) {
                return false;
            }
        }

        if !self.tag_globs.is_empty() {
            let any_match = result
                .header
                .tags
                .iter()
                .any(|t| self.tag_globs.iter().any(|p| p.matches(t)));
            if !any_match {
                return false;
            }
        }

        if !self.levels.is_empty() {
            match result.header.level {
                Some(lvl) if self.levels.contains(&lvl) => {}
                _ => return false,
            }
        }

        true
    }
}

impl TagPattern {
    fn matches(&self, tag: &str) -> bool {
        match self {
            TagPattern::Exact(t) => t == tag,
            TagPattern::Prefix(p) => tag.starts_with(p),
        }
    }
}

/// Cheap probe for glob metacharacters. Anything containing `*`, `?`, or
/// `[` is treated as a glob; otherwise the entry is a literal rule ID.
fn has_glob_meta(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::{DetectionBody, EvaluationResult, ResultBody, RuleHeader};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn det(
        title: &str,
        id: Option<&str>,
        tags: Vec<&str>,
        level: Option<Level>,
    ) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: title.to_string(),
                rule_id: id.map(|s| s.to_string()),
                level,
                tags: tags.into_iter().map(|s| s.to_string()).collect(),
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![],
                event: None,
            }),
        }
    }

    #[test]
    fn unrestricted_scope_matches_anything() {
        let scope = Scope::default();
        assert!(scope.is_unrestricted());
        assert!(scope.matches(&det("Anything", None, vec![], None)));
    }

    #[test]
    fn rule_id_exact_match() {
        let scope = Scope::new(vec!["abc-123".to_string()], vec![], vec![]).unwrap();
        assert!(scope.matches(&det("X", Some("abc-123"), vec![], None)));
        assert!(!scope.matches(&det("X", Some("abc-124"), vec![], None)));
        assert!(!scope.matches(&det("X", None, vec![], None)));
    }

    #[test]
    fn rule_title_glob_match() {
        let scope = Scope::new(vec!["Suspicious *".to_string()], vec![], vec![]).unwrap();
        assert!(scope.matches(&det("Suspicious PowerShell", None, vec![], None)));
        assert!(!scope.matches(&det("Innocent thing", None, vec![], None)));
    }

    #[test]
    fn tag_prefix_wildcard() {
        let scope = Scope::new(vec![], vec!["attack.*".to_string()], vec![]).unwrap();
        assert!(scope.matches(&det("X", None, vec!["attack.t1059.001"], None)));
        assert!(!scope.matches(&det("X", None, vec!["other.tag"], None)));
    }

    #[test]
    fn tag_exact_match_intersection() {
        let scope = Scope::new(
            vec![],
            vec!["attack.execution".to_string(), "exfil".to_string()],
            vec![],
        )
        .unwrap();
        assert!(scope.matches(&det("X", None, vec!["attack.execution"], None)));
        assert!(scope.matches(&det("X", None, vec!["exfil"], None)));
        assert!(!scope.matches(&det("X", None, vec!["attack.execution.123"], None)));
    }

    #[test]
    fn levels_membership() {
        let scope = Scope::new(
            vec![],
            vec![],
            vec!["high".to_string(), "critical".to_string()],
        )
        .unwrap();
        assert!(scope.matches(&det("X", None, vec![], Some(Level::High))));
        assert!(scope.matches(&det("X", None, vec![], Some(Level::Critical))));
        assert!(!scope.matches(&det("X", None, vec![], Some(Level::Medium))));
        assert!(!scope.matches(&det("X", None, vec![], None)));
    }

    #[test]
    fn axes_and_combine() {
        let scope = Scope::new(
            vec![],
            vec!["attack.*".to_string()],
            vec!["high".to_string()],
        )
        .unwrap();
        // Both match
        assert!(scope.matches(&det("X", None, vec!["attack.t1059"], Some(Level::High))));
        // Tag matches, level does not
        assert!(!scope.matches(&det("X", None, vec!["attack.t1059"], Some(Level::Low))));
        // Level matches, tag does not
        assert!(!scope.matches(&det("X", None, vec!["other"], Some(Level::High))));
    }

    #[test]
    fn invalid_glob_rejected_at_construction() {
        let err = Scope::new(vec!["[unclosed".to_string()], vec![], vec![]).unwrap_err();
        assert!(err.contains("invalid scope.rules glob"));
    }

    #[test]
    fn invalid_level_rejected() {
        let err = Scope::new(vec![], vec![], vec!["super-high".to_string()]).unwrap_err();
        assert!(err.contains("invalid scope.levels"));
    }
}
