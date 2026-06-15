//! Expectations file: schema, validation, and rule-reference resolution.
//!
//! An expectations file declares, per rule, how many times it must fire over
//! the corpus (and optionally within a single corpus file). It is plain YAML
//! deserialized into typed structs; there is no hand-rolled parsing. Every
//! shape error here is a configuration error (exit code 3): a malformed file,
//! a conflicting bound, an ambiguous rule title, or a reference to a rule that
//! is not in the loaded ruleset.

use std::collections::HashMap;
use std::path::Path;

use rsigma_parser::SigmaCollection;
use serde::{Deserialize, Serialize};

/// Policy for a detection/correlation that fires without a covering
/// expectation (a potential false positive on a known-benign corpus).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum UnexpectedPolicy {
    /// Treat an unexpected fire as a failure: exit 1 and emit a JUnit failure
    /// for each unexpected rule.
    Fail,
    /// Report unexpected fires but leave the exit code unchanged (default).
    #[default]
    Warn,
    /// Do not surface unexpected fires on the human report or in the exit code.
    Ignore,
}

impl UnexpectedPolicy {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            UnexpectedPolicy::Fail => "fail",
            UnexpectedPolicy::Warn => "warn",
            UnexpectedPolicy::Ignore => "ignore",
        }
    }

    /// Parse the wire value used by `--unexpected` and `backtest.unexpected`.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "fail" => Some(UnexpectedPolicy::Fail),
            "warn" => Some(UnexpectedPolicy::Warn),
            "ignore" => Some(UnexpectedPolicy::Ignore),
            _ => None,
        }
    }
}

/// Raw expectations document as it appears on disk.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectationsFile {
    #[serde(default)]
    defaults: Defaults,
    #[serde(default)]
    expectations: Vec<RawExpectation>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Defaults {
    /// File-level default policy. `None` means the file did not set one, so a
    /// higher layer (CLI flag, config, or the built-in `warn`) decides.
    #[serde(default)]
    unexpected_detections: Option<UnexpectedPolicy>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExpectation {
    /// Rule id (preferred) or exact title.
    rule: String,
    /// Optional corpus-file scope: a path relative to the `--corpus` root.
    #[serde(default)]
    corpus: Option<String>,
    #[serde(default)]
    at_least: Option<u64>,
    #[serde(default)]
    at_most: Option<u64>,
    #[serde(default)]
    exactly: Option<u64>,
}

/// A validated fire-count bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bound {
    /// The rule must fire exactly this many times.
    Exactly(u64),
    /// The rule fire count must fall within `[at_least, at_most]`; either end
    /// may be open.
    Range {
        at_least: Option<u64>,
        at_most: Option<u64>,
    },
}

impl Bound {
    /// Whether `actual` satisfies this bound.
    pub(crate) fn satisfied_by(&self, actual: u64) -> bool {
        match self {
            Bound::Exactly(n) => actual == *n,
            Bound::Range { at_least, at_most } => {
                at_least.is_none_or(|l| actual >= l) && at_most.is_none_or(|u| actual <= u)
            }
        }
    }

    /// A short human description used in reports (e.g. `exactly 0`, `>= 3`,
    /// `3..=10`).
    pub(crate) fn describe(&self) -> String {
        match self {
            Bound::Exactly(n) => format!("exactly {n}"),
            Bound::Range {
                at_least: Some(l),
                at_most: Some(u),
            } => format!("{l}..={u}"),
            Bound::Range {
                at_least: Some(l),
                at_most: None,
            } => format!(">= {l}"),
            Bound::Range {
                at_least: None,
                at_most: Some(u),
            } => format!("<= {u}"),
            // Validation rejects an all-open range, so this is unreachable in
            // practice; describe it defensively rather than panicking.
            Bound::Range {
                at_least: None,
                at_most: None,
            } => "any".to_string(),
        }
    }
}

/// A fully resolved expectation, ready to diff against accumulated fires.
#[derive(Debug, Clone)]
pub(crate) struct Expectation {
    /// The original reference string from the file (id or title).
    pub reference: String,
    /// The resolved rule key: `rule_id` if the rule has one, else its title.
    /// This matches the key the accumulator derives from each result.
    pub rule_key: String,
    /// Optional corpus-file scope (path relative to the `--corpus` root).
    pub corpus: Option<String>,
    pub bound: Bound,
}

/// The resolved expectations plus the file-level default policy.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedExpectations {
    /// File-level `defaults.unexpected_detections`, if the file set one.
    pub file_default_policy: Option<UnexpectedPolicy>,
    pub expectations: Vec<Expectation>,
}

/// Read an expectations file and resolve every rule reference against the
/// loaded collection. Returns a configuration-error message on any problem.
pub(crate) fn load_and_resolve(
    path: &Path,
    collection: &SigmaCollection,
) -> Result<ResolvedExpectations, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read expectations file {}: {e}", path.display()))?;
    let file: ExpectationsFile = yaml_serde::from_str(&content)
        .map_err(|e| format!("could not parse expectations file {}: {e}", path.display()))?;
    resolve(file, collection)
}

/// Resolve a parsed expectations document against the collection.
fn resolve(
    file: ExpectationsFile,
    collection: &SigmaCollection,
) -> Result<ResolvedExpectations, String> {
    let index = RuleIndex::build(collection);

    let mut expectations = Vec::with_capacity(file.expectations.len());
    for raw in file.expectations {
        let bound = validate_bound(&raw)?;
        let rule_key = index.resolve(&raw.rule)?;
        expectations.push(Expectation {
            reference: raw.rule,
            rule_key,
            corpus: raw.corpus,
            bound,
        });
    }

    Ok(ResolvedExpectations {
        file_default_policy: file.defaults.unexpected_detections,
        expectations,
    })
}

/// Validate the count fields of a single raw expectation into a [`Bound`].
fn validate_bound(raw: &RawExpectation) -> Result<Bound, String> {
    match (raw.exactly, raw.at_least, raw.at_most) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => Err(format!(
            "expectation for '{}': `exactly` cannot be combined with `at_least`/`at_most`",
            raw.rule
        )),
        (Some(n), None, None) => Ok(Bound::Exactly(n)),
        (None, None, None) => Err(format!(
            "expectation for '{}': set one of `exactly`, `at_least`, or `at_most`",
            raw.rule
        )),
        (None, at_least, at_most) => {
            if let (Some(l), Some(u)) = (at_least, at_most)
                && l > u
            {
                return Err(format!(
                    "expectation for '{}': at_least ({l}) is greater than at_most ({u})",
                    raw.rule
                ));
            }
            Ok(Bound::Range { at_least, at_most })
        }
    }
}

/// Lookup tables from rule references to the accumulator key.
///
/// `by_id` maps an id directly to its key. `by_title` maps a title to the set
/// of keys that carry it, so a duplicate title resolves to an ambiguity error
/// rather than silently picking one.
struct RuleIndex {
    by_id: HashMap<String, String>,
    by_title: HashMap<String, Vec<String>>,
}

impl RuleIndex {
    fn build(collection: &SigmaCollection) -> Self {
        let mut by_id: HashMap<String, String> = HashMap::new();
        let mut by_title: HashMap<String, Vec<String>> = HashMap::new();

        let mut insert = |id: Option<&str>, title: &str| {
            let key = id.unwrap_or(title).to_string();
            if let Some(id) = id {
                by_id.insert(id.to_string(), key.clone());
            }
            by_title.entry(title.to_string()).or_default().push(key);
        };

        for rule in &collection.rules {
            insert(rule.id.as_deref(), &rule.title);
        }
        for corr in &collection.correlations {
            insert(corr.id.as_deref(), &corr.title);
        }

        Self { by_id, by_title }
    }

    /// Resolve a reference (id preferred, then title) to its accumulator key.
    fn resolve(&self, reference: &str) -> Result<String, String> {
        if let Some(key) = self.by_id.get(reference) {
            return Ok(key.clone());
        }
        match self.by_title.get(reference).map(Vec::as_slice) {
            Some([key]) => Ok(key.clone()),
            Some(keys) if keys.len() > 1 => Err(format!(
                "expectation references ambiguous title '{reference}' ({} rules share it); \
                 reference it by rule id instead",
                keys.len()
            )),
            _ => Err(format!(
                "expectation references rule '{reference}', which is not in the loaded ruleset"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::parse_sigma_yaml;

    const RULES: &str = r#"
title: Suspicious Whoami Execution
id: 5f0d7d3c-3aab-43fa-952f-8f7b2d966ee5
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
level: low
"#;

    fn collection() -> SigmaCollection {
        parse_sigma_yaml(RULES).expect("rules parse")
    }

    fn parse(yaml: &str) -> Result<ResolvedExpectations, String> {
        let file: ExpectationsFile = yaml_serde::from_str(yaml).map_err(|e| e.to_string())?;
        resolve(file, &collection())
    }

    #[test]
    fn resolves_by_id() {
        let r = parse(
            "expectations:\n  - rule: 5f0d7d3c-3aab-43fa-952f-8f7b2d966ee5\n    at_least: 1\n",
        )
        .expect("resolves");
        assert_eq!(r.expectations.len(), 1);
        assert_eq!(
            r.expectations[0].rule_key,
            "5f0d7d3c-3aab-43fa-952f-8f7b2d966ee5"
        );
        assert!(matches!(
            r.expectations[0].bound,
            Bound::Range {
                at_least: Some(1),
                at_most: None
            }
        ));
    }

    #[test]
    fn resolves_by_title_to_id_key() {
        // Referenced by title, but the key is the rule id because the rule has one.
        let r = parse("expectations:\n  - rule: Suspicious Whoami Execution\n    exactly: 0\n")
            .expect("resolves");
        assert_eq!(
            r.expectations[0].rule_key,
            "5f0d7d3c-3aab-43fa-952f-8f7b2d966ee5"
        );
        assert!(matches!(r.expectations[0].bound, Bound::Exactly(0)));
    }

    #[test]
    fn unknown_rule_is_error() {
        let err = parse("expectations:\n  - rule: No Such Rule\n    at_least: 1\n").unwrap_err();
        assert!(err.contains("not in the loaded ruleset"), "{err}");
    }

    #[test]
    fn conflicting_bounds_is_error() {
        let err = parse(
            "expectations:\n  - rule: 5f0d7d3c-3aab-43fa-952f-8f7b2d966ee5\n    exactly: 1\n    at_least: 2\n",
        )
        .unwrap_err();
        assert!(err.contains("cannot be combined"), "{err}");
    }

    #[test]
    fn empty_bounds_is_error() {
        let err =
            parse("expectations:\n  - rule: 5f0d7d3c-3aab-43fa-952f-8f7b2d966ee5\n").unwrap_err();
        assert!(err.contains("set one of"), "{err}");
    }

    #[test]
    fn inverted_range_is_error() {
        let err = parse(
            "expectations:\n  - rule: 5f0d7d3c-3aab-43fa-952f-8f7b2d966ee5\n    at_least: 10\n    at_most: 3\n",
        )
        .unwrap_err();
        assert!(err.contains("greater than"), "{err}");
    }

    #[test]
    fn bound_satisfaction() {
        assert!(Bound::Exactly(0).satisfied_by(0));
        assert!(!Bound::Exactly(0).satisfied_by(1));
        let range = Bound::Range {
            at_least: Some(3),
            at_most: Some(10),
        };
        assert!(!range.satisfied_by(2));
        assert!(range.satisfied_by(3));
        assert!(range.satisfied_by(10));
        assert!(!range.satisfied_by(11));
    }

    #[test]
    fn file_default_policy_is_captured() {
        let r = parse("defaults:\n  unexpected_detections: fail\nexpectations: []\n")
            .expect("resolves");
        assert_eq!(r.file_default_policy, Some(UnexpectedPolicy::Fail));
        let r = parse("expectations: []\n").expect("resolves");
        assert_eq!(r.file_default_policy, None);
    }
}
