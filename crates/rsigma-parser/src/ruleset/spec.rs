//! Types and static validation for named rulesets declared in `rsigma.yaml`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ast::{Level, Status};

/// A named rule set: sources, selectors, dependency policy, overlays, and
/// pipelines.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RulesetSpec {
    /// Free-form description shown by `ruleset list`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Rule files or directories, processed in declaration order.
    pub sources: Vec<PathBuf>,
    /// Selectors that admit candidates. An empty list admits everything.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<RuleSelector>,
    /// Selectors that reject candidates. Exclusion always wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<RuleSelector>,
    /// Policy for unresolved correlation references: `error`, `include`, or
    /// `drop`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<String>,
    /// Metadata overlays, inline or loaded from files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overlays: Vec<OverlayEntry>,
    /// Policy for overlays that match no kept rule: `error` or `warn`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_overlays: Option<String>,
    /// Builtin pipeline names or YAML file paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pipelines: Vec<String>,
    /// Default output directory for `ruleset build`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<PathBuf>,
    /// Unknown keys, rejected at validation time.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

/// A metadata selector. Every key that is set must match; values within a key
/// are alternatives.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RuleSelector {
    /// Rule ids, case-insensitive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub id: Vec<String>,
    /// Rule `name` values, exact.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub name: Vec<String>,
    /// Title globs, case-insensitive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub title: Vec<String>,
    /// Tag globs, case-insensitive; a document matches when any tag does.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Levels, in their exact lowercase Sigma spelling.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub level: Vec<String>,
    /// Statuses, in their exact lowercase Sigma spelling.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status: Vec<String>,
    /// Document kinds: `detection`, `correlation`, or `filter`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kind: Vec<String>,
    /// Globs over the file path relative to its source root; `*` does not
    /// cross `/`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
    /// Logsource fields; a correlation matches through the rules it references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logsource: Option<LogsourceSelector>,
    /// Unknown keys, rejected at validation time.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

/// A logsource selector with exact, case-insensitive values.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct LogsourceSelector {
    /// Logsource products.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub product: Vec<String>,
    /// Logsource categories.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub category: Vec<String>,
    /// Logsource services.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<String>,
    /// Unknown keys, rejected at validation time.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

/// One overlay entry: either inline patches for an id, or a file or directory
/// of overlay files.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct OverlayEntry {
    /// Id or name of the document an inline entry patches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Overlay file holding a list of inline entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    /// Directory of overlay files, applied in sorted order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<PathBuf>,
    /// Keys to replace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<OverlayPatch>,
    /// Lists to extend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub append: Option<OverlayPatch>,
    /// Unknown keys, rejected at validation time.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

/// Metadata keys an overlay may set or append.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct OverlayPatch {
    /// Replacement level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Replacement status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Replacement description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Replacement author.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Tags to set or append; appended tags are deduplicated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// References to set or append.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    /// False positives to set or append.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub falsepositives: Option<Vec<String>>,
    /// Fields to set or append.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
    /// Custom attributes merged per key; `null` under `set` removes a key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_attributes: Option<BTreeMap<String, serde_json::Value>>,
    /// Unknown keys, rejected at validation time.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

/// Policy for unresolved correlation references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyPolicy {
    /// Fail resolution.
    Error,
    /// Pull the referenced rule in.
    Include,
    /// Drop the correlation, with a warning.
    Drop,
}

impl DependencyPolicy {
    /// Parse the config spelling.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "error" => Ok(Self::Error),
            "include" => Ok(Self::Include),
            "drop" => Ok(Self::Drop),
            other => Err(format!(
                "invalid dependencies policy '{other}'; expected error, include, or drop"
            )),
        }
    }

    /// The config spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Include => "include",
            Self::Drop => "drop",
        }
    }
}

/// Policy for overlays that match no kept rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleOverlayPolicy {
    /// Fail resolution.
    Error,
    /// Skip the overlay, with a warning.
    Warn,
}

impl StaleOverlayPolicy {
    /// Parse the config spelling.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            other => Err(format!(
                "invalid stale_overlays policy '{other}'; expected error or warn"
            )),
        }
    }

    /// The config spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
        }
    }
}

/// Ruleset names become metric labels, file names, and CLI arguments.
pub fn validate_ruleset_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => {
            return Err(format!(
                "invalid ruleset name '{name}': must start with a-z"
            ));
        }
    }
    if name.len() > 64 {
        return Err(format!(
            "invalid ruleset name '{name}': at most 64 characters"
        ));
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
        return Err(format!(
            "invalid ruleset name '{name}': use only a-z, 0-9, '_' and '-'"
        ));
    }
    Ok(())
}

pub(crate) const SET_KEYS: &[&str] = &[
    "level",
    "status",
    "description",
    "author",
    "tags",
    "references",
    "falsepositives",
    "fields",
    "custom_attributes",
];
pub(crate) const APPEND_KEYS: &[&str] = &[
    "tags",
    "references",
    "falsepositives",
    "fields",
    "custom_attributes",
];

/// Static validation of a ruleset spec: names, unknown keys, empty selectors,
/// enum values, globs, and overlay entry shapes.
pub fn validate_spec(name: &str, spec: &RulesetSpec) -> Vec<String> {
    let mut problems = Vec::new();

    if let Err(e) = validate_ruleset_name(name) {
        problems.push(e);
    }
    if spec.sources.is_empty() {
        problems.push(format!("ruleset '{name}': sources must not be empty"));
    }
    if let Some(policy) = &spec.dependencies
        && let Err(e) = DependencyPolicy::parse(policy)
    {
        problems.push(format!("ruleset '{name}': {e}"));
    }
    if let Some(policy) = &spec.stale_overlays
        && let Err(e) = StaleOverlayPolicy::parse(policy)
    {
        problems.push(format!("ruleset '{name}': {e}"));
    }
    for key in spec.unknown.keys() {
        problems.push(format!(
            "ruleset '{name}': unknown key '{key}'{}",
            suggestion(
                key,
                &[
                    "description",
                    "sources",
                    "include",
                    "exclude",
                    "dependencies",
                    "overlays",
                    "stale_overlays",
                    "pipelines",
                    "output",
                ]
            )
        ));
    }
    for pipeline in &spec.pipelines {
        if pipeline.trim().is_empty() {
            problems.push(format!(
                "ruleset '{name}': pipelines must not contain an empty name"
            ));
        }
    }

    for (index, selector) in spec.include.iter().enumerate() {
        validate_selector(
            name,
            selector,
            true,
            &format!("include[{index}]"),
            &mut problems,
        );
    }
    for (index, selector) in spec.exclude.iter().enumerate() {
        validate_selector(
            name,
            selector,
            false,
            &format!("exclude[{index}]"),
            &mut problems,
        );
    }
    for (index, entry) in spec.overlays.iter().enumerate() {
        validate_overlay_entry(name, entry, &format!("overlays[{index}]"), &mut problems);
    }

    problems
}

fn validate_selector(
    ruleset: &str,
    selector: &RuleSelector,
    is_include: bool,
    at: &str,
    problems: &mut Vec<String>,
) {
    if selector.id.is_empty()
        && selector.name.is_empty()
        && selector.title.is_empty()
        && selector.tags.is_empty()
        && selector.level.is_empty()
        && selector.status.is_empty()
        && selector.kind.is_empty()
        && selector.path.is_empty()
        && selector.logsource.is_none()
    {
        problems.push(format!("ruleset '{ruleset}': {at} sets no key"));
    }
    for key in selector.unknown.keys() {
        problems.push(format!(
            "ruleset '{ruleset}': {at} has unknown key '{key}'{}",
            suggestion(
                key,
                &[
                    "id",
                    "name",
                    "title",
                    "tags",
                    "level",
                    "status",
                    "kind",
                    "logsource",
                    "path",
                ]
            )
        ));
    }
    for value in &selector.level {
        if value.parse::<Level>().is_err() {
            problems.push(format!(
                "ruleset '{ruleset}': {at}.level has unknown level '{value}'"
            ));
        }
    }
    for value in &selector.status {
        if value.parse::<Status>().is_err() {
            problems.push(format!(
                "ruleset '{ruleset}': {at}.status has unknown status '{value}'"
            ));
        }
    }
    for value in &selector.kind {
        if !matches!(value.as_str(), "detection" | "correlation" | "filter") {
            problems.push(format!(
                "ruleset '{ruleset}': {at}.kind has unknown kind '{value}'"
            ));
        }
        if is_include && value == "filter" {
            problems.push(format!(
                "ruleset '{ruleset}': {at}.kind must not include 'filter'; filters follow their targets"
            ));
        }
    }
    for value in &selector.title {
        if let Err(e) = globset::GlobBuilder::new(value)
            .case_insensitive(true)
            .build()
        {
            problems.push(format!(
                "ruleset '{ruleset}': {at}.title has invalid glob '{value}': {e}"
            ));
        }
    }
    for value in &selector.tags {
        if let Err(e) = globset::GlobBuilder::new(value)
            .case_insensitive(true)
            .build()
        {
            problems.push(format!(
                "ruleset '{ruleset}': {at}.tags has invalid glob '{value}': {e}"
            ));
        }
    }
    for value in &selector.path {
        if let Err(e) = globset::GlobBuilder::new(value)
            .literal_separator(true)
            .build()
        {
            problems.push(format!(
                "ruleset '{ruleset}': {at}.path has invalid glob '{value}': {e}"
            ));
        }
    }
    if let Some(logsource) = &selector.logsource {
        if logsource.product.is_empty()
            && logsource.category.is_empty()
            && logsource.service.is_empty()
        {
            problems.push(format!("ruleset '{ruleset}': {at}.logsource sets no key"));
        }
        for key in logsource.unknown.keys() {
            problems.push(format!(
                "ruleset '{ruleset}': {at}.logsource has unknown key '{key}'{}",
                suggestion(key, &["product", "category", "service"])
            ));
        }
    }
}

fn validate_overlay_entry(
    ruleset: &str,
    entry: &OverlayEntry,
    at: &str,
    problems: &mut Vec<String>,
) {
    for key in entry.unknown.keys() {
        problems.push(format!(
            "ruleset '{ruleset}': {at} has unknown key '{key}'{}",
            suggestion(key, &["id", "file", "dir", "set", "append"])
        ));
    }
    let forms = [
        entry.id.is_some(),
        entry.file.is_some(),
        entry.dir.is_some(),
    ]
    .into_iter()
    .filter(|set| *set)
    .count();
    if forms != 1 {
        problems.push(format!(
            "ruleset '{ruleset}': {at} must set exactly one of id, file, or dir"
        ));
        return;
    }
    if entry.file.is_some() || entry.dir.is_some() {
        if entry.set.is_some() || entry.append.is_some() {
            problems.push(format!(
                "ruleset '{ruleset}': {at} must not combine file or dir with set or append"
            ));
        }
        return;
    }
    if entry.set.is_none() && entry.append.is_none() {
        problems.push(format!(
            "ruleset '{ruleset}': {at} needs at least one of set or append"
        ));
    }
    if let Some(patch) = &entry.set {
        validate_patch(ruleset, patch, at, "set", SET_KEYS, problems);
        for value in patch.level.iter() {
            if value.parse::<Level>().is_err() {
                problems.push(format!(
                    "ruleset '{ruleset}': {at}.set has unknown level '{value}'"
                ));
            }
        }
        for value in patch.status.iter() {
            if value.parse::<Status>().is_err() {
                problems.push(format!(
                    "ruleset '{ruleset}': {at}.set has unknown status '{value}'"
                ));
            }
        }
    }
    if let Some(patch) = &entry.append {
        validate_patch(ruleset, patch, at, "append", APPEND_KEYS, problems);
        if patch.level.is_some() {
            problems.push(format!(
                "ruleset '{ruleset}': {at}.append cannot set 'level'; use set"
            ));
        }
        if patch.status.is_some() {
            problems.push(format!(
                "ruleset '{ruleset}': {at}.append cannot set 'status'; use set"
            ));
        }
        if patch.description.is_some() {
            problems.push(format!(
                "ruleset '{ruleset}': {at}.append cannot set 'description'; use set"
            ));
        }
        if patch.author.is_some() {
            problems.push(format!(
                "ruleset '{ruleset}': {at}.append cannot set 'author'; use set"
            ));
        }
    }
}

/// Engine keys read from a correlation's top level, which the emitter would
/// write next to the parsed `window` and `gap`.
const ENGINE_CORRELATION_KEYS: &[&str] = &["rsigma.window", "rsigma.gap"];

/// Check one `set` or `append` patch: unknown keys, an empty patch, and
/// custom attributes that would shadow a standard key. The emitter flattens
/// custom attributes to the document's top level, so such a key would emit a
/// document that no longer parses.
pub(crate) fn validate_patch(
    ruleset: &str,
    patch: &OverlayPatch,
    at: &str,
    form: &str,
    allowed: &[&str],
    problems: &mut Vec<String>,
) {
    for key in patch.unknown.keys() {
        problems.push(format!(
            "ruleset '{ruleset}': {at}.{form} has unknown key '{key}'{}",
            suggestion(key, allowed)
        ));
    }
    let empty = patch.level.is_none()
        && patch.status.is_none()
        && patch.description.is_none()
        && patch.author.is_none()
        && patch.tags.is_none()
        && patch.references.is_none()
        && patch.falsepositives.is_none()
        && patch.fields.is_none()
        && patch
            .custom_attributes
            .as_ref()
            .is_none_or(BTreeMap::is_empty)
        && patch.unknown.is_empty();
    if empty {
        problems.push(format!("ruleset '{ruleset}': {at}.{form} is empty"));
    }
    for key in patch.custom_attributes.iter().flat_map(BTreeMap::keys) {
        let reserved = [
            crate::parser::STANDARD_RULE_KEYS,
            crate::parser::STANDARD_CORRELATION_KEYS,
            crate::parser::STANDARD_FILTER_KEYS,
            ENGINE_CORRELATION_KEYS,
        ]
        .iter()
        .any(|keys| keys.contains(&key.as_str()));
        if reserved {
            problems.push(format!(
                "ruleset '{ruleset}': {at}.{form}.custom_attributes cannot set '{key}', a standard Sigma or engine key"
            ));
        }
    }
}

/// Suggest a known key close to an unknown one, for typo messages.
pub(crate) fn suggestion(key: &str, known: &[&str]) -> String {
    let mut best: Option<(usize, &str)> = None;
    for candidate in known {
        let distance = edit_distance(key, candidate);
        if distance <= 2 && best.is_none_or(|(d, _)| distance < d) {
            best = Some((distance, candidate));
        }
    }
    match best {
        Some((_, candidate)) => format!(" (did you mean '{candidate}'?)"),
        None => String::new(),
    }
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut current = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(ca != cb);
            current[j + 1] = substitution.min(previous[j + 1] + 1).min(current[j] + 1);
        }
        previous = current;
    }
    previous[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_names() {
        assert!(validate_ruleset_name("linux_edge").is_ok());
        assert!(validate_ruleset_name("a").is_ok());
        assert!(validate_ruleset_name("Linux").is_err());
        assert!(validate_ruleset_name("9lives").is_err());
        assert!(validate_ruleset_name("has space").is_err());
    }

    #[test]
    fn reports_unknown_keys_with_suggestion() {
        let spec: RulesetSpec =
            yaml_serde::from_str("sources: [rules]\ninclude:\n  - tag: [attack.t1059]\n").unwrap();
        let problems = validate_spec("test", &spec);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("unknown key 'tag'") && p.contains("did you mean 'tags'")),
            "{problems:?}"
        );
    }

    #[test]
    fn rejects_empty_sources_and_selectors() {
        let spec = RulesetSpec::default();
        let problems = validate_spec("test", &spec);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("sources must not be empty"))
        );

        let spec = RulesetSpec {
            sources: vec![PathBuf::from("rules")],
            include: vec![RuleSelector::default()],
            ..Default::default()
        };
        let problems = validate_spec("test", &spec);
        assert!(problems.iter().any(|p| p.contains("sets no key")));
    }

    #[test]
    fn rejects_filter_in_include() {
        let spec = RulesetSpec {
            sources: vec![PathBuf::from("rules")],
            include: vec![RuleSelector {
                kind: vec!["filter".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let problems = validate_spec("test", &spec);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("must not include 'filter'"))
        );
    }

    #[test]
    fn rejects_invalid_glob_and_enum() {
        let spec = RulesetSpec {
            sources: vec![PathBuf::from("rules")],
            include: vec![RuleSelector {
                tags: vec!["[".into()],
                level: vec!["severe".into()],
                ..Default::default()
            }],
            dependencies: Some("ignore".into()),
            ..Default::default()
        };
        let problems = validate_spec("test", &spec);
        assert!(problems.iter().any(|p| p.contains("invalid glob")));
        assert!(problems.iter().any(|p| p.contains("unknown level")));
        assert!(problems.iter().any(|p| p.contains("dependencies policy")));
    }

    #[test]
    fn rejects_malformed_overlay_entries() {
        let spec = RulesetSpec {
            sources: vec![PathBuf::from("rules")],
            overlays: vec![
                OverlayEntry::default(),
                OverlayEntry {
                    id: Some("x".into()),
                    file: Some(PathBuf::from("y.yml")),
                    ..Default::default()
                },
                OverlayEntry {
                    file: Some(PathBuf::from("y.yml")),
                    set: Some(OverlayPatch::default()),
                    ..Default::default()
                },
                OverlayEntry {
                    id: Some("x".into()),
                    ..Default::default()
                },
                OverlayEntry {
                    id: Some("x".into()),
                    append: Some(OverlayPatch {
                        level: Some("high".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let problems = validate_spec("test", &spec);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("exactly one of id, file, or dir"))
        );
        assert!(problems.iter().any(|p| p.contains("must not combine")));
        assert!(
            problems
                .iter()
                .any(|p| p.contains("at least one of set or append"))
        );
        assert!(problems.iter().any(|p| p.contains("cannot set 'level'")));
    }

    #[test]
    fn rejects_empty_patches() {
        let spec: RulesetSpec = yaml_serde::from_str(
            "sources: [rules]\noverlays:\n  - id: x\n    set: {}\n  - id: y\n    append:\n      custom_attributes: {}\n",
        )
        .unwrap();
        let problems = validate_spec("test", &spec);
        assert!(
            problems
                .iter()
                .any(|p| p.ends_with("overlays[0].set is empty")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.ends_with("overlays[1].append is empty")),
            "{problems:?}"
        );
    }

    #[test]
    fn rejects_custom_attributes_that_shadow_standard_keys() {
        for key in [
            "title",
            "id",
            "level",
            "logsource",
            "detection",
            "correlation",
            "filter",
            "custom_attributes",
            "rsigma.window",
            "rsigma.gap",
        ] {
            let spec: RulesetSpec = yaml_serde::from_str(&format!(
                "sources: [rules]\noverlays:\n  - id: x\n    set:\n      custom_attributes:\n        {key}: v\n  - id: y\n    append:\n      custom_attributes:\n        {key}: [v]\n"
            ))
            .unwrap();
            let problems = validate_spec("test", &spec);
            let shadowing = problems
                .iter()
                .filter(|p| p.contains(&format!("custom_attributes cannot set '{key}'")))
                .count();
            assert_eq!(shadowing, 2, "{key}: {problems:?}");
        }

        let spec: RulesetSpec = yaml_serde::from_str(
            "sources: [rules]\noverlays:\n  - id: x\n    set:\n      custom_attributes:\n        rsigma.suppress: 5m\n        team: blue\n",
        )
        .unwrap();
        assert!(validate_spec("test", &spec).is_empty());
    }
}
