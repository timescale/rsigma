//! Metadata overlays: loading, application, and validation.
//!
//! Overlays change metadata on already-selected rules without editing the
//! source files. They target a kept detection rule or correlation by id and
//! apply after dependency closure, before any pipeline.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use yaml_serde::Value;

use crate::ads::{ADS_PREFIX, AdsContent, EXEMPT_KEY};
use crate::ast::{Level, Status};
use crate::exemplar::{EXEMPLARS_KEY, ExemplarRuleKind, exemplars_from_attrs};

use super::closure;
use super::error::RulesetError;
use super::select::Decision;
use super::source::{
    Candidate, CandidateDoc, DocumentKind, ResolveOptions, SourceFile, confine, relative_to,
};
use super::spec::{
    APPEND_KEYS, OverlayEntry, OverlayPatch, RulesetSpec, SET_KEYS, StaleOverlayPolicy, suggestion,
    validate_patch,
};

/// Where an applied overlay came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum OverlayOrigin {
    /// An inline entry at this index in the spec.
    Inline {
        /// Index into the spec's `overlays`.
        index: usize,
    },
    /// An entry at this index in an overlay file.
    File {
        /// The overlay file.
        path: PathBuf,
        /// Index of the entry in that file.
        index: usize,
    },
}

impl fmt::Display for OverlayOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline { index } => write!(f, "inline:{index}"),
            Self::File { path, index } => write!(f, "{}:{index}", path.display()),
        }
    }
}

/// An overlay that was applied to a kept document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedOverlay {
    /// Where the overlay entry was declared.
    pub origin: OverlayOrigin,
    /// Key paths that were set, such as `level` or
    /// `custom_attributes.rsigma.exemplars`.
    pub set: Vec<String>,
    /// Key paths that were appended.
    pub appended: Vec<String>,
}

/// Expands `file` and `dir` overlay entries. Inline entries are handled by the
/// resolver and are never passed to a loader.
pub trait OverlayLoader {
    /// Expand one `file` or `dir` entry into its inline entries, in order.
    fn load(
        &self,
        entry: &OverlayEntry,
    ) -> Result<Vec<(OverlayOrigin, OverlayEntry)>, RulesetError>;

    /// Overlay files read by this loader, for the lockfile.
    fn files(&self) -> Vec<SourceFile> {
        Vec::new()
    }
}

/// Reads overlay files and directories from disk, recording what it read.
pub struct FsOverlayLoader {
    /// Reject overlay paths outside this root.
    pub confine_to: Option<PathBuf>,
    files: Mutex<Vec<SourceFile>>,
}

impl FsOverlayLoader {
    /// A loader confined to `confine_to`, when set.
    pub fn new(confine_to: Option<PathBuf>) -> Self {
        Self {
            confine_to,
            files: Mutex::new(Vec::new()),
        }
    }

    fn load_file(
        &self,
        path: &Path,
        opts: &ResolveOptions,
        out: &mut Vec<(OverlayOrigin, OverlayEntry)>,
    ) -> Result<(), RulesetError> {
        let canonical = path.canonicalize().map_err(|e| RulesetError::Io {
            ruleset: None,
            path: path.to_path_buf(),
            source: e,
        })?;
        confine(&canonical, opts)?;
        let bytes = std::fs::read(path).map_err(|e| RulesetError::Io {
            ruleset: None,
            path: path.to_path_buf(),
            source: e,
        })?;
        let text = String::from_utf8_lossy(&bytes);
        let entries = parse_overlay_file(&text, path)?;
        self.files
            .lock()
            .expect("overlay file list lock")
            .push(SourceFile {
                source: 0,
                path: path.to_path_buf(),
                relative: relative_to(path, Path::new(".")),
                sha256_input: bytes,
            });
        for (index, entry) in entries.into_iter().enumerate() {
            out.push((
                OverlayOrigin::File {
                    path: path.to_path_buf(),
                    index,
                },
                entry,
            ));
        }
        Ok(())
    }

    fn load_dir(
        &self,
        dir: &Path,
        opts: &ResolveOptions,
        out: &mut Vec<(OverlayOrigin, OverlayEntry)>,
    ) -> Result<(), RulesetError> {
        if !dir.exists() {
            return Err(RulesetError::Io {
                ruleset: None,
                path: dir.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "overlay directory does not exist",
                ),
            });
        }
        let canonical = dir.canonicalize().map_err(|e| RulesetError::Io {
            ruleset: None,
            path: dir.to_path_buf(),
            source: e,
        })?;
        confine(&canonical, opts)?;
        let mut paths = Vec::new();
        let mut visited = HashSet::new();
        crate::walk::collect_yaml_files(dir, dir, None, &mut paths, &mut visited).map_err(|e| {
            RulesetError::Io {
                ruleset: None,
                path: dir.to_path_buf(),
                source: std::io::Error::other(e.to_string()),
            }
        })?;
        for path in paths {
            self.load_file(&path, opts, out)?;
        }
        Ok(())
    }
}

impl OverlayLoader for FsOverlayLoader {
    fn load(
        &self,
        entry: &OverlayEntry,
    ) -> Result<Vec<(OverlayOrigin, OverlayEntry)>, RulesetError> {
        if entry.id.is_some() {
            return Err(RulesetError::Overlay(
                "inline overlay entry passed to a filesystem loader".into(),
            ));
        }
        let opts = ResolveOptions {
            confine_to: self.confine_to.clone(),
        };
        let mut out = Vec::new();
        if let Some(file) = &entry.file {
            self.load_file(file, &opts, &mut out)?;
        } else if let Some(dir) = &entry.dir {
            self.load_dir(dir, &opts, &mut out)?;
        } else {
            return Err(RulesetError::Overlay(
                "overlay entry must set one of id, file, or dir".into(),
            ));
        }
        Ok(out)
    }

    fn files(&self) -> Vec<SourceFile> {
        self.files.lock().expect("overlay file list lock").clone()
    }
}

/// A loader that accepts only inline overlays, for fuzzing and benchmarks.
pub struct InlineOnlyOverlayLoader;

impl OverlayLoader for InlineOnlyOverlayLoader {
    fn load(
        &self,
        _entry: &OverlayEntry,
    ) -> Result<Vec<(OverlayOrigin, OverlayEntry)>, RulesetError> {
        Err(RulesetError::Overlay(
            "file and dir overlays need a filesystem loader".into(),
        ))
    }
}

fn parse_overlay_file(text: &str, path: &Path) -> Result<Vec<OverlayEntry>, RulesetError> {
    let entries: Option<Vec<OverlayEntry>> = yaml_serde::from_str(text).map_err(|e| {
        RulesetError::Overlay(format!("cannot parse overlay file {}: {e}", path.display()))
    })?;
    Ok(entries.unwrap_or_default())
}

/// Expand every overlay entry in declaration order, replacing file and dir
/// entries with their contents at that position.
pub(crate) fn expand_overlays(
    name: &str,
    spec: &RulesetSpec,
    loader: &dyn OverlayLoader,
) -> Result<Vec<(OverlayOrigin, OverlayEntry)>, RulesetError> {
    let mut expanded = Vec::new();
    for (index, entry) in spec.overlays.iter().enumerate() {
        if entry.id.is_some() {
            expanded.push((OverlayOrigin::Inline { index }, entry.clone()));
        } else {
            expanded.extend(loader.load(entry).map_err(|e| e.named(name))?);
        }
    }
    for (origin, entry) in &expanded {
        validate_expanded(name, origin, entry)?;
    }
    Ok(expanded)
}

/// Apply overlays to kept candidates and return per-candidate provenance.
pub(crate) fn apply_overlays(
    name: &str,
    spec: &RulesetSpec,
    candidates: &mut [Candidate],
    decisions: &[Decision],
    expanded: Vec<(OverlayOrigin, OverlayEntry)>,
) -> Result<(Vec<Vec<AppliedOverlay>>, Vec<String>), RulesetError> {
    let policy = match &spec.stale_overlays {
        Some(value) => StaleOverlayPolicy::parse(value)
            .map_err(|e| RulesetError::InvalidSpec(vec![format!("ruleset '{name}': {e}")]))?,
        None => StaleOverlayPolicy::Error,
    };

    let mut kept_by_id: HashMap<String, usize> = HashMap::new();
    let mut filter_ids: HashSet<String> = HashSet::new();
    let mut any_by_id: HashMap<String, usize> = HashMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let Some(id) = candidate.id() else {
            continue;
        };
        let key = id.to_ascii_lowercase();
        any_by_id.entry(key.clone()).or_insert(index);
        if candidate.kind() == DocumentKind::Filter {
            filter_ids.insert(key);
        } else if closure::is_kept(&decisions[index]) {
            kept_by_id.insert(key, index);
        }
    }

    let mut applied: Vec<Vec<AppliedOverlay>> = vec![Vec::new(); candidates.len()];
    let mut warnings = Vec::new();
    let mut stale = Vec::new();

    for (origin, entry) in expanded {
        let Some(id) = entry.id.as_deref() else {
            // `validate_expanded` guarantees an id.
            continue;
        };
        let key = id.to_ascii_lowercase();
        if let Some(index) = kept_by_id.get(&key).copied() {
            let (set, appended) =
                apply_to_candidate(name, &origin, &mut candidates[index], &entry)?;
            applied[index].push(AppliedOverlay {
                origin,
                set,
                appended,
            });
        } else if filter_ids.contains(&key) {
            return Err(RulesetError::Overlay(format!(
                "ruleset '{name}': overlay {origin} targets id '{id}', which is a filter; filters cannot be overlaid"
            )));
        } else {
            let reason = stale_reason(name, &origin, id, any_by_id.get(&key).copied(), decisions);
            match policy {
                StaleOverlayPolicy::Error => stale.push(reason),
                StaleOverlayPolicy::Warn => warnings.push(reason),
            }
        }
    }

    if !stale.is_empty() {
        return Err(RulesetError::StaleOverlay(stale));
    }
    Ok((applied, warnings))
}

fn stale_reason(
    name: &str,
    origin: &OverlayOrigin,
    id: &str,
    candidate_index: Option<usize>,
    decisions: &[Decision],
) -> String {
    let because = match candidate_index {
        None => "exists in no source".to_string(),
        Some(index) => match &decisions[index] {
            Decision::Excluded { selector } => {
                format!("is excluded by exclude selector {selector}")
            }
            Decision::NotSelected => "is not matched by include".to_string(),
            Decision::Dropped { reason } => format!("was dropped: {reason}"),
            other => format!("is {}", other.as_str()),
        },
    };
    format!("ruleset '{name}': overlay {origin} targets id '{id}', which {because}")
}

struct Metadata<'a> {
    level: &'a mut Option<Level>,
    status: &'a mut Option<Status>,
    description: &'a mut Option<String>,
    author: &'a mut Option<String>,
    tags: &'a mut Vec<String>,
    references: &'a mut Vec<String>,
    falsepositives: &'a mut Vec<String>,
    fields: &'a mut Vec<String>,
    custom_attributes: &'a mut HashMap<String, Value>,
}

fn metadata_mut(doc: &mut CandidateDoc) -> Metadata<'_> {
    match doc {
        CandidateDoc::Detection(rule) => Metadata {
            level: &mut rule.level,
            status: &mut rule.status,
            description: &mut rule.description,
            author: &mut rule.author,
            tags: &mut rule.tags,
            references: &mut rule.references,
            falsepositives: &mut rule.falsepositives,
            fields: &mut rule.fields,
            custom_attributes: &mut rule.custom_attributes,
        },
        CandidateDoc::Correlation(rule) => Metadata {
            level: &mut rule.level,
            status: &mut rule.status,
            description: &mut rule.description,
            author: &mut rule.author,
            tags: &mut rule.tags,
            references: &mut rule.references,
            falsepositives: &mut rule.falsepositives,
            fields: &mut rule.fields,
            custom_attributes: &mut rule.custom_attributes,
        },
        CandidateDoc::Filter(rule) => Metadata {
            level: &mut rule.level,
            status: &mut rule.status,
            description: &mut rule.description,
            author: &mut rule.author,
            tags: &mut rule.tags,
            references: &mut rule.references,
            falsepositives: &mut rule.falsepositives,
            fields: &mut rule.fields,
            custom_attributes: &mut rule.custom_attributes,
        },
    }
}

fn apply_to_candidate(
    name: &str,
    origin: &OverlayOrigin,
    candidate: &mut Candidate,
    entry: &OverlayEntry,
) -> Result<(Vec<String>, Vec<String>), RulesetError> {
    let mut set_keys = Vec::new();
    let mut appended_keys = Vec::new();
    {
        let mut meta = metadata_mut(&mut candidate.doc);
        if let Some(patch) = &entry.set {
            apply_set(name, origin, &mut meta, patch, &mut set_keys)?;
        }
        if let Some(patch) = &entry.append {
            apply_append(name, origin, &mut meta, patch, &mut appended_keys)?;
        }
    }
    validate_touched(name, origin, &candidate.doc, &set_keys, &appended_keys)?;
    Ok((set_keys, appended_keys))
}

fn apply_set(
    name: &str,
    origin: &OverlayOrigin,
    meta: &mut Metadata<'_>,
    patch: &OverlayPatch,
    keys: &mut Vec<String>,
) -> Result<(), RulesetError> {
    if let Some(value) = &patch.level {
        let level = value.parse::<Level>().map_err(|_| {
            overlay_error(
                name,
                origin,
                format!("set level '{value}' is not a valid level"),
            )
        })?;
        *meta.level = Some(level);
        keys.push("level".into());
    }
    if let Some(value) = &patch.status {
        let status = value.parse::<Status>().map_err(|_| {
            overlay_error(
                name,
                origin,
                format!("set status '{value}' is not a valid status"),
            )
        })?;
        *meta.status = Some(status);
        keys.push("status".into());
    }
    if let Some(value) = &patch.description {
        *meta.description = Some(value.clone());
        keys.push("description".into());
    }
    if let Some(value) = &patch.author {
        *meta.author = Some(value.clone());
        keys.push("author".into());
    }
    if let Some(value) = &patch.tags {
        *meta.tags = value.clone();
        keys.push("tags".into());
    }
    if let Some(value) = &patch.references {
        *meta.references = value.clone();
        keys.push("references".into());
    }
    if let Some(value) = &patch.falsepositives {
        *meta.falsepositives = value.clone();
        keys.push("falsepositives".into());
    }
    if let Some(value) = &patch.fields {
        *meta.fields = value.clone();
        keys.push("fields".into());
    }
    if let Some(attributes) = &patch.custom_attributes {
        for (key, value) in attributes {
            if value.is_null() {
                meta.custom_attributes.remove(key);
            } else {
                let converted = canonical_yaml_value(yaml_serde::to_value(value).map_err(|e| {
                    overlay_error(
                        name,
                        origin,
                        format!("cannot convert custom attribute '{key}': {e}"),
                    )
                })?);
                meta.custom_attributes.insert(key.clone(), converted);
            }
            keys.push(format!("custom_attributes.{key}"));
        }
    }
    Ok(())
}

fn apply_append(
    name: &str,
    origin: &OverlayOrigin,
    meta: &mut Metadata<'_>,
    patch: &OverlayPatch,
    keys: &mut Vec<String>,
) -> Result<(), RulesetError> {
    if let Some(values) = &patch.tags {
        for value in values {
            if !meta.tags.contains(value) {
                meta.tags.push(value.clone());
            }
        }
        keys.push("tags".into());
    }
    if let Some(values) = &patch.references {
        meta.references.extend(values.iter().cloned());
        keys.push("references".into());
    }
    if let Some(values) = &patch.falsepositives {
        meta.falsepositives.extend(values.iter().cloned());
        keys.push("falsepositives".into());
    }
    if let Some(values) = &patch.fields {
        meta.fields.extend(values.iter().cloned());
        keys.push("fields".into());
    }
    if let Some(attributes) = &patch.custom_attributes {
        for (key, value) in attributes {
            let converted = canonical_yaml_value(yaml_serde::to_value(value).map_err(|e| {
                overlay_error(
                    name,
                    origin,
                    format!("cannot convert custom attribute '{key}': {e}"),
                )
            })?);
            let Value::Sequence(items) = converted else {
                return Err(overlay_error(
                    name,
                    origin,
                    format!("append custom_attributes.{key} must be a sequence"),
                ));
            };
            match meta.custom_attributes.entry(key.clone()) {
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(Value::Sequence(items));
                }
                std::collections::hash_map::Entry::Occupied(mut slot) => match slot.get_mut() {
                    Value::Sequence(existing) => existing.extend(items),
                    _ => {
                        return Err(overlay_error(
                            name,
                            origin,
                            format!(
                                "append custom_attributes.{key} must target an existing sequence"
                            ),
                        ));
                    }
                },
            }
            keys.push(format!("custom_attributes.{key}"));
        }
    }
    Ok(())
}

fn validate_touched(
    name: &str,
    origin: &OverlayOrigin,
    doc: &CandidateDoc,
    set: &[String],
    appended: &[String],
) -> Result<(), RulesetError> {
    let exemplar_path = format!("custom_attributes.{EXEMPLARS_KEY}");
    let touched_exemplars = set.iter().chain(appended).any(|key| key == &exemplar_path);

    let attributes = match doc {
        CandidateDoc::Detection(rule) => &rule.custom_attributes,
        CandidateDoc::Correlation(rule) => &rule.custom_attributes,
        CandidateDoc::Filter(rule) => &rule.custom_attributes,
    };

    if touched_exemplars {
        let kind = match doc {
            CandidateDoc::Detection(_) => ExemplarRuleKind::Detection,
            CandidateDoc::Correlation(_) => ExemplarRuleKind::Correlation,
            CandidateDoc::Filter(_) => ExemplarRuleKind::Filter,
        };
        if let Err(errors) = exemplars_from_attrs(attributes, kind) {
            let detail = errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(overlay_error(
                name,
                origin,
                format!("{EXEMPLARS_KEY} is invalid: {detail}"),
            ));
        }
    }

    for key in set.iter().chain(appended) {
        let Some(attribute) = key.strip_prefix("custom_attributes.") else {
            continue;
        };
        let Some(value) = attributes.get(attribute) else {
            continue;
        };
        if attribute == EXEMPT_KEY {
            if value.as_bool().is_none() {
                return Err(overlay_error(
                    name,
                    origin,
                    format!("{EXEMPT_KEY} must be a boolean"),
                ));
            }
        } else if attribute.starts_with(ADS_PREFIX) && AdsContent::from_yaml(value).is_none() {
            return Err(overlay_error(
                name,
                origin,
                format!("{attribute} must be text or a list of text"),
            ));
        }
    }
    Ok(())
}

fn overlay_error(name: &str, origin: &OverlayOrigin, detail: impl fmt::Display) -> RulesetError {
    RulesetError::Overlay(format!("ruleset '{name}': overlay {origin}: {detail}"))
}

/// Sort mapping keys recursively so overlay-derived YAML does not depend on
/// whether the build enabled `serde_json`'s `preserve_order` feature.
fn canonical_yaml_value(value: Value) -> Value {
    match value {
        Value::Mapping(map) => {
            let mut entries: Vec<(String, Value)> = map
                .into_iter()
                .map(|(key, value)| {
                    let key = match key {
                        Value::String(text) => text,
                        other => format!("{other:?}"),
                    };
                    (key, canonical_yaml_value(value))
                })
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = yaml_serde::Mapping::new();
            for (key, value) in entries {
                sorted.insert(Value::String(key), value);
            }
            Value::Mapping(sorted)
        }
        Value::Sequence(items) => {
            Value::Sequence(items.into_iter().map(canonical_yaml_value).collect())
        }
        other => other,
    }
}

fn validate_expanded(
    name: &str,
    origin: &OverlayOrigin,
    entry: &OverlayEntry,
) -> Result<(), RulesetError> {
    let mut problems = Vec::new();
    let file_entry = matches!(origin, OverlayOrigin::File { .. });
    let at = format!("overlay {origin}");

    for key in entry.unknown.keys() {
        problems.push(format!(
            "ruleset '{name}': {at} has unknown key '{key}'{}",
            suggestion(key, &["id", "file", "dir", "set", "append"])
        ));
    }
    if file_entry {
        if entry.file.is_some() || entry.dir.is_some() {
            problems.push(format!(
                "ruleset '{name}': {at} must not use file or dir inside an overlay file"
            ));
        }
    } else {
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
                "ruleset '{name}': {at} must set exactly one of id, file, or dir"
            ));
        }
    }
    if entry.id.is_none() {
        problems.push(format!("ruleset '{name}': {at} needs an id"));
    }
    if entry.set.is_none() && entry.append.is_none() {
        problems.push(format!(
            "ruleset '{name}': {at} needs at least one of set or append"
        ));
    }
    if let Some(patch) = &entry.set {
        validate_patch(name, patch, &at, "set", SET_KEYS, &mut problems);
        for value in patch.level.iter() {
            if value.parse::<Level>().is_err() {
                problems.push(format!(
                    "ruleset '{name}': {at}.set has unknown level '{value}'"
                ));
            }
        }
        for value in patch.status.iter() {
            if value.parse::<Status>().is_err() {
                problems.push(format!(
                    "ruleset '{name}': {at}.set has unknown status '{value}'"
                ));
            }
        }
    }
    if let Some(patch) = &entry.append {
        validate_patch(name, patch, &at, "append", APPEND_KEYS, &mut problems);
        for (key, value) in [
            ("level", patch.level.is_some()),
            ("status", patch.status.is_some()),
            ("description", patch.description.is_some()),
            ("author", patch.author.is_some()),
        ] {
            if value {
                problems.push(format!(
                    "ruleset '{name}': {at}.append cannot set '{key}'; use set"
                ));
            }
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(RulesetError::InvalidSpec(problems))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::ResolvedRuleset;
    use crate::ruleset::source::RuleOrigin;
    use crate::ruleset::spec::RuleSelector;

    fn origin(id: &str) -> RuleOrigin {
        RuleOrigin {
            source: 0,
            root: PathBuf::from("."),
            file: PathBuf::from(format!("{id}.yml")),
            ordinal: 0,
        }
    }

    fn detection(id: &str) -> Candidate {
        let collection = crate::parse_sigma_yaml(&format!(
            "title: Rule {id}\nid: {id}\nlogsource:\n    product: linux\ndetection:\n    selection:\n        Field: value\n    condition: selection\n"
        ))
        .unwrap();
        Candidate {
            doc: CandidateDoc::Detection(collection.rules.into_iter().next().unwrap()),
            origin: origin(id),
        }
    }

    fn correlation(id: &str) -> Candidate {
        let collection = crate::parse_sigma_yaml(&format!(
            "title: Correlation {id}\nid: {id}\ncorrelation:\n    type: event_count\n    rules:\n        - base\n    timespan: 5m\n    condition:\n        gte: 2\n"
        ))
        .unwrap();
        Candidate {
            doc: CandidateDoc::Correlation(collection.correlations.into_iter().next().unwrap()),
            origin: origin(id),
        }
    }

    fn with_attr(candidate: &mut Candidate, key: &str, value: Value) {
        match &mut candidate.doc {
            CandidateDoc::Detection(rule) => {
                rule.custom_attributes.insert(key.to_string(), value);
            }
            CandidateDoc::Correlation(rule) => {
                rule.custom_attributes.insert(key.to_string(), value);
            }
            CandidateDoc::Filter(rule) => {
                rule.custom_attributes.insert(key.to_string(), value);
            }
        }
    }

    fn spec_with_overlays(overlays: Vec<OverlayEntry>) -> RulesetSpec {
        RulesetSpec {
            sources: vec![PathBuf::from("rules")],
            overlays,
            ..Default::default()
        }
    }

    fn resolve_with(
        name: &str,
        spec: &RulesetSpec,
        candidates: Vec<Candidate>,
    ) -> Result<ResolvedRuleset, RulesetError> {
        crate::ruleset::resolve_loaded(
            name,
            spec,
            crate::ruleset::LoadedSources {
                candidates,
                ..Default::default()
            },
            &InlineOnlyOverlayLoader,
        )
    }

    fn exemplar_value() -> Value {
        yaml_serde::to_value(serde_json::json!([{
            "name": "one",
            "expect": "match",
            "event": {"Field": "value"}
        }]))
        .unwrap()
    }

    fn inline(id: &str, set: Option<OverlayPatch>, append: Option<OverlayPatch>) -> OverlayEntry {
        OverlayEntry {
            id: Some(id.into()),
            set,
            append,
            ..Default::default()
        }
    }

    fn level_patch(value: &str) -> OverlayPatch {
        OverlayPatch {
            level: Some(value.into()),
            ..Default::default()
        }
    }

    #[test]
    fn set_replaces_level() {
        let spec = spec_with_overlays(vec![inline("d", Some(level_patch("critical")), None)]);
        let resolved = resolve_with("test", &spec, vec![detection("d")]).unwrap();
        assert_eq!(resolved.collection.rules[0].level, Some(Level::Critical));
        assert_eq!(resolved.entries[0].overlays.len(), 1);
        assert_eq!(resolved.entries[0].overlays[0].set, ["level"]);
    }

    #[test]
    fn invalid_level_errors() {
        let spec = spec_with_overlays(vec![inline("d", Some(level_patch("severe")), None)]);
        let error = resolve_with("test", &spec, vec![detection("d")]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "ruleset 'test': overlays[0].set has unknown level 'severe'"
        );
    }

    #[test]
    fn custom_attributes_merge_per_key_and_keep_exemplars() {
        let mut rule = detection("d");
        with_attr(&mut rule, "rsigma.exemplars", exemplar_value());
        with_attr(
            &mut rule,
            "rsigma.foo",
            yaml_serde::to_value("old").unwrap(),
        );
        let patch = OverlayPatch {
            custom_attributes: Some(
                [(
                    "rsigma.foo".to_string(),
                    serde_json::Value::String("new".into()),
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        };
        let spec = spec_with_overlays(vec![inline("d", Some(patch), None)]);
        let resolved = resolve_with("test", &spec, vec![rule]).unwrap();
        let attrs = &resolved.collection.rules[0].custom_attributes;
        assert_eq!(
            attrs.get("rsigma.foo"),
            Some(&yaml_serde::to_value("new").unwrap())
        );
        assert!(attrs.contains_key("rsigma.exemplars"));
    }

    #[test]
    fn null_removes_a_key() {
        let mut rule = detection("d");
        with_attr(&mut rule, "rsigma.foo", yaml_serde::to_value("x").unwrap());
        let patch = OverlayPatch {
            custom_attributes: Some(
                [("rsigma.foo".to_string(), serde_json::Value::Null)]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        };
        let spec = spec_with_overlays(vec![inline("d", Some(patch), None)]);
        let resolved = resolve_with("test", &spec, vec![rule]).unwrap();
        assert!(
            !resolved.collection.rules[0]
                .custom_attributes
                .contains_key("rsigma.foo")
        );
    }

    #[test]
    fn append_creates_absent_exemplars() {
        let patch = OverlayPatch {
            custom_attributes: Some(
                [(
                    "rsigma.exemplars".to_string(),
                    serde_json::json!([{
                        "name": "one",
                        "expect": "match",
                        "event": {"Field": "value"}
                    }]),
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        };
        let spec = spec_with_overlays(vec![inline("d", None, Some(patch))]);
        let resolved = resolve_with("test", &spec, vec![detection("d")]).unwrap();
        assert!(
            resolved.collection.rules[0]
                .custom_attributes
                .contains_key("rsigma.exemplars")
        );
        assert_eq!(
            resolved.entries[0].overlays[0].appended,
            ["custom_attributes.rsigma.exemplars"]
        );
    }

    #[test]
    fn append_onto_a_mapping_errors() {
        let mut rule = detection("d");
        with_attr(
            &mut rule,
            "rsigma.foo",
            yaml_serde::from_str("a: b").unwrap(),
        );
        let patch = OverlayPatch {
            custom_attributes: Some(
                [("rsigma.foo".to_string(), serde_json::json!(["x"]))]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        };
        let spec = spec_with_overlays(vec![inline("d", None, Some(patch))]);
        let error = resolve_with("test", &spec, vec![rule]).unwrap_err();
        assert!(error.to_string().contains("existing sequence"), "{error}");
    }

    #[test]
    fn tags_are_deduplicated() {
        let mut rule = detection("d");
        if let CandidateDoc::Detection(rule) = &mut rule.doc {
            rule.tags = vec!["attack.t1059".into()];
        }
        let patch = OverlayPatch {
            tags: Some(vec![
                "attack.t1059".into(),
                "attack.t1071".into(),
                "attack.t1071".into(),
            ]),
            ..Default::default()
        };
        let spec = spec_with_overlays(vec![inline("d", None, Some(patch))]);
        let resolved = resolve_with("test", &spec, vec![rule]).unwrap();
        assert_eq!(
            resolved.collection.rules[0].tags,
            ["attack.t1059", "attack.t1071"]
        );
    }

    #[test]
    fn set_then_append_within_one_entry() {
        let entry = inline(
            "d",
            Some(OverlayPatch {
                tags: Some(vec!["a".into()]),
                ..Default::default()
            }),
            Some(OverlayPatch {
                tags: Some(vec!["b".into()]),
                ..Default::default()
            }),
        );
        let spec = spec_with_overlays(vec![entry]);
        let resolved = resolve_with("test", &spec, vec![detection("d")]).unwrap();
        assert_eq!(resolved.collection.rules[0].tags, ["a", "b"]);
        assert_eq!(resolved.entries[0].overlays[0].set, ["tags"]);
        assert_eq!(resolved.entries[0].overlays[0].appended, ["tags"]);
    }

    #[test]
    fn two_entries_apply_in_order() {
        let spec = spec_with_overlays(vec![
            inline("d", Some(level_patch("low")), None),
            inline("d", Some(level_patch("high")), None),
        ]);
        let resolved = resolve_with("test", &spec, vec![detection("d")]).unwrap();
        assert_eq!(resolved.collection.rules[0].level, Some(Level::High));
        let origins: Vec<String> = resolved.entries[0]
            .overlays
            .iter()
            .map(|o| o.origin.to_string())
            .collect();
        assert_eq!(origins, ["inline:0", "inline:1"]);
    }

    #[test]
    fn directory_entries_expand_in_sorted_order_at_their_position() {
        let dir = tempfile::tempdir().unwrap();
        let overlays = dir.path().join("overlays");
        std::fs::create_dir_all(&overlays).unwrap();
        std::fs::write(overlays.join("b.yml"), "- id: d\n  set:\n    level: high\n").unwrap();
        std::fs::write(
            overlays.join("a.yml"),
            "- id: d\n  set:\n    level: medium\n",
        )
        .unwrap();

        let spec = RulesetSpec {
            sources: vec![PathBuf::from("rules")],
            overlays: vec![
                inline("d", Some(level_patch("low")), None),
                OverlayEntry {
                    dir: Some(overlays.clone()),
                    ..Default::default()
                },
                inline("d", Some(level_patch("critical")), None),
            ],
            ..Default::default()
        };
        let loader = FsOverlayLoader::new(None);
        let resolved = crate::ruleset::resolve_loaded(
            "test",
            &spec,
            crate::ruleset::LoadedSources {
                candidates: vec![detection("d")],
                ..Default::default()
            },
            &loader,
        )
        .unwrap();
        assert_eq!(resolved.collection.rules[0].level, Some(Level::Critical));
        let origins: Vec<String> = resolved.entries[0]
            .overlays
            .iter()
            .map(|o| o.origin.to_string())
            .collect();
        assert_eq!(
            origins,
            [
                "inline:0".to_string(),
                format!("{}:0", overlays.join("a.yml").display()),
                format!("{}:0", overlays.join("b.yml").display()),
                "inline:2".to_string(),
            ]
        );
        assert_eq!(resolved.overlay_files.len(), 2);
        let files: Vec<String> = resolved
            .overlay_files
            .iter()
            .map(|f| f.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(files, ["a.yml", "b.yml"]);
    }

    #[test]
    fn empty_and_null_overlay_files_contribute_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.yml");
        std::fs::write(&empty, "").unwrap();
        let null = dir.path().join("null.yml");
        std::fs::write(&null, "null\n").unwrap();
        let spec = spec_with_overlays(vec![
            OverlayEntry {
                file: Some(empty),
                ..Default::default()
            },
            OverlayEntry {
                file: Some(null),
                ..Default::default()
            },
        ]);
        let loader = FsOverlayLoader::new(None);
        let resolved = crate::ruleset::resolve_loaded(
            "test",
            &spec,
            crate::ruleset::LoadedSources {
                candidates: vec![detection("d")],
                ..Default::default()
            },
            &loader,
        )
        .unwrap();
        assert!(resolved.entries[0].overlays.is_empty());
        assert_eq!(resolved.overlay_files.len(), 2);
    }

    #[test]
    fn unknown_keys_in_a_file_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("overlay.yml");
        std::fs::write(&path, "- id: d\n  set:\n    level: low\n    tagz: [x]\n").unwrap();
        let spec = RulesetSpec {
            sources: vec![PathBuf::from("rules")],
            overlays: vec![OverlayEntry {
                file: Some(path),
                ..Default::default()
            }],
            ..Default::default()
        };
        let loader = FsOverlayLoader::new(None);
        let error = crate::ruleset::resolve_loaded(
            "test",
            &spec,
            crate::ruleset::LoadedSources {
                candidates: vec![detection("d")],
                ..Default::default()
            },
            &loader,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("unknown key 'tagz'"), "{message}");
        assert!(message.contains("did you mean 'tags'"), "{message}");
    }

    #[test]
    fn a_file_overlay_cannot_shadow_a_standard_key_or_be_empty() {
        for (body, expected) in [
            (
                "- id: d\n  set:\n    custom_attributes:\n      title: Renamed\n",
                "overlay.yml:0.set.custom_attributes cannot set 'title'",
            ),
            ("- id: d\n  append: {}\n", "overlay.yml:0.append is empty"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("overlay.yml");
            std::fs::write(&path, body).unwrap();
            let spec = RulesetSpec {
                sources: vec![PathBuf::from("rules")],
                overlays: vec![OverlayEntry {
                    file: Some(path),
                    ..Default::default()
                }],
                ..Default::default()
            };
            let error = crate::ruleset::resolve_loaded(
                "test",
                &spec,
                crate::ruleset::LoadedSources {
                    candidates: vec![detection("d")],
                    ..Default::default()
                },
                &FsOverlayLoader::new(None),
            )
            .unwrap_err();
            let message = error.to_string();
            assert!(message.contains(expected), "{message}");
        }
    }

    #[test]
    fn filter_target_errors() {
        let filter = crate::parse_sigma_yaml(
            "title: Filter\nid: f\nlogsource:\n    product: linux\nfilter:\n    rules: any\n    selection:\n        Field: value\n    condition: selection\n",
        )
        .unwrap()
        .filters
        .remove(0);
        let candidate = Candidate {
            doc: CandidateDoc::Filter(filter),
            origin: origin("f"),
        };
        let spec = spec_with_overlays(vec![inline("f", Some(level_patch("low")), None)]);
        let error = resolve_with("test", &spec, vec![candidate]).unwrap_err();
        assert!(error.to_string().contains("which is a filter"), "{error}");
    }

    #[test]
    fn stale_absent_and_excluded_are_errors() {
        let spec = spec_with_overlays(vec![inline("missing", Some(level_patch("low")), None)]);
        let error = resolve_with("test", &spec, vec![detection("d")]).unwrap_err();
        assert!(error.to_string().contains("exists in no source"), "{error}");

        let mut spec = spec_with_overlays(vec![inline("d", Some(level_patch("low")), None)]);
        spec.exclude = vec![RuleSelector {
            id: vec!["d".into()],
            ..Default::default()
        }];
        let error = resolve_with("test", &spec, vec![detection("d")]).unwrap_err();
        assert!(
            error.to_string().contains("excluded by exclude selector 0"),
            "{error}"
        );
    }

    #[test]
    fn stale_warn_records_a_warning() {
        let mut spec = spec_with_overlays(vec![inline("missing", Some(level_patch("low")), None)]);
        spec.stale_overlays = Some("warn".into());
        let resolved = resolve_with("test", &spec, vec![detection("d")]).unwrap();
        assert_eq!(resolved.warnings.len(), 1);
        assert!(
            resolved.warnings[0].contains("exists in no source"),
            "{:?}",
            resolved.warnings
        );
    }

    #[test]
    fn appended_exemplar_with_duplicate_name_errors() {
        let mut rule = detection("d");
        with_attr(&mut rule, "rsigma.exemplars", exemplar_value());
        let patch = OverlayPatch {
            custom_attributes: Some(
                [(
                    "rsigma.exemplars".to_string(),
                    serde_json::json!([{
                        "name": "one",
                        "expect": "no-match",
                        "event": {"Field": "other"}
                    }]),
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        };
        let spec = spec_with_overlays(vec![inline("d", None, Some(patch))]);
        let error = resolve_with("test", &spec, vec![rule]).unwrap_err();
        assert!(
            error.to_string().contains("duplicate exemplar name"),
            "{error}"
        );
    }

    #[test]
    fn correlation_exemplars_are_validated_as_correlations() {
        let patch = OverlayPatch {
            custom_attributes: Some(
                [(
                    "rsigma.exemplars".to_string(),
                    serde_json::json!([{
                        "name": "burst",
                        "expect": "match",
                        "events": [{"offset": "0s", "event": {"Field": "value"}}]
                    }]),
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        };
        let spec = spec_with_overlays(vec![inline("c", Some(patch.clone()), None)]);
        let resolved =
            resolve_with("test", &spec, vec![detection("base"), correlation("c")]).unwrap();
        assert!(
            resolved.collection.correlations[0]
                .custom_attributes
                .contains_key("rsigma.exemplars")
        );

        let detection_patch = OverlayPatch {
            custom_attributes: Some(
                [(
                    "rsigma.exemplars".to_string(),
                    serde_json::json!([{
                        "name": "burst",
                        "expect": "match",
                        "event": {"Field": "value"}
                    }]),
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        };
        let spec = spec_with_overlays(vec![inline("c", Some(detection_patch), None)]);
        let error =
            resolve_with("test", &spec, vec![detection("base"), correlation("c")]).unwrap_err();
        assert!(error.to_string().contains("must use 'events'"), "{error}");
    }

    #[test]
    fn ads_values_are_validated() {
        let list = OverlayPatch {
            custom_attributes: Some(
                [(
                    "rsigma.ads.blind_spots".to_string(),
                    serde_json::json!(["one", "two"]),
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        };
        let spec = spec_with_overlays(vec![inline("d", Some(list), None)]);
        resolve_with("test", &spec, vec![detection("d")]).unwrap();

        let mapping = OverlayPatch {
            custom_attributes: Some(
                [(
                    "rsigma.ads.blind_spots".to_string(),
                    serde_json::json!({"one": "two"}),
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        };
        let spec = spec_with_overlays(vec![inline("d", Some(mapping), None)]);
        let error = resolve_with("test", &spec, vec![detection("d")]).unwrap_err();
        assert!(
            error.to_string().contains("must be text or a list"),
            "{error}"
        );
    }

    #[test]
    fn provenance_records_set_and_appended_keys() {
        let entry = inline(
            "d",
            Some(OverlayPatch {
                level: Some("high".into()),
                ..Default::default()
            }),
            Some(OverlayPatch {
                tags: Some(vec!["attack.t1059".into()]),
                ..Default::default()
            }),
        );
        let spec = spec_with_overlays(vec![entry]);
        let resolved = resolve_with("test", &spec, vec![detection("d")]).unwrap();
        let overlay = &resolved.entries[0].overlays[0];
        assert_eq!(overlay.origin, OverlayOrigin::Inline { index: 0 });
        assert_eq!(overlay.set, ["level"]);
        assert_eq!(overlay.appended, ["tags"]);
    }

    fn attr_patch(key: &str, value: serde_json::Value) -> OverlayPatch {
        OverlayPatch {
            custom_attributes: Some([(key.to_string(), value)].into_iter().collect()),
            ..Default::default()
        }
    }

    /// Resolve `detection("d")` with one file or dir overlay entry through the
    /// filesystem loader, optionally confined to `root`.
    fn resolve_fs(
        entry: OverlayEntry,
        root: Option<&Path>,
    ) -> Result<ResolvedRuleset, RulesetError> {
        let spec = spec_with_overlays(vec![entry]);
        crate::ruleset::resolve_loaded(
            "test",
            &spec,
            crate::ruleset::LoadedSources {
                candidates: vec![detection("d")],
                ..Default::default()
            },
            &FsOverlayLoader::new(root.map(Path::to_path_buf)),
        )
    }

    fn file_entry(path: PathBuf) -> OverlayEntry {
        OverlayEntry {
            file: Some(path),
            ..Default::default()
        }
    }

    fn dir_entry(path: PathBuf) -> OverlayEntry {
        OverlayEntry {
            dir: Some(path),
            ..Default::default()
        }
    }

    #[test]
    fn ads_exempt_must_be_a_boolean() {
        let patch = attr_patch("rsigma.ads.exempt", serde_json::json!("yes"));
        let spec = spec_with_overlays(vec![inline("d", Some(patch), None)]);
        let error = resolve_with("test", &spec, vec![detection("d")]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("rsigma.ads.exempt must be a boolean"),
            "{error}"
        );
    }

    #[test]
    fn appending_a_non_sequence_errors() {
        let patch = attr_patch("team", serde_json::json!("blue"));
        let spec = spec_with_overlays(vec![inline("d", None, Some(patch))]);
        let error = resolve_with("test", &spec, vec![detection("d")]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("append custom_attributes.team must be a sequence"),
            "{error}"
        );
    }

    #[test]
    fn file_or_dir_inside_an_overlay_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("overlay.yml");
        std::fs::write(
            &path,
            "- id: d\n  file: other.yml\n  set:\n    level: low\n",
        )
        .unwrap();
        let error = resolve_fs(file_entry(path), None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must not use file or dir inside an overlay file"),
            "{error}"
        );
    }

    #[test]
    fn a_missing_overlay_directory_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let error = resolve_fs(dir_entry(missing.clone()), None).unwrap_err();
        assert!(
            matches!(&error, RulesetError::Io { path, .. } if *path == missing),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("overlay directory does not exist"),
            "{error}"
        );
    }

    #[test]
    fn an_unparseable_overlay_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("overlay.yml");
        std::fs::write(&path, "- id: [unclosed\n").unwrap();
        let error = resolve_fs(file_entry(path), None).unwrap_err();
        assert!(
            error.to_string().contains("cannot parse overlay file"),
            "{error}"
        );
    }

    #[test]
    fn the_filesystem_loader_confines_overlay_files_and_dirs() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("overlay.yml");
        std::fs::write(&outside_file, "- id: d\n  set:\n    level: low\n").unwrap();

        let error = resolve_fs(file_entry(outside_file.clone()), Some(root.path())).unwrap_err();
        assert!(matches!(error, RulesetError::Confinement { .. }), "{error}");

        #[cfg(unix)]
        {
            let overlays = root.path().join("overlays");
            std::fs::create_dir(&overlays).unwrap();
            std::os::unix::fs::symlink(&outside_file, overlays.join("link.yml")).unwrap();
            let error = resolve_fs(dir_entry(overlays), Some(root.path())).unwrap_err();
            assert!(matches!(error, RulesetError::Confinement { .. }), "{error}");
        }
    }

    #[test]
    fn stale_overlays_name_unselected_and_dropped_targets() {
        let mut spec = spec_with_overlays(vec![inline("d", Some(level_patch("low")), None)]);
        spec.include = vec![RuleSelector {
            id: vec!["other".into()],
            ..Default::default()
        }];
        let error =
            resolve_with("test", &spec, vec![detection("d"), detection("other")]).unwrap_err();
        assert!(
            error.to_string().contains("is not matched by include"),
            "{error}"
        );

        let mut spec = spec_with_overlays(vec![inline("c", Some(level_patch("low")), None)]);
        spec.dependencies = Some("drop".into());
        spec.exclude = vec![RuleSelector {
            id: vec!["base".into()],
            ..Default::default()
        }];
        let error =
            resolve_with("test", &spec, vec![detection("base"), correlation("c")]).unwrap_err();
        assert!(error.to_string().contains("was dropped"), "{error}");
    }
}
