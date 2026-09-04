//! Rule drafting: turn exemplar events into a draft Sigma detection rule.
//!
//! The operator feeds exemplar events (the malicious or noteworthy ones),
//! optionally contrasted against a baseline corpus of normal traffic. This
//! module profiles every field across the exemplars, drops volatile fields
//! (timestamps, GUIDs, counters, high-entropy uniques), scores the rest by
//! stability across exemplars times rarity in the baseline, infers a value
//! form and a small Sigma modifier vocabulary per field, assembles a minimal
//! selection, and emits a complete draft rule as standard Sigma YAML.
//!
//! The draft is verified end-to-end before it is returned: the emitted YAML is
//! parsed via [`rsigma_parser::parse_sigma_yaml`] and compiled into the real
//! [`Engine`], every exemplar must match (with a bounded
//! predicate-drop relaxation and a minimum-field floor that errors instead of
//! emitting an over-broad draft), and the baseline hit count and rate are
//! recorded as the draft's estimated false-positive rate.
//!
//! The core is pure and deterministic: no randomness (the rule `id` is
//! caller-supplied; the CLI generates a UUIDv4), and repeated runs over the
//! same input yield byte-identical YAML. The draft uses the exemplars' native
//! field names, so it must be evaluated without a mapping pipeline.
//!
//! This is the detection-authoring sibling of
//! [`schema_discovery`](crate::schema_discovery): discovery mines unrecognized
//! events into schema signatures, drafting mines exemplar events into a
//! detection rule. Both follow the same contract: the tool proposes, a human
//! reviews and commits.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use crate::engine::Engine;
use crate::event::Event;
use crate::schema::SchemaClassifier;

pub(crate) mod draft_core;
use draft_core::*;

// =============================================================================
// Configuration
// =============================================================================

/// Tunables for a draft run. [`Default`] is a sensible starting point; the CLI
/// exposes each as a flag.
#[derive(Debug, Clone)]
pub struct DraftConfig {
    /// Maximum fields in a selection. Kept small so drafts stay readable.
    pub max_fields: usize,
    /// Relaxation floor: verification may drop failing fields down to this
    /// count, below it drafting errors instead of emitting an over-broad rule.
    pub min_fields: usize,
    /// Fraction (0.0-1.0) of exemplars a field must appear in to be a
    /// candidate. The default 1.0 keeps AND-selections sound.
    pub min_prevalence: f64,
    /// A field whose distinct exemplar values do not exceed this cap is
    /// "enumerable" and emitted as an OR value list.
    pub max_value_cardinality: usize,
    /// Minimum length of a shared prefix/suffix/token before it becomes a
    /// `startswith`/`endswith`/`contains` pattern, so short generic fragments
    /// are never chosen.
    pub min_token_len: usize,
    /// A `contains` token matching more than this fraction of baseline events
    /// is rejected as too generic.
    pub max_baseline_token_prevalence: f64,
    /// Force these fields into the selection (a warning is recorded when a
    /// forced field is absent from some exemplars).
    pub include_fields: Vec<String>,
    /// Never consider these fields.
    pub exclude_fields: Vec<String>,
    /// Rule title override; derived from the dominant marker when unset.
    pub title: Option<String>,
    /// Rule `id`. The core is deterministic and never generates one; the CLI
    /// passes a fresh UUIDv4. Unset omits the `id` key (lint reports it).
    pub rule_id: Option<String>,
    /// Rule `date` (YYYY-MM-DD). Defaults to today (UTC) when unset; tests
    /// pass a fixed date for byte-identical output.
    pub date: Option<String>,
    /// Logsource overrides; each set dimension wins over inference.
    pub logsource_category: Option<String>,
    pub logsource_product: Option<String>,
    pub logsource_service: Option<String>,
    /// Evaluate the final draft against the baseline (the baseline is still
    /// used for contrastive scoring when this is off).
    pub evaluate_baseline: bool,
}

impl Default for DraftConfig {
    fn default() -> Self {
        Self {
            max_fields: 4,
            min_fields: 2,
            min_prevalence: 1.0,
            max_value_cardinality: 4,
            min_token_len: 4,
            max_baseline_token_prevalence: 0.05,
            include_fields: Vec::new(),
            exclude_fields: Vec::new(),
            title: None,
            rule_id: None,
            date: None,
            logsource_category: None,
            logsource_product: None,
            logsource_service: None,
            evaluate_baseline: true,
        }
    }
}

// =============================================================================
// Errors
// =============================================================================

/// Why a draft could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum DraftError {
    /// No exemplar events were provided.
    #[error("no exemplar events to draft from")]
    NoExemplars,
    /// No field survived profiling (all volatile, excluded, or below the
    /// prevalence threshold).
    #[error(
        "no candidate fields: every field was volatile (timestamps, ids, unique values), \
         excluded, or below the prevalence threshold ({0} exemplars profiled)"
    )]
    NoCandidateFields(usize),
    /// Even after relaxing to the minimum-field floor the draft does not match
    /// every exemplar, so an honest rule cannot be emitted.
    #[error(
        "draft cannot match all exemplars: {matched}/{total} match at the {floor}-field floor; \
         exemplars may be too heterogeneous for one rule (failing exemplar indexes: {failing:?})"
    )]
    CannotMatchExemplars {
        matched: usize,
        total: usize,
        floor: usize,
        failing: Vec<usize>,
    },
    /// A field forced via `include_fields` is absent from some exemplars, so
    /// no draft containing it can match them. Forced fields are user intent
    /// and are never dropped by relaxation.
    #[error(
        "forced field(s) {fields:?} are absent from exemplar(s) {failing:?}; \
         remove the --include-field or drop those exemplars"
    )]
    ForcedFieldMismatch {
        fields: Vec<String>,
        failing: Vec<usize>,
    },
    /// The emitted YAML failed to parse or compile (a bug, surfaced honestly).
    #[error("internal error: emitted draft failed to {stage}: {message}")]
    Internal { stage: String, message: String },
}

// =============================================================================
// Public report types
// =============================================================================

/// How a field's values behave across the exemplars.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stability {
    /// The same value in every exemplar.
    Constant,
    /// A small distinct value set (an OR list).
    Enumerable,
    /// Differing values sharing a prefix, suffix, or token.
    Patterned,
    /// No usable structure; never selected.
    Volatile,
}

impl fmt::Display for Stability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Stability::Constant => "constant",
            Stability::Enumerable => "enumerable",
            Stability::Patterned => "patterned",
            Stability::Volatile => "volatile",
        };
        f.write_str(s)
    }
}

/// One profiled field in the report, ranked.
#[derive(Debug, Clone, Serialize)]
pub struct DraftFieldReport {
    /// Dot-joined field path.
    pub field: String,
    /// Contrastive score used for ranking (higher is better).
    pub score: f64,
    /// Value-stability class across the exemplars.
    pub stability: Stability,
    /// Sigma modifier chain chosen for the field (empty for a plain match).
    pub modifier: String,
    /// Display values or derived pattern, capped.
    pub values: Vec<String>,
    /// Fraction of baseline events this field's value form matches, when a
    /// baseline was provided.
    pub baseline_prevalence: Option<f64>,
    /// Whether the field made it into the final selection.
    pub selected: bool,
}

/// The result of a draft run: the rule plus the evidence behind it.
#[derive(Debug, Clone)]
pub struct DraftReport {
    /// The complete draft rule, standard Sigma YAML, parse- and lint-checked.
    pub rule_yaml: String,
    /// Profiled candidate fields, ranked (selected fields first).
    pub fields: Vec<DraftFieldReport>,
    /// Number of exemplar events.
    pub exemplar_total: usize,
    /// Exemplars the final draft matches (always equals `exemplar_total`; a
    /// draft that cannot match every exemplar is an error, not a result).
    pub exemplar_matched: usize,
    /// Number of baseline events provided.
    pub baseline_total: usize,
    /// Baseline events the draft matches (its estimated false-positive count),
    /// when the baseline evaluation ran.
    pub baseline_hits: Option<usize>,
    /// `baseline_hits / baseline_total` (0.0-1.0), when computed.
    pub baseline_hit_rate: Option<f64>,
    /// Advisory notes: lint findings, relaxation drops, inference caveats.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct DraftCandidate {
    pub(crate) profiles: Vec<DraftFieldProfile>,
    pub(crate) selected: Vec<usize>,
    logsource: DraftLogsource,
    pub(crate) warnings: Vec<String>,
}

impl DraftCandidate {
    pub(crate) fn build<E: Event>(
        exemplars: &[E],
        baseline: &[E],
        config: &DraftConfig,
    ) -> Result<Self, DraftError> {
        if exemplars.is_empty() {
            return Err(DraftError::NoExemplars);
        }
        let mut warnings = Vec::new();
        let mut profiles = profile_fields(exemplars, config, &mut warnings);
        if profiles.is_empty() {
            return Err(DraftError::NoCandidateFields(exemplars.len()));
        }
        for profile in &mut profiles {
            infer_form(profile, config);
        }
        if !baseline.is_empty() {
            for profile in &mut profiles {
                apply_baseline(profile, baseline, config);
            }
        }
        let has_baseline = !baseline.is_empty();
        for profile in &mut profiles {
            profile.score = score_field(profile, has_baseline);
        }
        profiles.sort_by(|a, b| {
            b.forced
                .cmp(&a.forced)
                .then_with(|| {
                    b.score
                        .partial_cmp(&a.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.field().cmp(b.field()))
        });
        let usable: Vec<usize> = profiles
            .iter()
            .enumerate()
            .filter(|(_, profile)| {
                profile.form.is_some() && profile.stability != Stability::Volatile
            })
            .map(|(index, _)| index)
            .collect();
        if usable.is_empty() {
            return Err(DraftError::NoCandidateFields(exemplars.len()));
        }
        let selected: Vec<usize> = usable.iter().copied().take(config.max_fields).collect();
        if selected.len() < config.min_fields {
            warnings.push(format!(
                "only {} usable field(s) found (floor is {}); the draft may be broad",
                selected.len(),
                config.min_fields
            ));
        }
        let logsource = infer_logsource(exemplars, config, &mut warnings);
        Ok(Self {
            profiles,
            selected,
            logsource,
            warnings,
        })
    }

    pub(crate) fn emit<E: Event>(&self, exemplars: &[E], config: &DraftConfig) -> String {
        let detection = build_detection(&self.profiles, &self.selected, exemplars, config);
        emit_rule_yaml(
            &self.profiles,
            &self.selected,
            &detection,
            &self.logsource,
            config,
        )
    }

    pub(crate) fn drop_lowest_eligible(&mut self, failing: Option<&[usize]>) -> Option<usize> {
        let absent_in_failing = |index: usize| {
            failing.is_some_and(|indexes| {
                indexes
                    .iter()
                    .any(|&event| self.profiles[index].values[event].is_none())
            })
        };
        let position = self
            .selected
            .iter()
            .rposition(|&index| !self.profiles[index].forced && absent_in_failing(index))
            .or_else(|| {
                self.selected
                    .iter()
                    .rposition(|&index| !self.profiles[index].forced)
            })?;
        Some(self.selected.remove(position))
    }
}

// =============================================================================
// Entry point
// =============================================================================

/// Draft a Sigma detection rule from exemplar events, optionally contrasted
/// against a baseline corpus (pass an empty slice for no baseline).
///
/// The returned draft is guaranteed to parse, compile, and match every
/// exemplar; drafting errors instead of emitting a rule that does not.
pub fn draft_rule<E: Event>(
    exemplars: &[E],
    baseline: &[E],
    config: &DraftConfig,
) -> Result<DraftReport, DraftError> {
    let mut candidate = DraftCandidate::build(exemplars, baseline, config)?;
    let floor = config.min_fields.min(candidate.selected.len()).max(1);

    // ---- Emit + verify (bounded relaxation) --------------------------------
    let (yaml, matched, failing) = loop {
        let yaml = candidate.emit(exemplars, config);
        let engine = compile_draft(&yaml)?;
        let failing: Vec<usize> = exemplars
            .iter()
            .enumerate()
            .filter(|(_, e)| engine.evaluate(e).is_empty())
            .map(|(i, _)| i)
            .collect();
        if failing.is_empty() {
            break (yaml, exemplars.len(), failing);
        }

        // A field is a provable culprit when it is absent from a failing
        // exemplar (the common case: partial-prevalence fields admitted by
        // `min_prevalence`).
        let absent_in_failing = |i: usize| {
            failing
                .iter()
                .any(|&idx| candidate.profiles[i].values[idx].is_none())
        };

        // A forced field that provably breaks the match is a user decision we
        // refuse to override; dropping other fields could never fix it, so
        // error out immediately with the culprit named.
        let forced_culprits: Vec<String> = candidate
            .selected
            .iter()
            .filter(|&&i| candidate.profiles[i].forced && absent_in_failing(i))
            .map(|&i| candidate.profiles[i].field().to_string())
            .collect();
        if !forced_culprits.is_empty() {
            return Err(DraftError::ForcedFieldMismatch {
                fields: forced_culprits,
                failing,
            });
        }

        if candidate.selected.len() <= floor {
            return Err(DraftError::CannotMatchExemplars {
                matched: exemplars.len() - failing.len(),
                total: exemplars.len(),
                floor,
                failing,
            });
        }

        // Drop the lowest-ranked non-forced culprit; when no field is provably
        // at fault (a value-form edge case), shed the weakest non-forced field.
        let Some(dropped) = candidate.drop_lowest_eligible(Some(&failing)) else {
            return Err(DraftError::CannotMatchExemplars {
                matched: exemplars.len() - failing.len(),
                total: exemplars.len(),
                floor,
                failing,
            });
        };
        candidate.warnings.push(format!(
            "relaxed: dropped field '{}' because the draft did not match every exemplar with it",
            candidate.profiles[dropped].field()
        ));
    };
    debug_assert!(failing.is_empty());

    // ---- Baseline hits ------------------------------------------------------
    let (baseline_hits, baseline_hit_rate) = if !baseline.is_empty() && config.evaluate_baseline {
        let engine = compile_draft(&yaml)?;
        let hits = baseline
            .iter()
            .filter(|e| !engine.evaluate(e).is_empty())
            .count();
        let rate = hits as f64 / baseline.len() as f64;
        if hits > 0 {
            candidate.warnings.push(format!(
                "draft matches {hits}/{} baseline events ({:.1}%); consider a tighter field",
                baseline.len(),
                rate * 100.0
            ));
        }
        (Some(hits), Some(rate))
    } else {
        (None, None)
    };

    // ---- Lint ----------------------------------------------------------------
    for w in rsigma_parser::lint_yaml_str(&yaml) {
        candidate
            .warnings
            .push(format!("lint {}: {}", w.rule, w.message));
    }

    // ---- Report ---------------------------------------------------------------
    let selected_set: BTreeSet<usize> = candidate.selected.iter().copied().collect();
    let fields = candidate
        .profiles
        .iter()
        .enumerate()
        .map(|(i, p)| DraftFieldReport {
            field: p.field().to_string(),
            score: p.score,
            stability: p.stability,
            modifier: p
                .form
                .as_ref()
                .map(|f| f.modifier().trim_start_matches('|').to_string())
                .unwrap_or_default(),
            values: p
                .form
                .as_ref()
                .map(|f| f.display_values())
                .unwrap_or_else(|| {
                    p.distinct()
                        .into_iter()
                        .take(4)
                        .map(|v| v.as_display())
                        .collect()
                }),
            baseline_prevalence: p.baseline_prevalence,
            selected: selected_set.contains(&i),
        })
        .collect();

    Ok(DraftReport {
        rule_yaml: yaml,
        fields,
        exemplar_total: exemplars.len(),
        exemplar_matched: matched,
        baseline_total: baseline.len(),
        baseline_hits,
        baseline_hit_rate,
        warnings: candidate.warnings,
    })
}

// =============================================================================
// Selection assembly and grouping
// =============================================================================

/// One named selection: field, modifier chain, and values in emission order.
struct Selection {
    name: String,
    entries: Vec<(String, ValueForm)>,
}

struct DetectionBlock {
    selections: Vec<Selection>,
    condition: String,
}

fn build_detection<E: Event>(
    profiles: &[DraftFieldProfile],
    selected: &[usize],
    exemplars: &[E],
    config: &DraftConfig,
) -> DetectionBlock {
    // Try a value-group split: partition exemplars by the highest-ranked
    // selected field with a small distinct value set, and split only when it
    // makes another multi-valued field single-valued in every partition.
    if let Some(block) = try_group_split(profiles, selected, exemplars, config) {
        return block;
    }
    let entries: Vec<(String, ValueForm)> = selected
        .iter()
        .filter_map(|&i| {
            profiles[i]
                .form
                .clone()
                .map(|f| (profiles[i].field().to_string(), f))
        })
        .collect();
    DetectionBlock {
        selections: vec![Selection {
            name: "selection".to_string(),
            entries,
        }],
        condition: "selection".to_string(),
    }
}

const MAX_VALUE_GROUPS: usize = 3;

fn try_group_split<E: Event>(
    profiles: &[DraftFieldProfile],
    selected: &[usize],
    exemplars: &[E],
    config: &DraftConfig,
) -> Option<DetectionBlock> {
    if selected.len() < 2 || exemplars.len() < 2 {
        return None;
    }
    // Splitter: first selected field (rank order) with 2..=MAX_VALUE_GROUPS
    // distinct string values.
    let (splitter_pos, splitter) = selected.iter().enumerate().find_map(|(pos, &i)| {
        let p = &profiles[i];
        let d = p.distinct();
        let all_str = d.iter().all(|v| matches!(v, DraftValue::Str(_)));
        if all_str && d.len() >= 2 && d.len() <= MAX_VALUE_GROUPS {
            Some((pos, i))
        } else {
            None
        }
    })?;

    // Partition exemplar indexes by the splitter value, in first-seen order.
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    for (idx, v) in profiles[splitter].values.iter().enumerate() {
        let key = v.as_ref()?.as_display();
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, members)) => members.push(idx),
            None => groups.push((key, vec![idx])),
        }
    }
    if groups.len() < 2 {
        return None;
    }
    // Every group needs real support; splitting one exemplar per selection
    // would just memorize the input.
    if groups.iter().any(|(_, members)| members.len() < 2) {
        return None;
    }

    // The split must earn its keep: some other selected field is multi-valued
    // globally but single-valued within every partition.
    let improves = selected.iter().enumerate().any(|(pos, &i)| {
        if pos == splitter_pos {
            return false;
        }
        let p = &profiles[i];
        if p.distinct().len() < 2 {
            return false;
        }
        groups.iter().all(|(_, members)| {
            let mut vals = members.iter().filter_map(|&m| p.values[m].as_ref());
            let first = vals.next();
            first.is_some() && vals.all(|v| Some(v) == first)
        })
    });
    if !improves {
        return None;
    }

    // Build one selection per group, deriving per-group forms.
    let mut used_names: BTreeMap<String, u32> = BTreeMap::new();
    let selections: Vec<Selection> = groups
        .iter()
        .map(|(key, members)| {
            let entries: Vec<(String, ValueForm)> = selected
                .iter()
                .filter_map(|&i| {
                    let p = &profiles[i];
                    let mut distinct: Vec<DraftValue> = Vec::new();
                    for &m in members {
                        if let Some(v) = &p.values[m]
                            && !distinct.contains(v)
                        {
                            distinct.push(v.clone());
                        }
                    }
                    derive_form(&distinct, config).map(|f| (p.field().to_string(), f))
                })
                .collect();
            let base = selection_slug(key);
            let n = used_names.entry(base.clone()).or_insert(0);
            *n += 1;
            let name = if *n == 1 {
                format!("selection_{base}")
            } else {
                format!("selection_{base}_{n}")
            };
            Selection { name, entries }
        })
        .collect();

    Some(DetectionBlock {
        selections,
        condition: "1 of selection_*".to_string(),
    })
}

/// A short selection-name suffix from a splitter value: the first token of the
/// last path segment's stem (`C:\W\vssadmin.exe` and `vssadmin delete shadows`
/// both slug to `vssadmin`), lowercased.
fn selection_slug(value: &str) -> String {
    let last_segment = value.rsplit(['\\', '/']).next().unwrap_or(value);
    let stem = last_segment
        .split_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(last_segment);
    let first_token = stem
        .split(|c: char| !c.is_ascii_alphanumeric())
        .find(|t| !t.is_empty())
        .unwrap_or("");
    let out: String = first_token.to_ascii_lowercase();
    if out.is_empty() {
        "group".to_string()
    } else {
        out
    }
}

// =============================================================================
// Logsource inference
// =============================================================================

#[derive(Debug, Clone, Default)]
struct DraftLogsource {
    category: Option<String>,
    product: Option<String>,
    service: Option<String>,
    inferred: bool,
}

/// Sysmon EventID to Sigma category, for the unambiguous mappings only.
fn sysmon_category(event_id: i64) -> Option<&'static str> {
    Some(match event_id {
        1 => "process_creation",
        3 => "network_connection",
        6 => "driver_load",
        7 => "image_load",
        8 => "create_remote_thread",
        10 => "process_access",
        11 => "file_event",
        22 => "dns_query",
        23 => "file_delete",
        _ => return None,
    })
}

fn infer_logsource<E: Event>(
    exemplars: &[E],
    config: &DraftConfig,
    warnings: &mut Vec<String>,
) -> DraftLogsource {
    let mut out = DraftLogsource::default();

    // Majority schema over the exemplars.
    let classifier = SchemaClassifier::builtin();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for e in exemplars {
        if let Some(m) = classifier.classify(e) {
            *counts.entry(m.name).or_insert(0) += 1;
        }
    }
    let majority = counts
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(name, _)| name.as_str());

    match majority {
        Some("sysmon") => {
            out.product = Some("windows".to_string());
            // One shared EventID across all exemplars maps to a category and
            // drops the service (Sigma sysmon rules use category + product).
            let ids: BTreeSet<i64> = exemplars
                .iter()
                .filter_map(|e| e.get_field("EventID").and_then(|v| v.as_i64()))
                .collect();
            let category = if ids.len() == 1 {
                ids.first().copied().and_then(sysmon_category)
            } else {
                None
            };
            match category {
                Some(c) => out.category = Some(c.to_string()),
                None => out.service = Some("sysmon".to_string()),
            }
            out.inferred = true;
        }
        Some("windows_eventlog") | Some("ecs_windows") => {
            out.product = Some("windows".to_string());
            out.inferred = true;
        }
        Some("ecs_linux") => {
            out.product = Some("linux".to_string());
            out.inferred = true;
        }
        _ => {}
    }

    // Overrides win per dimension.
    if config.logsource_category.is_some() {
        out.category = config.logsource_category.clone();
        out.inferred = true;
    }
    if config.logsource_product.is_some() {
        out.product = config.logsource_product.clone();
        out.inferred = true;
    }
    if config.logsource_service.is_some() {
        out.service = config.logsource_service.clone();
        out.inferred = true;
    }

    if !out.inferred {
        warnings.push(
            "logsource could not be inferred from the exemplars; \
             replace the 'todo' placeholder before committing"
                .to_string(),
        );
        out.product = Some("todo".to_string());
    }
    out
}

/// A short human marker for the title, from the dominant (first selected)
/// field's form.
fn title_marker(profiles: &[DraftFieldProfile], selected: &[usize]) -> Option<String> {
    let first = selected.first().map(|&i| &profiles[i])?;
    let form = first.form.as_ref()?;
    let raw = match form {
        ValueForm::Exact(v) => v.as_display(),
        ValueForm::OneOf(vs) => vs.first().map(|v| v.as_display()).unwrap_or_default(),
        ValueForm::EndsWith(s) | ValueForm::StartsWith(s) | ValueForm::Contains(s) => s.clone(),
        ValueForm::ContainsAll(ts) => ts.first().cloned().unwrap_or_default(),
    };
    let trimmed = raw.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if trimmed.is_empty() {
        None
    } else {
        Some(format!("{trimmed} ({})", first.field()))
    }
}

fn emit_rule_yaml(
    profiles: &[DraftFieldProfile],
    selected: &[usize],
    detection: &DetectionBlock,
    logsource: &DraftLogsource,
    config: &DraftConfig,
) -> String {
    let title = config.title.clone().unwrap_or_else(|| {
        title_marker(profiles, selected)
            .map(|m| format!("Draft: {m}"))
            .unwrap_or_else(|| "Draft rule".to_string())
    });
    let date = config
        .date
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());

    let mut out = String::new();
    out.push_str(&format!("title: {}\n", yaml_title_str(&title)));
    if let Some(id) = &config.rule_id {
        out.push_str(&format!("id: {id}\n"));
    }
    out.push_str("status: experimental\n");
    out.push_str("description: 'TODO: describe what this rule detects and why it matters.'\n");
    out.push_str("author: 'TODO: your name'\n");
    out.push_str(&format!("date: {date}\n"));
    out.push_str("logsource:\n");
    if let Some(c) = &logsource.category {
        out.push_str(&format!("    category: {}\n", yaml_str(c)));
    }
    if let Some(p) = &logsource.product {
        out.push_str(&format!("    product: {}\n", yaml_str(p)));
    }
    if let Some(s) = &logsource.service {
        out.push_str(&format!("    service: {}\n", yaml_str(s)));
    }
    out.push_str("detection:\n");
    for sel in &detection.selections {
        out.push_str(&format!("    {}:\n", sel.name));
        for (field, form) in &sel.entries {
            emit_form(&mut out, field, form, "        ");
        }
    }
    out.push_str(&format!("    condition: {}\n", detection.condition));
    out.push_str("falsepositives:\n");
    out.push_str("    - 'TODO: list known benign triggers.'\n");
    out.push_str("level: medium\n");
    out
}

// =============================================================================
// Verification
// =============================================================================

fn compile_draft(yaml: &str) -> Result<Engine, DraftError> {
    let collection = rsigma_parser::parse_sigma_yaml(yaml).map_err(|e| DraftError::Internal {
        stage: "parse".to_string(),
        message: e.to_string(),
    })?;
    let mut engine = Engine::new();
    engine
        .add_collection(&collection)
        .map_err(|e| DraftError::Internal {
            stage: "compile".to_string(),
            message: e.to_string(),
        })?;
    Ok(engine)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::JsonEvent;
    use serde_json::{Value, json};

    fn events(values: &[Value]) -> Vec<JsonEvent<'_>> {
        values.iter().map(JsonEvent::borrow).collect()
    }

    fn fixed_config() -> DraftConfig {
        DraftConfig {
            rule_id: Some("00000000-0000-4000-8000-000000000000".to_string()),
            date: Some("2026-07-03".to_string()),
            ..DraftConfig::default()
        }
    }

    fn draft(
        exemplars: &[Value],
        baseline: &[Value],
        config: &DraftConfig,
    ) -> Result<DraftReport, DraftError> {
        draft_rule(&events(exemplars), &events(baseline), config)
    }

    // ---- Volatility heuristics ---------------------------------------------

    #[test]
    fn timestamp_names_and_values_are_volatile() {
        assert!(is_volatile_name("UtcTime"));
        assert!(is_volatile_name("@timestamp"));
        assert!(is_volatile_name("event.created_date"));
        assert!(is_volatile_value(&DraftValue::Str(
            "2026-07-03T12:00:00Z".into()
        )));
        assert!(is_volatile_value(&DraftValue::Str("2026-07-03".into())));
        assert!(!is_volatile_value(&DraftValue::Str("whoami.exe".into())));
    }

    #[test]
    fn uuid_values_and_guid_names_are_volatile() {
        assert!(is_volatile_name("ProcessGuid"));
        assert!(is_uuid_string("6bde842e-a2f4-441e-b027-3aa79b1b2fc2"));
        assert!(is_uuid_string("{6bde842e-a2f4-441e-b027-3aa79b1b2fc2}"));
        assert!(!is_uuid_string("not-a-uuid"));
    }

    #[test]
    fn counter_names_and_epoch_values_are_volatile() {
        assert!(is_volatile_name("ProcessId"));
        assert!(is_volatile_name("Event.System.EventRecordID"));
        assert!(is_volatile_name("logon_id"));
        assert!(is_epoch_number(1_751_500_000.0)); // seconds
        assert!(is_epoch_number(1_751_500_000_000.0)); // milliseconds
        assert!(!is_epoch_number(4688.0)); // an EventID is not an epoch
    }

    #[test]
    fn time_date_name_match_is_word_bounded() {
        // Real timestamp fields are volatile...
        assert!(is_volatile_name("EventTime"));
        assert!(is_volatile_name("event_date"));
        assert!(is_volatile_name("datetime"));
        // ...but content fields that merely contain "time"/"date" as a
        // substring are not (regression: substring matching dropped these).
        assert!(!is_volatile_name("runtime"));
        assert!(!is_volatile_name("update"));
        assert!(!is_volatile_name("candidate"));
        assert!(!is_volatile_name("CommandLine"));
        assert!(!is_volatile_name("validate_action"));
    }

    #[test]
    fn shared_affix_never_splits_a_multibyte_char() {
        // The common byte run ends inside 'é' (both é and è start 0xC3), so the
        // prefix must snap to a char boundary rather than panic on the slice.
        assert_eq!(
            shared_prefix(&["abcé1", "abcè2"], 3).as_deref(),
            Some("abc")
        );
        assert_eq!(shared_prefix(&["abcé1", "abcè2"], 4), None);
        // Suffix: 'Ω' and 'é' both end in the continuation byte 0xA9, so the
        // overlap starts mid-character; snapping up yields no suffix and no panic.
        assert_eq!(shared_suffix(&["x\u{03a9}", "y\u{00e9}"], 1), None);
        // A fully-shared multibyte affix is preserved intact.
        assert_eq!(
            shared_suffix(&["1éabc", "2éabc"], 3).as_deref(),
            Some("éabc")
        );
    }

    #[test]
    fn random_unique_values_are_volatile() {
        let exemplars: Vec<Value> = (0..4)
            .map(|i| {
                json!({
                    "tool": "runner",
                    "task": "sync",
                    "token": format!("a9f{i}c2d4e6b8a0f1c3d5e7f9b1a3c5d{i}"),
                })
            })
            .collect();
        let report = draft(&exemplars, &[], &fixed_config()).unwrap();
        let token = report.fields.iter().find(|f| f.field == "token").unwrap();
        assert_eq!(token.stability, Stability::Volatile);
        assert!(!token.selected);
    }

    // ---- Scoring -------------------------------------------------------------

    #[test]
    fn baseline_contrast_prefers_rare_fields() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"action": "exfil", "proto": "tcp"}))
            .collect();
        // proto: tcp is ubiquitous in the baseline; action: exfil never occurs.
        let baseline: Vec<Value> = (0..20)
            .map(|i| json!({"action": format!("browse{i}"), "proto": "tcp"}))
            .collect();
        let report = draft(&exemplars, &baseline, &fixed_config()).unwrap();
        let action = report.fields.iter().find(|f| f.field == "action").unwrap();
        let proto = report.fields.iter().find(|f| f.field == "proto").unwrap();
        assert!(
            action.score > proto.score,
            "baseline-rare field must outrank the ubiquitous one"
        );
        assert_eq!(proto.baseline_prevalence, Some(1.0));
        assert_eq!(action.baseline_prevalence, Some(0.0));
    }

    #[test]
    fn structural_fields_are_demoted_without_baseline() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"hostname": "web-01", "action": "exfil"}))
            .collect();
        let report = draft(&exemplars, &[], &fixed_config()).unwrap();
        let host = report
            .fields
            .iter()
            .find(|f| f.field == "hostname")
            .unwrap();
        let action = report.fields.iter().find(|f| f.field == "action").unwrap();
        assert!(action.score > host.score);
    }

    #[test]
    fn deterministic_output_across_runs() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"vendor": "acme", "action": "alert", "sig": "S-1001"}))
            .collect();
        let a = draft(&exemplars, &[], &fixed_config()).unwrap().rule_yaml;
        let b = draft(&exemplars, &[], &fixed_config()).unwrap().rule_yaml;
        assert_eq!(a, b, "draft output must be byte-identical across runs");
    }

    #[test]
    fn structured_candidate_reemits_deterministically_after_drop() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"vendor": "acme", "action": "alert", "kind": "auth"}))
            .collect();
        let events = events(&exemplars);
        let mut candidate = DraftCandidate::build(&events, &[], &fixed_config()).unwrap();
        assert!(candidate.drop_lowest_eligible(None).is_some());
        let first = candidate.emit(&events, &fixed_config());
        let second = candidate.emit(&events, &fixed_config());
        assert_eq!(first, second);
    }

    #[test]
    fn structured_candidate_never_drops_forced_fields() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"forced": "keep", "action": "alert"}))
            .collect();
        let events = events(&exemplars);
        let config = DraftConfig {
            include_fields: vec!["forced".to_string()],
            max_fields: 1,
            ..fixed_config()
        };
        let mut candidate = DraftCandidate::build(&events, &[], &config).unwrap();
        assert!(candidate.drop_lowest_eligible(None).is_none());
        assert_eq!(candidate.profiles[candidate.selected[0]].field(), "forced");
    }

    #[test]
    fn structured_candidate_excludes_all_grouping_fields() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"tenant": "one", "user": "alice", "action": "alert"}))
            .collect();
        let events = events(&exemplars);
        let config = DraftConfig {
            exclude_fields: vec!["tenant".to_string(), "user".to_string()],
            ..fixed_config()
        };
        let candidate = DraftCandidate::build(&events, &[], &config).unwrap();
        assert!(
            candidate
                .profiles
                .iter()
                .all(|profile| !matches!(profile.field(), "tenant" | "user"))
        );
    }

    // ---- Modifier inference ---------------------------------------------------

    #[test]
    fn shared_path_tail_becomes_endswith() {
        let exemplars = vec![
            json!({"Image": "C:\\Tools\\whoami.exe", "kind": "proc"}),
            json!({"Image": "C:\\Windows\\System32\\whoami.exe", "kind": "proc"}),
            json!({"Image": "D:\\stage\\whoami.exe", "kind": "proc"}),
            json!({"Image": "E:\\x\\whoami.exe", "kind": "proc"}),
            json!({"Image": "F:\\y\\whoami.exe", "kind": "proc"}),
        ];
        let cfg = DraftConfig {
            max_value_cardinality: 3,
            ..fixed_config()
        };
        let report = draft(&exemplars, &[], &cfg).unwrap();
        assert!(
            report.rule_yaml.contains("Image|endswith: '\\whoami.exe'"),
            "expected endswith derivation, got:\n{}",
            report.rule_yaml
        );
    }

    #[test]
    fn shared_prefix_becomes_startswith() {
        let exemplars: Vec<Value> = (0..5)
            .map(|i| json!({"url": format!("https://evil.example/payload{i}"), "verb": "GET"}))
            .collect();
        let cfg = DraftConfig {
            max_value_cardinality: 3,
            ..fixed_config()
        };
        let report = draft(&exemplars, &[], &cfg).unwrap();
        assert!(
            report
                .rule_yaml
                .contains("url|startswith: 'https://evil.example/payload'"),
            "expected startswith derivation, got:\n{}",
            report.rule_yaml
        );
    }

    #[test]
    fn short_generic_tokens_are_never_chosen() {
        // The only shared token is 3 chars ("run"), below min_token_len 4.
        let exemplars: Vec<Value> = (0..5)
            .map(|i| json!({"cmd": format!("{i}zz run q{i}"), "kind": "x"}))
            .collect();
        let cfg = DraftConfig {
            max_value_cardinality: 3,
            ..fixed_config()
        };
        let report = draft(&exemplars, &[], &cfg).unwrap();
        let cmd = report.fields.iter().find(|f| f.field == "cmd").unwrap();
        assert_eq!(cmd.stability, Stability::Volatile);
        assert!(!report.rule_yaml.contains("cmd|contains"));
    }

    #[test]
    fn baseline_generic_token_is_rejected() {
        // "powershell" is a stable exemplar token but ubiquitous in baseline.
        let exemplars: Vec<Value> = (0..5)
            .map(|i| json!({"proc": format!("powershell -x {i}q{i}w{i}"), "kind": "spawn"}))
            .collect();
        let baseline: Vec<Value> = (0..20)
            .map(|i| json!({"proc": format!("powershell -File login{i}.ps1"), "kind": "spawn"}))
            .collect();
        let cfg = DraftConfig {
            max_value_cardinality: 3,
            min_fields: 1,
            ..fixed_config()
        };
        let report = draft(&exemplars, &baseline, &cfg).unwrap();
        assert!(
            !report.rule_yaml.contains("proc|contains: powershell"),
            "generic baseline token must be rejected, got:\n{}",
            report.rule_yaml
        );
    }

    #[test]
    fn wildcard_specials_in_values_are_escaped() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"query": "SELECT * FROM users?", "app": "dbd"}))
            .collect();
        let report = draft(&exemplars, &[], &fixed_config()).unwrap();
        assert!(
            report.rule_yaml.contains(r"SELECT \* FROM users\?"),
            "wildcards must be escaped, got:\n{}",
            report.rule_yaml
        );
        // And the escaped rule still matches the exemplars end-to-end (the
        // verification loop enforces this; assert the report agrees).
        assert_eq!(report.exemplar_matched, 3);
    }

    #[test]
    fn escape_sigma_value_handles_backslash_adjacency() {
        assert_eq!(escape_sigma_value(r"C:\Windows"), r"C:\Windows");
        assert_eq!(escape_sigma_value("a*b"), r"a\*b");
        assert_eq!(escape_sigma_value("a?b"), r"a\?b");
        assert_eq!(escape_sigma_value(r"a\*b"), r"a\\\*b");
        assert_eq!(escape_sigma_value(r"a\\b"), r"a\\\\b");
        assert_eq!(escape_sigma_value(r"trailing\"), r"trailing\\");
    }

    // ---- Grouping ----------------------------------------------------------------

    #[test]
    fn distinct_value_groups_split_into_selections() {
        let exemplars = vec![
            json!({"Image": "C:\\W\\vssadmin.exe", "CommandLine": "vssadmin delete shadows", "k": "p"}),
            json!({"Image": "C:\\W\\vssadmin.exe", "CommandLine": "vssadmin delete shadows", "k": "p"}),
            json!({"Image": "C:\\W\\wmic.exe", "CommandLine": "wmic shadowcopy delete", "k": "p"}),
            json!({"Image": "C:\\W\\wmic.exe", "CommandLine": "wmic shadowcopy delete", "k": "p"}),
        ];
        let report = draft(&exemplars, &[], &fixed_config()).unwrap();
        assert!(
            report.rule_yaml.contains("condition: 1 of selection_*"),
            "expected a group split, got:\n{}",
            report.rule_yaml
        );
        assert!(report.rule_yaml.contains("selection_vssadmin:"));
        assert!(report.rule_yaml.contains("selection_wmic:"));
        assert_eq!(report.exemplar_matched, 4);
    }

    #[test]
    fn no_split_when_values_do_not_partition() {
        let exemplars: Vec<Value> = (0..4)
            .map(|_| json!({"vendor": "acme", "action": "alert"}))
            .collect();
        let report = draft(&exemplars, &[], &fixed_config()).unwrap();
        assert!(report.rule_yaml.contains("condition: selection\n"));
    }

    // ---- Logsource -------------------------------------------------------------

    #[test]
    fn sysmon_event_id_maps_to_category() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| {
                json!({
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "EventID": 1,
                    "Image": "C:\\W\\evil.exe",
                    "CommandLine": "evil.exe --run",
                })
            })
            .collect();
        let report = draft(&exemplars, &[], &fixed_config()).unwrap();
        assert!(report.rule_yaml.contains("category: process_creation"));
        assert!(report.rule_yaml.contains("product: windows"));
        assert!(!report.rule_yaml.contains("service: sysmon"));
    }

    #[test]
    fn sysmon_without_shared_event_id_keeps_service() {
        let exemplars = vec![
            json!({"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\W\\a.exe", "RuleName": "t"}),
            json!({"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 3, "Image": "C:\\W\\a.exe", "RuleName": "t"}),
        ];
        let report = draft(&exemplars, &[], &fixed_config()).unwrap();
        assert!(report.rule_yaml.contains("service: sysmon"));
        assert!(report.rule_yaml.contains("product: windows"));
    }

    #[test]
    fn logsource_overrides_win() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"vendor": "acme", "action": "alert"}))
            .collect();
        let cfg = DraftConfig {
            logsource_product: Some("acme_fw".to_string()),
            logsource_category: Some("firewall".to_string()),
            ..fixed_config()
        };
        let report = draft(&exemplars, &[], &cfg).unwrap();
        assert!(report.rule_yaml.contains("product: acme_fw"));
        assert!(report.rule_yaml.contains("category: firewall"));
        assert!(!report.rule_yaml.contains("todo"));
    }

    #[test]
    fn unknown_schema_gets_todo_placeholder() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"vendor": "acme", "action": "alert"}))
            .collect();
        let report = draft(&exemplars, &[], &fixed_config()).unwrap();
        assert!(report.rule_yaml.contains("product: todo"));
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("logsource could not be inferred"))
        );
    }

    // ---- Emission, round-trip, verification -----------------------------------

    #[test]
    fn draft_round_trips_and_matches_exemplars() {
        let exemplars: Vec<Value> = (0..4)
            .map(|_| json!({"vendor": "acme", "action": "exfil", "dst_port": 443}))
            .collect();
        let report = draft(&exemplars, &[], &fixed_config()).unwrap();
        // Parses and compiles (draft_rule already enforced it; do it again
        // from the public surface).
        let collection =
            rsigma_parser::parse_sigma_yaml(&report.rule_yaml).expect("emitted draft must parse");
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();
        for e in &events(&exemplars) {
            assert!(!engine.evaluate(e).is_empty(), "exemplar must match");
        }
        assert_eq!(report.exemplar_matched, report.exemplar_total);
        assert!(
            report
                .rule_yaml
                .contains("id: 00000000-0000-4000-8000-000000000000")
        );
        assert!(report.rule_yaml.contains("status: experimental"));
        assert!(report.rule_yaml.contains("level: medium"));
        assert!(report.rule_yaml.contains("date: 2026-07-03"));
    }

    #[test]
    fn typed_values_emit_as_numbers() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"vendor": "acme", "code": 4688}))
            .collect();
        let report = draft(&exemplars, &[], &fixed_config()).unwrap();
        assert!(
            report.rule_yaml.contains("code: 4688"),
            "integers must emit bare, got:\n{}",
            report.rule_yaml
        );
    }

    #[test]
    fn baseline_hits_are_counted_with_rate() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"vendor": "acme", "action": "alert"}))
            .collect();
        let mut baseline: Vec<Value> = (0..8)
            .map(|i| json!({"vendor": "other", "action": format!("a{i}")}))
            .collect();
        // Two baseline events the draft will also match.
        baseline.push(json!({"vendor": "acme", "action": "alert"}));
        baseline.push(json!({"vendor": "acme", "action": "alert"}));
        let report = draft(&exemplars, &baseline, &fixed_config()).unwrap();
        assert_eq!(report.baseline_total, 10);
        assert_eq!(report.baseline_hits, Some(2));
        assert!((report.baseline_hit_rate.unwrap() - 0.2).abs() < 1e-9);
        assert!(report.warnings.iter().any(|w| w.contains("baseline")));
    }

    #[test]
    fn skip_baseline_eval_keeps_scoring_but_not_hits() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"vendor": "acme", "action": "alert"}))
            .collect();
        let baseline: Vec<Value> = (0..5)
            .map(|i| json!({"vendor": "other", "action": format!("a{i}")}))
            .collect();
        let cfg = DraftConfig {
            evaluate_baseline: false,
            ..fixed_config()
        };
        let report = draft(&exemplars, &baseline, &cfg).unwrap();
        assert_eq!(report.baseline_hits, None);
        assert!(
            report
                .fields
                .iter()
                .any(|f| f.baseline_prevalence.is_some()),
            "contrastive scoring still uses the baseline"
        );
    }

    // ---- Relaxation and error paths ------------------------------------------

    #[test]
    fn relaxation_drops_partial_prevalence_fields() {
        // "extra" appears in half the exemplars; selecting it breaks the AND
        // selection, so verification must drop it and still succeed.
        let mut exemplars: Vec<Value> = (0..2)
            .map(|_| json!({"vendor": "acme", "action": "alert", "extra": "x"}))
            .collect();
        exemplars.extend((0..2).map(|_| json!({"vendor": "acme", "action": "alert"})));
        let cfg = DraftConfig {
            min_prevalence: 0.4,
            ..fixed_config()
        };
        let report = draft(&exemplars, &[], &cfg).unwrap();
        assert_eq!(report.exemplar_matched, 4);
        assert!(!report.rule_yaml.contains("extra"));
        assert!(report.warnings.iter().any(|w| w.contains("relaxed")));
    }

    #[test]
    fn floor_errors_instead_of_emitting_overbroad_draft() {
        // Two disjoint half-prevalence fields and nothing else: no 2-field AND
        // can match every exemplar, and the floor forbids going below 2.
        let mut exemplars: Vec<Value> = (0..2)
            .map(|_| json!({"alpha": "one", "beta": "x"}))
            .collect();
        exemplars.extend((0..2).map(|_| json!({"alpha": "two", "gamma": "y"})));
        let cfg = DraftConfig {
            min_prevalence: 0.4,
            min_fields: 2,
            max_value_cardinality: 1,
            ..fixed_config()
        };
        let err = draft(&exemplars, &[], &cfg).unwrap_err();
        assert!(
            matches!(err, DraftError::CannotMatchExemplars { floor: 2, .. }),
            "expected the floor error, got: {err}"
        );
    }

    #[test]
    fn forced_field_absent_from_exemplars_errors_immediately() {
        // "extra" is forced but absent from half the exemplars: relaxation
        // must not strip the useful fields around it, it must name the
        // culprit and stop.
        let mut exemplars: Vec<Value> = (0..2)
            .map(|_| json!({"vendor": "acme", "action": "alert", "extra": "x"}))
            .collect();
        exemplars.extend((0..2).map(|_| json!({"vendor": "acme", "action": "alert"})));
        let cfg = DraftConfig {
            include_fields: vec!["extra".to_string()],
            min_prevalence: 0.4,
            ..fixed_config()
        };
        let err = draft(&exemplars, &[], &cfg).unwrap_err();
        match err {
            DraftError::ForcedFieldMismatch { fields, failing } => {
                assert_eq!(fields, vec!["extra".to_string()]);
                assert_eq!(failing, vec![2, 3]);
            }
            other => panic!("expected ForcedFieldMismatch, got: {other}"),
        }
    }

    #[test]
    fn no_exemplars_is_an_error() {
        let err = draft(&[], &[], &fixed_config()).unwrap_err();
        assert!(matches!(err, DraftError::NoExemplars));
    }

    #[test]
    fn all_volatile_fields_is_an_error() {
        let exemplars: Vec<Value> = (0..3)
            .map(|i| {
                json!({
                    "UtcTime": format!("2026-07-03T12:00:0{i}Z"),
                    "ProcessGuid": format!("6bde842e-a2f4-441e-b027-3aa79b1b2fc{i}"),
                })
            })
            .collect();
        let err = draft(&exemplars, &[], &fixed_config()).unwrap_err();
        assert!(matches!(err, DraftError::NoCandidateFields(3)));
    }

    // ---- Flags -------------------------------------------------------------------

    #[test]
    fn include_and_exclude_fields_are_honored() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"vendor": "acme", "action": "alert", "noise": "same"}))
            .collect();
        let cfg = DraftConfig {
            include_fields: vec!["noise".to_string()],
            exclude_fields: vec!["vendor".to_string()],
            max_fields: 2,
            ..fixed_config()
        };
        let report = draft(&exemplars, &[], &cfg).unwrap();
        assert!(report.rule_yaml.contains("noise: same"));
        assert!(!report.rule_yaml.contains("vendor"));
    }

    #[test]
    fn title_override_and_derived_title() {
        let exemplars: Vec<Value> = (0..3)
            .map(|_| json!({"vendor": "acme", "action": "alert"}))
            .collect();
        let derived = draft(&exemplars, &[], &fixed_config()).unwrap();
        assert!(
            derived.rule_yaml.starts_with("title: 'Draft:")
                || derived.rule_yaml.starts_with("title: Draft"),
            "derived title expected, got:\n{}",
            derived.rule_yaml
        );
        let cfg = DraftConfig {
            title: Some("Acme Exfil Detection".to_string()),
            ..fixed_config()
        };
        let titled = draft(&exemplars, &[], &cfg).unwrap();
        assert!(titled.rule_yaml.starts_with("title: Acme Exfil Detection"));
    }
}
