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
//! [`Engine`](crate::Engine), every exemplar must match (with a bounded
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
use crate::event::{Event, EventValue};
use crate::schema::SchemaClassifier;
use crate::schema_discovery::FieldProfile;

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

// =============================================================================
// Internal value and form model
// =============================================================================

/// A scalar exemplar value, kept typed so numbers emit as numbers.
#[derive(Debug, Clone, PartialEq)]
enum DraftValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

impl DraftValue {
    fn from_event_value(v: &EventValue<'_>) -> Option<Self> {
        match v {
            EventValue::Str(s) => Some(DraftValue::Str(s.to_string())),
            EventValue::Int(n) => Some(DraftValue::Int(*n)),
            EventValue::Float(f) => Some(DraftValue::Float(*f)),
            EventValue::Bool(b) => Some(DraftValue::Bool(*b)),
            EventValue::Null | EventValue::Array(_) | EventValue::Map(_) => None,
        }
    }

    fn as_display(&self) -> String {
        match self {
            DraftValue::Str(s) => s.clone(),
            DraftValue::Int(n) => n.to_string(),
            DraftValue::Float(f) => f.to_string(),
            DraftValue::Bool(b) => b.to_string(),
        }
    }

    fn as_match_str(&self) -> String {
        self.as_display()
    }
}

/// The value form chosen for one field, mapping to a Sigma modifier.
#[derive(Debug, Clone, PartialEq)]
enum ValueForm {
    /// Single stable value; plain equals.
    Exact(DraftValue),
    /// Small distinct set; OR value list.
    OneOf(Vec<DraftValue>),
    /// Differing values sharing a suffix; `|endswith`.
    EndsWith(String),
    /// Differing values sharing a prefix; `|startswith`.
    StartsWith(String),
    /// Differing values sharing one stable token; `|contains`.
    Contains(String),
    /// Differing values sharing several stable tokens; `|contains|all`.
    ContainsAll(Vec<String>),
}

impl ValueForm {
    fn modifier(&self) -> &'static str {
        match self {
            ValueForm::Exact(_) | ValueForm::OneOf(_) => "",
            ValueForm::EndsWith(_) => "|endswith",
            ValueForm::StartsWith(_) => "|startswith",
            ValueForm::Contains(_) => "|contains",
            ValueForm::ContainsAll(_) => "|contains|all",
        }
    }

    fn display_values(&self) -> Vec<String> {
        match self {
            ValueForm::Exact(v) => vec![v.as_display()],
            ValueForm::OneOf(vs) => vs.iter().map(|v| v.as_display()).collect(),
            ValueForm::EndsWith(s) => vec![format!("*{s}")],
            ValueForm::StartsWith(s) => vec![format!("{s}*")],
            ValueForm::Contains(s) => vec![format!("*{s}*")],
            ValueForm::ContainsAll(ts) => ts.iter().map(|t| format!("*{t}*")).collect(),
        }
    }

    /// Would this form match the given string value? Mirrors Sigma's default
    /// case-insensitive matching; used only for baseline prevalence scoring.
    fn matches_str(&self, value: &str) -> bool {
        let lv = value.to_lowercase();
        match self {
            ValueForm::Exact(v) => lv == v.as_match_str().to_lowercase(),
            ValueForm::OneOf(vs) => vs.iter().any(|v| lv == v.as_match_str().to_lowercase()),
            ValueForm::EndsWith(s) => lv.ends_with(&s.to_lowercase()),
            ValueForm::StartsWith(s) => lv.starts_with(&s.to_lowercase()),
            ValueForm::Contains(t) => lv.contains(&t.to_lowercase()),
            ValueForm::ContainsAll(ts) => ts.iter().all(|t| lv.contains(&t.to_lowercase())),
        }
    }
}

/// One profiled field: the shared per-field statistics plus the aligned
/// per-exemplar values that drafting needs on top of them.
#[derive(Debug, Clone)]
struct DraftFieldProfile {
    /// The base statistics, shared with schema discovery's profile type.
    stats: FieldProfile,
    /// Value per exemplar index (`None` when absent or non-scalar).
    values: Vec<Option<DraftValue>>,
    stability: Stability,
    /// The chosen value form (None for volatile fields).
    form: Option<ValueForm>,
    score: f64,
    baseline_prevalence: Option<f64>,
    forced: bool,
}

impl DraftFieldProfile {
    fn field(&self) -> &str {
        &self.stats.field
    }

    fn distinct(&self) -> Vec<&DraftValue> {
        let mut seen: Vec<&DraftValue> = Vec::new();
        for v in self.values.iter().flatten() {
            if !seen.contains(&v) {
                seen.push(v);
            }
        }
        seen
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
    if exemplars.is_empty() {
        return Err(DraftError::NoExemplars);
    }
    let mut warnings: Vec<String> = Vec::new();

    // ---- Profile ----------------------------------------------------------
    let mut profiles = profile_fields(exemplars, config, &mut warnings);
    if profiles.is_empty() {
        return Err(DraftError::NoCandidateFields(exemplars.len()));
    }

    // ---- Infer value forms -------------------------------------------------
    for p in &mut profiles {
        infer_form(p, config);
    }

    // ---- Baseline prevalence + token guard ---------------------------------
    if !baseline.is_empty() {
        for p in &mut profiles {
            apply_baseline(p, baseline, config);
        }
    }

    // ---- Score -------------------------------------------------------------
    let has_baseline = !baseline.is_empty();
    for p in &mut profiles {
        p.score = score_field(p, has_baseline);
    }
    // Rank: forced first, then score descending, then field name ascending
    // (the deterministic tie-break).
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

    // ---- Select ------------------------------------------------------------
    let usable: Vec<usize> = profiles
        .iter()
        .enumerate()
        .filter(|(_, p)| p.form.is_some() && p.stability != Stability::Volatile)
        .map(|(i, _)| i)
        .collect();
    if usable.is_empty() {
        return Err(DraftError::NoCandidateFields(exemplars.len()));
    }
    let mut selected: Vec<usize> = usable.iter().copied().take(config.max_fields).collect();
    if selected.len() < config.min_fields {
        warnings.push(format!(
            "only {} usable field(s) found (floor is {}); the draft may be broad",
            selected.len(),
            config.min_fields
        ));
    }

    // ---- Logsource ---------------------------------------------------------
    let logsource = infer_logsource(exemplars, config, &mut warnings);

    // ---- Emit + verify (bounded relaxation) --------------------------------
    let floor = config.min_fields.min(selected.len()).max(1);
    let (yaml, matched, failing) = loop {
        let detection = build_detection(&profiles, &selected, exemplars, config);
        let yaml = emit_rule_yaml(&profiles, &selected, &detection, &logsource, config);
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
        if selected.len() <= floor {
            return Err(DraftError::CannotMatchExemplars {
                matched: exemplars.len() - failing.len(),
                total: exemplars.len(),
                floor,
                failing,
            });
        }
        // Drop the lowest-ranked selected field and retry.
        let dropped = selected.pop().expect("selected is non-empty");
        warnings.push(format!(
            "relaxed: dropped field '{}' because the draft did not match every exemplar with it",
            profiles[dropped].field()
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
            warnings.push(format!(
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
        warnings.push(format!("lint {}: {}", w.rule, w.message));
    }

    // ---- Report ---------------------------------------------------------------
    let selected_set: BTreeSet<usize> = selected.iter().copied().collect();
    let fields = profiles
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
        warnings,
    })
}

// =============================================================================
// Profiling
// =============================================================================

fn profile_fields<E: Event>(
    exemplars: &[E],
    config: &DraftConfig,
    warnings: &mut Vec<String>,
) -> Vec<DraftFieldProfile> {
    // Union of leaf field paths across all exemplars, sorted for determinism.
    let mut all_fields: BTreeSet<String> = BTreeSet::new();
    for e in exemplars {
        for k in e.field_keys() {
            all_fields.insert(k.into_owned());
        }
    }

    let excluded = |f: &str| {
        config
            .exclude_fields
            .iter()
            .any(|x| x.eq_ignore_ascii_case(f))
    };
    let forced = |f: &str| {
        config
            .include_fields
            .iter()
            .any(|x| x.eq_ignore_ascii_case(f))
    };

    // Warn about forced fields that do not exist at all.
    for inc in &config.include_fields {
        if !all_fields.iter().any(|f| f.eq_ignore_ascii_case(inc)) {
            warnings.push(format!(
                "--include-field '{inc}' does not appear in any exemplar; ignored"
            ));
        }
    }

    let total = exemplars.len();
    let mut out = Vec::new();
    for field in all_fields {
        if excluded(&field) {
            continue;
        }
        let values: Vec<Option<DraftValue>> = exemplars
            .iter()
            .map(|e| {
                e.get_field(&field)
                    .and_then(|v| DraftValue::from_event_value(&v))
            })
            .collect();
        let present = exemplars
            .iter()
            .filter(|e| e.get_field(&field).is_some())
            .count();
        let prevalence = present as f64 / total as f64;
        let is_forced = forced(&field);
        if prevalence < config.min_prevalence && !is_forced {
            continue;
        }
        if is_forced && prevalence < 1.0 {
            warnings.push(format!(
                "--include-field '{field}' is absent from some exemplars \
                 ({present}/{total}); the draft may not match them"
            ));
        }

        let mut distinct_values: Vec<String> = values
            .iter()
            .flatten()
            .map(|v| v.as_display())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        distinct_values.sort();
        let stats = FieldProfile {
            field: field.clone(),
            present: present as u64,
            total: total as u64,
            distinct_values,
            value_overflow: false,
        };

        let stability = classify_stability(&field, &values, present, config);
        out.push(DraftFieldProfile {
            stats,
            values,
            stability,
            form: None,
            score: 0.0,
            baseline_prevalence: None,
            forced: is_forced,
        });
    }
    out
}

fn classify_stability(
    field: &str,
    values: &[Option<DraftValue>],
    present: usize,
    config: &DraftConfig,
) -> Stability {
    let scalars: Vec<&DraftValue> = values.iter().flatten().collect();
    // A field that is present but non-scalar (array, map, null) in some
    // exemplar cannot back a plain selection value. Absence alone is fine:
    // partial-prevalence fields are admitted by `min_prevalence` and the
    // verification loop drops them if they break the AND selection.
    if scalars.is_empty() || scalars.len() < present {
        return Stability::Volatile;
    }
    // Name- and shape-based volatility comes first: a timestamp constant
    // across exemplars is still a timestamp.
    if is_volatile_name(field) {
        return Stability::Volatile;
    }
    if scalars.iter().any(|v| is_volatile_value(v)) {
        return Stability::Volatile;
    }

    let mut distinct: Vec<&DraftValue> = Vec::new();
    for v in &scalars {
        if !distinct.contains(v) {
            distinct.push(v);
        }
    }
    if distinct.len() == 1 {
        return Stability::Constant;
    }
    if distinct.len() <= config.max_value_cardinality && distinct.len() < scalars.len() {
        return Stability::Enumerable;
    }
    // All-string values may still share a pattern.
    let strings: Vec<&str> = distinct
        .iter()
        .filter_map(|v| match v {
            DraftValue::Str(s) => Some(s.as_str()),
            _ => None,
        })
        .collect();
    if strings.len() == distinct.len() {
        // Unique-per-exemplar random-looking values are volatile even when a
        // short prefix happens to be shared.
        if distinct.len() == scalars.len() && strings.iter().all(|s| is_random_string(s)) {
            return Stability::Volatile;
        }
        if shared_suffix(&strings, config.min_token_len).is_some()
            || shared_prefix(&strings, config.min_token_len).is_some()
            || !shared_tokens(&strings, config.min_token_len).is_empty()
        {
            return Stability::Patterned;
        }
        // A small distinct set that repeats across exemplars was handled above;
        // what is left is either enumerable-but-unique (each exemplar its own
        // value, still a small set) or volatile.
        if distinct.len() <= config.max_value_cardinality {
            return Stability::Enumerable;
        }
    } else if distinct.len() <= config.max_value_cardinality {
        return Stability::Enumerable;
    }
    Stability::Volatile
}

// =============================================================================
// Volatility heuristics
// =============================================================================

/// Field names that denote per-event bookkeeping rather than content.
fn is_volatile_name(field: &str) -> bool {
    let last = field.rsplit('.').next().unwrap_or(field).to_lowercase();
    let normalized: String = last.chars().filter(|c| *c != '_' && *c != '-').collect();
    if last == "@timestamp" || normalized == "ts" {
        return true;
    }
    if normalized.contains("time") || normalized.contains("date") {
        return true;
    }
    if normalized.contains("guid") || normalized.contains("uuid") {
        return true;
    }
    matches!(
        normalized.as_str(),
        "recordid"
            | "recordnumber"
            | "eventrecordid"
            | "sequence"
            | "seq"
            | "seqno"
            | "processid"
            | "pid"
            | "parentprocessid"
            | "ppid"
            | "threadid"
            | "tid"
            | "logonid"
            | "sessionid"
            | "executionprocessid"
            | "executionthreadid"
    )
}

/// Values that look like timestamps, UUIDs, or epoch counters.
fn is_volatile_value(value: &DraftValue) -> bool {
    match value {
        DraftValue::Str(s) => is_timestamp_string(s) || is_uuid_string(s),
        DraftValue::Int(n) => is_epoch_number(*n as f64),
        DraftValue::Float(f) => is_epoch_number(*f),
        DraftValue::Bool(_) => false,
    }
}

/// RFC3339-ish or `YYYY-MM-DD HH:MM` shaped strings.
fn is_timestamp_string(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 10 {
        return false;
    }
    let date = b[0].is_ascii_digit()
        && b[1].is_ascii_digit()
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit()
        && b[4] == b'-'
        && b[5].is_ascii_digit()
        && b[6].is_ascii_digit()
        && b[7] == b'-'
        && b[8].is_ascii_digit()
        && b[9].is_ascii_digit();
    if !date {
        return false;
    }
    // A bare date, or a date followed by a time separator.
    b.len() == 10 || b[10] == b'T' || b[10] == b' '
}

/// UUID/GUID shape: 8-4-4-4-12 hex, with or without braces.
fn is_uuid_string(s: &str) -> bool {
    let s = s.strip_prefix('{').unwrap_or(s);
    let s = s.strip_suffix('}').unwrap_or(s);
    if s.len() != 36 {
        return false;
    }
    s.char_indices().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => c == '-',
        _ => c.is_ascii_hexdigit(),
    })
}

/// Plausible Unix epoch in seconds, milliseconds, microseconds, or nanoseconds
/// (2001-2286 in seconds and the equivalent ranges for the finer units).
fn is_epoch_number(n: f64) -> bool {
    const RANGES: [(f64, f64); 4] = [
        (1e9, 1e10),  // seconds
        (1e12, 1e13), // milliseconds
        (1e15, 1e16), // microseconds
        (1e18, 1e19), // nanoseconds
    ];
    RANGES.iter().any(|(lo, hi)| n >= *lo && n < *hi)
}

/// Long, alphanumeric, digit-and-letter mixed values (hashes, tokens) that are
/// unique per exemplar.
fn is_random_string(s: &str) -> bool {
    s.len() >= 16
        && s.chars().all(|c| c.is_ascii_alphanumeric())
        && s.chars().any(|c| c.is_ascii_digit())
        && s.chars().any(|c| c.is_ascii_alphabetic())
}

/// Envelope fields demoted (not dropped) when there is no baseline to score
/// against: nearly every event carries them, so they rarely discriminate.
fn is_structural_name(field: &str) -> bool {
    let last = field.rsplit('.').next().unwrap_or(field).to_lowercase();
    matches!(
        last.as_str(),
        "host" | "hostname" | "computer" | "computername" | "domain" | "level" | "severity"
    )
}

// =============================================================================
// Pattern derivation
// =============================================================================

fn shared_prefix(values: &[&str], min_len: usize) -> Option<String> {
    let first = values.first()?;
    let mut len = first.len();
    for v in &values[1..] {
        len = len.min(common_prefix_len(first, v));
    }
    // Don't call a full-equality overlap a "prefix".
    if len >= min_len && values.iter().any(|v| v.len() > len) {
        Some(first[..len].to_string())
    } else {
        None
    }
}

fn shared_suffix(values: &[&str], min_len: usize) -> Option<String> {
    let first = values.first()?;
    let mut len = first.len();
    for v in &values[1..] {
        len = len.min(common_suffix_len(first, v));
    }
    if len >= min_len && values.iter().any(|v| v.len() > len) {
        Some(first[first.len() - len..].to_string())
    } else {
        None
    }
}

fn common_prefix_len(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

fn common_suffix_len(a: &str, b: &str) -> usize {
    a.bytes()
        .rev()
        .zip(b.bytes().rev())
        .take_while(|(x, y)| x == y)
        .count()
}

/// Tokens (runs of alphanumerics, `min_len` or longer) present in every value,
/// case-insensitively. Sorted longest first, then lexicographic, capped at 3.
fn shared_tokens(values: &[&str], min_len: usize) -> Vec<String> {
    let Some(first) = values.first() else {
        return Vec::new();
    };
    let lowers: Vec<String> = values.iter().map(|v| v.to_lowercase()).collect();
    let mut tokens: Vec<String> = tokenize(first, min_len)
        .into_iter()
        .filter(|t| {
            let lt = t.to_lowercase();
            lowers.iter().all(|v| v.contains(&lt))
        })
        .collect();
    tokens.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    tokens.dedup();
    tokens.truncate(3);
    tokens
}

fn tokenize(s: &str, min_len: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for token in s.split(|c: char| !c.is_ascii_alphanumeric()) {
        if token.len() >= min_len && !out.iter().any(|t| t == token) {
            out.push(token.to_string());
        }
    }
    out
}

// =============================================================================
// Value-form inference
// =============================================================================

fn infer_form(profile: &mut DraftFieldProfile, config: &DraftConfig) {
    if profile.stability == Stability::Volatile {
        return;
    }
    let distinct: Vec<DraftValue> = profile.distinct().into_iter().cloned().collect();
    profile.form = derive_form(&distinct, config);
    if profile.form.is_none() {
        profile.stability = Stability::Volatile;
    }
}

fn derive_form(distinct: &[DraftValue], config: &DraftConfig) -> Option<ValueForm> {
    match distinct {
        [] => None,
        [one] => Some(ValueForm::Exact(one.clone())),
        many if many.len() <= config.max_value_cardinality => Some(ValueForm::OneOf(many.to_vec())),
        many => {
            let strings: Vec<&str> = many
                .iter()
                .filter_map(|v| match v {
                    DraftValue::Str(s) => Some(s.as_str()),
                    _ => None,
                })
                .collect();
            if strings.len() != many.len() {
                return None;
            }
            derive_pattern_form(&strings, config)
        }
    }
}

fn derive_pattern_form(strings: &[&str], config: &DraftConfig) -> Option<ValueForm> {
    // Suffix beats prefix beats tokens: path tails (`\whoami.exe`) are the
    // most discriminating shape in practice.
    if let Some(suffix) = shared_suffix(strings, config.min_token_len) {
        return Some(ValueForm::EndsWith(suffix));
    }
    if let Some(prefix) = shared_prefix(strings, config.min_token_len) {
        return Some(ValueForm::StartsWith(prefix));
    }
    let tokens = shared_tokens(strings, config.min_token_len);
    match tokens.len() {
        0 => None,
        1 => Some(ValueForm::Contains(tokens.into_iter().next().unwrap())),
        _ => Some(ValueForm::ContainsAll(tokens)),
    }
}

// =============================================================================
// Baseline scoring
// =============================================================================

fn apply_baseline<E: Event>(profile: &mut DraftFieldProfile, baseline: &[E], config: &DraftConfig) {
    let Some(form) = profile.form.clone() else {
        return;
    };
    let field = profile.field().to_string();
    let match_count = |f: &ValueForm| {
        baseline
            .iter()
            .filter(|e| {
                e.get_field(&field)
                    .and_then(|v| v.as_str().map(|s| f.matches_str(s.as_ref())))
                    .unwrap_or(false)
            })
            .count()
    };

    // Token guard: drop `contains` tokens that are generic in the baseline.
    let guarded = match form {
        ValueForm::Contains(ref t) => {
            let frac = match_count(&ValueForm::Contains(t.clone())) as f64 / baseline.len() as f64;
            if frac > config.max_baseline_token_prevalence {
                profile.form = None;
                profile.stability = Stability::Volatile;
                return;
            }
            form
        }
        ValueForm::ContainsAll(ref ts) => {
            let kept: Vec<String> = ts
                .iter()
                .filter(|t| {
                    let frac = match_count(&ValueForm::Contains((*t).clone())) as f64
                        / baseline.len() as f64;
                    frac <= config.max_baseline_token_prevalence
                })
                .cloned()
                .collect();
            match kept.len() {
                0 => {
                    profile.form = None;
                    profile.stability = Stability::Volatile;
                    return;
                }
                1 => ValueForm::Contains(kept.into_iter().next().unwrap()),
                _ => ValueForm::ContainsAll(kept),
            }
        }
        other => other,
    };

    let hits = match_count(&guarded);
    profile.form = Some(guarded);
    profile.baseline_prevalence = Some(hits as f64 / baseline.len() as f64);
}

fn score_field(profile: &DraftFieldProfile, has_baseline: bool) -> f64 {
    if profile.form.is_none() || profile.stability == Stability::Volatile {
        return f64::MIN;
    }
    let stability_base = match profile.stability {
        Stability::Constant => 3.0,
        Stability::Enumerable => 2.0,
        Stability::Patterned => 1.0,
        Stability::Volatile => 0.0,
    };
    let prevalence = profile.stats.prevalence();
    match profile.baseline_prevalence {
        Some(bp) => stability_base * prevalence * (1.0 - bp),
        None => {
            let demotion = if !has_baseline && is_structural_name(profile.field()) {
                0.5
            } else {
                0.0
            };
            stability_base * prevalence - demotion
        }
    }
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

// =============================================================================
// Sigma value escaping
// =============================================================================

/// Escape a literal value for use in a Sigma detection value, so an observed
/// `*`, `?`, or wildcard-adjacent backslash never silently becomes a wildcard.
///
/// Per the Sigma spec: `\*` and `\?` are literal wildcard characters, `\\` is a
/// literal backslash, and a backslash before a non-special character is kept
/// as-is (so plain Windows paths stay readable).
fn escape_sigma_value(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => out.push_str("\\*"),
            '?' => out.push_str("\\?"),
            '\\' => {
                // Handle the whole run of consecutive backslashes at once: a
                // lone backslash before a normal character stays as-is (plain
                // Windows paths remain readable), while runs and backslashes
                // adjacent to a wildcard or the end of the value are escaped
                // so the parser cannot reinterpret them.
                let mut j = i;
                while j < chars.len() && chars[j] == '\\' {
                    j += 1;
                }
                let run = j - i;
                let next = chars.get(j);
                let must_escape = run > 1 || matches!(next, Some('*') | Some('?') | None);
                for _ in 0..run {
                    if must_escape {
                        out.push_str("\\\\");
                    } else {
                        out.push('\\');
                    }
                }
                i = j;
                continue;
            }
            c => out.push(c),
        }
        i += 1;
    }
    out
}

// =============================================================================
// YAML emission
// =============================================================================

/// Quote a YAML scalar in Sigma's single-quote convention when it is not a
/// plain-safe bare scalar. Numbers and booleans are emitted bare upstream.
fn yaml_str(s: &str) -> String {
    let bare_safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && !s.starts_with('-')
        // Bare scalars that YAML would type-coerce need quoting.
        && s.parse::<f64>().is_err()
        && !matches!(
            s.to_ascii_lowercase().as_str(),
            "true" | "false" | "null" | "yes" | "no" | "on" | "off"
        );
    if bare_safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "''"))
    }
}

/// Looser quoting for prose scalars (the title): plain YAML allows internal
/// spaces, so common titles stay unquoted; anything risky falls back to
/// [`yaml_str`].
fn yaml_title_str(s: &str) -> String {
    let bare_safe = !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && !s.ends_with(' ')
        && !s.contains(": ")
        && !s.contains(" #")
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.' | ',' | '(' | ')')
        });
    if bare_safe {
        s.to_string()
    } else {
        yaml_str(s)
    }
}

fn emit_value(v: &DraftValue) -> String {
    match v {
        DraftValue::Str(s) => yaml_str(&escape_sigma_value(s)),
        DraftValue::Int(n) => n.to_string(),
        DraftValue::Float(f) => f.to_string(),
        DraftValue::Bool(b) => b.to_string(),
    }
}

fn emit_form(out: &mut String, field: &str, form: &ValueForm, indent: &str) {
    let key = format!("{field}{}", form.modifier());
    match form {
        ValueForm::Exact(v) => {
            out.push_str(&format!("{indent}{key}: {}\n", emit_value(v)));
        }
        ValueForm::OneOf(vs) => {
            out.push_str(&format!("{indent}{key}:\n"));
            for v in vs {
                out.push_str(&format!("{indent}    - {}\n", emit_value(v)));
            }
        }
        ValueForm::EndsWith(s) | ValueForm::StartsWith(s) | ValueForm::Contains(s) => {
            out.push_str(&format!(
                "{indent}{key}: {}\n",
                yaml_str(&escape_sigma_value(s))
            ));
        }
        ValueForm::ContainsAll(ts) => {
            out.push_str(&format!("{indent}{key}:\n"));
            for t in ts {
                out.push_str(&format!(
                    "{indent}    - {}\n",
                    yaml_str(&escape_sigma_value(t))
                ));
            }
        }
    }
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
