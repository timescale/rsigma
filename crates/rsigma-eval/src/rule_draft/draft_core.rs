//! Shared deterministic profiling, value-form inference, and Sigma YAML helpers.

use std::collections::BTreeSet;

use crate::event::{Event, EventValue};
use crate::schema_discovery::FieldProfile;

use super::{DraftConfig, Stability};

// =============================================================================
// Internal value and form model
// =============================================================================

/// A scalar exemplar value, kept typed so numbers emit as numbers.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DraftValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

impl DraftValue {
    pub(crate) fn from_event_value(v: &EventValue<'_>) -> Option<Self> {
        match v {
            EventValue::Str(s) => Some(DraftValue::Str(s.to_string())),
            EventValue::Int(n) => Some(DraftValue::Int(*n)),
            EventValue::Float(f) => Some(DraftValue::Float(*f)),
            EventValue::Bool(b) => Some(DraftValue::Bool(*b)),
            EventValue::Null | EventValue::Array(_) | EventValue::Map(_) => None,
        }
    }

    pub(crate) fn as_display(&self) -> String {
        match self {
            DraftValue::Str(s) => s.clone(),
            DraftValue::Int(n) => n.to_string(),
            DraftValue::Float(f) => f.to_string(),
            DraftValue::Bool(b) => b.to_string(),
        }
    }

    pub(crate) fn as_match_str(&self) -> String {
        self.as_display()
    }
}

/// The value form chosen for one field, mapping to a Sigma modifier.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ValueForm {
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
    pub(crate) fn modifier(&self) -> &'static str {
        match self {
            ValueForm::Exact(_) | ValueForm::OneOf(_) => "",
            ValueForm::EndsWith(_) => "|endswith",
            ValueForm::StartsWith(_) => "|startswith",
            ValueForm::Contains(_) => "|contains",
            ValueForm::ContainsAll(_) => "|contains|all",
        }
    }

    pub(crate) fn display_values(&self) -> Vec<String> {
        match self {
            ValueForm::Exact(v) => vec![v.as_display()],
            ValueForm::OneOf(vs) => vs.iter().map(|v| v.as_display()).collect(),
            ValueForm::EndsWith(s) => vec![format!("*{s}")],
            ValueForm::StartsWith(s) => vec![format!("{s}*")],
            ValueForm::Contains(s) => vec![format!("*{s}*")],
            ValueForm::ContainsAll(ts) => ts.iter().map(|t| format!("*{t}*")).collect(),
        }
    }

    /// Would this form match the given already-lowercased string value?
    /// Mirrors Sigma's default case-insensitive matching; used only for
    /// baseline prevalence scoring.
    pub(crate) fn matches_lower(&self, lv: &str) -> bool {
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
pub(crate) struct DraftFieldProfile {
    /// The base statistics, shared with schema discovery's profile type.
    pub(crate) stats: FieldProfile,
    /// Value per exemplar index (`None` when absent or non-scalar).
    pub(crate) values: Vec<Option<DraftValue>>,
    pub(crate) stability: Stability,
    /// The chosen value form (None for volatile fields).
    pub(crate) form: Option<ValueForm>,
    pub(crate) score: f64,
    pub(crate) baseline_prevalence: Option<f64>,
    pub(crate) forced: bool,
}

impl DraftFieldProfile {
    pub(crate) fn field(&self) -> &str {
        &self.stats.field
    }

    pub(crate) fn distinct(&self) -> Vec<&DraftValue> {
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
// Profiling
// =============================================================================

pub(crate) fn profile_fields<E: Event>(
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
        if let Some(reason) = unwritable_field_name(&field) {
            warnings.push(format!(
                "skipped field {:?}: {reason}, so it cannot be written as a Sigma field",
                truncate_for_message(&field)
            ));
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

pub(crate) fn classify_stability(
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
pub(crate) fn is_volatile_name(field: &str) -> bool {
    let segment = field.rsplit('.').next().unwrap_or(field);
    let last = segment.to_lowercase();
    let normalized: String = last.chars().filter(|c| *c != '_' && *c != '-').collect();
    if last == "@timestamp" || normalized == "ts" {
        return true;
    }
    // Match time/date at word granularity (camelCase and separators), so
    // `UtcTime` and `created_date` are volatile while `runtime`, `update`, and
    // `candidate` are not mistaken for timestamps.
    if segment_words(segment)
        .iter()
        .any(|w| matches!(w.as_str(), "time" | "date" | "datetime" | "timestamp"))
    {
        return true;
    }
    if normalized.contains("timestamp")
        || normalized.contains("guid")
        || normalized.contains("uuid")
    {
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

/// Split a field segment into lowercase words on non-alphanumeric separators and
/// camelCase boundaries, so `UtcTime` -> `[utc, time]` and `created_date` ->
/// `[created, date]`, while `runtime` stays a single word.
pub(crate) fn segment_words(segment: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut prev: Option<char> = None;
    for c in segment.chars() {
        if !c.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            prev = None;
            continue;
        }
        // A lower/digit to upper transition starts a new camelCase word.
        if let Some(p) = prev
            && c.is_ascii_uppercase()
            && (p.is_ascii_lowercase() || p.is_ascii_digit())
            && !cur.is_empty()
        {
            words.push(std::mem::take(&mut cur));
        }
        cur.push(c.to_ascii_lowercase());
        prev = Some(c);
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

/// Values that look like timestamps, UUIDs, or epoch counters.
pub(crate) fn is_volatile_value(value: &DraftValue) -> bool {
    match value {
        DraftValue::Str(s) => is_timestamp_string(s) || is_uuid_string(s),
        DraftValue::Int(n) => is_epoch_number(*n as f64),
        DraftValue::Float(f) => is_epoch_number(*f),
        DraftValue::Bool(_) => false,
    }
}

/// RFC3339-ish or `YYYY-MM-DD HH:MM` shaped strings.
pub(crate) fn is_timestamp_string(s: &str) -> bool {
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
pub(crate) fn is_uuid_string(s: &str) -> bool {
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
pub(crate) fn is_epoch_number(n: f64) -> bool {
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
pub(crate) fn is_random_string(s: &str) -> bool {
    s.len() >= 16
        && s.chars().all(|c| c.is_ascii_alphanumeric())
        && s.chars().any(|c| c.is_ascii_digit())
        && s.chars().any(|c| c.is_ascii_alphabetic())
}

/// Envelope fields demoted (not dropped) when there is no baseline to score
/// against: nearly every event carries them, so they rarely discriminate.
pub(crate) fn is_structural_name(field: &str) -> bool {
    let last = field.rsplit('.').next().unwrap_or(field).to_lowercase();
    matches!(
        last.as_str(),
        "host" | "hostname" | "computer" | "computername" | "domain" | "level" | "severity"
    )
}

// =============================================================================
// Pattern derivation
// =============================================================================

pub(crate) fn shared_prefix(values: &[&str], min_len: usize) -> Option<String> {
    let first = values.first()?;
    let mut len = first.len();
    for v in &values[1..] {
        len = len.min(common_prefix_len(first, v));
    }
    // The byte overlap may end inside a multibyte character; snap down to a
    // char boundary so slicing never panics on non-ASCII values.
    while len > 0 && !first.is_char_boundary(len) {
        len -= 1;
    }
    // Don't call a full-equality overlap a "prefix".
    if len >= min_len && values.iter().any(|v| v.len() > len) {
        Some(first[..len].to_string())
    } else {
        None
    }
}

pub(crate) fn shared_suffix(values: &[&str], min_len: usize) -> Option<String> {
    let first = values.first()?;
    let mut len = first.len();
    for v in &values[1..] {
        len = len.min(common_suffix_len(first, v));
    }
    // Snap the suffix start up to a char boundary so the byte overlap never
    // splits a multibyte character (which would panic when sliced).
    let mut start = first.len() - len;
    while start < first.len() && !first.is_char_boundary(start) {
        start += 1;
    }
    let len = first.len() - start;
    if len >= min_len && values.iter().any(|v| v.len() > len) {
        Some(first[start..].to_string())
    } else {
        None
    }
}

pub(crate) fn common_prefix_len(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

pub(crate) fn common_suffix_len(a: &str, b: &str) -> usize {
    a.bytes()
        .rev()
        .zip(b.bytes().rev())
        .take_while(|(x, y)| x == y)
        .count()
}

/// Tokens (runs of alphanumerics, `min_len` or longer) present in every value,
/// case-insensitively. Sorted longest first, then lexicographic, capped at 3.
pub(crate) fn shared_tokens(values: &[&str], min_len: usize) -> Vec<String> {
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

pub(crate) fn tokenize(s: &str, min_len: usize) -> Vec<String> {
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

pub(crate) fn infer_form(profile: &mut DraftFieldProfile, config: &DraftConfig) {
    if profile.stability == Stability::Volatile {
        return;
    }
    let distinct: Vec<DraftValue> = profile.distinct().into_iter().cloned().collect();
    // A patterned field generalizes better as its shared pattern than as an
    // exact OR list that would just memorize the exemplars.
    if profile.stability == Stability::Patterned {
        let strings: Vec<&str> = distinct
            .iter()
            .filter_map(|v| match v {
                DraftValue::Str(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        if strings.len() == distinct.len() {
            profile.form = derive_pattern_form(&strings, config);
        }
    }
    if profile.form.is_none() {
        profile.form = derive_form(&distinct, config);
    }
    if profile.form.is_none() {
        profile.stability = Stability::Volatile;
    }
}

pub(crate) fn derive_form(distinct: &[DraftValue], config: &DraftConfig) -> Option<ValueForm> {
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

pub(crate) fn derive_pattern_form(strings: &[&str], config: &DraftConfig) -> Option<ValueForm> {
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

pub(crate) fn apply_baseline<E: Event>(
    profile: &mut DraftFieldProfile,
    baseline: &[E],
    config: &DraftConfig,
) {
    let Some(form) = profile.form.clone() else {
        return;
    };
    // Extract the field once per baseline event; the guard and prevalence
    // counts below then run over the in-memory values instead of re-walking
    // the events per token.
    let field = profile.field().to_string();
    let values: Vec<String> = baseline
        .iter()
        .filter_map(|e| {
            e.get_field(&field)
                .and_then(|v| v.as_str().map(|s| s.to_lowercase()))
        })
        .collect();
    let match_count = |f: &ValueForm| values.iter().filter(|lv| f.matches_lower(lv)).count();
    let token_is_generic = |t: &str| {
        let lt = t.to_lowercase();
        let hits = values.iter().filter(|lv| lv.contains(&lt)).count();
        hits as f64 / baseline.len() as f64 > config.max_baseline_token_prevalence
    };

    // Token guard: drop `contains` tokens that are generic in the baseline.
    let guarded = match form {
        ValueForm::Contains(ref t) => {
            if token_is_generic(t) {
                profile.form = None;
                profile.stability = Stability::Volatile;
                return;
            }
            form
        }
        ValueForm::ContainsAll(ref ts) => {
            let kept: Vec<String> = ts
                .iter()
                .filter(|t| !token_is_generic(t))
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

pub(crate) fn score_field(profile: &DraftFieldProfile, has_baseline: bool) -> f64 {
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
// Sigma value escaping
// =============================================================================

/// Escape a literal value for use in a Sigma detection value, so an observed
/// `*`, `?`, or wildcard-adjacent backslash never silently becomes a wildcard.
///
/// Per the Sigma spec: `\*` and `\?` are literal wildcard characters, `\\` is a
/// literal backslash, and a backslash before a non-special character is kept
/// as-is (so plain Windows paths stay readable).
pub(crate) fn escape_sigma_value(s: &str) -> String {
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
/// plain-safe bare scalar, falling back to a double-quoted scalar with escapes
/// for line breaks and control characters. Numbers and booleans are emitted
/// bare upstream.
pub(crate) fn yaml_str(s: &str) -> String {
    let bare_safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && !s.starts_with('-')
        // Bare scalars that YAML would type-coerce need quoting.
        && s.parse::<f64>().is_err()
        && !is_yaml_keyword(s)
        && reads_back_plain(s);
    if bare_safe {
        s.to_string()
    } else {
        rsigma_parser::quote_yaml_string(s)
    }
}

fn is_yaml_keyword(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "true" | "false" | "null" | "yes" | "no" | "on" | "off"
    )
}

/// Whether YAML reads `s` written plain back as the string `s`, rather than
/// as a number in another spelling (`0x1F`, `0o17`, `.inf`) or YAML 1.1's
/// underscore-grouped integers (`1_000`), which pySigma would read as one.
fn reads_back_plain(s: &str) -> bool {
    let grouped_number = s.starts_with(|c: char| c.is_ascii_digit() || c == '.') && s.contains('_');
    !grouped_number
        && matches!(
            yaml_serde::from_str::<yaml_serde::Value>(s),
            Ok(yaml_serde::Value::String(ref v)) if v == s
        )
}

/// Write a detection key (a field name plus its modifier chain) so YAML reads
/// it back as exactly that string: bare when it starts with a letter or `_`
/// and holds only characters a plain key keeps, quoted otherwise.
pub(crate) fn yaml_key(key: &str) -> String {
    let bare_safe = key
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '|' | '/'))
        && !is_yaml_keyword(key)
        && reads_back_plain(key);
    if bare_safe {
        key.to_string()
    } else {
        rsigma_parser::quote_yaml_string(key)
    }
}

/// Longest field name a draft writes. YAML caps a plain mapping key at 1024
/// characters, and a longer name is not a realistic event field.
pub(crate) const MAX_FIELD_NAME_BYTES: usize = 256;

/// Why an event field name cannot be written as a Sigma detection key, if it
/// cannot: the parser splits keys on `|`, a bare `.` is the array-member
/// reference, `\[`/`\]` read as escaped brackets, and line breaks and control
/// characters do not survive as a field name.
pub(crate) fn unwritable_field_name(field: &str) -> Option<&'static str> {
    if field.is_empty() || field == "." {
        return Some("it is empty or a bare '.'");
    }
    if field.len() > MAX_FIELD_NAME_BYTES {
        return Some("it is longer than 256 bytes");
    }
    if field.contains('|') {
        return Some("it contains '|', which separates modifiers");
    }
    if field.contains("\\[") || field.contains("\\]") {
        return Some("it contains an escaped bracket");
    }
    if field.chars().any(is_line_break_or_control) {
        return Some("it contains a line break or control character");
    }
    None
}

/// Line breaks YAML honours, control characters, and the characters YAML
/// readers reject raw.
pub(crate) fn is_line_break_or_control(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{FEFF}' | '\u{FFFE}' | '\u{FFFF}'
        )
}

/// The first 64 characters of a field name, for a warning.
fn truncate_for_message(field: &str) -> String {
    let mut chars = field.chars();
    let head: String = chars.by_ref().take(64).collect();
    if chars.next().is_some() {
        format!("{head}...")
    } else {
        head
    }
}

/// `s` on one line: line breaks and control characters become spaces.
pub(crate) fn single_line(s: &str) -> String {
    s.chars()
        .map(|c| if is_line_break_or_control(c) { ' ' } else { c })
        .collect()
}

/// Looser quoting for prose scalars (the title): plain YAML allows internal
/// spaces, so common titles stay unquoted; anything risky falls back to
/// [`yaml_str`].
pub(crate) fn yaml_title_str(s: &str) -> String {
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

pub(crate) fn emit_value(v: &DraftValue) -> String {
    match v {
        DraftValue::Str(s) => yaml_str(&escape_sigma_value(s)),
        DraftValue::Int(n) => n.to_string(),
        DraftValue::Float(f) => float_token(*f),
        DraftValue::Bool(b) => b.to_string(),
    }
}

/// A float YAML reads back as the same float: `3.0` stays a float rather than
/// collapsing to the integer `3`.
fn float_token(f: f64) -> String {
    if f.is_nan() {
        return ".nan".to_string();
    }
    if f.is_infinite() {
        return if f > 0.0 { ".inf" } else { "-.inf" }.to_string();
    }
    let s = f.to_string();
    if s.contains(['.', 'e', 'E']) {
        s
    } else {
        format!("{s}.0")
    }
}

// =============================================================================
// Round-trip verification
// =============================================================================

/// One selection a generator meant to write: its name and field forms.
pub(crate) struct PlannedSelection<'a> {
    pub(crate) name: &'a str,
    pub(crate) entries: &'a [(String, ValueForm)],
}

/// Parse generated YAML that must hold exactly one document without errors.
pub(crate) fn parse_one_document(yaml: &str) -> Result<rsigma_parser::SigmaCollection, String> {
    let documents = yaml_serde::Deserializer::from_str(yaml).count();
    if documents != 1 {
        return Err(format!("expected one YAML document, found {documents}"));
    }
    parse_without_errors(yaml)
}

/// Parse generated YAML, failing on any document error.
pub(crate) fn parse_without_errors(yaml: &str) -> Result<rsigma_parser::SigmaCollection, String> {
    let collection = rsigma_parser::parse_sigma_yaml(yaml).map_err(|e| e.to_string())?;
    if let Some(error) = collection.errors().next() {
        return Err(error.to_string());
    }
    Ok(collection)
}

/// Check that a parsed detection block is exactly the one a generator meant to
/// write: the same selection names, the same field names, modifiers, and
/// values in each, and the same condition.
pub(crate) fn verify_detection(
    detection: &rsigma_parser::Detections,
    selections: &[PlannedSelection<'_>],
    condition: &str,
) -> Result<(), String> {
    use rsigma_parser::Detection;

    if detection.condition_strings != [condition] {
        return Err(format!(
            "condition is {:?}, expected {condition:?}",
            detection.condition_strings
        ));
    }
    if detection.timeframe.is_some() {
        return Err("unexpected timeframe".to_string());
    }
    if detection.named.len() != selections.len() {
        let mut found: Vec<&String> = detection.named.keys().collect();
        found.sort();
        return Err(format!(
            "found selections {found:?}, expected {} selection(s)",
            selections.len()
        ));
    }
    for selection in selections {
        let Some(Detection::AllOf(items)) = detection.named.get(selection.name) else {
            return Err(format!(
                "selection {:?} is missing or not a field mapping",
                selection.name
            ));
        };
        if items.len() != selection.entries.len() {
            return Err(format!(
                "selection {:?} has {} field(s), expected {}",
                selection.name,
                items.len(),
                selection.entries.len()
            ));
        }
        for (item, (field, form)) in items.iter().zip(selection.entries) {
            let expected_name = rsigma_parser::fieldpath::escape_brackets(field);
            if item.field.name.as_deref() != Some(expected_name.as_ref()) {
                return Err(format!(
                    "selection {:?} has field {:?}, expected {field:?}",
                    selection.name, item.field.name
                ));
            }
            let modifiers: Vec<rsigma_parser::Modifier> = form
                .modifier()
                .split('|')
                .skip(1)
                .filter_map(|m| m.parse().ok())
                .collect();
            if item.field.modifiers != modifiers {
                return Err(format!(
                    "field {field:?} has modifiers {:?}, expected {:?}",
                    item.field.modifiers, modifiers
                ));
            }
            let values = form_values(form);
            if item.values != values {
                return Err(format!(
                    "field {field:?} has values {:?}, expected {values:?}",
                    item.values
                ));
            }
        }
    }
    Ok(())
}

/// The parsed values a form's emitted text must read back as.
fn form_values(form: &ValueForm) -> Vec<rsigma_parser::SigmaValue> {
    let string = |s: &str| {
        rsigma_parser::SigmaValue::from_yaml(&yaml_serde::Value::String(escape_sigma_value(s)))
    };
    let value = |v: &DraftValue| match v {
        DraftValue::Str(s) => string(s),
        DraftValue::Int(n) => rsigma_parser::SigmaValue::Integer(*n),
        DraftValue::Float(f) => rsigma_parser::SigmaValue::Float(*f),
        DraftValue::Bool(b) => rsigma_parser::SigmaValue::Bool(*b),
    };
    match form {
        ValueForm::Exact(v) => vec![value(v)],
        ValueForm::OneOf(vs) => vs.iter().map(value).collect(),
        ValueForm::EndsWith(s) | ValueForm::StartsWith(s) | ValueForm::Contains(s) => {
            vec![string(s)]
        }
        ValueForm::ContainsAll(ts) => ts.iter().map(|t| string(t)).collect(),
    }
}

pub(crate) fn emit_form(out: &mut String, field: &str, form: &ValueForm, indent: &str) {
    let key = yaml_key(&format!("{field}{}", form.modifier()));
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
