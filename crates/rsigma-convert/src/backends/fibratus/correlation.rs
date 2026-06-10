//! Sigma correlation rule → Fibratus sequence DSL lowering.
//!
//! Fibratus 1.10 decommissioned the old `policy: sequence` block in favor
//! of an inline DSL inside `condition:`:
//!
//! ```text
//! sequence
//! maxspan <duration>
//!   |<stage 1 filter>
//!   | by <group field>
//!   |<stage 2 filter>
//!   | by <group field>
//! ```
//!
//! This module builds that DSL from a [`CorrelationRule`] and the
//! per-rule query map injected by
//! [`crate::convert_collection`](crate::convert::convert_collection)
//! into the pipeline state under `_rule_queries`.
//!
//! Coverage matrix:
//!
//! | Sigma correlation type | Mapping                                                                       |
//! |------------------------|-------------------------------------------------------------------------------|
//! | `temporal_ordered`     | `sequence` with one stage per `rules:` entry, `| by <group_by>` per stage.    |
//! | `temporal` (any-order) | `sequence` (ordered fallback); a `description:` note records the divergence.  |
//! | `event_count`          | `sequence` with `<count>` repeated stages of the referenced rule.             |
//! | `value_count`          | `sequence` with `<count>` aliased stages plus pairwise distinctness on field. |
//! | `value_sum` / `avg` / `percentile` / `median` | `UnsupportedCorrelation` (no Fibratus primitive).      |
//!
//! Repeated/distinct slot expansion is capped at
//! [`super::FibratusConfig::max_repeated_slots`] (default 5) to keep
//! the generated YAML bounded.

use std::collections::HashMap;

use rsigma_eval::pipeline::state::PipelineState;
use rsigma_parser::{
    ConditionOperator, CorrelationCondition, CorrelationRule, CorrelationType, WindowMode,
};

use super::FibratusBackend;
use super::config::FibratusConfig;
use super::envelope::render_correlation_yaml;
use super::macros;
use crate::backend::Backend;
use crate::error::{ConvertError, Result};

/// Apply backend-level macro recognition to a single stage body. Each
/// stage in a `sequence ... | <stage> | by ...` DSL is itself a
/// Fibratus filter expression, so the same `EXPRESSION_MACROS`
/// rewriting that runs on detection rules also reads naturally here
/// (`spawn_process and ...` rather than
/// `evt.name imatches 'CreateProcess' and ...`).
fn maybe_apply_macros(body: String, cfg: &FibratusConfig) -> String {
    if cfg.use_macros {
        macros::recognize(&body)
    } else {
        body
    }
}

// ---------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------

/// Convert a Sigma correlation rule into one or more Fibratus YAML rule
/// documents.
///
/// Single-document output is the default. With
/// `-O temporal_permute=true` and a `temporal` (any-order) correlation
/// of N <= 3 referenced rules, the backend emits one document per
/// stage permutation (N!: 1/2/6 docs) so any matching order alerts.
/// Each permutation gets a distinct title suffix (`(order: r1 -> r2)`)
/// and id suffix (`-perm-<idx>`) so the Fibratus loader treats them as
/// separate rules. The cap stops the exponential at N <= 3; for larger
/// any-order correlations the user should either drop
/// `-O temporal_permute` (and accept the documented ordered fallback)
/// or split the correlation into smaller groups.
///
/// The returned strings are full rule envelopes already;
/// [`FibratusBackend`]'s `finalize_output` joins multiple documents
/// (whether multiple correlations or multiple permutations of one
/// correlation) with `---` like detection rules.
pub fn convert(
    backend: &FibratusBackend,
    rule: &CorrelationRule,
    output_format: &str,
    pipeline_state: &PipelineState,
    warnings: &mut Vec<String>,
) -> Result<Vec<String>> {
    let rule_queries = load_rule_queries(pipeline_state);
    let cfg = &backend.fibratus;

    // Honor the user's per-conversion override (`-O correlation_method`)
    // first, falling back to the rule's own `window` attribute (default
    // `WindowMode::Sliding`).
    let window = resolve_window_mode(backend, rule)?;

    match window {
        WindowMode::Sliding => {
            // Fibratus's `sequence ... maxspan <duration>` is itself a
            // sliding total-span constraint per stage, so the existing
            // builders are already a faithful sliding lowering. Nothing
            // window-specific to do.
        }
        WindowMode::Tumbling => {
            // Fibratus has no calendar-aligned bucket primitive; the
            // intent of a tumbling window (fixed boundaries) cannot be
            // represented without changing semantics. Per the SEP this
            // is a "must error" case.
            return Err(ConvertError::UnsupportedCorrelation(format!(
                "tumbling window is unsupported (Fibratus has no calendar-aligned bucket primitive; the `sequence ... maxspan` DSL is sliding by construction). \
                 Drop `window: tumbling` (rule defaults to sliding) or convert with `-O correlation_method=sliding`. \
                 Affected rule: `{}`",
                rule.title,
            )));
        }
        WindowMode::Session => {
            // Fibratus has `maxspan` (total-span cap) but no `maxpause`
            // / per-step inactivity timeout. Per the SEP this is a
            // "should warn" case: emit the closest faithful
            // approximation (sliding sequence with the rule's
            // `timespan` as `maxspan`) and surface a warning that the
            // `gap` is not enforced.
            let declared_gap = rule
                .gap
                .as_ref()
                .map(|g| g.original.clone())
                .or_else(|| cfg.session_gap_secs.map(|s| format!("{s}s")));
            let gap_phrase = declared_gap
                .as_deref()
                .map(|g| format!("the requested {g} gap"))
                .unwrap_or_else(|| "the session gap".to_string());
            warnings.push(format!(
                "Fibratus session window: {gap_phrase} is NOT enforced (no `maxpause`-style primitive); emitted a sliding sequence with `maxspan {}` as the closest faithful approximation. Rule: `{}`",
                rule.timespan.original, rule.title,
            ));
        }
    }

    if should_emit_permutations(rule, cfg) {
        return build_temporal_permutations(backend, rule, &rule_queries, output_format);
    }

    let condition = build_sequence_condition(rule, &rule_queries, cfg)?;
    let rendered = match output_format {
        "expr" => condition,
        "default" | "yaml" | "rule" => render_correlation_yaml(rule, &condition, cfg),
        other => {
            return Err(ConvertError::RuleConversion(format!(
                "unknown output format: {other}"
            )));
        }
    };
    Ok(vec![rendered])
}

/// Resolve the effective window mode for this conversion.
///
/// `correlation_method` (when set) is the converting user's explicit
/// pySigma-style choice and overrides the rule's own `window` hint
/// for this run; otherwise the rule's `window` (default `Sliding`) is
/// used. A `correlation_method` value that is not in the backend's
/// advertised [`Backend::correlation_methods`] is rejected with a
/// rationale.
fn resolve_window_mode(backend: &FibratusBackend, rule: &CorrelationRule) -> Result<WindowMode> {
    let Some(method) = backend.fibratus.correlation_method.as_deref() else {
        return Ok(rule.window);
    };
    if !backend
        .correlation_methods()
        .iter()
        .any(|(n, _)| *n == method)
    {
        let available = backend
            .correlation_methods()
            .iter()
            .map(|(n, _)| *n)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ConvertError::UnsupportedCorrelation(format!(
            "unknown correlation_method '{method}' for the Fibratus backend; available: {available}"
        )));
    }
    method.parse::<WindowMode>().map_err(|_| {
        ConvertError::UnsupportedCorrelation(format!(
            "correlation_method '{method}' has no window mapping"
        ))
    })
}

// ---------------------------------------------------------------------
// temporal_permute: any-order temporal -> N! ordered sequences
// ---------------------------------------------------------------------

/// Whether this correlation should expand into one document per stage
/// permutation rather than a single ordered sequence. Only `temporal`
/// (any-order) with `-O temporal_permute=true` qualifies; the hard cap
/// on N is enforced later in [`build_temporal_permutations`].
fn should_emit_permutations(rule: &CorrelationRule, cfg: &FibratusConfig) -> bool {
    cfg.temporal_permute
        && rule.correlation_type == CorrelationType::Temporal
        && !rule.rules.is_empty()
}

/// Generate N! ordered sequence documents for a `temporal` correlation.
///
/// Caps at N <= 3 (so at most 6 permutations) to keep the output
/// bounded; larger correlations return `UnsupportedCorrelation` with a
/// rationale rather than silently producing dozens of rules.
fn build_temporal_permutations(
    backend: &FibratusBackend,
    rule: &CorrelationRule,
    rule_queries: &HashMap<String, String>,
    output_format: &str,
) -> Result<Vec<String>> {
    const MAX_PERMUTABLE_RULES: usize = 3;

    if rule.rules.len() > MAX_PERMUTABLE_RULES {
        return Err(ConvertError::UnsupportedCorrelation(format!(
            "temporal_permute=true with {} referenced rules would emit {}! rule documents; cap is N <= {}. Drop -O temporal_permute (the backend falls back to an ordered sequence) or split the correlation into smaller groups.",
            rule.rules.len(),
            rule.rules.len(),
            MAX_PERMUTABLE_RULES,
        )));
    }

    let perms = permutations(&rule.rules);
    let cfg = &backend.fibratus;
    let mut out: Vec<String> = Vec::with_capacity(perms.len());

    for (idx, perm) in perms.iter().enumerate() {
        // Build a single-permutation `CorrelationRule` clone with the
        // referenced rules in this order and a permutation-tagged
        // title/id so each document is a distinct Fibratus rule.
        let mut perm_rule = rule.clone();
        perm_rule.rules = perm.clone();

        let suffix_label = perm.join(" -> ");
        perm_rule.title = format!("{} (order: {suffix_label})", rule.title);
        perm_rule.id = rule.id.as_ref().map(|id| format!("{id}-perm-{idx}"));

        let stages: Vec<String> = perm
            .iter()
            .map(|name| resolve_query(name, rule_queries).map(|body| maybe_apply_macros(body, cfg)))
            .collect::<Result<Vec<_>>>()?;
        let mut stages_with_bindings: Vec<String> = Vec::with_capacity(stages.len());
        for (i, body) in stages.iter().enumerate() {
            stages_with_bindings.push(pin_group_by_after_first(body, &rule.group_by, i));
        }
        let condition = format_sequence(
            &rule.timespan.original,
            &stages_with_bindings,
            &rule.group_by,
        );

        let rendered = match output_format {
            "expr" => condition,
            "default" | "yaml" | "rule" => render_correlation_yaml(&perm_rule, &condition, cfg),
            other => {
                return Err(ConvertError::RuleConversion(format!(
                    "unknown output format: {other}"
                )));
            }
        };
        out.push(rendered);
    }
    Ok(out)
}

/// Generate every permutation of `items` in lexicographic order (a
/// simple Heap-style enumeration tweaked to preserve the input order
/// when N <= 1). Used by [`build_temporal_permutations`]; the small
/// cap (N <= 3) means the O(N!) cost is bounded at 6 calls per
/// correlation.
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.is_empty() {
        return vec![Vec::new()];
    }
    if items.len() == 1 {
        return vec![items.to_vec()];
    }
    let mut out: Vec<Vec<T>> = Vec::new();
    for (i, head) in items.iter().enumerate() {
        let mut rest: Vec<T> = Vec::with_capacity(items.len() - 1);
        rest.extend_from_slice(&items[..i]);
        rest.extend_from_slice(&items[i + 1..]);
        for tail in permutations(&rest) {
            let mut full = Vec::with_capacity(items.len());
            full.push(head.clone());
            full.extend(tail);
            out.push(full);
        }
    }
    out
}

// ---------------------------------------------------------------------
// Sequence builder
// ---------------------------------------------------------------------

/// Build the full multi-line `sequence ... maxspan ... | stage | by ...`
/// condition body. Stage bodies come from `_rule_queries`; missing rule
/// references fall back to a `MissingRuleReference` error so the caller
/// can surface it.
fn build_sequence_condition(
    rule: &CorrelationRule,
    rule_queries: &HashMap<String, String>,
    cfg: &FibratusConfig,
) -> Result<String> {
    require_supported_correlation_type(rule)?;

    let threshold = match &rule.condition {
        CorrelationCondition::Threshold { predicates, .. } => extract_threshold(predicates)?,
        CorrelationCondition::Extended(_) => {
            return Err(ConvertError::UnsupportedCorrelation(
                "extended boolean correlation conditions are not yet supported (Fibratus sequence DSL is a list of stages, not a boolean tree)"
                    .into(),
            ));
        }
    };

    match rule.correlation_type {
        CorrelationType::TemporalOrdered | CorrelationType::Temporal => {
            build_temporal_sequence(rule, rule_queries, cfg)
        }
        CorrelationType::EventCount => {
            build_event_count_sequence(rule, rule_queries, cfg, threshold)
        }
        CorrelationType::ValueCount => {
            build_value_count_sequence(rule, rule_queries, cfg, threshold)
        }
        // The four math-aggregate types have no Fibratus equivalent; the
        // entry point pre-screens them via `require_supported_correlation_type`.
        _ => unreachable!("aggregate types rejected earlier"),
    }
}

/// Returns the integer threshold from a single `gte`/`gt` predicate or
/// an error otherwise. Fibratus's repeat-stage emulation can only
/// express "at least N occurrences"; ranges, `eq`/`neq`/`lt`/`lte`
/// require primitives Fibratus does not have.
fn extract_threshold(predicates: &[(ConditionOperator, u64)]) -> Result<u64> {
    if predicates.len() != 1 {
        return Err(ConvertError::UnsupportedCorrelation(format!(
            "correlation condition with {} predicates is unsupported (Fibratus sequences can only emulate single 'at least N' thresholds)",
            predicates.len(),
        )));
    }
    let (op, val) = predicates[0];
    match op {
        ConditionOperator::Gte => Ok(val),
        ConditionOperator::Gt => Ok(val.saturating_add(1)),
        ConditionOperator::Lt
        | ConditionOperator::Lte
        | ConditionOperator::Eq
        | ConditionOperator::Neq => Err(ConvertError::UnsupportedCorrelation(format!(
            "correlation condition operator {op:?} cannot be emulated as a Fibratus sequence (only gt/gte are expressible as 'at least N occurrences')"
        ))),
    }
}

fn require_supported_correlation_type(rule: &CorrelationRule) -> Result<()> {
    match rule.correlation_type {
        CorrelationType::TemporalOrdered
        | CorrelationType::Temporal
        | CorrelationType::EventCount
        | CorrelationType::ValueCount => Ok(()),
        CorrelationType::ValueSum
        | CorrelationType::ValueAvg
        | CorrelationType::ValuePercentile
        | CorrelationType::ValueMedian => Err(ConvertError::UnsupportedCorrelation(format!(
            "{} correlation has no Fibratus primitive (sequences cannot express running sums/averages/quantiles over field values)",
            rule.correlation_type.as_str(),
        ))),
    }
}

// ---------------------------------------------------------------------
// Per-type builders
// ---------------------------------------------------------------------

/// `temporal_ordered` (and `temporal`, with a doc warning) → one stage
/// per referenced rule in declaration order, each followed by the
/// configured `| by` group-by field(s).
fn build_temporal_sequence(
    rule: &CorrelationRule,
    rule_queries: &HashMap<String, String>,
    cfg: &FibratusConfig,
) -> Result<String> {
    if rule.rules.is_empty() {
        return Err(ConvertError::UnsupportedCorrelation(
            "temporal correlation must reference at least one rule".into(),
        ));
    }

    let stages: Vec<String> = rule
        .rules
        .iter()
        .map(|name| resolve_query(name, rule_queries).map(|body| maybe_apply_macros(body, cfg)))
        .collect::<Result<Vec<_>>>()?;

    let mut stages_with_bindings: Vec<String> = Vec::with_capacity(stages.len());
    for (idx, body) in stages.iter().enumerate() {
        let with_binds = pin_group_by_after_first(body, &rule.group_by, idx);
        stages_with_bindings.push(with_binds);
    }

    Ok(format_sequence(
        &rule.timespan.original,
        &stages_with_bindings,
        &rule.group_by,
    ))
}

/// `event_count` with a small `gte`/`gt` threshold → N repeated stages
/// of the referenced rule, pinned on the group-by field(s).
fn build_event_count_sequence(
    rule: &CorrelationRule,
    rule_queries: &HashMap<String, String>,
    cfg: &FibratusConfig,
    threshold: u64,
) -> Result<String> {
    if rule.rules.len() != 1 {
        return Err(ConvertError::UnsupportedCorrelation(format!(
            "event_count correlation referencing {} rules is unsupported (Fibratus sequence emulation repeats one rule N times)",
            rule.rules.len(),
        )));
    }
    if threshold == 0 {
        return Err(ConvertError::UnsupportedCorrelation(
            "event_count threshold of 0 events has no useful Fibratus emulation".into(),
        ));
    }
    if threshold > cfg.max_repeated_slots {
        return Err(ConvertError::UnsupportedCorrelation(format!(
            "event_count threshold {threshold} exceeds -O max_repeated_slots={} (Fibratus sequences are bounded; raise the cap or use a sliding-window backend)",
            cfg.max_repeated_slots,
        )));
    }

    let body = maybe_apply_macros(resolve_query(&rule.rules[0], rule_queries)?, cfg);
    let mut stages: Vec<String> = Vec::with_capacity(threshold as usize);
    for idx in 0..threshold as usize {
        stages.push(pin_group_by_after_first(&body, &rule.group_by, idx));
    }
    Ok(format_sequence(
        &rule.timespan.original,
        &stages,
        &rule.group_by,
    ))
}

/// `value_count` with a small `gte`/`gt` threshold and a single
/// `field:` → N aliased stages, each pinned on the group-by field(s),
/// with pairwise distinctness constraints (`field != $e1.field and
/// field != $e2.field and ...`) on the value field so the N stitched
/// events carry distinct values.
fn build_value_count_sequence(
    rule: &CorrelationRule,
    rule_queries: &HashMap<String, String>,
    cfg: &FibratusConfig,
    threshold: u64,
) -> Result<String> {
    if rule.rules.len() != 1 {
        return Err(ConvertError::UnsupportedCorrelation(format!(
            "value_count correlation referencing {} rules is unsupported (Fibratus sequence emulation repeats one rule N times)",
            rule.rules.len(),
        )));
    }
    let field = match &rule.condition {
        CorrelationCondition::Threshold {
            field: Some(fields),
            ..
        } if fields.len() == 1 => fields[0].clone(),
        CorrelationCondition::Threshold {
            field: Some(fields),
            ..
        } => {
            return Err(ConvertError::UnsupportedCorrelation(format!(
                "value_count over a tuple of {} fields is unsupported (Fibratus pairwise-distinctness emulation handles one field at a time)",
                fields.len(),
            )));
        }
        _ => {
            return Err(ConvertError::UnsupportedCorrelation(
                "value_count correlation requires a `field:` in its condition".into(),
            ));
        }
    };
    if threshold == 0 {
        return Err(ConvertError::UnsupportedCorrelation(
            "value_count threshold of 0 distinct values has no useful Fibratus emulation".into(),
        ));
    }
    if threshold > cfg.max_repeated_slots {
        return Err(ConvertError::UnsupportedCorrelation(format!(
            "value_count threshold {threshold} exceeds -O max_repeated_slots={} (Fibratus sequences are bounded; raise the cap or use a sliding-window backend)",
            cfg.max_repeated_slots,
        )));
    }

    let body = maybe_apply_macros(resolve_query(&rule.rules[0], rule_queries)?, cfg);
    let mut stages: Vec<String> = Vec::with_capacity(threshold as usize);
    for idx in 0..threshold as usize {
        // Alias each stage so later stages can reference prior values.
        let mut stage = pin_group_by_after_first(&body, &rule.group_by, idx);
        // Pairwise distinctness against every earlier alias.
        for prior in 0..idx {
            stage.push_str(&format!(
                " and {field} != $e{prior_alias}.{field}",
                prior_alias = prior + 1
            ));
        }
        stages.push(stage);
    }
    Ok(format_sequence_aliased(
        &rule.timespan.original,
        &stages,
        &rule.group_by,
    ))
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Look up a referenced rule's converted query string. The `_rule_queries`
/// map is keyed by both rule ID and rule title (see
/// [`crate::convert_collection`]); try both before giving up.
fn resolve_query(name: &str, rule_queries: &HashMap<String, String>) -> Result<String> {
    let raw = rule_queries
        .get(name)
        .cloned()
        .ok_or_else(|| ConvertError::UnsupportedCorrelation(format!(
            "correlation references rule `{name}` but no converted query was found; ensure the referenced rule is in the same collection"
        )))?;
    Ok(strip_envelope(&raw))
}

/// Extract the bare Fibratus condition body from a `default`-format
/// rule envelope.
///
/// `convert_collection` populates `_rule_queries` with the first output
/// query for each rule. For Fibratus's `default`/`yaml`/`rule` formats
/// that is the full YAML rule document; for `expr` it is already the
/// bare expression. Both shapes need to lower to a bare expression
/// suitable for embedding inside a `sequence ... | <stage> | ...` DSL.
///
/// Recognized envelope shapes (all emitted by [`super::envelope`]):
///
/// - Single-line: `condition: <expr>\n` — capture the rest of the line.
/// - Folded multi-line: `condition: >\n  <line1>\n  <line2>\n...` —
///   capture every indented line until the next zero-indent key (e.g.
///   `min-engine-version:`), join them with a single space.
///
/// If `input` does not look like an envelope (no `condition:` line),
/// return it verbatim so the `expr` format round-trips cleanly.
fn strip_envelope(input: &str) -> String {
    // Detect the start of a `condition:` block at column 0.
    let condition_start = input
        .lines()
        .enumerate()
        .find_map(|(i, line)| line.strip_prefix("condition:").map(|tail| (i, tail)));
    let Some((idx, tail)) = condition_start else {
        return input.to_string();
    };

    let tail = tail.trim_start();
    // Single-line `condition: <expr>` — return the trimmed tail.
    if !tail.starts_with('>') && !tail.starts_with('|') {
        return tail.to_string();
    }

    // Folded/literal block scalar: gather indented body lines until the
    // next zero-indent line that looks like a YAML key (`foo:`).
    let mut body_lines: Vec<String> = Vec::new();
    for line in input.lines().skip(idx + 1) {
        if line.is_empty() {
            // Blank lines inside a folded scalar collapse to a single
            // space when joined; skip them here.
            continue;
        }
        let leading = line.chars().take_while(|c| c.is_whitespace()).count();
        if leading == 0 {
            // Back to top-level YAML keys: end of the block scalar.
            break;
        }
        body_lines.push(line.trim().to_string());
    }
    body_lines.join(" ")
}

/// For every stage after the first, append `and $1.field = field` for
/// every group-by field beyond the first one. Single-field group-by is
/// expressed via the per-stage `| by <field>` clause emitted by
/// [`format_sequence`], so this helper only emits inline bindings for
/// the second through Nth fields where `by` cannot.
fn pin_group_by_after_first(body: &str, group_by: &[String], stage_idx: usize) -> String {
    if stage_idx == 0 || group_by.len() <= 1 {
        return body.to_string();
    }
    let mut out = body.to_string();
    for field in group_by.iter().skip(1) {
        out.push_str(&format!(" and $1.{field} = {field}"));
    }
    out
}

/// Render `sequence`/`maxspan`/`| <stage> | by <field>` form. The first
/// group-by field becomes the per-stage `by` key; secondary fields are
/// pinned via inline bindings in [`pin_group_by_after_first`].
fn format_sequence(timespan: &str, stages: &[String], group_by: &[String]) -> String {
    let mut out = String::with_capacity(stages.iter().map(|s| s.len()).sum::<usize>() + 64);
    out.push_str("sequence\n");
    out.push_str(&format!("maxspan {timespan}\n"));
    let primary_by = group_by.first().map(String::as_str);
    for stage in stages {
        out.push_str("  |");
        out.push_str(stage);
        out.push('\n');
        if let Some(by) = primary_by {
            out.push_str(&format!("  | by {by}\n"));
        }
    }
    // Trim the trailing newline so the envelope's folded scalar gets
    // a clean last line.
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Same as [`format_sequence`] but emits `| as eN` aliases after each
/// stage so subsequent stages can reference prior matched values
/// (`$e1.field`/`$e2.field`/...). Used by the value-count distinctness
/// emulation.
fn format_sequence_aliased(timespan: &str, stages: &[String], group_by: &[String]) -> String {
    let mut out = String::with_capacity(stages.iter().map(|s| s.len()).sum::<usize>() + 96);
    out.push_str("sequence\n");
    out.push_str(&format!("maxspan {timespan}\n"));
    let primary_by = group_by.first().map(String::as_str);
    for (idx, stage) in stages.iter().enumerate() {
        out.push_str("  |");
        out.push_str(stage);
        out.push('\n');
        out.push_str(&format!("  | as e{}\n", idx + 1));
        if let Some(by) = primary_by {
            out.push_str(&format!("  | by {by}\n"));
        }
    }
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Pull the `_rule_queries` map injected by
/// [`crate::convert_collection`] into the correlation pipeline state.
fn load_rule_queries(state: &PipelineState) -> HashMap<String, String> {
    state
        .state
        .get("_rule_queries")
        .and_then(|v| serde_json::from_value::<HashMap<String, String>>(v.clone()).ok())
        .unwrap_or_default()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::parse_sigma_yaml;

    fn collection(yaml: &str) -> rsigma_parser::SigmaCollection {
        parse_sigma_yaml(yaml).unwrap()
    }

    /// Helper: convert a multi-document YAML where the first N entries
    /// are detection rules and the last is a correlation; return the
    /// rendered correlation queries.
    fn run(yaml: &str) -> crate::Result<Vec<String>> {
        run_with_format(yaml, "expr")
    }

    fn run_with_format(yaml: &str, format: &str) -> crate::Result<Vec<String>> {
        run_with_backend(yaml, format, FibratusBackend::new())
    }

    fn run_with_backend(
        yaml: &str,
        format: &str,
        backend: FibratusBackend,
    ) -> crate::Result<Vec<String>> {
        let coll = collection(yaml);
        let result = crate::convert_collection(&backend, &coll, &[], format)?;
        let mut out = Vec::new();
        for query_group in &result.queries {
            for q in &query_group.queries {
                if q.contains("sequence") || (format != "expr" && q.contains("condition: >")) {
                    out.push(q.clone());
                }
            }
        }
        if let Some((title, err)) = result.errors.into_iter().next() {
            return Err(crate::ConvertError::RuleConversion(format!(
                "{title}: {err}"
            )));
        }
        Ok(out)
    }

    /// Build a `FibratusBackend` with `temporal_permute=true` so the
    /// any-order tests below opt into the permutation path.
    fn backend_with_temporal_permute() -> FibratusBackend {
        let mut opts = std::collections::HashMap::new();
        opts.insert("temporal_permute".to_string(), "true".to_string());
        FibratusBackend::from_options(&opts)
    }

    // -----------------------------------------------------------------
    // temporal_ordered
    // -----------------------------------------------------------------

    #[test]
    fn temporal_ordered_two_rules_with_group_by() {
        let q = run(r#"
title: First Stage
id: 00000000-0000-0000-0000-000000000001
detection:
  s:
    evt.name: Connect
  condition: s
---
title: Second Stage
id: 00000000-0000-0000-0000-000000000002
detection:
  s:
    evt.name: CreateProcess
  condition: s
---
title: Connect then Spawn
correlation:
  type: temporal_ordered
  rules:
    - 00000000-0000-0000-0000-000000000001
    - 00000000-0000-0000-0000-000000000002
  group-by:
    - ps.pid
  timespan: 1m
"#)
        .unwrap();
        assert_eq!(q.len(), 1);
        let body = &q[0];
        assert!(body.starts_with("sequence\nmaxspan 1m\n"));
        // Per-stage bodies pass through the macro recognizer too, so
        // `evt.name imatches 'Connect'` becomes `connect_socket`.
        assert!(body.contains("|connect_socket\n"));
        assert!(body.contains("| by ps.pid"));
        assert!(body.contains("|spawn_process\n"));
    }

    #[test]
    fn temporal_ordered_multi_field_group_by_pins_inline_bindings() {
        let q = run(r#"
title: First
id: 00000000-0000-0000-0000-00000000000a
detection:
  s:
    evt.name: Connect
  condition: s
---
title: Second
id: 00000000-0000-0000-0000-00000000000b
detection:
  s:
    evt.name: CreateProcess
  condition: s
---
title: Stitched
correlation:
  type: temporal_ordered
  rules:
    - 00000000-0000-0000-0000-00000000000a
    - 00000000-0000-0000-0000-00000000000b
  group-by:
    - ps.pid
    - ps.username
  timespan: 30s
"#)
        .unwrap();
        let body = &q[0];
        // Primary field via the `by` clause, secondary via inline binding.
        assert!(body.contains("| by ps.pid"));
        assert!(
            body.contains("and $1.ps.username = ps.username"),
            "expected secondary field binding, got: {body}",
        );
    }

    // -----------------------------------------------------------------
    // temporal (any-order falls back to ordered)
    // -----------------------------------------------------------------

    #[test]
    fn temporal_any_order_falls_back_to_ordered_sequence() {
        let q = run(r#"
title: R1
id: 00000000-0000-0000-0000-000000000010
detection:
  s:
    evt.name: A
  condition: s
---
title: R2
id: 00000000-0000-0000-0000-000000000011
detection:
  s:
    evt.name: B
  condition: s
---
title: Any-order
correlation:
  type: temporal
  rules:
    - 00000000-0000-0000-0000-000000000010
    - 00000000-0000-0000-0000-000000000011
  group-by:
    - ps.pid
  timespan: 5m
"#)
        .unwrap();
        // Same DSL shape as temporal_ordered; the divergence is documented
        // in the rule's description block by the docs layer.
        assert!(q[0].contains("sequence\nmaxspan 5m\n"));
    }

    #[test]
    fn temporal_permute_emits_n_factorial_rules_for_n2() {
        let q = run_with_backend(
            r#"
title: R1
id: 00000000-0000-0000-0000-000000000010
detection:
  s:
    evt.name: A
  condition: s
---
title: R2
id: 00000000-0000-0000-0000-000000000011
detection:
  s:
    evt.name: B
  condition: s
---
title: Any-order
id: deadbeef-0000-0000-0000-000000000000
correlation:
  type: temporal
  rules:
    - 00000000-0000-0000-0000-000000000010
    - 00000000-0000-0000-0000-000000000011
  group-by:
    - ps.pid
  timespan: 5m
"#,
            "expr",
            backend_with_temporal_permute(),
        )
        .unwrap();
        // N=2 -> 2 permutations. Both orderings must appear; the helper
        // strips the YAML envelope so we compare the bare sequence body.
        assert_eq!(q.len(), 2, "expected 2 permutations, got {q:?}");
        let joined = q.join("\n===\n");
        // Stage A first ordering
        assert!(
            joined.contains(
                "|evt.name imatches 'A'\n  | by ps.pid\n  |evt.name imatches 'B'\n  | by ps.pid"
            ),
            "missing A->B ordering, joined: {joined}"
        );
        // Stage B first ordering
        assert!(
            joined.contains(
                "|evt.name imatches 'B'\n  | by ps.pid\n  |evt.name imatches 'A'\n  | by ps.pid"
            ),
            "missing B->A ordering, joined: {joined}"
        );
    }

    #[test]
    fn temporal_permute_n3_emits_six_documents_with_distinct_titles() {
        let q = run_with_backend(
            r#"
title: R1
id: 00000000-0000-0000-0000-000000000020
detection:
  s:
    evt.name: A
  condition: s
---
title: R2
id: 00000000-0000-0000-0000-000000000021
detection:
  s:
    evt.name: B
  condition: s
---
title: R3
id: 00000000-0000-0000-0000-000000000022
detection:
  s:
    evt.name: C
  condition: s
---
title: Three any-order
id: 11111111-1111-1111-1111-111111111111
correlation:
  type: temporal
  rules:
    - 00000000-0000-0000-0000-000000000020
    - 00000000-0000-0000-0000-000000000021
    - 00000000-0000-0000-0000-000000000022
  group-by:
    - ps.pid
  timespan: 5m
"#,
            "default",
            backend_with_temporal_permute(),
        )
        .unwrap();
        assert_eq!(q.len(), 6, "expected 3! = 6 permutations, got {}", q.len());
        // Each permutation gets a distinct id suffix.
        for idx in 0..6 {
            let needle = format!("id: 11111111-1111-1111-1111-111111111111-perm-{idx}");
            assert!(
                q.iter().any(|doc| doc.contains(&needle)),
                "missing permutation id suffix `{needle}` in {q:?}",
            );
        }
        // And a distinct order-tagged title.
        assert!(q.iter().any(|d| d.contains("(order: 00000000-0000-0000-0000-000000000020 -> 00000000-0000-0000-0000-000000000021 -> 00000000-0000-0000-0000-000000000022)")));
        assert!(q.iter().any(|d| d.contains("(order: 00000000-0000-0000-0000-000000000022 -> 00000000-0000-0000-0000-000000000021 -> 00000000-0000-0000-0000-000000000020)")));
    }

    #[test]
    fn temporal_permute_rejects_n_above_cap() {
        let yaml = r#"
title: R1
id: 00000000-0000-0000-0000-000000000030
detection:
  s:
    evt.name: A
  condition: s
---
title: R2
id: 00000000-0000-0000-0000-000000000031
detection:
  s:
    evt.name: B
  condition: s
---
title: R3
id: 00000000-0000-0000-0000-000000000032
detection:
  s:
    evt.name: C
  condition: s
---
title: R4
id: 00000000-0000-0000-0000-000000000033
detection:
  s:
    evt.name: D
  condition: s
---
title: Too many
correlation:
  type: temporal
  rules:
    - 00000000-0000-0000-0000-000000000030
    - 00000000-0000-0000-0000-000000000031
    - 00000000-0000-0000-0000-000000000032
    - 00000000-0000-0000-0000-000000000033
  group-by:
    - ps.pid
  timespan: 5m
"#;
        let err = run_with_backend(yaml, "expr", backend_with_temporal_permute()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("temporal_permute") && msg.contains("cap is N <="),
            "expected cap-exceeded error, got: {msg}",
        );
    }

    // -----------------------------------------------------------------
    // window: sliding / tumbling / session (#192)
    // -----------------------------------------------------------------

    fn collection_and_backend(
        yaml: &str,
        backend: FibratusBackend,
    ) -> (rsigma_parser::SigmaCollection, FibratusBackend) {
        (collection(yaml), backend)
    }

    /// Convert a multi-doc YAML (detections + one correlation) with the
    /// supplied backend, returning `(queries, warnings)` for the
    /// correlation rule(s).
    fn convert_with_warnings(
        yaml: &str,
        backend: &FibratusBackend,
    ) -> crate::Result<(Vec<String>, Vec<String>)> {
        let coll = collection(yaml);
        let result = crate::convert_collection(backend, &coll, &[], "expr")?;
        let mut queries = Vec::new();
        let mut warnings = Vec::new();
        for group in &result.queries {
            for q in &group.queries {
                if q.contains("sequence") {
                    queries.push(q.clone());
                }
            }
            warnings.extend(group.warnings.iter().cloned());
        }
        if let Some((title, err)) = result.errors.into_iter().next() {
            return Err(crate::ConvertError::RuleConversion(format!(
                "{title}: {err}"
            )));
        }
        Ok((queries, warnings))
    }

    fn backend_with_correlation_method(method: &str) -> FibratusBackend {
        let mut opts = std::collections::HashMap::new();
        opts.insert("correlation_method".to_string(), method.to_string());
        FibratusBackend::from_options(&opts)
    }

    fn backend_with_session_gap_default(gap: &str) -> FibratusBackend {
        let mut opts = std::collections::HashMap::new();
        opts.insert("correlation_method".to_string(), "session".to_string());
        opts.insert("gap".to_string(), gap.to_string());
        FibratusBackend::from_options(&opts)
    }

    const TWO_RULE_TEMPORAL: &str = r#"
title: R1
id: 00000000-0000-0000-0000-000000000050
detection:
  s:
    evt.name: A
  condition: s
---
title: R2
id: 00000000-0000-0000-0000-000000000051
detection:
  s:
    evt.name: B
  condition: s
"#;

    #[test]
    fn sliding_window_is_a_native_pass_through() {
        // Sliding is the default; the Fibratus sequence DSL's `maxspan`
        // is already a sliding total-span constraint per stage, so the
        // rendered output should be byte-identical to the existing
        // temporal_ordered path and the warnings list should stay
        // empty.
        let (q, w) = convert_with_warnings(
            &format!(
                r#"{TWO_RULE_TEMPORAL}
---
title: Sliding
correlation:
  type: temporal_ordered
  rules:
    - 00000000-0000-0000-0000-000000000050
    - 00000000-0000-0000-0000-000000000051
  group-by:
    - ps.pid
  timespan: 5m
rsigma.window: sliding
"#,
            ),
            &FibratusBackend::new(),
        )
        .unwrap();
        assert_eq!(q.len(), 1);
        assert!(q[0].contains("sequence\nmaxspan 5m\n"));
        assert!(w.is_empty(), "sliding must not warn, got: {w:?}");
    }

    #[test]
    fn tumbling_window_returns_unsupported_with_actionable_message() {
        let (_coll, backend) = collection_and_backend(
            &format!(
                r#"{TWO_RULE_TEMPORAL}
---
title: Tumbling
correlation:
  type: temporal_ordered
  rules:
    - 00000000-0000-0000-0000-000000000050
    - 00000000-0000-0000-0000-000000000051
  group-by:
    - ps.pid
  timespan: 1h
rsigma.window: tumbling
"#,
            ),
            FibratusBackend::new(),
        );
        let err = convert_with_warnings(
            &format!(
                r#"{TWO_RULE_TEMPORAL}
---
title: Tumbling
correlation:
  type: temporal_ordered
  rules:
    - 00000000-0000-0000-0000-000000000050
    - 00000000-0000-0000-0000-000000000051
  group-by:
    - ps.pid
  timespan: 1h
rsigma.window: tumbling
"#,
            ),
            &backend,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("tumbling")
                && msg.contains("calendar-aligned")
                && msg.contains("Tumbling"),
            "tumbling error must explain the gap and name the rule, got: {msg}",
        );
    }

    #[test]
    fn session_window_degrades_to_sliding_with_warning() {
        let (q, w) = convert_with_warnings(
            &format!(
                r#"{TWO_RULE_TEMPORAL}
---
title: Session degrade
correlation:
  type: temporal_ordered
  rules:
    - 00000000-0000-0000-0000-000000000050
    - 00000000-0000-0000-0000-000000000051
  group-by:
    - ps.pid
  timespan: 1h
rsigma.window: session
rsigma.gap: 5m
"#,
            ),
            &FibratusBackend::new(),
        )
        .unwrap();
        assert_eq!(q.len(), 1, "session must still emit one rule, got {q:?}");
        // The condition body is the same shape as a sliding emission
        // (no native gap primitive); we just expect `maxspan 1h`.
        assert!(q[0].contains("maxspan 1h"), "got: {q:?}");
        assert_eq!(w.len(), 1, "expected one warning, got {w:?}");
        let warn = &w[0];
        assert!(
            warn.contains("session window") && warn.contains("NOT enforced") && warn.contains("5m"),
            "warning must explain the degradation, got: {warn}",
        );
    }

    #[test]
    fn correlation_method_session_default_gap_supplies_warning_text() {
        // The rule does not declare its own `gap`; the `-O gap=` option
        // provides the fallback that ends up in the warning text.
        let backend = backend_with_session_gap_default("10m");
        let (q, w) = convert_with_warnings(
            &format!(
                r#"{TWO_RULE_TEMPORAL}
---
title: Method session
correlation:
  type: temporal_ordered
  rules:
    - 00000000-0000-0000-0000-000000000050
    - 00000000-0000-0000-0000-000000000051
  group-by:
    - ps.pid
  timespan: 30m
"#,
            ),
            &backend,
        )
        .unwrap();
        assert_eq!(q.len(), 1);
        assert!(q[0].contains("maxspan 30m"));
        assert_eq!(w.len(), 1);
        assert!(
            w[0].contains("600s") || w[0].contains("10m"),
            "got: {}",
            w[0]
        );
    }

    #[test]
    fn correlation_method_overrides_rule_window() {
        // Rule asks for sliding; the operator passes
        // `-O correlation_method=session`, so the conversion runs as
        // session (and warns), even though the rule itself didn't
        // declare a session window.
        let backend = backend_with_session_gap_default("15m");
        let (q, w) = convert_with_warnings(
            &format!(
                r#"{TWO_RULE_TEMPORAL}
---
title: Method overrides rule
correlation:
  type: temporal_ordered
  rules:
    - 00000000-0000-0000-0000-000000000050
    - 00000000-0000-0000-0000-000000000051
  group-by:
    - ps.pid
  timespan: 1h
rsigma.window: sliding
"#,
            ),
            &backend,
        )
        .unwrap();
        assert_eq!(q.len(), 1);
        assert_eq!(w.len(), 1, "operator override must surface the warning");
    }

    #[test]
    fn correlation_method_unknown_is_rejected() {
        let backend = backend_with_correlation_method("tumbling");
        // `tumbling` is intentionally absent from the Fibratus
        // backend's `correlation_methods()` list because Fibratus
        // cannot represent it; the override must be rejected up front.
        let err = convert_with_warnings(
            &format!(
                r#"{TWO_RULE_TEMPORAL}
---
title: t
correlation:
  type: temporal_ordered
  rules:
    - 00000000-0000-0000-0000-000000000050
    - 00000000-0000-0000-0000-000000000051
  group-by:
    - ps.pid
  timespan: 1h
"#,
            ),
            &backend,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown correlation_method 'tumbling'")
                && msg.contains("sliding")
                && msg.contains("session"),
            "rejection must name the available methods, got: {msg}",
        );
    }

    #[test]
    fn temporal_permute_does_not_affect_temporal_ordered() {
        // `temporal_ordered` is already strictly ordered; the
        // permutation flag must not duplicate it into N! rules.
        let q = run_with_backend(
            r#"
title: R1
id: 00000000-0000-0000-0000-000000000040
detection:
  s:
    evt.name: A
  condition: s
---
title: R2
id: 00000000-0000-0000-0000-000000000041
detection:
  s:
    evt.name: B
  condition: s
---
title: Ordered
correlation:
  type: temporal_ordered
  rules:
    - 00000000-0000-0000-0000-000000000040
    - 00000000-0000-0000-0000-000000000041
  group-by:
    - ps.pid
  timespan: 5m
"#,
            "expr",
            backend_with_temporal_permute(),
        )
        .unwrap();
        assert_eq!(q.len(), 1, "temporal_ordered must stay single-document");
    }

    // -----------------------------------------------------------------
    // event_count
    // -----------------------------------------------------------------

    #[test]
    fn event_count_emits_repeated_stages() {
        let q = run(r#"
title: Failed Auth
id: 00000000-0000-0000-0000-000000000020
detection:
  s:
    evt.name: AuthFail
  condition: s
---
title: Brute force
correlation:
  type: event_count
  rules:
    - 00000000-0000-0000-0000-000000000020
  group-by:
    - net.sip
  timespan: 5m
  condition:
    gte: 3
"#)
        .unwrap();
        let body = &q[0];
        assert!(body.starts_with("sequence\nmaxspan 5m\n"));
        // 3 repeated stages each followed by `| by net.sip`.
        let stages = body.matches("|evt.name imatches 'AuthFail'\n").count();
        assert_eq!(stages, 3, "want 3 repeated stages, got: {body}");
        let bys = body.matches("| by net.sip").count();
        assert_eq!(bys, 3, "want 3 by-clauses, got: {body}");
    }

    #[test]
    fn event_count_threshold_above_cap_is_rejected() {
        let err = run(r#"
title: R
id: 00000000-0000-0000-0000-000000000030
detection:
  s:
    evt.name: X
  condition: s
---
title: Big
correlation:
  type: event_count
  rules:
    - 00000000-0000-0000-0000-000000000030
  group-by:
    - net.sip
  timespan: 1h
  condition:
    gte: 50
"#)
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("max_repeated_slots"), "got: {msg}");
    }

    #[test]
    fn event_count_with_gt_operator_adds_one() {
        let q = run(r#"
title: R
id: 00000000-0000-0000-0000-000000000035
detection:
  s:
    evt.name: X
  condition: s
---
title: GT
correlation:
  type: event_count
  rules:
    - 00000000-0000-0000-0000-000000000035
  group-by:
    - ps.pid
  timespan: 1m
  condition:
    gt: 2
"#)
        .unwrap();
        // gt: 2 means at-least-3 occurrences; expect 3 repeated stages.
        let stages = q[0].matches("|evt.name imatches 'X'\n").count();
        assert_eq!(stages, 3);
    }

    // -----------------------------------------------------------------
    // value_count
    // -----------------------------------------------------------------

    #[test]
    fn value_count_distinct_emits_aliased_stages_with_pairwise_inequality() {
        let q = run(r#"
title: AuthFail
id: 00000000-0000-0000-0000-000000000040
detection:
  s:
    evt.name: AuthFail
  condition: s
---
title: 3 distinct usernames
correlation:
  type: value_count
  rules:
    - 00000000-0000-0000-0000-000000000040
  group-by:
    - net.sip
  timespan: 5m
  condition:
    gte: 3
    field: ps.username
"#)
        .unwrap();
        let body = &q[0];
        assert!(body.contains("| as e1"));
        assert!(body.contains("| as e2"));
        assert!(body.contains("| as e3"));
        assert!(body.contains("ps.username != $e1.ps.username"));
        assert!(body.contains("ps.username != $e2.ps.username"));
    }

    #[test]
    fn value_count_missing_field_rejected() {
        let err = run(r#"
title: R
id: 00000000-0000-0000-0000-000000000050
detection:
  s:
    evt.name: X
  condition: s
---
title: ValueCount
correlation:
  type: value_count
  rules:
    - 00000000-0000-0000-0000-000000000050
  group-by:
    - net.sip
  timespan: 5m
  condition:
    gte: 2
"#)
        .unwrap_err();
        assert!(format!("{err}").contains("field"));
    }

    // -----------------------------------------------------------------
    // Aggregate types — all rejected with structured errors
    // -----------------------------------------------------------------

    fn assert_aggregate_rejected(ctype: &str, field: Option<&str>) {
        let field_block = field
            .map(|f| format!("    field: {f}\n"))
            .unwrap_or_default();
        let yaml = format!(
            r#"
title: R
id: 00000000-0000-0000-0000-000000000060
detection:
  s:
    evt.name: X
  condition: s
---
title: Agg
correlation:
  type: {ctype}
  rules:
    - 00000000-0000-0000-0000-000000000060
  group-by:
    - net.sip
  timespan: 5m
  condition:
    gte: 10
{field_block}"#
        );
        let err = run(&yaml).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains(ctype) && msg.contains("Fibratus"),
            "{ctype}: expected structured rejection, got: {msg}",
        );
    }

    #[test]
    fn value_sum_rejected() {
        assert_aggregate_rejected("value_sum", Some("file.io.size"));
    }

    #[test]
    fn value_avg_rejected() {
        assert_aggregate_rejected("value_avg", Some("file.io.size"));
    }

    #[test]
    fn value_percentile_rejected() {
        assert_aggregate_rejected("value_percentile", Some("file.io.size"));
    }

    #[test]
    fn value_median_rejected() {
        assert_aggregate_rejected("value_median", Some("file.io.size"));
    }

    // -----------------------------------------------------------------
    // Missing rule reference
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // Envelope stripping (called for every referenced rule)
    // -----------------------------------------------------------------

    #[test]
    fn strip_envelope_handles_single_line_condition() {
        let env = "name: x\nid: y\ncondition: ps.exe = 'cmd.exe'\nmin-engine-version: 3.0.0\n";
        assert_eq!(super::strip_envelope(env), "ps.exe = 'cmd.exe'");
    }

    #[test]
    fn strip_envelope_handles_folded_condition() {
        let env =
            "name: x\ncondition: >\n  a = 1 and b = 2\n  and c = 3\nmin-engine-version: 3.0.0\n";
        assert_eq!(super::strip_envelope(env), "a = 1 and b = 2 and c = 3");
    }

    #[test]
    fn strip_envelope_passes_bare_expression_through() {
        let bare = "ps.exe = 'cmd.exe'";
        assert_eq!(super::strip_envelope(bare), "ps.exe = 'cmd.exe'");
    }

    // -----------------------------------------------------------------
    // Missing rule reference
    // -----------------------------------------------------------------

    #[test]
    fn missing_rule_reference_surfaces_structured_error() {
        let err = run(r#"
title: Orphan
correlation:
  type: event_count
  rules:
    - 00000000-0000-0000-0000-deaddeaddead
  group-by:
    - net.sip
  timespan: 5m
  condition:
    gte: 2
"#)
        .unwrap_err();
        assert!(format!("{err}").contains("no converted query"));
    }
}
