//! False-positive-driven Sigma filter rule proposals.
//!
//! Tuning contrasts events classified as false positives with known true
//! positives, proposes the narrowest filter that separates them, and verifies
//! the result through the same filter application path used by [`Engine`].

use std::collections::{BTreeMap, BTreeSet};

use rsigma_parser::ast::{FilterRuleTarget, LogSource, SigmaCollection, SigmaRule};
use rsigma_parser::lint::Severity;
use serde::Serialize;
use serde_json::Value;

use crate::Engine;
use crate::event::JsonEvent;
use crate::rule_draft::draft_core::{
    PlannedSelection, ValueForm, emit_form, infer_form, parse_one_document, profile_fields,
    score_field, unwritable_field_name, verify_detection, yaml_str, yaml_title_str,
};
use crate::rule_draft::{DraftConfig, Stability};

/// Tunables for a tuning run.
#[derive(Debug, Clone)]
pub struct TuneConfig {
    /// Maximum fields in one filter selection.
    pub max_fields: usize,
    /// Minimum fields required in every emitted selection.
    pub min_fields: usize,
    /// Maximum exact values emitted as one OR list.
    pub max_value_cardinality: usize,
    /// Minimum shared token length for inferred string forms.
    pub min_token_len: usize,
    /// Minimum FP events required for every emitted selection.
    pub min_cluster_support: usize,
    /// Maximum selections emitted in one filter rule.
    pub max_clusters: usize,
    /// Emit cleanly separable clusters even when some FPs remain uncovered.
    pub allow_partial: bool,
    /// Caller-supplied filter UUID. The core never generates randomness.
    pub filter_id: Option<String>,
    /// Filter author metadata.
    pub author: String,
}

impl Default for TuneConfig {
    fn default() -> Self {
        Self {
            max_fields: 4,
            min_fields: 2,
            max_value_cardinality: 8,
            min_token_len: 4,
            min_cluster_support: 2,
            max_clusters: 5,
            allow_partial: false,
            filter_id: None,
            author: "rsigma rule tune".to_string(),
        }
    }
}

/// Why a tuning proposal could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum TuneError {
    /// A reviewability or inference bound is invalid.
    #[error("invalid tuning config: {0}")]
    InvalidConfig(String),
    /// No false-positive events were provided.
    #[error("no false-positive events to tune")]
    NoFalsePositives,
    /// No true-positive events were provided.
    #[error("no true-positive events to protect")]
    NoTruePositives,
    /// Some labeled exemplars do not fire the target rule before filtering.
    #[error(
        "labeled exemplars do not fire the target rule before filtering \
         (false-positive indexes: {fp:?}, true-positive indexes: {tp:?})"
    )]
    NonFiringExemplars {
        /// False-positive indexes that did not fire.
        fp: Vec<usize>,
        /// True-positive indexes that did not fire.
        tp: Vec<usize>,
    },
    /// No stable scalar field could be profiled.
    #[error("no candidate fields survived profiling across {0} false positives")]
    NoCandidateFields(usize),
    /// No verified separator protected every TP and covered the required FPs.
    #[error(
        "no clean separator found (closest fields: {closest:?}, blocking true-positive indexes: \
         {blocking_tp:?}, uncovered false-positive indexes: {uncovered_fp:?})"
    )]
    NoCleanSeparator {
        /// Highest-ranked fields considered.
        closest: Vec<String>,
        /// True positives suppressed by the closest candidate.
        blocking_tp: Vec<usize>,
        /// False positives not covered by the partial proposal.
        uncovered_fp: Vec<usize>,
    },
    /// Emitted YAML failed its own parse, lint, compile, or verification pass.
    #[error("internal error: emitted filter failed to {stage}: {message}")]
    Internal {
        /// Failing stage.
        stage: String,
        /// Underlying message.
        message: String,
    },
}

/// Why one profiled field was selected or rejected.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TuneFieldDisposition {
    /// Included in at least one emitted selection.
    Selected,
    /// The field form would suppress one or more protected true positives.
    MatchesTruePositive,
    /// The field was useful but ranked below the selected fields.
    LowerRank,
    /// No stable value form could be inferred.
    Volatile,
}

/// One profiled field in the tuning rationale.
#[derive(Debug, Clone, Serialize)]
pub struct TuneFieldReport {
    /// Dot-joined field path.
    pub field: String,
    /// Contrastive score used for deterministic ranking.
    pub score: f64,
    /// FP-side value stability.
    pub stability: Stability,
    /// Sigma modifier chain selected for the field.
    pub modifier: String,
    /// Display values or inferred pattern.
    pub values: Vec<String>,
    /// Number of protected TPs matched by this field alone.
    pub true_positive_hits: usize,
    /// Selection/rejection rationale.
    pub disposition: TuneFieldDisposition,
}

/// One emitted selection and the FP exemplars it covers.
#[derive(Debug, Clone, Serialize)]
pub struct TuneSelectionReport {
    /// Detection identifier in the filter rule.
    pub name: String,
    /// Fields included in this conjunction.
    pub fields: Vec<String>,
    /// Original FP indexes covered by this selection.
    pub false_positive_indexes: Vec<usize>,
}

/// Before/after verification counts.
#[derive(Debug, Clone, Serialize)]
pub struct TuneVerification {
    /// FPs firing before the filter.
    pub false_positives_before: usize,
    /// FPs firing after the filter.
    pub false_positives_after: usize,
    /// TPs firing before the filter.
    pub true_positives_before: usize,
    /// TPs firing after the filter.
    pub true_positives_after: usize,
}

/// Backtest expectation evidence attached by a caller.
#[derive(Debug, Clone, Serialize)]
pub struct TuneExpectationDiff {
    /// Existing bounds for the target rule from the supplied expectations file.
    pub existing: Vec<String>,
    /// Target fires over the FP corpus before filtering.
    pub false_positives_before: usize,
    /// Target fires over the FP corpus after filtering.
    pub false_positives_after: usize,
    /// Target fires over the TP corpus before filtering.
    pub true_positives_before: usize,
    /// Target fires over the TP corpus after filtering.
    pub true_positives_after: usize,
    /// Paste-ready expectations YAML for the two supplied corpora.
    pub fragment: String,
}

/// A verified tuning proposal and its rationale.
#[derive(Debug, Clone, Serialize)]
pub struct TuneReport {
    /// Paste-ready Sigma filter rule.
    pub filter_yaml: String,
    /// Ranked field rationale.
    pub fields: Vec<TuneFieldReport>,
    /// Emitted selection clusters.
    pub selections: Vec<TuneSelectionReport>,
    /// Closed before/after verification.
    pub verification: TuneVerification,
    /// Fraction of supplied FPs suppressed by the proposal.
    pub false_positive_coverage: f64,
    /// Advisory notes, including title targeting fallback and partial coverage.
    pub warnings: Vec<String>,
    /// Optional before/after backtest expectation evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expectation_diff: Option<TuneExpectationDiff>,
}

#[derive(Debug, Clone)]
struct Selection {
    name: String,
    entries: Vec<(String, ValueForm)>,
    fp_indexes: Vec<usize>,
}

#[derive(Debug)]
struct GroupProposal {
    selection: Selection,
    fields: Vec<TuneFieldReport>,
    blocking_tp: Vec<usize>,
}

/// Propose and verify a Sigma filter for one target rule.
pub fn tune_rule(
    rule: &SigmaRule,
    false_positives: &[Value],
    true_positives: &[Value],
    config: &TuneConfig,
) -> Result<TuneReport, TuneError> {
    for (name, value) in [
        ("max_fields", config.max_fields),
        ("min_fields", config.min_fields),
        ("max_value_cardinality", config.max_value_cardinality),
        ("min_token_len", config.min_token_len),
        ("min_cluster_support", config.min_cluster_support),
        ("max_clusters", config.max_clusters),
    ] {
        if value == 0 {
            return Err(TuneError::InvalidConfig(format!(
                "{name} must be greater than zero"
            )));
        }
    }
    if config.min_fields > config.max_fields {
        return Err(TuneError::InvalidConfig(format!(
            "min_fields ({}) cannot exceed max_fields ({})",
            config.min_fields, config.max_fields
        )));
    }
    if false_positives.is_empty() {
        return Err(TuneError::NoFalsePositives);
    }
    if true_positives.is_empty() {
        return Err(TuneError::NoTruePositives);
    }
    let fp_before = firing_indexes(rule, false_positives)?;
    let tp_before = firing_indexes(rule, true_positives)?;
    if fp_before.len() != false_positives.len() || tp_before.len() != true_positives.len() {
        return Err(TuneError::NonFiringExemplars {
            fp: missing_indexes(false_positives.len(), &fp_before),
            tp: missing_indexes(true_positives.len(), &tp_before),
        });
    }
    if false_positives.len() < config.min_cluster_support {
        return Err(TuneError::NoCleanSeparator {
            closest: Vec::new(),
            blocking_tp: Vec::new(),
            uncovered_fp: (0..false_positives.len()).collect(),
        });
    }

    let all_fp_indexes: Vec<usize> = (0..false_positives.len()).collect();
    let whole = propose_group(
        rule,
        false_positives,
        &all_fp_indexes,
        true_positives,
        config,
        "selection",
    )?;

    let (mut proposals, mut uncovered) = if whole.blocking_tp.is_empty() {
        (vec![whole], Vec::new())
    } else {
        propose_clusters(rule, false_positives, true_positives, config, whole)?
    };

    for (index, proposal) in proposals.iter_mut().enumerate() {
        proposal.selection.name = if index == 0 {
            "selection".to_string()
        } else {
            format!("selection_{}", index + 1)
        };
    }

    let target = rule
        .id
        .as_deref()
        .or(rule.name.as_deref())
        .unwrap_or(&rule.title);
    let mut warnings = skipped_field_warnings(false_positives);
    if rule.id.is_none() && rule.name.is_none() {
        warnings.push(format!(
            "target rule has no id or name; filter targets exact title '{}'",
            rule.title
        ));
    }
    let selections: Vec<Selection> = proposals.iter().map(|p| p.selection.clone()).collect();
    let mut filter_yaml = emit_filter_yaml(
        rule,
        target,
        &selections,
        false_positives.len() - uncovered.len(),
        true_positives.len(),
        config,
    );
    validate_filter_yaml(&filter_yaml, rule, target, &selections, config)?;

    let fp_after = firing_indexes_with_filter(rule, &filter_yaml, false_positives)?;
    let tp_after = firing_indexes_with_filter(rule, &filter_yaml, true_positives)?;
    if !tp_after.iter().copied().eq(0..true_positives.len())
        || fp_after.iter().any(|index| !uncovered.contains(index))
    {
        return Err(TuneError::Internal {
            stage: "verify".to_string(),
            message: format!(
                "expected all {} TPs and only uncovered FPs to fire; got TP indexes {tp_after:?}, \
                 FP indexes {fp_after:?}",
                true_positives.len()
            ),
        });
    }
    if fp_after != uncovered {
        uncovered = fp_after.clone();
        filter_yaml = emit_filter_yaml(
            rule,
            target,
            &selections,
            false_positives.len() - uncovered.len(),
            true_positives.len(),
            config,
        );
        validate_filter_yaml(&filter_yaml, rule, target, &selections, config)?;
    }
    if !uncovered.is_empty() {
        warnings.push(format!(
            "partial proposal leaves false-positive indexes {uncovered:?} uncovered"
        ));
    }

    let selected_fields: BTreeSet<&str> = selections
        .iter()
        .flat_map(|selection| selection.entries.iter().map(|(field, _)| field.as_str()))
        .collect();
    let mut fields = merge_field_reports(proposals.into_iter().flat_map(|p| p.fields));
    for field in &mut fields {
        if selected_fields.contains(field.field.as_str()) {
            field.disposition = TuneFieldDisposition::Selected;
        }
    }

    let selection_reports = selections
        .iter()
        .map(|selection| TuneSelectionReport {
            name: selection.name.clone(),
            fields: selection
                .entries
                .iter()
                .map(|(field, _)| field.clone())
                .collect(),
            false_positive_indexes: selection.fp_indexes.clone(),
        })
        .collect();

    Ok(TuneReport {
        filter_yaml,
        fields,
        selections: selection_reports,
        verification: TuneVerification {
            false_positives_before: false_positives.len(),
            false_positives_after: fp_after.len(),
            true_positives_before: true_positives.len(),
            true_positives_after: tp_after.len(),
        },
        false_positive_coverage: (false_positives.len() - uncovered.len()) as f64
            / false_positives.len() as f64,
        warnings,
        expectation_diff: None,
    })
}

/// One warning per false-positive field whose name cannot be a Sigma field,
/// so it was never considered for the filter.
fn skipped_field_warnings(false_positives: &[Value]) -> Vec<String> {
    let mut skipped: BTreeMap<String, &'static str> = BTreeMap::new();
    for value in false_positives {
        let event = JsonEvent::borrow(value);
        for field in crate::event::Event::field_keys(&event) {
            if let Some(reason) = unwritable_field_name(&field) {
                skipped.entry(field.into_owned()).or_insert(reason);
            }
        }
    }
    skipped
        .into_iter()
        .map(|(field, reason)| {
            format!(
                "skipped field {:?}: {reason}, so it cannot be written as a Sigma field",
                field.chars().take(64).collect::<String>()
            )
        })
        .collect()
}

fn propose_group(
    rule: &SigmaRule,
    all_false_positives: &[Value],
    fp_indexes: &[usize],
    true_positives: &[Value],
    config: &TuneConfig,
    name: &str,
) -> Result<GroupProposal, TuneError> {
    let values: Vec<&Value> = fp_indexes
        .iter()
        .map(|&index| &all_false_positives[index])
        .collect();
    let events: Vec<JsonEvent<'_>> = values
        .iter()
        .map(|value| JsonEvent::borrow(value))
        .collect();
    let draft_config = DraftConfig {
        max_fields: config.max_fields,
        min_fields: 1,
        min_prevalence: 1.0,
        max_value_cardinality: config.max_value_cardinality,
        min_token_len: config.min_token_len,
        ..DraftConfig::default()
    };
    let mut warnings = Vec::new();
    let mut profiles = profile_fields(&events, &draft_config, &mut warnings);
    for profile in &mut profiles {
        infer_form(profile, &draft_config);
        profile.score = score_field(profile, false);
    }
    profiles.retain(|profile| profile.form.is_some() && profile.stability != Stability::Volatile);
    if profiles.is_empty() {
        return Err(TuneError::NoCandidateFields(fp_indexes.len()));
    }

    let mut ranked = Vec::new();
    for profile in profiles {
        let entry = (
            profile.field().to_string(),
            profile.form.clone().expect("retained form"),
        );
        let selection = Selection {
            name: name.to_string(),
            entries: vec![entry],
            fp_indexes: fp_indexes.to_vec(),
        };
        let yaml = emit_filter_yaml(
            rule,
            rule.id.as_deref().unwrap_or(&rule.title),
            std::slice::from_ref(&selection),
            fp_indexes.len(),
            true_positives.len(),
            config,
        );
        let tp_after = firing_indexes_with_filter(rule, &yaml, true_positives)?;
        let tp_hits = true_positives.len() - tp_after.len();
        let adjusted_score = profile.score * (1.0 - tp_hits as f64 / true_positives.len() as f64);
        ranked.push((profile, tp_hits, adjusted_score));
    }
    ranked.sort_by(|(a, a_hits, a_score), (b, b_hits, b_score)| {
        a_hits
            .cmp(b_hits)
            .then_with(|| {
                b_score
                    .partial_cmp(a_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.field().cmp(b.field()))
    });

    let mut entries = Vec::new();
    let mut blocking_tp: Vec<usize> = (0..true_positives.len()).collect();
    let mut selected = BTreeSet::new();
    while entries.len() < config.max_fields && selected.len() < ranked.len() {
        let mut best: Option<(usize, Vec<usize>)> = None;
        for (index, (profile, _, _)) in ranked.iter().enumerate() {
            if selected.contains(&index) {
                continue;
            }
            let mut candidate_entries = entries.clone();
            candidate_entries.push((
                profile.field().to_string(),
                profile.form.clone().expect("ranked form"),
            ));
            let selection = Selection {
                name: name.to_string(),
                entries: candidate_entries,
                fp_indexes: fp_indexes.to_vec(),
            };
            let yaml = emit_filter_yaml(
                rule,
                rule.id.as_deref().unwrap_or(&rule.title),
                std::slice::from_ref(&selection),
                fp_indexes.len(),
                true_positives.len(),
                config,
            );
            let tp_after = firing_indexes_with_filter(rule, &yaml, true_positives)?;
            let candidate_blocking = missing_indexes(true_positives.len(), &tp_after);
            if best
                .as_ref()
                .is_none_or(|(_, current)| candidate_blocking.len() < current.len())
            {
                best = Some((index, candidate_blocking));
            }
        }
        let Some((index, candidate_blocking)) = best else {
            break;
        };
        selected.insert(index);
        let profile = &ranked[index].0;
        entries.push((
            profile.field().to_string(),
            profile.form.clone().expect("ranked form"),
        ));
        blocking_tp = candidate_blocking;
        if blocking_tp.is_empty() && entries.len() >= config.min_fields {
            break;
        }
    }
    if entries.len() < config.min_fields {
        blocking_tp = (0..true_positives.len()).collect();
    }

    let fields = ranked
        .into_iter()
        .map(|(profile, tp_hits, adjusted_score)| TuneFieldReport {
            field: profile.field().to_string(),
            score: adjusted_score,
            stability: profile.stability,
            modifier: profile
                .form
                .as_ref()
                .map_or_else(String::new, |form| form.modifier().to_string()),
            values: profile
                .form
                .as_ref()
                .map_or_else(Vec::new, ValueForm::display_values),
            true_positive_hits: tp_hits,
            disposition: if tp_hits > 0 {
                TuneFieldDisposition::MatchesTruePositive
            } else {
                TuneFieldDisposition::LowerRank
            },
        })
        .collect();

    Ok(GroupProposal {
        selection: Selection {
            name: name.to_string(),
            entries,
            fp_indexes: fp_indexes.to_vec(),
        },
        fields,
        blocking_tp,
    })
}

fn propose_clusters(
    rule: &SigmaRule,
    false_positives: &[Value],
    true_positives: &[Value],
    config: &TuneConfig,
    whole: GroupProposal,
) -> Result<(Vec<GroupProposal>, Vec<usize>), TuneError> {
    let partitions = scalar_partitions(false_positives);
    let mut best_full: Option<Vec<GroupProposal>> = None;
    let mut best_partial: Option<(Vec<GroupProposal>, Vec<usize>)> = None;

    for groups in partitions.values() {
        if groups.len() < 2 || groups.len() > config.max_clusters {
            continue;
        }
        if groups
            .values()
            .any(|indexes| indexes.len() < config.min_cluster_support)
        {
            continue;
        }

        let mut proposals = Vec::new();
        let mut uncovered = Vec::new();
        for indexes in groups.values() {
            match propose_group(
                rule,
                false_positives,
                indexes,
                true_positives,
                config,
                "selection",
            ) {
                Ok(proposal) if proposal.blocking_tp.is_empty() => proposals.push(proposal),
                Ok(_) | Err(TuneError::NoCandidateFields(_)) => {
                    uncovered.extend(indexes.iter().copied());
                }
                Err(error) => return Err(error),
            }
        }
        uncovered.sort_unstable();
        if uncovered.is_empty() {
            if best_full
                .as_ref()
                .is_none_or(|best| proposals.len() < best.len())
            {
                best_full = Some(proposals);
            }
            continue;
        }
        if config.allow_partial && !proposals.is_empty() {
            let covered = false_positives.len() - uncovered.len();
            let replace = best_partial.as_ref().is_none_or(|(_, best_uncovered)| {
                covered > false_positives.len() - best_uncovered.len()
            });
            if replace {
                best_partial = Some((proposals, uncovered));
            }
        }
    }

    if let Some(proposals) = best_full {
        return Ok((proposals, Vec::new()));
    }
    if let Some(partial) = best_partial {
        return Ok(partial);
    }

    Err(TuneError::NoCleanSeparator {
        closest: whole
            .fields
            .iter()
            .take(config.max_fields)
            .map(|field| field.field.clone())
            .collect(),
        blocking_tp: whole.blocking_tp,
        uncovered_fp: if config.allow_partial {
            (0..false_positives.len()).collect()
        } else {
            Vec::new()
        },
    })
}

fn scalar_partitions(events: &[Value]) -> BTreeMap<String, BTreeMap<String, Vec<usize>>> {
    let mut fields: BTreeMap<String, BTreeMap<String, Vec<usize>>> = BTreeMap::new();
    for (index, value) in events.iter().enumerate() {
        let event = JsonEvent::borrow(value);
        for field in crate::event::Event::field_keys(&event) {
            let field = field.into_owned();
            let Some(value) = crate::event::Event::get_field(&event, &field) else {
                continue;
            };
            let key = match value {
                crate::event::EventValue::Str(value) => value.to_string(),
                crate::event::EventValue::Int(value) => value.to_string(),
                crate::event::EventValue::Float(value) => value.to_string(),
                crate::event::EventValue::Bool(value) => value.to_string(),
                crate::event::EventValue::Null
                | crate::event::EventValue::Array(_)
                | crate::event::EventValue::Map(_) => continue,
            };
            fields
                .entry(field)
                .or_default()
                .entry(key)
                .or_default()
                .push(index);
        }
    }
    fields.retain(|_, groups| groups.values().map(Vec::len).sum::<usize>() == events.len());
    fields
}

fn emit_filter_yaml(
    rule: &SigmaRule,
    target: &str,
    selections: &[Selection],
    fp_covered: usize,
    tp_total: usize,
    config: &TuneConfig,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("title: {}\n", yaml_title_str(&filter_title(rule))));
    if let Some(id) = &config.filter_id {
        out.push_str(&format!("id: {}\n", yaml_str(id)));
    }
    out.push_str(&format!(
        "description: {}\n",
        yaml_str(&format!(
            "Suppresses {fp_covered} observed false-positive exemplars; verified against {tp_total} true-positive exemplars."
        ))
    ));
    out.push_str(&format!("author: {}\n", yaml_str(&config.author)));
    emit_logsource(&mut out, &rule.logsource);
    out.push_str("filter:\n");
    out.push_str("    rules:\n");
    out.push_str(&format!("        - {}\n", yaml_str(target)));
    for selection in selections {
        out.push_str(&format!("    {}:\n", selection.name));
        for (field, form) in &selection.entries {
            emit_form(&mut out, field, form, "        ");
        }
    }
    out.push_str(&format!(
        "    condition: {}\n",
        filter_condition(selections)
    ));
    out
}

fn filter_title(rule: &SigmaRule) -> String {
    format!("Tuning filter for {}", rule.title)
}

fn filter_condition(selections: &[Selection]) -> String {
    if selections.len() == 1 {
        "not selection".to_string()
    } else {
        let names = selections
            .iter()
            .map(|selection| selection.name.as_str())
            .collect::<Vec<_>>()
            .join(" or ");
        format!("not ({names})")
    }
}

fn emit_logsource(out: &mut String, logsource: &LogSource) {
    out.push_str("logsource:\n");
    for (key, value) in [
        ("category", logsource.category.as_deref()),
        ("product", logsource.product.as_deref()),
        ("service", logsource.service.as_deref()),
        ("definition", logsource.definition.as_deref()),
    ] {
        if let Some(value) = value {
            out.push_str(&format!("    {key}: {}\n", yaml_str(value)));
        }
    }
    let mut custom: Vec<_> = logsource.custom.iter().collect();
    custom.sort_by_key(|(key, _)| *key);
    for (key, value) in custom {
        out.push_str(&format!("    {}: {}\n", yaml_str(key), yaml_str(value)));
    }
}

fn validate_filter_yaml(
    yaml: &str,
    rule: &SigmaRule,
    target: &str,
    selections: &[Selection],
    config: &TuneConfig,
) -> Result<(), TuneError> {
    verify_filter_document(yaml, rule, target, selections, config).map_err(|message| {
        TuneError::Internal {
            stage: "round-trip".to_string(),
            message,
        }
    })?;
    let errors: Vec<_> = rsigma_parser::lint_yaml_str(yaml)
        .into_iter()
        .filter(|warning| warning.severity == Severity::Error)
        .map(|warning| warning.to_string())
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(TuneError::Internal {
            stage: "lint".to_string(),
            message: errors.join("; "),
        })
    }
}

/// Check that the emitted filter parses back as exactly one filter with the
/// planned title, id, target, logsource, and detection.
fn verify_filter_document(
    yaml: &str,
    rule: &SigmaRule,
    target: &str,
    selections: &[Selection],
    config: &TuneConfig,
) -> Result<(), String> {
    let collection = parse_one_document(yaml)?;
    let [filter] = collection.filters.as_slice() else {
        return Err("expected exactly one filter".to_string());
    };
    if !collection.rules.is_empty() || !collection.correlations.is_empty() {
        return Err("expected exactly one filter".to_string());
    }
    let title = filter_title(rule);
    if filter.title != title {
        return Err(format!("title is {:?}, expected {title:?}", filter.title));
    }
    if filter.id != config.filter_id {
        return Err(format!(
            "id is {:?}, expected {:?}",
            filter.id, config.filter_id
        ));
    }
    if filter.rules != FilterRuleTarget::Specific(vec![target.to_string()]) {
        return Err(format!("targets {:?}, expected [{target:?}]", filter.rules));
    }
    if filter.logsource.as_ref() != Some(&rule.logsource) {
        return Err(format!(
            "logsource is {:?}, expected {:?}",
            filter.logsource, rule.logsource
        ));
    }
    let planned: Vec<PlannedSelection<'_>> = selections
        .iter()
        .map(|selection| PlannedSelection {
            name: &selection.name,
            entries: &selection.entries,
        })
        .collect();
    verify_detection(&filter.detection, &planned, &filter_condition(selections))
}

fn firing_indexes(rule: &SigmaRule, events: &[Value]) -> Result<Vec<usize>, TuneError> {
    let mut collection = SigmaCollection::new();
    collection.rules.push(rule.clone());
    evaluate_collection(&collection, events)
}

fn firing_indexes_with_filter(
    rule: &SigmaRule,
    filter_yaml: &str,
    events: &[Value],
) -> Result<Vec<usize>, TuneError> {
    let parsed =
        rsigma_parser::parse_sigma_yaml(filter_yaml).map_err(|error| TuneError::Internal {
            stage: "parse".to_string(),
            message: error.to_string(),
        })?;
    let mut collection = SigmaCollection::new();
    collection.rules.push(rule.clone());
    collection.filters.extend(parsed.filters);
    evaluate_collection(&collection, events)
}

fn evaluate_collection(
    collection: &SigmaCollection,
    events: &[Value],
) -> Result<Vec<usize>, TuneError> {
    let mut engine = Engine::new();
    engine
        .add_collection(collection)
        .map_err(|error| TuneError::Internal {
            stage: "compile".to_string(),
            message: error.to_string(),
        })?;
    Ok(events
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            let event = JsonEvent::borrow(value);
            (!engine.evaluate(&event).is_empty()).then_some(index)
        })
        .collect())
}

fn missing_indexes(total: usize, present: &[usize]) -> Vec<usize> {
    let present: BTreeSet<usize> = present.iter().copied().collect();
    (0..total)
        .filter(|index| !present.contains(index))
        .collect()
}

fn merge_field_reports(reports: impl Iterator<Item = TuneFieldReport>) -> Vec<TuneFieldReport> {
    let mut by_field: BTreeMap<String, TuneFieldReport> = BTreeMap::new();
    for report in reports {
        by_field
            .entry(report.field.clone())
            .and_modify(|existing| {
                if report.score > existing.score {
                    *existing = report.clone();
                }
            })
            .or_insert(report);
    }
    let mut reports: Vec<_> = by_field.into_values().collect();
    reports.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.field.cmp(&b.field))
    });
    reports
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rule() -> SigmaRule {
        rsigma_parser::parse_sigma_yaml(
            r#"
title: Suspicious Backup Tool
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\backup.exe'
    condition: selection
level: medium
"#,
        )
        .unwrap()
        .rules
        .remove(0)
    }

    fn config() -> TuneConfig {
        TuneConfig {
            filter_id: Some("3f7b1c2e-9a44-4d1e-8f61-2b0c5d9e7a10".to_string()),
            min_cluster_support: 1,
            ..TuneConfig::default()
        }
    }

    #[test]
    fn emits_verified_filter_with_clean_polarity() {
        let fps = vec![
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
        ];
        let tps = vec![json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"})];

        let report = tune_rule(&rule(), &fps, &tps, &config()).unwrap();

        assert_eq!(report.verification.false_positives_after, 0);
        assert_eq!(report.verification.true_positives_after, 1);
        assert!(report.filter_yaml.contains("condition: not selection"));
        assert!(report.filter_yaml.contains("category: process_creation"));
        assert!(report.filter_yaml.contains("Image:"));
        assert!(report.filter_yaml.contains("User: svc_backup"));
        assert_eq!(report.selections[0].fields.len(), 2);
        assert!(!report.filter_yaml.contains("status:"));
        assert!(
            rsigma_parser::lint_yaml_str(&report.filter_yaml)
                .iter()
                .all(|warning| warning.severity != Severity::Error)
        );
    }

    #[test]
    fn rejects_nonfiring_labels_before_profiling() {
        let fps = vec![json!({"Image": r"C:\Windows\notepad.exe", "User": "svc"})];
        let tps = vec![json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"})];

        let error = tune_rule(&rule(), &fps, &tps, &config()).unwrap_err();
        assert!(matches!(
            error,
            TuneError::NonFiringExemplars { fp, tp }
                if fp == vec![0] && tp.is_empty()
        ));
    }

    #[test]
    fn refuses_single_event_memorization_by_default() {
        let fps = vec![json!({
            "Image": r"C:\Program Files\Veeam\backup.exe",
            "User": "svc_backup"
        })];
        let tps = vec![json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"})];
        let config = TuneConfig {
            filter_id: Some("3f7b1c2e-9a44-4d1e-8f61-2b0c5d9e7a10".to_string()),
            ..TuneConfig::default()
        };

        let error = tune_rule(&rule(), &fps, &tps, &config).unwrap_err();
        assert!(matches!(
            error,
            TuneError::NoCleanSeparator { uncovered_fp, .. } if uncovered_fp == vec![0]
        ));
    }

    #[test]
    fn rejects_zero_token_length() {
        let fps = vec![
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
        ];
        let tps = vec![json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"})];
        let config = TuneConfig {
            min_token_len: 0,
            ..config()
        };

        let error = tune_rule(&rule(), &fps, &tps, &config).unwrap_err();
        assert!(matches!(
            error,
            TuneError::InvalidConfig(message) if message.contains("min_token_len")
        ));
    }

    #[test]
    fn rejects_minimum_fields_above_maximum() {
        let fps = vec![
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
        ];
        let tps = vec![json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"})];
        let config = TuneConfig {
            min_fields: 3,
            max_fields: 2,
            ..config()
        };

        let error = tune_rule(&rule(), &fps, &tps, &config).unwrap_err();
        assert!(matches!(
            error,
            TuneError::InvalidConfig(message) if message.contains("cannot exceed")
        ));
    }

    #[test]
    fn emits_multiple_selections_for_disjoint_fp_clusters() {
        let fps = vec![
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
            json!({"Image": r"D:\Tools\Acronis\backup.exe", "User": "svc_acronis"}),
            json!({"Image": r"D:\Tools\Acronis\backup.exe", "User": "svc_acronis"}),
        ];
        let tps = vec![
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_acronis"}),
            json!({"Image": r"D:\Tools\Acronis\backup.exe", "User": "svc_backup"}),
        ];

        let report = tune_rule(&rule(), &fps, &tps, &config()).unwrap();

        assert_eq!(report.selections.len(), 2);
        assert!(
            report
                .filter_yaml
                .contains("condition: not (selection or selection_2)")
        );
        assert_eq!(report.verification.false_positives_after, 0);
        assert_eq!(report.verification.true_positives_after, 2);
    }

    #[test]
    fn one_of_supports_six_benign_values_without_clustering() {
        let users = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"];
        let fps: Vec<Value> = users
            .iter()
            .map(|user| {
                json!({
                    "Image": r"C:\Program Files\Veeam\backup.exe",
                    "User": user
                })
            })
            .collect();
        let tps = vec![json!({
            "Image": r"C:\Program Files\Veeam\backup.exe",
            "User": "attacker"
        })];

        let report = tune_rule(&rule(), &fps, &tps, &config()).unwrap();

        assert_eq!(report.selections.len(), 1);
        assert!(report.filter_yaml.contains("foxtrot"));
    }

    #[test]
    fn partial_mode_emits_only_clean_supported_clusters() {
        let fps = vec![
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_good"}),
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_good"}),
            json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"}),
            json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"}),
        ];
        let tps = vec![json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"})];
        let partial = TuneConfig {
            allow_partial: true,
            min_cluster_support: 2,
            ..config()
        };

        let report = tune_rule(&rule(), &fps, &tps, &partial).unwrap();

        assert_eq!(report.verification.false_positives_after, 2);
        assert_eq!(report.verification.true_positives_after, 1);
        assert_eq!(report.false_positive_coverage, 0.5);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("[2, 3]"))
        );
    }

    #[test]
    fn default_mode_refuses_an_inseparable_cluster() {
        let fps = vec![
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_good"}),
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_good"}),
            json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"}),
            json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"}),
        ];
        let tps = vec![json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"})];

        let error = tune_rule(&rule(), &fps, &tps, &config()).unwrap_err();
        assert!(matches!(error, TuneError::NoCleanSeparator { .. }));
    }

    #[test]
    fn title_fallback_is_explicit_and_deterministic() {
        let mut target = rule();
        target.id = None;
        let fps = vec![
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
        ];
        let tps = vec![json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"})];

        let first = tune_rule(&target, &fps, &tps, &config()).unwrap();
        let second = tune_rule(&target, &fps, &tps, &config()).unwrap();

        assert_eq!(first.filter_yaml, second.filter_yaml);
        assert!(first.filter_yaml.contains("- 'Suspicious Backup Tool'"));
        assert!(
            first
                .warnings
                .iter()
                .any(|warning| warning.contains("exact title"))
        );
    }

    #[test]
    fn name_is_targeted_when_rule_has_no_id() {
        let mut target = rule();
        target.id = None;
        target.name = Some("suspicious_backup_tool".to_string());
        let fps = vec![
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
        ];
        let tps = vec![json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"})];

        let report = tune_rule(&target, &fps, &tps, &config()).unwrap();

        assert!(report.filter_yaml.contains("- suspicious_backup_tool"));
        assert!(!report.filter_yaml.contains("Suspicious Backup Tool'"));
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn hostile_field_names_round_trip_or_are_skipped() {
        for key in [
            "a\nb",
            "a\u{2028}b",
            "User: x",
            "#User",
            "User #x",
            "'User'",
            "User|endswith",
            "---",
            "...x",
            "[User]",
            "- User",
            "true",
            "1",
            "@User",
            " User",
        ] {
            let event = |user: &str| {
                let mut map = serde_json::Map::new();
                map.insert("Image".into(), json!(r"C:\Program Files\Veeam\backup.exe"));
                map.insert(key.into(), json!(user));
                Value::Object(map)
            };
            let fps = vec![event("svc: backup"), event("svc: backup")];
            let tps = vec![event("attacker")];
            let result = tune_rule(&rule(), &fps, &tps, &config());
            let skipped = crate::rule_draft::draft_core::unwritable_field_name(key).is_some();
            if skipped {
                assert!(
                    matches!(result, Err(TuneError::NoCleanSeparator { .. })),
                    "{key:?}: {result:?}"
                );
                continue;
            }
            let report = result.unwrap_or_else(|e| panic!("{key:?}: {e}"));
            let filter = &rsigma_parser::parse_sigma_yaml(&report.filter_yaml)
                .unwrap()
                .filters[0];
            let items = match &filter.detection.named["selection"] {
                rsigma_parser::Detection::AllOf(items) => items,
                other => panic!("{other:?}"),
            };
            let written = rsigma_parser::fieldpath::escape_brackets(key);
            let item = items
                .iter()
                .find(|item| item.field.name.as_deref() == Some(written.as_ref()))
                .unwrap_or_else(|| panic!("{key:?}:\n{}", report.filter_yaml));
            assert_eq!(item.values.len(), 1);
            assert_eq!(item.values[0].to_string(), "svc: backup");
            assert_eq!(report.verification.true_positives_after, 1);
        }
    }

    #[test]
    fn hostile_target_title_round_trips() {
        let mut target = rule();
        target.id = None;
        target.title = "Backup\n---\nlevel: low # tool".to_string();
        let fps = vec![
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
            json!({"Image": r"C:\Program Files\Veeam\backup.exe", "User": "svc_backup"}),
        ];
        let tps = vec![json!({"Image": r"C:\Temp\backup.exe", "User": "attacker"})];
        let report = tune_rule(&target, &fps, &tps, &config()).unwrap();
        let filter = &rsigma_parser::parse_sigma_yaml(&report.filter_yaml)
            .unwrap()
            .filters[0];
        assert_eq!(
            filter.rules,
            FilterRuleTarget::Specific(vec![target.title.clone()])
        );
        assert_eq!(report.verification.false_positives_after, 0);
    }

    #[test]
    fn tampered_filter_output_is_rejected() {
        let target = rule();
        let selection = Selection {
            name: "selection".to_string(),
            entries: vec![(
                "User".to_string(),
                ValueForm::Exact(crate::rule_draft::draft_core::DraftValue::Str(
                    "svc_backup".to_string(),
                )),
            )],
            fp_indexes: vec![0, 1],
        };
        let selections = vec![selection];
        let target_id = target.id.clone().unwrap();
        let yaml = emit_filter_yaml(&target, &target_id, &selections, 2, 1, &config());
        verify_filter_document(&yaml, &target, &target_id, &selections, &config())
            .expect("untouched output verifies");
        for text in [
            format!("{yaml}---\n{yaml}"),
            yaml.replace(
                "    condition: not selection\n",
                "    condition: selection\n",
            ),
            yaml.replace("User: svc_backup", "User: svc_admin"),
            yaml.replace("User: svc_backup", "User|contains: svc_backup"),
            yaml.replace(&format!("- {target_id}"), "- other"),
            yaml.replace("    condition:", "    extra:\n        a: b\n    condition:"),
            yaml.replace("category: process_creation", "category: file_event"),
        ] {
            assert_ne!(text, yaml);
            assert!(
                verify_filter_document(&text, &target, &target_id, &selections, &config()).is_err(),
                "{text}"
            );
        }
    }

    #[test]
    fn hostile_keys_golden() {
        let event = |user: &str| {
            let mut map = serde_json::Map::new();
            map.insert("Image".into(), json!(r"C:\Program Files\Veeam\backup.exe"));
            map.insert("User: name #1".into(), json!(user));
            map.insert("line\nbreak".into(), json!(user));
            Value::Object(map)
        };
        let fps = vec![event("svc\nbackup"), event("svc\nbackup")];
        let tps = vec![event("attacker")];
        let report = tune_rule(&rule(), &fps, &tps, &config()).unwrap();
        assert_eq!(
            report.filter_yaml,
            include_str!("rule_draft/golden/tune_hostile_keys.yaml")
        );
        assert_eq!(
            report.warnings,
            [
                "skipped field \"line\\nbreak\": it contains a line break or control character, so it cannot be written as a Sigma field"
            ]
        );
    }
}
