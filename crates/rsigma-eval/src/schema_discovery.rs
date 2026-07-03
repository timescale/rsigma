//! Schema signature discovery: mine unrecognized events into candidate
//! declarative [`SchemaSignature`]s a human reviews and commits.
//!
//! The shipped schema work recognizes events against declarative signatures
//! ([`crate::schema`]) and surfaces whatever matches none: the classifier
//! reports `unknown`, and the [`SchemaObserver`](crate::SchemaObserver) samples
//! bounded, redacted field-key shapes of those unknowns. This module turns that
//! signal into ranked candidate signatures, so an operator stops hand-authoring
//! every signature from scratch.
//!
//! The "learning" here is glass-box unsupervised mining, not a black-box model:
//! cluster the unrecognized events by structural fingerprint, pick the fields
//! (and low-cardinality values) that discriminate each cluster, and emit the
//! same `schemas:` YAML the classifier already consumes via
//! [`parse_schema_signatures`](crate::parse_schema_signatures). Every proposed
//! predicate is human-readable and explainable from the reported stats.
//!
//! # Two inputs, one core
//!
//! - **Offline** ([`mine_events`]): a raw event corpus. Events already
//!   recognized by a built-in or user signature are excluded; only `unknown`
//!   and `generic_json` events are mined. Low-cardinality, non-sensitive field
//!   values are retained in-process so candidates can carry `equals`/`in` value
//!   predicates.
//! - **Online** ([`mine_shapes`]): the daemon's already-captured
//!   [`UnknownShapeEntry`] sample. That sample is
//!   keys-only by construction (values are never retained), so online proposals
//!   use presence predicates only and are tagged [`CandidateSource::KeysOnly`].
//!
//! Both feed the same cluster/select/rank stages, so the two surfaces cannot
//! drift on what a "good" signature looks like.
//!
//! Detection-side only: discovery reads events or a redacted sample and
//! proposes config. It does not collect, transport, or normalize events, and it
//! never applies a discovered signature on its own.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;

use crate::event::Event;
use crate::schema::{
    SchemaClassifier, SchemaPredicate, SchemaSignature, UnknownShapeEntry, validate_schema_config,
};

// =============================================================================
// Configuration
// =============================================================================

/// Tunables for a discovery run. [`Default`] is a sensible starting point;
/// the CLI exposes each as a flag.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Minimum number of events a cluster must contain to yield a candidate.
    /// Filters out one-off shapes that are not worth a signature.
    pub min_support: u64,
    /// Jaccard similarity (0.0-1.0) at or above which a shape merges into an
    /// existing cluster. Higher means stricter (more, tighter clusters).
    pub similarity: f64,
    /// Maximum number of candidates emitted, highest support first.
    pub max_candidates: usize,
    /// Maximum predicates in a single candidate signature. Kept small so
    /// proposals stay readable and reviewable.
    pub max_predicates: usize,
    /// Whether to propose `equals`/`in` value predicates (offline only; the
    /// online path never has values regardless of this flag).
    pub value_markers: bool,
    /// A field is only a value-marker candidate when its distinct string values
    /// within a cluster do not exceed this cap (a low-cardinality constant like
    /// `vendor` or `Channel`, not a free-form field).
    pub max_value_cardinality: usize,
    /// Fraction (0.0-1.0) of a cluster's events a field must appear in to be a
    /// "core" field eligible as a predicate.
    pub core_presence: f64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            min_support: 3,
            similarity: 0.6,
            max_candidates: 20,
            max_predicates: 3,
            value_markers: true,
            max_value_cardinality: 8,
            core_presence: 0.9,
        }
    }
}

// =============================================================================
// Public report types
// =============================================================================

/// Where a candidate's evidence came from, and therefore how strong it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateSource {
    /// Mined from a raw corpus; may carry value predicates.
    Corpus,
    /// Mined from the daemon's keys-only unknown-shape sample; presence
    /// predicates only.
    KeysOnly,
}

/// Per-field statistics gathered over a set of events in scope (a cluster or a
/// whole corpus). A small standalone type so other corpus-analysis features can
/// build on the same profile rather than duplicating the aggregation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldProfile {
    /// Dot-joined field path.
    pub field: String,
    /// Events in scope that contained the field.
    pub present: u64,
    /// Total events in scope.
    pub total: u64,
    /// Distinct string values seen, sorted, capped for memory. Empty when
    /// values were not retained (the online path) or the field is not
    /// string-valued.
    pub distinct_values: Vec<String>,
    /// True when more distinct values were seen than retained, or a value was
    /// dropped as too long/sensitive to retain, so `distinct_values` is not the
    /// full set and the field is not a safe value marker.
    pub value_overflow: bool,
}

impl FieldProfile {
    /// Fraction of in-scope events that contained the field (0.0-1.0).
    pub fn prevalence(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.present as f64 / self.total as f64
        }
    }

    /// Number of distinct retained string values.
    pub fn cardinality(&self) -> usize {
        self.distinct_values.len()
    }
}

/// One proposed signature plus the evidence behind it.
#[derive(Debug, Clone)]
pub struct DiscoveryCandidate {
    /// Placeholder schema name (a human should rename it).
    pub name: String,
    /// Suggested tie-break specificity, above `generic_json` and below the
    /// strong built-ins.
    pub specificity: u32,
    /// The conjunction of predicates that recognizes the cluster.
    pub predicates: Vec<SchemaPredicate>,
    /// Events in the cluster this candidate was mined from.
    pub support: u64,
    /// `support` as a fraction of all mined events (0.0-1.0).
    pub coverage_of_unknown: f64,
    /// A few representative (redacted) field-key sets from the cluster, capped.
    pub sample_field_sets: Vec<Vec<String>>,
    /// Advisory notes: shadowing against built-ins, incomplete separation, etc.
    pub overlap_warnings: Vec<String>,
    /// Corpus (value-capable) or keys-only (presence-only).
    pub source: CandidateSource,
}

impl DiscoveryCandidate {
    /// The candidate as a [`SchemaSignature`] (for validation, dry-run
    /// reclassification, or loading into a classifier).
    pub fn signature(&self) -> SchemaSignature {
        SchemaSignature {
            name: self.name.clone(),
            predicates: self.predicates.clone(),
            specificity: self.specificity,
        }
    }

    /// Human-readable one-line descriptions of the predicates, in order.
    pub fn predicate_descriptions(&self) -> Vec<String> {
        self.predicates.iter().map(describe_predicate).collect()
    }
}

/// Summary counters for a discovery run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryStats {
    /// Events fed into mining (offline: unknown/generic_json only; online: the
    /// sum of sampled shape counts).
    pub events_mined: u64,
    /// Distinct field-key shapes seen.
    pub shapes: usize,
    /// Clusters formed.
    pub clusters: usize,
    /// Candidates emitted (after `min_support` and `max_candidates`).
    pub candidates: usize,
}

/// The result of a discovery run: ranked candidates plus run stats.
#[derive(Debug, Clone)]
pub struct DiscoveryReport {
    /// Candidates, highest support first.
    pub candidates: Vec<DiscoveryCandidate>,
    /// Run stats.
    pub stats: DiscoveryStats,
}

impl DiscoveryReport {
    /// Render the candidates as a `schemas:` YAML block ready to paste into a
    /// `--schema-config` file. Guaranteed to round-trip through
    /// [`parse_schema_signatures`](crate::parse_schema_signatures).
    pub fn to_signatures_yaml(&self) -> String {
        if self.candidates.is_empty() {
            return "schemas: []\n".to_string();
        }
        let mut out = String::from("schemas:\n");
        for c in &self.candidates {
            out.push_str(&format!("  - name: {}\n", yaml_scalar(&c.name)));
            out.push_str(&format!("    specificity: {}\n", c.specificity));
            out.push_str("    match:\n");
            for p in &c.predicates {
                out.push_str(&predicate_to_yaml(p));
            }
        }
        out
    }
}

// =============================================================================
// Entry points
// =============================================================================

/// Mine a raw event corpus (offline). Events recognized by `classifier` as any
/// specific schema are excluded; only `unknown` and `generic_json` events are
/// mined. Pass a classifier built from the built-ins plus any user signatures
/// (via [`SchemaClassifier::with_user_signatures`]) so already-defined schemas
/// are never re-proposed.
pub fn mine_events<E, I>(
    events: I,
    classifier: &SchemaClassifier,
    config: &DiscoveryConfig,
) -> DiscoveryReport
where
    E: Event,
    I: IntoIterator<Item = E>,
{
    // Aggregate mined events into distinct key-set shapes, tracking
    // low-cardinality string values per field for value-marker proposals.
    let mut shapes: HashMap<Vec<String>, ShapeStat> = HashMap::new();
    let mut events_mined: u64 = 0;

    for event in events {
        // Prefilter: skip anything a specific schema already recognizes.
        // generic_json is the low-specificity catch-all, so it counts as
        // "unrecognized" and is mineable.
        match classifier.classify(&event) {
            Some(m) if m.name != "generic_json" => continue,
            _ => {}
        }

        let mut keys: Vec<String> = event
            .field_keys()
            .into_iter()
            .map(|k| k.into_owned())
            .collect();
        keys.sort();
        keys.dedup();
        if keys.is_empty() {
            continue;
        }
        events_mined += 1;

        let entry = shapes.entry(keys.clone()).or_insert_with(|| ShapeStat {
            keys,
            count: 0,
            values: HashMap::new(),
        });
        entry.count += 1;
        if config.value_markers {
            for field in &entry.keys.clone() {
                if let Some(val) = event
                    .get_field(field)
                    .and_then(|v| v.as_str().map(|s| s.into_owned()))
                {
                    entry
                        .values
                        .entry(field.clone())
                        .or_default()
                        .record(&val, config.max_value_cardinality);
                }
            }
        }
    }

    let shape_vec: Vec<ShapeStat> = shapes.into_values().collect();
    build_report(shape_vec, events_mined, config, CandidateSource::Corpus)
}

/// Mine the daemon's keys-only unknown-shape sample (online). Proposals use
/// presence predicates only (values are never retained in the sample).
pub fn mine_shapes(shapes: &[UnknownShapeEntry], config: &DiscoveryConfig) -> DiscoveryReport {
    let (shape_vec, events_mined) = shape_stats_from_entries(shapes);
    build_report(shape_vec, events_mined, config, CandidateSource::KeysOnly)
}

/// Count how many distinct schema clusters the keys-only sample forms, without
/// the cost of selecting, validating, and ranking candidates. Cheap enough to
/// refresh a gauge on every metrics scrape; equal to
/// [`mine_shapes`]`(shapes, config).stats.clusters`.
pub fn cluster_count(shapes: &[UnknownShapeEntry], config: &DiscoveryConfig) -> usize {
    let (mut shape_vec, _) = shape_stats_from_entries(shapes);
    shape_vec.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.keys.cmp(&b.keys)));
    cluster_shapes(&shape_vec, config).len()
}

/// Convert redacted keys-only shape entries into internal `ShapeStat`s (no
/// values), returning the total event count. Skips empty-key shapes.
fn shape_stats_from_entries(shapes: &[UnknownShapeEntry]) -> (Vec<ShapeStat>, u64) {
    let mut events_mined: u64 = 0;
    let shape_vec: Vec<ShapeStat> = shapes
        .iter()
        .filter(|s| !s.keys.is_empty())
        .map(|s| {
            events_mined += s.count;
            let mut keys = s.keys.clone();
            keys.sort();
            keys.dedup();
            ShapeStat {
                keys,
                count: s.count,
                values: HashMap::new(),
            }
        })
        .collect();
    (shape_vec, events_mined)
}

// =============================================================================
// Internal aggregation types
// =============================================================================

/// A distinct field-key shape with its event count and (offline) per-field
/// value accumulators.
struct ShapeStat {
    keys: Vec<String>,
    count: u64,
    values: HashMap<String, ValueAcc>,
}

/// Accumulates the distinct string values of one field, capped, dropping values
/// that are too long or structured to be safe, stable markers.
#[derive(Default, Clone)]
struct ValueAcc {
    values: BTreeSet<String>,
    /// Events (with this shape) where the field held a usable string value.
    count: u64,
    /// True once the distinct set exceeded the cap or an unusable value was
    /// seen, disqualifying the field as a value marker.
    overflow: bool,
}

impl ValueAcc {
    fn record(&mut self, value: &str, cap: usize) {
        if looks_sensitive(value) {
            self.overflow = true;
            return;
        }
        self.count += 1;
        if self.values.contains(value) {
            return;
        }
        if self.values.len() >= cap {
            self.overflow = true;
            return;
        }
        self.values.insert(value.to_string());
    }

    /// The field is a usable value marker: values retained, none dropped, and
    /// present with a string value in nearly every event.
    fn usable(&self, cluster_total: u64, core_presence: f64) -> bool {
        !self.overflow
            && !self.values.is_empty()
            && cluster_total > 0
            && (self.count as f64 / cluster_total as f64) >= core_presence
    }
}

/// A merged cluster of similar shapes.
struct Cluster {
    /// Key set of the first shape that formed the cluster (the merge anchor).
    seed_keys: Vec<String>,
    total: u64,
    /// Per-key event count within the cluster.
    key_counts: HashMap<String, u64>,
    /// Per-field merged value accumulators (empty on the online path).
    values: HashMap<String, ValueAcc>,
    /// A few representative key sets, capped, for the report.
    sample_keys: Vec<Vec<String>>,
}

const MAX_SAMPLE_KEYSETS: usize = 3;
const MAX_SAMPLE_KEYS_PER_SET: usize = 24;
/// Ceiling on distinct values retained per field while merging shapes into a
/// cluster; past this the field is flagged overflow and disqualified as a value
/// marker.
const VALUE_MERGE_CAP: usize = 64;

impl Cluster {
    fn from_shape(shape: &ShapeStat) -> Self {
        let mut key_counts = HashMap::new();
        for k in &shape.keys {
            key_counts.insert(k.clone(), shape.count);
        }
        Cluster {
            seed_keys: shape.keys.clone(),
            total: shape.count,
            key_counts,
            values: shape.values.clone(),
            sample_keys: vec![truncate_keys(&shape.keys)],
        }
    }

    fn merge(&mut self, shape: &ShapeStat) {
        self.total += shape.count;
        for k in &shape.keys {
            *self.key_counts.entry(k.clone()).or_insert(0) += shape.count;
        }
        for (field, acc) in &shape.values {
            let dst = self.values.entry(field.clone()).or_default();
            dst.count += acc.count;
            dst.overflow |= acc.overflow;
            for v in &acc.values {
                if dst.values.len() >= VALUE_MERGE_CAP {
                    dst.overflow = true;
                    break;
                }
                dst.values.insert(v.clone());
            }
        }
        if self.sample_keys.len() < MAX_SAMPLE_KEYSETS {
            let t = truncate_keys(&shape.keys);
            if !self.sample_keys.contains(&t) {
                self.sample_keys.push(t);
            }
        }
    }

    /// Fields present in nearly every cluster event, sorted by name.
    fn core_fields(&self, core_presence: f64) -> Vec<String> {
        let mut fields: Vec<String> = self
            .key_counts
            .iter()
            .filter(|&(_, &c)| self.total > 0 && (c as f64 / self.total as f64) >= core_presence)
            .map(|(k, _)| k.clone())
            .collect();
        fields.sort();
        fields
    }
}

// =============================================================================
// Mining pipeline
// =============================================================================

fn build_report(
    mut shapes: Vec<ShapeStat>,
    events_mined: u64,
    config: &DiscoveryConfig,
    source: CandidateSource,
) -> DiscoveryReport {
    let shape_count = shapes.len();

    // Deterministic order: most frequent first, then lexicographic by keys.
    shapes.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.keys.cmp(&b.keys)));

    let clusters = cluster_shapes(&shapes, config);

    // Global per-key counts for cross-cluster discriminativeness.
    let mut global_key_counts: HashMap<String, u64> = HashMap::new();
    for cluster in &clusters {
        for (k, c) in &cluster.key_counts {
            *global_key_counts.entry(k.clone()).or_insert(0) += *c;
        }
    }
    let total_events: u64 = clusters.iter().map(|c| c.total).sum();

    // Build one candidate per qualifying cluster.
    let mut candidates: Vec<DiscoveryCandidate> = Vec::new();
    let mut used_names: BTreeMap<String, u32> = BTreeMap::new();
    for (idx, cluster) in clusters.iter().enumerate() {
        if cluster.total < config.min_support {
            continue;
        }
        if let Some(mut candidate) = select_candidate(
            cluster,
            idx,
            &clusters,
            &global_key_counts,
            total_events,
            config,
            source,
        ) {
            candidate.name = unique_name(candidate.name, &mut used_names);
            candidates.push(candidate);
        }
    }

    // Rank: support desc, coverage desc, name asc. Then cap.
    candidates.sort_by(|a, b| {
        b.support
            .cmp(&a.support)
            .then_with(|| {
                b.coverage_of_unknown
                    .partial_cmp(&a.coverage_of_unknown)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.name.cmp(&b.name))
    });
    candidates.truncate(config.max_candidates);

    let stats = DiscoveryStats {
        events_mined,
        shapes: shape_count,
        clusters: clusters.len(),
        candidates: candidates.len(),
    };
    DiscoveryReport { candidates, stats }
}

/// Greedy Jaccard clustering with a value-based diversity guard. Expects
/// `shapes` already ordered most-frequent-first (the merge anchor is the first
/// shape of each cluster), so the result is deterministic.
fn cluster_shapes(shapes: &[ShapeStat], config: &DiscoveryConfig) -> Vec<Cluster> {
    let mut clusters: Vec<Cluster> = Vec::new();
    for shape in shapes {
        let mut placed = false;
        for cluster in &mut clusters {
            if jaccard(&shape.keys, &cluster.seed_keys) >= config.similarity
                && diversity_ok(cluster, shape)
            {
                cluster.merge(shape);
                placed = true;
                break;
            }
        }
        if !placed {
            clusters.push(Cluster::from_shape(shape));
        }
    }
    clusters
}

/// Refuse to merge a shape into a cluster when they disagree on a single
/// otherwise-constant marker field (for example `vendor: foo` vs `vendor: bar`),
/// which would fuse two genuinely different schemas. Value-based, so it is a
/// no-op on the keys-only online path.
fn diversity_ok(cluster: &Cluster, shape: &ShapeStat) -> bool {
    for (field, shape_acc) in &shape.values {
        if shape_acc.overflow || shape_acc.values.is_empty() {
            continue;
        }
        let Some(cluster_acc) = cluster.values.get(field) else {
            continue;
        };
        if cluster_acc.overflow || cluster_acc.values.is_empty() {
            continue;
        }
        // Only guard on fields that look like a constant marker on both sides
        // (low cardinality) and that are core to the cluster.
        let core = cluster
            .key_counts
            .get(field)
            .is_some_and(|&c| cluster.total > 0 && (c as f64 / cluster.total as f64) >= 0.9);
        let low_card = cluster_acc.values.len() <= 4 && shape_acc.values.len() <= 4;
        if core && low_card && cluster_acc.values.is_disjoint(&shape_acc.values) {
            return false;
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn select_candidate(
    cluster: &Cluster,
    cluster_idx: usize,
    all: &[Cluster],
    global_key_counts: &HashMap<String, u64>,
    total_events: u64,
    config: &DiscoveryConfig,
    source: CandidateSource,
) -> Option<DiscoveryCandidate> {
    let core = cluster.core_fields(config.core_presence);
    if core.is_empty() {
        return None;
    }

    // Score each core field by discriminativeness minus a value-cardinality
    // penalty, so a rarer / lower-cardinality marker ranks above a near-ubiquitous
    // field. Deterministic tie-break by field name.
    let out_total = total_events.saturating_sub(cluster.total);
    let mut scored: Vec<(String, f64)> = core
        .iter()
        .map(|field| {
            let in_count = cluster.key_counts.get(field).copied().unwrap_or(0);
            let in_frac = in_count as f64 / cluster.total.max(1) as f64;
            let out_count = global_key_counts
                .get(field)
                .copied()
                .unwrap_or(0)
                .saturating_sub(in_count);
            let out_frac = if out_total == 0 {
                0.0
            } else {
                out_count as f64 / out_total as f64
            };
            let value_card = cluster
                .values
                .get(field)
                .map(|a| a.values.len())
                .unwrap_or(0);
            let card_penalty = 0.15 * ((1 + value_card) as f64).ln();
            (field.clone(), in_frac - out_frac - card_penalty)
        })
        .collect();
    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });

    // Greedily add predicates until the conjunction separates this cluster from
    // the others, or the predicate budget is spent.
    let mut predicates: Vec<SchemaPredicate> = Vec::new();
    let mut has_value_pred = false;
    for (field, _) in &scored {
        if predicates.len() >= config.max_predicates {
            break;
        }
        let pred = field_predicate(cluster, field, config);
        if matches!(
            pred,
            SchemaPredicate::Equals { .. } | SchemaPredicate::In { .. }
        ) {
            has_value_pred = true;
        }
        predicates.push(pred);
        if separates(&predicates, cluster_idx, all) {
            break;
        }
    }
    if predicates.is_empty() {
        return None;
    }

    let separated = separates(&predicates, cluster_idx, all);
    let mut overlap_warnings = Vec::new();
    if !separated {
        overlap_warnings.push(
            "predicates do not fully separate this cluster from other unrecognized shapes; \
             add a distinguishing field before committing"
                .to_string(),
        );
    }

    let specificity = suggest_specificity(predicates.len(), has_value_pred);
    let name = suggest_name(&predicates);

    let mut candidate = DiscoveryCandidate {
        name,
        specificity,
        predicates,
        support: cluster.total,
        coverage_of_unknown: if total_events == 0 {
            0.0
        } else {
            cluster.total as f64 / total_events as f64
        },
        sample_field_sets: cluster.sample_keys.clone(),
        overlap_warnings,
        source,
    };

    // Reject / annotate proposals shadowed by a built-in signature.
    let findings = validate_schema_config(&[candidate.signature()], None);
    for f in findings {
        if f.contains("unreachable") {
            return None;
        }
        candidate.overlap_warnings.push(f);
    }

    Some(candidate)
}

/// Choose the predicate for one field: a value predicate when the field is a
/// safe low-cardinality marker (offline only), otherwise field-presence.
fn field_predicate(cluster: &Cluster, field: &str, config: &DiscoveryConfig) -> SchemaPredicate {
    if config.value_markers
        && let Some(acc) = cluster.values.get(field)
        && acc.usable(cluster.total, config.core_presence)
        && acc.values.len() <= config.max_value_cardinality
    {
        let values: Vec<String> = acc.values.iter().cloned().collect();
        if values.len() == 1 {
            return SchemaPredicate::Equals {
                field: field.to_string(),
                value: values.into_iter().next().unwrap(),
            };
        }
        return SchemaPredicate::In {
            field: field.to_string(),
            values,
        };
    }
    SchemaPredicate::FieldPresent(field.to_string())
}

/// Does the predicate conjunction match only this cluster, and no other? Uses
/// cluster aggregates (a conservative check on core presence and retained
/// values), not raw events.
fn separates(predicates: &[SchemaPredicate], cluster_idx: usize, all: &[Cluster]) -> bool {
    for (idx, other) in all.iter().enumerate() {
        if idx == cluster_idx {
            continue;
        }
        if predicates.iter().all(|p| cluster_may_match(other, p)) {
            return false;
        }
    }
    true
}

/// Conservative: could this cluster plausibly satisfy the predicate, judged
/// from its aggregates? Errs toward "yes" so separation is not overclaimed.
fn cluster_may_match(cluster: &Cluster, pred: &SchemaPredicate) -> bool {
    match pred {
        SchemaPredicate::FieldPresent(f) => cluster.key_counts.contains_key(f),
        SchemaPredicate::AnyOf(fs) => fs.iter().any(|f| cluster.key_counts.contains_key(f)),
        SchemaPredicate::Equals { field, value } => match cluster.values.get(field) {
            Some(acc) => acc.overflow || acc.values.contains(value),
            None => cluster.key_counts.contains_key(field),
        },
        SchemaPredicate::In { field, values } => match cluster.values.get(field) {
            Some(acc) => acc.overflow || values.iter().any(|v| acc.values.contains(v)),
            None => cluster.key_counts.contains_key(field),
        },
        // Discovery only emits the forms above; anything else is treated as
        // possibly matching so separation stays conservative.
        _ => true,
    }
}

fn suggest_specificity(predicate_count: usize, has_value_pred: bool) -> u32 {
    let mut spec = 60u32;
    if has_value_pred {
        spec += 10;
    }
    spec += (predicate_count.saturating_sub(1) as u32) * 3;
    spec.clamp(55, 104)
}

/// A placeholder name derived from the strongest marker, prefixed `discovered_`
/// so it reads as a suggestion a human should rename.
fn suggest_name(predicates: &[SchemaPredicate]) -> String {
    let marker = predicates.iter().find_map(|p| match p {
        SchemaPredicate::Equals { value, .. } => Some(value.clone()),
        SchemaPredicate::In { field, .. } => Some(field.clone()),
        _ => None,
    });
    let base = marker
        .or_else(|| {
            predicates.iter().find_map(|p| match p {
                SchemaPredicate::FieldPresent(f) => Some(f.clone()),
                SchemaPredicate::AnyOf(fs) => fs.first().cloned(),
                _ => None,
            })
        })
        .unwrap_or_default();
    let slug = slugify(&base);
    if slug.is_empty() {
        "discovered".to_string()
    } else {
        format!("discovered_{slug}")
    }
}

fn unique_name(name: String, used: &mut BTreeMap<String, u32>) -> String {
    let n = used.entry(name.clone()).or_insert(0);
    *n += 1;
    if *n == 1 { name } else { format!("{name}_{n}") }
}

// =============================================================================
// Small helpers
// =============================================================================

fn jaccard(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let sa: BTreeSet<&String> = a.iter().collect();
    let sb: BTreeSet<&String> = b.iter().collect();
    let inter = sa.intersection(&sb).count();
    let union = sa.union(&sb).count();
    if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    }
}

fn truncate_keys(keys: &[String]) -> Vec<String> {
    keys.iter().take(MAX_SAMPLE_KEYS_PER_SET).cloned().collect()
}

/// A value we should not retain or turn into a predicate: too long, or a
/// free-form / structured value (command line, path, IP, URL) rather than a
/// stable low-cardinality marker.
fn looks_sensitive(value: &str) -> bool {
    if value.len() > 64 || value.is_empty() {
        return true;
    }
    if value
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '/' | '\\'))
    {
        return true;
    }
    // IPv4-ish: four or more dot-separated numeric segments.
    let segments: Vec<&str> = value.split('.').collect();
    segments.len() >= 4
        && segments
            .iter()
            .all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
}

fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut prev_us = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_us = false;
        } else if !prev_us && !out.is_empty() {
            out.push('_');
            prev_us = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

fn describe_predicate(p: &SchemaPredicate) -> String {
    match p {
        SchemaPredicate::FieldPresent(f) => format!("field_present: {f}"),
        SchemaPredicate::AnyOf(fs) => format!("any_of: [{}]", fs.join(", ")),
        SchemaPredicate::Equals { field, value } => format!("{field} == \"{value}\""),
        SchemaPredicate::In { field, values } => format!("{field} in [{}]", values.join(", ")),
        other => format!("{other:?}"),
    }
}

/// Render one predicate as YAML lines under a `match:` list. Only the forms
/// discovery emits are handled explicitly.
fn predicate_to_yaml(p: &SchemaPredicate) -> String {
    match p {
        SchemaPredicate::FieldPresent(f) => format!("      - field_present: {}\n", yaml_scalar(f)),
        SchemaPredicate::AnyOf(fs) => {
            let items: Vec<String> = fs.iter().map(|f| yaml_scalar(f)).collect();
            format!("      - any_of: [{}]\n", items.join(", "))
        }
        SchemaPredicate::Equals { field, value } => format!(
            "      - equals:\n          field: {}\n          value: {}\n",
            yaml_scalar(field),
            yaml_scalar(value)
        ),
        SchemaPredicate::In { field, values } => {
            let items: Vec<String> = values.iter().map(|v| yaml_scalar(v)).collect();
            format!(
                "      - in:\n          field: {}\n          values: [{}]\n",
                yaml_scalar(field),
                items.join(", ")
            )
        }
        // Not emitted by discovery; fall back to a presence predicate on a
        // best-effort field so the YAML stays parseable rather than panicking.
        other => format!("      # unsupported predicate omitted: {other:?}\n"),
    }
}

/// Quote a scalar when needed so the emitted YAML always parses.
fn yaml_scalar(s: &str) -> String {
    let needs_quote = s.is_empty()
        || s.chars().next().is_some_and(|c| {
            matches!(
                c,
                '!' | '&'
                    | '*'
                    | '-'
                    | '?'
                    | '{'
                    | '}'
                    | '['
                    | ']'
                    | ','
                    | '#'
                    | '|'
                    | '>'
                    | '@'
                    | '`'
                    | '"'
                    | '\''
                    | '%'
                    | ':'
                    | ' '
            )
        })
        || s.contains(": ")
        || s.contains(" #")
        || s.contains(['"', '\'', '\n', '\t'])
        || s.ends_with(':')
        || s.ends_with(' ');
    if needs_quote {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::JsonEvent;
    use serde_json::{Value, json};

    fn events(values: &[Value]) -> Vec<JsonEvent<'_>> {
        values.iter().map(JsonEvent::borrow).collect()
    }

    fn mine(values: &[Value], config: &DiscoveryConfig) -> DiscoveryReport {
        let classifier = SchemaClassifier::builtin();
        mine_events(events(values), &classifier, config)
    }

    fn vendor_corpus(n: usize, vendor: &str) -> Vec<Value> {
        (0..n)
            .map(|i| json!({"vendor": vendor, "event_type": "alert", "seq": i}))
            .collect()
    }

    #[test]
    fn mines_a_candidate_from_repeated_vendor_events() {
        let corpus = vendor_corpus(10, "acme");
        let report = mine(&corpus, &DiscoveryConfig::default());
        assert_eq!(report.stats.events_mined, 10);
        assert!(!report.candidates.is_empty());
        let c = &report.candidates[0];
        assert_eq!(c.support, 10);
        assert_eq!(c.source, CandidateSource::Corpus);
        // A constant low-cardinality field (vendor or event_type) becomes an
        // equals value marker rather than a bare presence predicate.
        assert!(
            c.predicates
                .iter()
                .any(|p| matches!(p, SchemaPredicate::Equals { .. })),
            "expected a value (equals) marker, got {:?}",
            c.predicate_descriptions()
        );
    }

    #[test]
    fn excludes_events_recognized_by_builtins() {
        let mut corpus = vendor_corpus(5, "acme");
        // ECS events must never be mined or re-proposed.
        for _ in 0..5 {
            corpus.push(json!({"ecs.version": "8.11.0", "process.command_line": "whoami"}));
        }
        let report = mine(&corpus, &DiscoveryConfig::default());
        assert_eq!(report.stats.events_mined, 5, "only the 5 vendor events");
        assert!(report.candidates.iter().all(|c| c.name != "ecs"));
    }

    #[test]
    fn generic_json_is_mineable_offline() {
        // A single-field event classifies as generic_json (specificity 0), which
        // counts as unrecognized and is mined.
        let corpus: Vec<Value> = (0..4).map(|_| json!({"foo": "bar"})).collect();
        let report = mine(&corpus, &DiscoveryConfig::default());
        assert_eq!(report.stats.events_mined, 4);
        assert!(!report.candidates.is_empty());
    }

    #[test]
    fn diversity_guard_keeps_distinct_vendors_separate() {
        // Two shapes with high key overlap (Jaccard 4/6 > the 0.6 default) that
        // disagree on a constant marker field. Without the guard they would
        // merge into one cluster; with it they stay separate.
        let mut corpus: Vec<Value> = (0..6)
            .map(|_| json!({"vendor": "foo", "a": 1, "b": 1, "c": 1, "d": 1}))
            .collect();
        corpus.extend((0..6).map(|_| json!({"vendor": "bar", "a": 1, "b": 1, "c": 1, "e": 1})));
        let report = mine(&corpus, &DiscoveryConfig::default());
        assert_eq!(
            report.candidates.len(),
            2,
            "diversity guard should keep the two shapes separate, got {}",
            report.candidates.len()
        );
        assert!(report.candidates.iter().all(|c| c.support == 6));
    }

    #[test]
    fn min_support_filters_one_off_shapes() {
        let mut corpus = vendor_corpus(10, "acme");
        corpus.push(json!({"totally": "unique", "one": "off"}));
        let cfg = DiscoveryConfig {
            min_support: 3,
            ..DiscoveryConfig::default()
        };
        let report = mine(&corpus, &cfg);
        assert!(
            report.candidates.iter().all(|c| c.support >= 3),
            "no candidate below min_support"
        );
    }

    #[test]
    fn keys_only_path_uses_presence_predicates() {
        let shapes = vec![
            UnknownShapeEntry {
                keys: vec!["a".into(), "b".into(), "vendor".into()],
                count: 8,
            },
            UnknownShapeEntry {
                keys: vec!["x".into(), "y".into(), "z".into()],
                count: 5,
            },
        ];
        let report = mine_shapes(&shapes, &DiscoveryConfig::default());
        assert_eq!(report.stats.events_mined, 13);
        assert!(!report.candidates.is_empty());
        for c in &report.candidates {
            assert_eq!(c.source, CandidateSource::KeysOnly);
            assert!(
                c.predicates.iter().all(|p| matches!(
                    p,
                    SchemaPredicate::FieldPresent(_) | SchemaPredicate::AnyOf(_)
                )),
                "keys-only proposals must be presence-only"
            );
        }
    }

    #[test]
    fn cluster_count_matches_full_mine() {
        let shapes = vec![
            UnknownShapeEntry {
                keys: vec!["a".into(), "b".into(), "vendor".into()],
                count: 8,
            },
            UnknownShapeEntry {
                keys: vec!["x".into(), "y".into(), "z".into()],
                count: 5,
            },
            // An empty-key shape is skipped by both paths.
            UnknownShapeEntry {
                keys: vec![],
                count: 3,
            },
        ];
        let cfg = DiscoveryConfig::default();
        assert_eq!(
            cluster_count(&shapes, &cfg),
            mine_shapes(&shapes, &cfg).stats.clusters,
            "the cheap cluster count must equal the full pipeline's cluster count"
        );
    }

    #[test]
    fn yaml_round_trips_through_parser() {
        let mut corpus = vendor_corpus(8, "acme");
        corpus.extend((0..6).map(|i| json!({"deviceName": "fw", "srcip": format!("h{i}")})));
        let report = mine(&corpus, &DiscoveryConfig::default());
        assert!(!report.candidates.is_empty());
        let yaml = report.to_signatures_yaml();
        let parsed = crate::schema::parse_schema_signatures(&yaml)
            .expect("emitted YAML must parse via parse_schema_signatures");
        assert_eq!(parsed.len(), report.candidates.len());
        // Loading the proposals into a classifier reclassifies the mined events.
        let classifier = SchemaClassifier::with_user_signatures(parsed);
        let hits = corpus
            .iter()
            .filter(|v| {
                classifier
                    .classify(&JsonEvent::borrow(v))
                    .is_some_and(|m| m.name != "generic_json")
            })
            .count();
        assert!(hits >= 8, "proposals should recognize the mined events");
    }

    #[test]
    fn deterministic_across_runs() {
        let mut corpus = vendor_corpus(7, "acme");
        corpus.extend(vendor_corpus(4, "beta"));
        let a = mine(&corpus, &DiscoveryConfig::default()).to_signatures_yaml();
        let b = mine(&corpus, &DiscoveryConfig::default()).to_signatures_yaml();
        assert_eq!(a, b, "discovery output must be byte-identical across runs");
    }

    #[test]
    fn high_cardinality_values_do_not_become_markers() {
        // command_line-like free-form values must never be emitted as markers.
        let corpus: Vec<Value> = (0..10)
            .map(|i| json!({"tool": "runner", "command_line": format!("run --job {i} /tmp/x")}))
            .collect();
        let report = mine(&corpus, &DiscoveryConfig::default());
        assert!(!report.candidates.is_empty());
        for c in &report.candidates {
            assert!(
                !c.predicates.iter().any(|p| matches!(
                    p,
                    SchemaPredicate::Equals { field, .. } if field == "command_line"
                )),
                "sensitive/free-form values must not become equals markers"
            );
        }
    }

    #[test]
    fn empty_corpus_yields_no_candidates() {
        let report = mine(&[], &DiscoveryConfig::default());
        assert_eq!(report.stats.events_mined, 0);
        assert!(report.candidates.is_empty());
        assert_eq!(report.to_signatures_yaml(), "schemas: []\n");
    }

    #[test]
    fn specificity_stays_below_strong_builtins() {
        let corpus = vendor_corpus(10, "acme");
        let report = mine(&corpus, &DiscoveryConfig::default());
        for c in &report.candidates {
            assert!(c.specificity >= 55 && c.specificity <= 104);
        }
    }
}
