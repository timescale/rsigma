//! Draft temporal correlations from grouped, timed exemplar events.

use std::collections::{BTreeMap, BTreeSet};

use chrono::DateTime;
use rsigma_parser::Timespan;
use serde::Serialize;
use serde_json::Value;

use crate::correlation_engine::{CorrelationConfig, CorrelationEngine};
use crate::event::{Event, JsonEvent};
use crate::key_shape::cluster_by_key_shape;

use super::draft_core::{ValueForm, yaml_str, yaml_title_str};
use super::{DraftCandidate, DraftConfig, DraftError};

/// Source context attached by a grouped-input reader.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SourceLocation {
    /// Input file, when the event came from a file.
    pub file: Option<String>,
    /// One-based source line, when available.
    pub line: Option<usize>,
}

impl SourceLocation {
    fn label(&self) -> String {
        match (&self.file, self.line) {
            (Some(file), Some(line)) => format!("{file}:{line}"),
            (Some(file), None) => file.clone(),
            (None, Some(line)) => format!("line {line}"),
            (None, None) => "unknown source".to_string(),
        }
    }
}

/// One event carrying exactly one absolute timestamp or relative offset.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TimedEvent {
    /// RFC3339 timestamp. Mutually exclusive with [`Self::offset`].
    pub timestamp: Option<String>,
    /// Sigma timespan offset. Mutually exclusive with [`Self::timestamp`].
    pub offset: Option<String>,
    /// Event body.
    pub event: Value,
    /// Optional file/line context for validation errors.
    pub source: SourceLocation,
}

/// One observed instance of the multi-event behavior.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GroupedExemplar {
    /// Stable group identifier.
    pub id: String,
    /// Timed events in arbitrary input order.
    pub events: Vec<TimedEvent>,
}

/// Requested correlation ordering.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationDraftType {
    /// Infer ordered only when every positive group agrees.
    #[default]
    Auto,
    /// Emit an unordered temporal correlation.
    Temporal,
    /// Require and emit identical ordering across groups.
    TemporalOrdered,
}

impl CorrelationDraftType {
    fn emitted_name(self, ordered: bool) -> &'static str {
        match self {
            Self::Temporal => "temporal",
            Self::Auto if !ordered => "temporal",
            Self::Auto | Self::TemporalOrdered => "temporal_ordered",
        }
    }
}

/// Tunables and caller-supplied metadata for correlation drafting.
#[derive(Debug, Clone)]
pub struct CorrelationDraftConfig {
    /// Minimum number of positive groups.
    pub min_groups: usize,
    /// Minimum number of recurring slots.
    pub min_slots: usize,
    /// Key-shape Jaccard threshold.
    pub similarity: f64,
    /// Multiplier applied to the maximum observed positive span.
    pub window_margin: f64,
    /// Ordering mode.
    pub correlation_type: CorrelationDraftType,
    /// Explicit grouping fields. Empty means infer one field.
    pub group_by: Vec<String>,
    /// Correlation title override.
    pub title: Option<String>,
    /// Caller-supplied correlation id.
    pub correlation_id: Option<String>,
    /// Caller-supplied slot ids, in inferred slot order.
    pub slot_ids: Vec<String>,
    /// Shared per-slot detection drafting configuration.
    pub detection: DraftConfig,
}

impl Default for CorrelationDraftConfig {
    fn default() -> Self {
        Self {
            min_groups: 3,
            min_slots: 2,
            similarity: 0.6,
            window_margin: 1.5,
            correlation_type: CorrelationDraftType::Auto,
            group_by: Vec::new(),
            title: None,
            correlation_id: None,
            slot_ids: Vec::new(),
            detection: DraftConfig::default(),
        }
    }
}

/// One drafted slot in the report.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationSlotReport {
    /// Correlation rule reference.
    pub name: String,
    /// Detection rule id.
    pub id: Option<String>,
    /// Positive event count assigned to the slot.
    pub support: usize,
    /// Number of positive groups represented.
    pub group_support: usize,
    /// Selected detection field descriptions.
    pub selected_fields: Vec<String>,
}

/// Isolated replay result for one positive or negative group.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationVerification {
    /// Group identifier.
    pub group: String,
    /// Whether this was a negative group.
    pub negative: bool,
    /// Whether the target correlation fired.
    pub fired: bool,
}

/// A verified drafted correlation and its evidence.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationDraftReport {
    /// Paste-ready multi-document Sigma YAML.
    pub rule_yaml: String,
    /// `temporal` or `temporal_ordered`.
    pub correlation_type: String,
    /// Explicit or inferred grouping fields.
    pub group_by: Vec<String>,
    /// Chosen window.
    pub timespan: String,
    /// Raw positive first-to-last spans in seconds.
    pub span_seconds: Vec<u64>,
    /// Consecutive retained-slot gaps in seconds.
    pub gap_seconds: Vec<u64>,
    /// Per-slot drafting evidence.
    pub slots: Vec<CorrelationSlotReport>,
    /// Isolated positive and negative verification rows.
    pub verification: Vec<CorrelationVerification>,
    /// Advisory inference and lint notes.
    pub warnings: Vec<String>,
}

/// Why a grouped correlation draft could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum CorrelationDraftError {
    /// Too few positive groups were provided.
    #[error("at least {minimum} positive groups are required, got {actual}")]
    TooFewGroups { minimum: usize, actual: usize },
    /// A group has fewer than two events.
    #[error("group '{group}' needs at least two events, got {actual}")]
    TooFewEvents { group: String, actual: usize },
    /// An event carries neither or both supported time keys.
    #[error(
        "group '{group}' event {event} at {location} must contain exactly one of timestamp or offset"
    )]
    InvalidTimeKeys {
        group: String,
        event: usize,
        location: String,
    },
    /// A group mixes absolute and relative time.
    #[error("group '{group}' mixes timestamp and offset time modes")]
    MixedTimeMode { group: String },
    /// A timestamp or offset is invalid.
    #[error("group '{group}' event {event} at {location} has invalid {kind} value '{value}'")]
    InvalidTime {
        group: String,
        event: usize,
        location: String,
        kind: &'static str,
        value: String,
    },
    /// Two events in a group have the same parsed time.
    #[error(
        "group '{group}' events {first_event} and {second_event} have duplicate parsed time {time}"
    )]
    DuplicateTime {
        group: String,
        first_event: usize,
        second_event: usize,
        time: i64,
    },
    /// Too few recurring event slots survived.
    #[error("at least {minimum} recurring slots are required, got {actual}")]
    TooFewSlots { minimum: usize, actual: usize },
    /// A recurring slot appears more than once in one group.
    #[error("group '{group}' repeats slot {slot} at event indexes {events:?}")]
    DuplicateSlot {
        group: String,
        slot: usize,
        events: Vec<usize>,
    },
    /// Forced ordering disagrees with observed groups.
    #[error("temporal_ordered was requested but groups disagree on slot order: {groups:?}")]
    OrderInversion { groups: Vec<String> },
    /// Window margin is invalid.
    #[error("window margin must be finite and at least 1.0, got {0}")]
    InvalidWindowMargin(f64),
    /// The inferred window overflowed.
    #[error("inferred correlation window overflowed")]
    WindowOverflow,
    /// Grouping inference found zero or multiple valid fields.
    #[error("correlation entity is ambiguous; candidates: {candidates:?}")]
    AmbiguousEntity { candidates: Vec<String> },
    /// An explicit grouping field is absent or unstable.
    #[error(
        "group-by field '{field}' is absent or unstable in group '{group}' at retained event {event}"
    )]
    InvalidEntity {
        field: String,
        group: String,
        event: usize,
    },
    /// A per-slot detection could not be drafted.
    #[error("failed to draft slot {slot}: {source}")]
    SlotDraft {
        slot: usize,
        #[source]
        source: DraftError,
    },
    /// One event matches the wrong slot rules.
    #[error(
        "group '{group}' event {event} assigned to '{assigned}' collides with {colliding:?}; selected forms: {forms:?}. Use cleaner exemplars, a representative baseline, or manual rule editing"
    )]
    CrossSlotMatch {
        group: String,
        event: usize,
        assigned: String,
        colliding: Vec<String>,
        forms: Vec<String>,
    },
    /// A slot cannot match its assigned positives at the field floor.
    #[error("slot '{slot}' cannot match assigned positives at the {floor}-field floor")]
    SlotFloor { slot: String, floor: usize },
    /// Emitted YAML did not parse or compile.
    #[error("internal correlation draft error during {stage}: {message}")]
    Internal {
        stage: &'static str,
        message: String,
    },
    /// An isolated positive group did not fire correctly.
    #[error("positive group '{group}' {reason}")]
    PositiveVerification { group: String, reason: String },
    /// One or more negative groups fired the target correlation.
    #[error("drafted correlation matched negative groups: {groups:?}")]
    NegativeGroupMatched { groups: Vec<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeMode {
    Timestamp,
    Offset,
}

#[derive(Debug, Clone)]
struct NormalizedEvent {
    input_index: usize,
    time: i64,
    event: Value,
    keys: Vec<String>,
    cluster: usize,
}

#[derive(Debug, Clone)]
struct NormalizedGroup {
    id: String,
    events: Vec<NormalizedEvent>,
}

#[derive(Debug)]
struct ShapeCluster {
    seed_keys: Vec<String>,
    members: Vec<(usize, usize)>,
}

#[derive(Debug)]
struct ShapeItem {
    keys: Vec<String>,
    member: (usize, usize),
}

#[derive(Debug)]
struct Slot {
    cluster: usize,
    name: String,
    id: Option<String>,
    members: Vec<(usize, usize)>,
    candidate: DraftCandidate,
    config: DraftConfig,
}

/// Draft, emit, and verify a temporal correlation from positive groups.
///
/// Every positive and negative group is replayed through a fresh correlation
/// engine. `baseline` is a flat corpus used only for per-slot contrast.
pub fn draft_correlation(
    groups: &[GroupedExemplar],
    negative_groups: &[GroupedExemplar],
    baseline: &[Value],
    config: &CorrelationDraftConfig,
) -> Result<CorrelationDraftReport, CorrelationDraftError> {
    let mut groups = normalize_groups(groups, config.min_groups)?;
    let negatives = normalize_groups(negative_groups, 0)?;
    let positive_count = groups.len();
    groups.extend(negatives);
    assign_clusters(&mut groups, config.similarity);
    let negatives = groups.split_off(positive_count);

    let (retained, mut warnings) = retained_clusters(&groups, config.min_slots)?;
    validate_slot_counts(&groups, &retained)?;
    let group_by = resolve_group_by(&groups, &retained, &config.group_by)?;
    let (ordered, order, disagreeing) = infer_order(&groups, &retained);
    if config.correlation_type == CorrelationDraftType::TemporalOrdered && !disagreeing.is_empty() {
        return Err(CorrelationDraftError::OrderInversion {
            groups: disagreeing,
        });
    }
    if config.correlation_type == CorrelationDraftType::Auto && !disagreeing.is_empty() {
        warnings.push(format!(
            "slot order differs in groups {}; emitted temporal instead of temporal_ordered",
            disagreeing.join(", ")
        ));
    }
    let correlation_type = config.correlation_type.emitted_name(ordered);
    let (timespan, spans, gaps) = infer_window(&groups, &retained, config.window_margin)?;
    let correlation_id = config
        .correlation_id
        .clone()
        .unwrap_or_else(|| "draft-correlation".to_string());

    let mut slots = build_slots(
        &groups,
        baseline,
        &group_by,
        &order,
        &config.slot_ids,
        &config.detection,
    )?;

    let (rule_yaml, verification) = loop {
        let yaml = emit_collection(
            &groups,
            &retained,
            &slots,
            correlation_type,
            &group_by,
            &timespan,
            &correlation_id,
            config,
        );
        let collection = rsigma_parser::parse_sigma_yaml(&yaml).map_err(|error| {
            CorrelationDraftError::Internal {
                stage: "parse",
                message: error.to_string(),
            }
        })?;

        match verify_identity(&collection, &groups, &retained, &slots)? {
            Some((slot_index, local_event)) => {
                let slot = &mut slots[slot_index];
                let floor = slot
                    .config
                    .min_fields
                    .min(slot.candidate.selected.len())
                    .max(1);
                if slot.candidate.selected.len() <= floor
                    || slot
                        .candidate
                        .drop_lowest_eligible(Some(&[local_event]))
                        .is_none()
                {
                    return Err(CorrelationDraftError::SlotFloor {
                        slot: slot.name.clone(),
                        floor,
                    });
                }
                warnings.push(format!(
                    "relaxed slot '{}' after an assigned positive failed verification",
                    slot.name
                ));
                continue;
            }
            None => {}
        }

        let mut verification =
            verify_groups(&collection, &groups, &retained, &correlation_id, false)?;
        let mut negative_rows =
            verify_groups(&collection, &negatives, &retained, &correlation_id, true)?;
        verification.append(&mut negative_rows);
        break (yaml, verification);
    };

    for finding in rsigma_parser::lint_yaml_str(&rule_yaml) {
        warnings.push(format!("lint {}: {}", finding.rule, finding.message));
    }

    let slot_reports = slots
        .iter()
        .map(|slot| CorrelationSlotReport {
            name: slot.name.clone(),
            id: slot.id.clone(),
            support: slot.members.len(),
            group_support: groups.len(),
            selected_fields: selected_forms(slot),
        })
        .collect();

    Ok(CorrelationDraftReport {
        rule_yaml,
        correlation_type: correlation_type.to_string(),
        group_by,
        timespan: timespan.original,
        span_seconds: spans,
        gap_seconds: gaps,
        slots: slot_reports,
        verification,
        warnings,
    })
}

fn normalize_groups(
    groups: &[GroupedExemplar],
    minimum: usize,
) -> Result<Vec<NormalizedGroup>, CorrelationDraftError> {
    if groups.len() < minimum {
        return Err(CorrelationDraftError::TooFewGroups {
            minimum,
            actual: groups.len(),
        });
    }
    let mut normalized = Vec::with_capacity(groups.len());
    for group in groups {
        if group.events.len() < 2 {
            return Err(CorrelationDraftError::TooFewEvents {
                group: group.id.clone(),
                actual: group.events.len(),
            });
        }
        let mut mode = None;
        let mut events = Vec::with_capacity(group.events.len());
        for (index, timed) in group.events.iter().enumerate() {
            let current = match (&timed.timestamp, &timed.offset) {
                (Some(_), None) => TimeMode::Timestamp,
                (None, Some(_)) => TimeMode::Offset,
                _ => {
                    return Err(CorrelationDraftError::InvalidTimeKeys {
                        group: group.id.clone(),
                        event: index,
                        location: timed.source.label(),
                    });
                }
            };
            if mode.is_some_and(|expected| expected != current) {
                return Err(CorrelationDraftError::MixedTimeMode {
                    group: group.id.clone(),
                });
            }
            mode = Some(current);
            let time = match current {
                TimeMode::Timestamp => {
                    let raw = timed.timestamp.as_deref().unwrap();
                    let parsed = DateTime::parse_from_rfc3339(raw).map_err(|_| {
                        CorrelationDraftError::InvalidTime {
                            group: group.id.clone(),
                            event: index,
                            location: timed.source.label(),
                            kind: "timestamp",
                            value: raw.to_string(),
                        }
                    })?;
                    parsed.timestamp()
                }
                TimeMode::Offset => {
                    let raw = timed.offset.as_deref().unwrap();
                    let parsed =
                        Timespan::parse(raw).map_err(|_| CorrelationDraftError::InvalidTime {
                            group: group.id.clone(),
                            event: index,
                            location: timed.source.label(),
                            kind: "offset",
                            value: raw.to_string(),
                        })?;
                    let seconds = i64::try_from(parsed.seconds).map_err(|_| {
                        CorrelationDraftError::InvalidTime {
                            group: group.id.clone(),
                            event: index,
                            location: timed.source.label(),
                            kind: "offset",
                            value: raw.to_string(),
                        }
                    })?;
                    seconds
                }
            };
            let json = JsonEvent::borrow(&timed.event);
            let mut keys: Vec<String> = json
                .field_keys()
                .into_iter()
                .map(|key| key.into_owned())
                .collect();
            keys.sort();
            keys.dedup();
            events.push(NormalizedEvent {
                input_index: index,
                time,
                event: timed.event.clone(),
                keys,
                cluster: usize::MAX,
            });
        }
        events.sort_by_key(|event| (event.time, event.input_index));
        for pair in events.windows(2) {
            if pair[0].time == pair[1].time {
                return Err(CorrelationDraftError::DuplicateTime {
                    group: group.id.clone(),
                    first_event: pair[0].input_index,
                    second_event: pair[1].input_index,
                    time: pair[0].time,
                });
            }
        }
        normalized.push(NormalizedGroup {
            id: group.id.clone(),
            events,
        });
    }
    normalized.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(normalized)
}

fn assign_clusters(groups: &mut [NormalizedGroup], similarity: f64) {
    let items: Vec<ShapeItem> = groups
        .iter()
        .enumerate()
        .flat_map(|(group, value)| {
            value
                .events
                .iter()
                .enumerate()
                .map(move |(event, value)| ShapeItem {
                    keys: value.keys.clone(),
                    member: (group, event),
                })
        })
        .collect();
    let clusters = cluster_by_key_shape(
        &items,
        similarity,
        |item| &item.keys,
        |cluster: &ShapeCluster| &cluster.seed_keys,
        |item| ShapeCluster {
            seed_keys: item.keys.clone(),
            members: vec![item.member],
        },
        |_, _| true,
        |cluster, item| cluster.members.push(item.member),
    );
    for (cluster_index, cluster) in clusters.iter().enumerate() {
        for &(group, event) in &cluster.members {
            groups[group].events[event].cluster = cluster_index;
        }
    }
}

fn retained_clusters(
    groups: &[NormalizedGroup],
    minimum: usize,
) -> Result<(BTreeSet<usize>, Vec<String>), CorrelationDraftError> {
    let all: BTreeSet<usize> = groups
        .iter()
        .flat_map(|group| group.events.iter().map(|event| event.cluster))
        .collect();
    let retained: BTreeSet<usize> = all
        .iter()
        .copied()
        .filter(|cluster| {
            groups
                .iter()
                .all(|group| group.events.iter().any(|event| event.cluster == *cluster))
        })
        .collect();
    if retained.len() < minimum {
        return Err(CorrelationDraftError::TooFewSlots {
            minimum,
            actual: retained.len(),
        });
    }
    let dropped: Vec<String> = all
        .difference(&retained)
        .map(|cluster| cluster.to_string())
        .collect();
    let warnings = if dropped.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "dropped incidental key-shape clusters absent from one or more positive groups: {}",
            dropped.join(", ")
        )]
    };
    Ok((retained, warnings))
}

fn validate_slot_counts(
    groups: &[NormalizedGroup],
    retained: &BTreeSet<usize>,
) -> Result<(), CorrelationDraftError> {
    for group in groups {
        for &slot in retained {
            let events: Vec<usize> = group
                .events
                .iter()
                .enumerate()
                .filter(|(_, event)| event.cluster == slot)
                .map(|(index, _)| index)
                .collect();
            if events.len() > 1 {
                return Err(CorrelationDraftError::DuplicateSlot {
                    group: group.id.clone(),
                    slot,
                    events,
                });
            }
        }
    }
    Ok(())
}

fn infer_order(
    groups: &[NormalizedGroup],
    retained: &BTreeSet<usize>,
) -> (bool, Vec<usize>, Vec<String>) {
    let orders: Vec<Vec<usize>> = groups
        .iter()
        .map(|group| {
            group
                .events
                .iter()
                .filter(|event| retained.contains(&event.cluster))
                .map(|event| event.cluster)
                .collect()
        })
        .collect();
    let expected = orders.first().cloned().unwrap_or_default();
    let disagreeing: Vec<String> = groups
        .iter()
        .zip(&orders)
        .filter(|(_, order)| **order != expected)
        .map(|(group, _)| group.id.clone())
        .collect();
    (disagreeing.is_empty(), expected, disagreeing)
}

fn infer_window(
    groups: &[NormalizedGroup],
    retained: &BTreeSet<usize>,
    margin: f64,
) -> Result<(Timespan, Vec<u64>, Vec<u64>), CorrelationDraftError> {
    if !margin.is_finite() || margin < 1.0 {
        return Err(CorrelationDraftError::InvalidWindowMargin(margin));
    }
    let mut spans = Vec::with_capacity(groups.len());
    let mut gaps = Vec::new();
    for group in groups {
        let times: Vec<i64> = group
            .events
            .iter()
            .filter(|event| retained.contains(&event.cluster))
            .map(|event| event.time)
            .collect();
        let first = *times.first().expect("retained slots exist");
        let last = *times.last().expect("retained slots exist");
        spans.push(
            u64::try_from(
                last.checked_sub(first)
                    .ok_or(CorrelationDraftError::WindowOverflow)?,
            )
            .map_err(|_| CorrelationDraftError::WindowOverflow)?,
        );
        for pair in times.windows(2) {
            gaps.push(
                u64::try_from(
                    pair[1]
                        .checked_sub(pair[0])
                        .ok_or(CorrelationDraftError::WindowOverflow)?,
                )
                .map_err(|_| CorrelationDraftError::WindowOverflow)?,
            );
        }
    }
    let maximum = spans.iter().copied().max().unwrap_or(0).max(1);
    let scaled = (maximum as f64 * margin).ceil();
    if !scaled.is_finite() || scaled > u64::MAX as f64 {
        return Err(CorrelationDraftError::WindowOverflow);
    }
    let rounded = round_window(scaled as u64)?;
    let timespan = Timespan::parse(&rounded).map_err(|error| CorrelationDraftError::Internal {
        stage: "window construction",
        message: error.to_string(),
    })?;
    Ok((timespan, spans, gaps))
}

fn round_window(seconds: u64) -> Result<String, CorrelationDraftError> {
    const STEPS: &[(u64, &str)] = &[
        (30, "30s"),
        (60, "1m"),
        (300, "5m"),
        (900, "15m"),
        (3_600, "1h"),
        (21_600, "6h"),
        (86_400, "24h"),
    ];
    if let Some((_, label)) = STEPS.iter().find(|(step, _)| seconds <= *step) {
        return Ok((*label).to_string());
    }
    let days = seconds
        .checked_add(86_399)
        .ok_or(CorrelationDraftError::WindowOverflow)?
        / 86_400;
    Ok(format!("{days}d"))
}

fn resolve_group_by(
    groups: &[NormalizedGroup],
    retained: &BTreeSet<usize>,
    explicit: &[String],
) -> Result<Vec<String>, CorrelationDraftError> {
    if !explicit.is_empty() {
        for field in explicit {
            validate_entity_field(groups, retained, field)?;
        }
        return Ok(explicit.to_vec());
    }
    let mut common: Option<BTreeSet<String>> = None;
    for group in groups {
        for event in group
            .events
            .iter()
            .filter(|event| retained.contains(&event.cluster))
        {
            let keys: BTreeSet<String> = event.keys.iter().cloned().collect();
            common = Some(match common {
                Some(existing) => existing.intersection(&keys).cloned().collect(),
                None => keys,
            });
        }
    }
    let candidates: Vec<String> = common
        .unwrap_or_default()
        .into_iter()
        .filter(|field| validate_entity_field(groups, retained, field).is_ok())
        .filter(|field| {
            let values: BTreeSet<String> = groups
                .iter()
                .filter_map(|group| stable_group_value(group, retained, field))
                .collect();
            values.len() == groups.len()
        })
        .collect();
    if candidates.len() != 1 {
        return Err(CorrelationDraftError::AmbiguousEntity { candidates });
    }
    Ok(candidates)
}

fn validate_entity_field(
    groups: &[NormalizedGroup],
    retained: &BTreeSet<usize>,
    field: &str,
) -> Result<(), CorrelationDraftError> {
    for group in groups {
        let mut expected = None;
        for (index, event) in group
            .events
            .iter()
            .enumerate()
            .filter(|(_, event)| retained.contains(&event.cluster))
        {
            let value = JsonEvent::borrow(&event.event)
                .get_field(field)
                .map(|value| format!("{value:?}"));
            if value.is_none()
                || expected
                    .as_ref()
                    .is_some_and(|known| Some(known) != value.as_ref())
            {
                return Err(CorrelationDraftError::InvalidEntity {
                    field: field.to_string(),
                    group: group.id.clone(),
                    event: index,
                });
            }
            expected = value;
        }
    }
    Ok(())
}

fn stable_group_value(
    group: &NormalizedGroup,
    retained: &BTreeSet<usize>,
    field: &str,
) -> Option<String> {
    let mut values = group
        .events
        .iter()
        .filter(|event| retained.contains(&event.cluster))
        .map(|event| {
            JsonEvent::borrow(&event.event)
                .get_field(field)
                .map(|value| format!("{value:?}"))
        });
    let first = values.next()??;
    values
        .all(|value| value.as_deref() == Some(first.as_str()))
        .then_some(first)
}

fn build_slots(
    groups: &[NormalizedGroup],
    baseline: &[Value],
    group_by: &[String],
    order: &[usize],
    slot_ids: &[String],
    detection_config: &DraftConfig,
) -> Result<Vec<Slot>, CorrelationDraftError> {
    let mut slots = Vec::with_capacity(order.len());
    let mut used_names = BTreeMap::new();
    for (position, &cluster) in order.iter().enumerate() {
        let members: Vec<(usize, usize)> = groups
            .iter()
            .enumerate()
            .flat_map(|(group_index, group)| {
                group
                    .events
                    .iter()
                    .enumerate()
                    .filter(move |(_, event)| event.cluster == cluster)
                    .map(move |(event_index, _)| (group_index, event_index))
            })
            .collect();
        let positives: Vec<Value> = members
            .iter()
            .map(|&(group, event)| groups[group].events[event].event.clone())
            .collect();
        let mut contrast = baseline.to_vec();
        for group in groups {
            contrast.extend(
                group
                    .events
                    .iter()
                    .filter(|event| event.cluster != cluster)
                    .map(|event| event.event.clone()),
            );
        }
        let mut slot_config = detection_config.clone();
        for field in group_by {
            if !slot_config
                .exclude_fields
                .iter()
                .any(|excluded| excluded.eq_ignore_ascii_case(field))
            {
                slot_config.exclude_fields.push(field.clone());
            }
        }
        slot_config.rule_id = slot_ids.get(position).cloned().or_else(|| {
            detection_config
                .rule_id
                .as_ref()
                .map(|base| format!("{base}-{}", position + 1))
        });
        let positive_events: Vec<JsonEvent<'_>> = positives.iter().map(JsonEvent::borrow).collect();
        let contrast_events: Vec<JsonEvent<'_>> = contrast.iter().map(JsonEvent::borrow).collect();
        let candidate = DraftCandidate::build(&positive_events, &contrast_events, &slot_config)
            .map_err(|source| CorrelationDraftError::SlotDraft {
                slot: position,
                source,
            })?;
        let base = slot_name(&candidate, position);
        let count = used_names.entry(base.clone()).or_insert(0usize);
        *count += 1;
        let name = if *count == 1 {
            base
        } else {
            format!("{base}_{count}")
        };
        slots.push(Slot {
            cluster,
            name,
            id: slot_config.rule_id.clone(),
            members,
            candidate,
            config: slot_config,
        });
    }
    Ok(slots)
}

fn slot_name(candidate: &DraftCandidate, position: usize) -> String {
    let marker = candidate.selected.first().and_then(|&index| {
        candidate.profiles[index]
            .form
            .as_ref()
            .and_then(form_marker)
    });
    let slug = marker
        .as_deref()
        .map(slugify)
        .filter(|slug| !slug.is_empty())
        .unwrap_or_else(|| format!("{}", position + 1));
    format!("slot_{slug}")
}

fn form_marker(form: &ValueForm) -> Option<String> {
    match form {
        ValueForm::Exact(value) => Some(value.as_display()),
        ValueForm::OneOf(values) => values.first().map(|value| value.as_display()),
        ValueForm::EndsWith(value) | ValueForm::StartsWith(value) | ValueForm::Contains(value) => {
            Some(value.clone())
        }
        ValueForm::ContainsAll(values) => values.first().cloned(),
    }
}

fn slugify(value: &str) -> String {
    let mut slug = String::new();
    let mut separator = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
            separator = false;
        } else if !slug.is_empty() && !separator {
            slug.push('_');
            separator = true;
        }
    }
    while slug.ends_with('_') {
        slug.pop();
    }
    slug
}

#[allow(clippy::too_many_arguments)]
fn emit_collection(
    groups: &[NormalizedGroup],
    retained: &BTreeSet<usize>,
    slots: &[Slot],
    correlation_type: &str,
    group_by: &[String],
    timespan: &Timespan,
    correlation_id: &str,
    config: &CorrelationDraftConfig,
) -> String {
    let mut output = String::new();
    for (index, slot) in slots.iter().enumerate() {
        if index > 0 {
            output.push_str("---\n");
        }
        let positives: Vec<Value> = slot
            .members
            .iter()
            .map(|&(group, event)| groups[group].events[event].event.clone())
            .collect();
        let events: Vec<JsonEvent<'_>> = positives.iter().map(JsonEvent::borrow).collect();
        output.push_str(
            &slot
                .candidate
                .emit_named(&events, &slot.config, Some(&slot.name)),
        );
    }
    output.push_str("---\n");
    let title = config
        .title
        .clone()
        .unwrap_or_else(|| "Draft temporal correlation".to_string());
    output.push_str(&format!("title: {}\n", yaml_title_str(&title)));
    output.push_str(&format!("id: {}\n", yaml_str(correlation_id)));
    output.push_str("status: experimental\n");
    output.push_str("correlation:\n");
    output.push_str(&format!("    type: {correlation_type}\n"));
    output.push_str("    rules:\n");
    for slot in slots {
        output.push_str(&format!("        - {}\n", yaml_str(&slot.name)));
    }
    output.push_str("    group-by:\n");
    for field in group_by {
        output.push_str(&format!("        - {}\n", yaml_str(field)));
    }
    output.push_str(&format!("    timespan: {}\n", timespan.original));
    output.push_str("    condition:\n");
    output.push_str(&format!("        gte: {}\n", slots.len()));
    output.push_str("custom_attributes:\n");
    output.push_str("    rsigma.exemplars:\n");
    let representative = representative_group(groups, retained);
    output.push_str(&format!(
        "        - name: {}\n",
        yaml_str(&format!("observed group {}", representative.id))
    ));
    output.push_str("          expect: match\n");
    output.push_str("          events:\n");
    let first = representative
        .events
        .iter()
        .find(|event| retained.contains(&event.cluster))
        .map(|event| event.time)
        .unwrap_or(0);
    for event in representative
        .events
        .iter()
        .filter(|event| retained.contains(&event.cluster))
    {
        output.push_str(&format!(
            "              - offset: {}s\n",
            event.time - first
        ));
        output.push_str("                event:\n");
        emit_json_mapping(&mut output, &event.event, "                    ");
    }
    output.push_str("level: medium\n");
    output
}

fn representative_group<'a>(
    groups: &'a [NormalizedGroup],
    retained: &BTreeSet<usize>,
) -> &'a NormalizedGroup {
    let mut ranked: Vec<(u64, &str, &NormalizedGroup)> = groups
        .iter()
        .map(|group| {
            let times: Vec<i64> = group
                .events
                .iter()
                .filter(|event| retained.contains(&event.cluster))
                .map(|event| event.time)
                .collect();
            let span = times
                .last()
                .zip(times.first())
                .and_then(|(last, first)| last.checked_sub(*first))
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(0);
            (span, group.id.as_str(), group)
        })
        .collect();
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    ranked[ranked.len() / 2].2
}

fn emit_json_mapping(output: &mut String, value: &Value, indent: &str) {
    let Some(mapping) = value.as_object() else {
        output.push_str(&format!(
            "{indent}value: {}\n",
            yaml_str(&value.to_string())
        ));
        return;
    };
    let mut keys: Vec<&String> = mapping.keys().collect();
    keys.sort();
    for key in keys {
        emit_json_value(output, key, &mapping[key], indent);
    }
}

fn emit_json_value(output: &mut String, key: &str, value: &Value, indent: &str) {
    let key = yaml_str(key);
    match value {
        Value::Null => output.push_str(&format!("{indent}{key}: null\n")),
        Value::Bool(value) => output.push_str(&format!("{indent}{key}: {value}\n")),
        Value::Number(value) => output.push_str(&format!("{indent}{key}: {value}\n")),
        Value::String(value) => {
            output.push_str(&format!("{indent}{key}: {}\n", yaml_str(value)));
        }
        Value::Object(_) => {
            output.push_str(&format!("{indent}{key}:\n"));
            emit_json_mapping(output, value, &format!("{indent}    "));
        }
        Value::Array(values) => {
            output.push_str(&format!("{indent}{key}:\n"));
            for value in values {
                match value {
                    Value::Null => output.push_str(&format!("{indent}    - null\n")),
                    Value::Bool(value) => {
                        output.push_str(&format!("{indent}    - {value}\n"));
                    }
                    Value::Number(value) => {
                        output.push_str(&format!("{indent}    - {value}\n"));
                    }
                    Value::String(value) => {
                        output.push_str(&format!("{indent}    - {}\n", yaml_str(value)));
                    }
                    _ => output
                        .push_str(&format!("{indent}    - {}\n", yaml_str(&value.to_string()))),
                }
            }
        }
    }
}

fn verify_identity(
    collection: &rsigma_parser::SigmaCollection,
    groups: &[NormalizedGroup],
    retained: &BTreeSet<usize>,
    slots: &[Slot],
) -> Result<Option<(usize, usize)>, CorrelationDraftError> {
    for (group_index, group) in groups.iter().enumerate() {
        for (event_index, event) in group
            .events
            .iter()
            .enumerate()
            .filter(|(_, event)| retained.contains(&event.cluster))
        {
            let assigned = slots
                .iter()
                .position(|slot| slot.cluster == event.cluster)
                .expect("retained cluster has a slot");
            let local_event = slots[assigned]
                .members
                .iter()
                .position(|member| *member == (group_index, event_index))
                .expect("slot member exists");
            let mut engine = CorrelationEngine::new(CorrelationConfig::default());
            engine
                .add_collection(collection)
                .map_err(|error| CorrelationDraftError::Internal {
                    stage: "compile",
                    message: error.to_string(),
                })?;
            let json = JsonEvent::borrow(&event.event);
            let results = engine.process_event_at(&json, 1_700_000_000);
            let matched: BTreeSet<&str> = results
                .iter()
                .filter(|result| result.is_detection())
                .filter_map(|result| result.header.rule_id.as_deref())
                .collect();
            let assigned_id = slots[assigned].id.as_deref();
            if assigned_id.is_none_or(|id| !matched.contains(id)) {
                return Ok(Some((assigned, local_event)));
            }
            let colliding: Vec<String> = slots
                .iter()
                .enumerate()
                .filter(|(index, slot)| {
                    *index != assigned && slot.id.as_deref().is_some_and(|id| matched.contains(id))
                })
                .map(|(_, slot)| slot.name.clone())
                .collect();
            if !colliding.is_empty() {
                let mut forms = selected_forms(&slots[assigned]);
                for slot in slots.iter().filter(|slot| colliding.contains(&slot.name)) {
                    forms.extend(selected_forms(slot));
                }
                return Err(CorrelationDraftError::CrossSlotMatch {
                    group: group.id.clone(),
                    event: event_index,
                    assigned: slots[assigned].name.clone(),
                    colliding,
                    forms,
                });
            }
        }
    }
    Ok(None)
}

fn selected_forms(slot: &Slot) -> Vec<String> {
    slot.candidate
        .selected
        .iter()
        .map(|&index| {
            let profile = &slot.candidate.profiles[index];
            format!(
                "{}={:?}",
                profile.field(),
                profile.form.as_ref().expect("selected form")
            )
        })
        .collect()
}

fn verify_groups(
    collection: &rsigma_parser::SigmaCollection,
    groups: &[NormalizedGroup],
    retained: &BTreeSet<usize>,
    correlation_id: &str,
    negative: bool,
) -> Result<Vec<CorrelationVerification>, CorrelationDraftError> {
    let mut rows = Vec::with_capacity(groups.len());
    let mut failed_negatives = Vec::new();
    for group in groups {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine
            .add_collection(collection)
            .map_err(|error| CorrelationDraftError::Internal {
                stage: "compile",
                message: error.to_string(),
            })?;
        let retained_events: Vec<&NormalizedEvent> = group
            .events
            .iter()
            .filter(|event| retained.contains(&event.cluster))
            .collect();
        let first = retained_events.first().map(|event| event.time).unwrap_or(0);
        let mut fired = false;
        for (index, event) in retained_events.iter().enumerate() {
            let json = JsonEvent::borrow(&event.event);
            let timestamp = 1_700_000_000i64
                .checked_add(event.time - first)
                .ok_or(CorrelationDraftError::WindowOverflow)?;
            let target = engine
                .process_event_at(&json, timestamp)
                .iter()
                .any(|result| {
                    result.is_correlation()
                        && result.header.rule_id.as_deref() == Some(correlation_id)
                });
            if target {
                fired = true;
                if !negative && index + 1 < retained_events.len() {
                    return Err(CorrelationDraftError::PositiveVerification {
                        group: group.id.clone(),
                        reason: format!("fired prematurely at retained event {index}"),
                    });
                }
            }
        }
        if negative && fired {
            failed_negatives.push(group.id.clone());
        } else if !negative && !fired {
            return Err(CorrelationDraftError::PositiveVerification {
                group: group.id.clone(),
                reason: "did not fire by the end of the group".to_string(),
            });
        }
        rows.push(CorrelationVerification {
            group: group.id.clone(),
            negative,
            fired,
        });
    }
    if !failed_negatives.is_empty() {
        return Err(CorrelationDraftError::NegativeGroupMatched {
            groups: failed_negatives,
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn timed(offset: Option<&str>, timestamp: Option<&str>, event: Value) -> TimedEvent {
        TimedEvent {
            timestamp: timestamp.map(str::to_string),
            offset: offset.map(str::to_string),
            event,
            source: SourceLocation::default(),
        }
    }

    fn group(id: &str, user: &str, reversed: bool) -> GroupedExemplar {
        let first = timed(
            Some(if reversed { "20s" } else { "0s" }),
            None,
            json!({"kind": "reset", "user": user, "factor": "totp", "reset_reason": "recovery"}),
        );
        let second = timed(
            Some(if reversed { "0s" } else { "20s" }),
            None,
            json!({"kind": "session", "user": user, "new_asn": true, "asn": 64512, "session_type": "web"}),
        );
        GroupedExemplar {
            id: id.to_string(),
            events: vec![first, second],
        }
    }

    fn groups() -> Vec<GroupedExemplar> {
        vec![
            group("g1", "alice", false),
            group("g2", "bob", false),
            group("g3", "carol", false),
        ]
    }

    fn config() -> CorrelationDraftConfig {
        CorrelationDraftConfig {
            correlation_id: Some("00000000-0000-4000-8000-000000000003".to_string()),
            slot_ids: vec![
                "00000000-0000-4000-8000-000000000001".to_string(),
                "00000000-0000-4000-8000-000000000002".to_string(),
            ],
            detection: DraftConfig {
                date: Some("2026-09-04".to_string()),
                min_fields: 1,
                ..DraftConfig::default()
            },
            ..CorrelationDraftConfig::default()
        }
    }

    #[test]
    fn validates_and_sorts_timestamp_groups() {
        let mut values = groups();
        for (index, group) in values.iter_mut().enumerate() {
            group.events[0].offset = None;
            group.events[0].timestamp = Some(format!("2026-01-01T00:00:{:02}Z", 20 + index));
            group.events[1].offset = None;
            group.events[1].timestamp = Some(format!("2026-01-01T00:00:{index:02}Z"));
        }
        let normalized = normalize_groups(&values, 3).unwrap();
        assert!(
            normalized
                .iter()
                .all(|group| group.events[0].time < group.events[1].time)
        );
    }

    #[test]
    fn validates_offset_groups() {
        let normalized = normalize_groups(&groups(), 3).unwrap();
        assert_eq!(normalized[0].events[0].time, 0);
        assert_eq!(normalized[0].events[1].time, 20);
    }

    #[test]
    fn rejects_mixed_neither_both_invalid_and_duplicate_times() {
        let mut mixed = groups();
        mixed[0].events[1].offset = None;
        mixed[0].events[1].timestamp = Some("2026-01-01T00:00:00Z".to_string());
        assert!(matches!(
            normalize_groups(&mixed, 3),
            Err(CorrelationDraftError::MixedTimeMode { .. })
        ));

        let mut neither = groups();
        neither[0].events[0].offset = None;
        assert!(matches!(
            normalize_groups(&neither, 3),
            Err(CorrelationDraftError::InvalidTimeKeys { .. })
        ));

        let mut both = groups();
        both[0].events[0].timestamp = Some("2026-01-01T00:00:00Z".to_string());
        assert!(matches!(
            normalize_groups(&both, 3),
            Err(CorrelationDraftError::InvalidTimeKeys { .. })
        ));

        let mut invalid = groups();
        invalid[0].events[0].offset = Some("bad".to_string());
        assert!(matches!(
            normalize_groups(&invalid, 3),
            Err(CorrelationDraftError::InvalidTime { .. })
        ));

        let mut duplicate = groups();
        duplicate[0].events[1].offset = Some("0s".to_string());
        assert!(matches!(
            normalize_groups(&duplicate, 3),
            Err(CorrelationDraftError::DuplicateTime { .. })
        ));
    }

    #[test]
    fn rejects_too_few_groups_and_events() {
        assert!(matches!(
            normalize_groups(&groups()[..2], 3),
            Err(CorrelationDraftError::TooFewGroups { .. })
        ));
        let mut values = groups();
        values[0].events.pop();
        assert!(matches!(
            normalize_groups(&values, 3),
            Err(CorrelationDraftError::TooFewEvents { .. })
        ));
    }

    #[test]
    fn drafts_ordered_collection_deterministically() {
        let first = draft_correlation(&groups(), &[], &[], &config()).unwrap();
        let second = draft_correlation(&groups(), &[], &[], &config()).unwrap();
        assert_eq!(first.rule_yaml, second.rule_yaml);
        assert_eq!(
            first.rule_yaml,
            include_str!("golden/correlation_ordered.yaml")
        );
        assert_eq!(first.correlation_type, "temporal_ordered");
        assert_eq!(first.group_by, vec!["user"]);
        assert!(first.rule_yaml.contains("rsigma.exemplars:"));
        assert!(rsigma_parser::parse_sigma_yaml(&first.rule_yaml).is_ok());
        assert!(first.verification.iter().all(|row| row.fired));
    }

    #[test]
    fn unordered_collection_matches_golden() {
        let mut cfg = config();
        cfg.correlation_type = CorrelationDraftType::Temporal;
        let report = draft_correlation(&groups(), &[], &[], &cfg).unwrap();
        assert_eq!(
            report.rule_yaml,
            include_str!("golden/correlation_unordered.yaml")
        );
    }

    #[test]
    fn auto_downgrades_order_inversions_and_forced_order_errors() {
        let mut values = groups();
        values[2] = group("g3", "carol", true);
        let report = draft_correlation(&values, &[], &[], &config()).unwrap();
        assert_eq!(report.correlation_type, "temporal");
        assert!(report.warnings.iter().any(|warning| warning.contains("g3")));

        let mut forced = config();
        forced.correlation_type = CorrelationDraftType::TemporalOrdered;
        assert!(matches!(
            draft_correlation(&values, &[], &[], &forced),
            Err(CorrelationDraftError::OrderInversion { .. })
        ));
    }

    #[test]
    fn window_uses_maximum_span_and_never_rounds_down() {
        let mut values = groups();
        values[1].events[1].offset = Some("61s".to_string());
        let report = draft_correlation(&values, &[], &[], &config()).unwrap();
        assert_eq!(report.span_seconds, vec![20, 61, 20]);
        assert_eq!(report.timespan, "5m");
        assert!(matches!(
            infer_window(
                &normalize_groups(&groups(), 3).unwrap(),
                &BTreeSet::new(),
                0.9
            ),
            Err(CorrelationDraftError::InvalidWindowMargin(_))
        ));
        assert_eq!(round_window(86_401).unwrap(), "2d");
    }

    #[test]
    fn explicit_composite_entity_is_excluded_from_slots() {
        let mut values = groups();
        for group in &mut values {
            let tenant = format!("tenant-{}", group.id);
            for event in &mut group.events {
                event.event["tenant"] = json!(tenant);
            }
        }
        let mut cfg = config();
        cfg.group_by = vec!["user".to_string(), "tenant".to_string()];
        let report = draft_correlation(&values, &[], &[], &cfg).unwrap();
        assert_eq!(report.group_by, cfg.group_by);
        assert!(
            report
                .slots
                .iter()
                .flat_map(|slot| &slot.selected_fields)
                .all(|field| !field.starts_with("user=") && !field.starts_with("tenant="))
        );
    }

    #[test]
    fn rejects_ambiguous_entity_and_negative_matches() {
        let mut ambiguous = groups();
        for group in &mut ambiguous {
            let tenant = format!("tenant-{}", group.id);
            for event in &mut group.events {
                event.event["tenant"] = json!(tenant);
            }
        }
        match draft_correlation(&ambiguous, &[], &[], &config()) {
            Err(CorrelationDraftError::AmbiguousEntity { candidates }) => {
                assert_eq!(candidates, vec!["tenant", "user"]);
            }
            other => panic!("expected deterministic entity ambiguity, got {other:?}"),
        }
        assert!(matches!(
            draft_correlation(&groups(), &[group("bad", "mallory", false)], &[], &config()),
            Err(CorrelationDraftError::NegativeGroupMatched { .. })
        ));
    }

    #[test]
    fn entity_inference_refuses_to_guess_when_no_field_is_group_stable() {
        let mut values = groups();
        for group in &mut values {
            group.events[1].event["user"] = json!(format!("{}-other", group.id));
        }
        assert!(matches!(
            draft_correlation(&values, &[], &[], &config()),
            Err(CorrelationDraftError::AmbiguousEntity { candidates }) if candidates.is_empty()
        ));
    }

    #[test]
    fn verification_ignores_unrelated_correlation_results() {
        let report = draft_correlation(&groups(), &[], &[], &config()).unwrap();
        let collection = rsigma_parser::parse_sigma_yaml(&report.rule_yaml).unwrap();
        let mut normalized = normalize_groups(&groups(), 3).unwrap();
        assign_clusters(&mut normalized, 0.6);
        let (retained, _) = retained_clusters(&normalized, 2).unwrap();
        assert!(matches!(
            verify_groups(
                &collection,
                &normalized,
                &retained,
                "unrelated-correlation",
                false
            ),
            Err(CorrelationDraftError::PositiveVerification { .. })
        ));
    }

    #[test]
    fn verification_rejects_premature_target_firing() {
        let report = draft_correlation(&groups(), &[], &[], &config()).unwrap();
        let yaml = report
            .rule_yaml
            .replace(
                "        - slot_totp\n        - slot_64512\n",
                "        - slot_totp\n",
            )
            .replace("        gte: 2\n", "        gte: 1\n");
        let collection = rsigma_parser::parse_sigma_yaml(&yaml).unwrap();
        let mut normalized = normalize_groups(&groups(), 3).unwrap();
        assign_clusters(&mut normalized, 0.6);
        let (retained, _) = retained_clusters(&normalized, 2).unwrap();
        assert!(matches!(
            verify_groups(
                &collection,
                &normalized,
                &retained,
                "00000000-0000-4000-8000-000000000003",
                false
            ),
            Err(CorrelationDraftError::PositiveVerification { reason, .. })
                if reason.contains("prematurely")
        ));
    }
}
