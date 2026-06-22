//! The visibility join and scoring heuristic.
//!
//! [`analyze`] joins three sets in one pass: the rule logsource inventory and
//! rule field set (from `--rules`), the observed field signal (from
//! `--observed`), and the mapping table. It produces a [`VisibilityAnalysis`]
//! that the DeTT&CT emitters, the Navigator layer, and the human report all
//! render from, so those surfaces cannot drift on the scoring.

use std::collections::{BTreeMap, BTreeSet};

use rsigma_eval::RuleFieldSet;
use rsigma_parser::{LogSource, SigmaCollection};

use super::mapping::{MappingTable, entry_products};

/// The observed field signal, parsed from the `--observed` JSON (or empty when
/// the flag is omitted).
#[derive(Debug, Default)]
pub(crate) struct Observed {
    /// Whether `--observed` (or `--addr`) supplied a signal at all.
    pub present: bool,
    /// Rule field names that were referenced but never observed.
    pub missing: BTreeSet<String>,
    /// Observed field names not referenced by any rule, with their counts.
    pub unknown: Vec<ObservedField>,
    /// Total events the observer saw.
    pub events_observed: u64,
    /// Distinct field keys observed.
    pub unique_keys: usize,
}

impl Observed {
    /// A rule field is observed when a signal is present and the field is not
    /// in the broken-coverage `missing` set. With no signal nothing is
    /// observed, which yields the "what would full visibility look like"
    /// baseline.
    fn is_observed(&self, field: &str) -> bool {
        self.present && !self.missing.contains(field)
    }
}

/// A single observed field name and its event count.
#[derive(Debug, Clone)]
pub(crate) struct ObservedField {
    pub field: String,
    pub count: u64,
}

/// Per-data-source visibility, the spine of every output.
#[derive(Debug, Clone)]
pub(crate) struct DataSourceVisibility {
    pub data_source: String,
    /// DeTT&CT 0-to-4 visibility score (none/minimal/medium/good/excellent).
    pub score: u8,
    pub data_components: Vec<String>,
    pub products: Vec<String>,
    pub logsources: Vec<String>,
    pub mapped_fields: Vec<String>,
    pub observed_fields: Vec<String>,
    /// True when the source has mapped rule fields but none were observed.
    pub blind_spot: bool,
}

impl DataSourceVisibility {
    /// True once at least one mapped field was observed.
    pub(crate) fn available(&self) -> bool {
        !self.observed_fields.is_empty()
    }
}

/// Per-technique rolled-up visibility (the max over contributing data sources).
#[derive(Debug, Clone)]
pub(crate) struct TechniqueVisibility {
    pub technique_id: String,
    pub score: u8,
    pub data_sources: Vec<String>,
}

/// An observed data source that no rule consumes (the inverse of a blind spot).
#[derive(Debug, Clone)]
pub(crate) struct UntappedSource {
    pub data_source: String,
    pub observed_fields: Vec<ObservedField>,
}

/// The complete visibility picture rendered by every output surface.
#[derive(Debug, Clone)]
pub(crate) struct VisibilityAnalysis {
    pub data_sources: Vec<DataSourceVisibility>,
    pub techniques: Vec<TechniqueVisibility>,
    pub untapped: Vec<UntappedSource>,
    pub unmapped_logsources: Vec<String>,
    pub rules_total: usize,
    pub logsources_total: usize,
    pub events_observed: u64,
    pub observed_unique_keys: usize,
    pub has_observed: bool,
}

impl VisibilityAnalysis {
    /// Rule-expected data sources whose mapped fields are all unobserved.
    pub(crate) fn blind_spots(&self) -> Vec<&DataSourceVisibility> {
        self.data_sources.iter().filter(|d| d.blind_spot).collect()
    }
}

/// Per-data-source accumulator used during the join.
#[derive(Default)]
struct Agg {
    components: BTreeSet<String>,
    products: BTreeSet<String>,
    logsources: BTreeSet<String>,
    mapped_fields: BTreeSet<String>,
    observed_fields: BTreeSet<String>,
}

/// Map an `(observed, mapped)` field tally to the DeTT&CT 0-to-4 scale.
///
/// The heuristic is deliberately conservative (DeTT&CT files are analyst
/// tuned): all-observed scores 4, all-unobserved scores 0, and the band
/// between is split into minimal/medium/good. A data source with no mapped
/// fields has no field signal and scores 0.
pub(crate) fn score_fraction(observed: usize, mapped: usize) -> u8 {
    if mapped == 0 {
        return 0;
    }
    let frac = observed as f64 / mapped as f64;
    if frac <= 0.0 {
        0
    } else if frac >= 1.0 {
        4
    } else if frac <= 0.25 {
        1
    } else if frac <= 0.5 {
        2
    } else {
        3
    }
}

/// The DeTT&CT visibility level name for a 0-to-4 score.
pub(crate) fn level_name(score: u8) -> &'static str {
    match score {
        0 => "none",
        1 => "minimal",
        2 => "medium",
        3 => "good",
        _ => "excellent",
    }
}

/// Compact display form of a logsource: the present `category/product/service`
/// parts joined with `/`. Returns `None` for an empty logsource.
fn logsource_display(ls: &LogSource) -> Option<String> {
    let parts: Vec<&str> = [&ls.category, &ls.product, &ls.service]
        .into_iter()
        .filter_map(|p| p.as_deref())
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

/// Join the rule inventory, the observed signal, and the mapping table.
pub(crate) fn analyze(
    collection: &SigmaCollection,
    rule_field_set: &RuleFieldSet,
    observed: &Observed,
    mapping: &MappingTable,
) -> VisibilityAnalysis {
    let mut sources: BTreeMap<String, Agg> = BTreeMap::new();
    let mut logsources_seen: BTreeSet<String> = BTreeSet::new();
    let mut unmapped: BTreeSet<String> = BTreeSet::new();

    // Logsource inventory: each rule logsource resolves to the data sources it
    // expects to receive.
    for rule in &collection.rules {
        let Some(display) = logsource_display(&rule.logsource) else {
            continue;
        };
        logsources_seen.insert(display.clone());
        let matches = mapping.logsource_matches(&rule.logsource);
        if matches.is_empty() {
            unmapped.insert(display.clone());
            continue;
        }
        for entry in matches {
            let agg = sources.entry(entry.data_source.clone()).or_default();
            agg.components.insert(entry.data_component.clone());
            agg.products.extend(entry_products(&rule.logsource, entry));
            agg.logsources.insert(display.clone());
        }
    }

    // Field attribution: every rule field that maps to a data component scores
    // its data source, whether or not a logsource reached that source.
    for (field, _origin) in rule_field_set.iter() {
        let Some(component) = mapping.field_component(field) else {
            continue;
        };
        let Some(ds) = mapping.component_source(component) else {
            continue;
        };
        let agg = sources.entry(ds.to_string()).or_default();
        agg.components.insert(component.to_string());
        agg.mapped_fields.insert(field.to_string());
        if observed.is_observed(field) {
            agg.observed_fields.insert(field.to_string());
        }
    }

    // Finalize per-source scores.
    let mut data_sources: Vec<DataSourceVisibility> = sources
        .into_iter()
        .map(|(name, agg)| {
            let score = score_fraction(agg.observed_fields.len(), agg.mapped_fields.len());
            let blind_spot = !agg.mapped_fields.is_empty() && agg.observed_fields.is_empty();
            DataSourceVisibility {
                data_source: name,
                score,
                data_components: agg.components.into_iter().collect(),
                products: agg.products.into_iter().collect(),
                logsources: agg.logsources.into_iter().collect(),
                mapped_fields: agg.mapped_fields.into_iter().collect(),
                observed_fields: agg.observed_fields.into_iter().collect(),
                blind_spot,
            }
        })
        .collect();
    data_sources.sort_by(|a, b| a.data_source.cmp(&b.data_source));

    let expected: BTreeSet<&str> = data_sources
        .iter()
        .map(|d| d.data_source.as_str())
        .collect();

    // Technique rollup: a technique's visibility is the best (max) score among
    // the data sources whose components inform it.
    let mut tech: BTreeMap<String, (u8, BTreeSet<String>)> = BTreeMap::new();
    for ds in &data_sources {
        for component in &ds.data_components {
            for technique in mapping.component_techniques(component) {
                let entry = tech
                    .entry(technique.clone())
                    .or_insert((0, BTreeSet::new()));
                entry.0 = entry.0.max(ds.score);
                entry.1.insert(ds.data_source.clone());
            }
        }
    }
    let techniques: Vec<TechniqueVisibility> = tech
        .into_iter()
        .map(|(technique_id, (score, ds))| TechniqueVisibility {
            technique_id,
            score,
            data_sources: ds.into_iter().collect(),
        })
        .collect();

    // Untapped: observed, unreferenced fields whose data source no rule
    // consumes -- telemetry you receive but write no rule against.
    let mut untapped_map: BTreeMap<String, Vec<ObservedField>> = BTreeMap::new();
    for uf in &observed.unknown {
        let Some(component) = mapping.field_component(&uf.field) else {
            continue;
        };
        let Some(ds) = mapping.component_source(component) else {
            continue;
        };
        if expected.contains(ds) {
            continue;
        }
        untapped_map
            .entry(ds.to_string())
            .or_default()
            .push(uf.clone());
    }
    let untapped: Vec<UntappedSource> = untapped_map
        .into_iter()
        .map(|(data_source, mut fields)| {
            fields.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.field.cmp(&b.field)));
            UntappedSource {
                data_source,
                observed_fields: fields,
            }
        })
        .collect();

    VisibilityAnalysis {
        data_sources,
        techniques,
        untapped,
        unmapped_logsources: unmapped.into_iter().collect(),
        rules_total: collection.rules.len(),
        logsources_total: logsources_seen.len(),
        events_observed: observed.events_observed,
        observed_unique_keys: observed.unique_keys,
        has_observed: observed.present,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analysis(yaml: &str, observed: Observed) -> VisibilityAnalysis {
        let collection = rsigma_parser::parse_sigma_yaml(yaml).expect("rules parse");
        let rfs = RuleFieldSet::collect(&collection, &[], true);
        let mapping = MappingTable::bundled();
        analyze(&collection, &rfs, &observed, &mapping)
    }

    const RULE: &str = r#"
title: Suspicious Process
id: 00000000-0000-0000-0000-0000000000a1
logsource: {category: process_creation, product: windows}
detection:
    sel:
        Image|endswith: '\evil.exe'
        CommandLine|contains: '--steal'
    condition: sel
"#;

    #[test]
    fn score_fraction_boundaries() {
        assert_eq!(score_fraction(0, 0), 0);
        assert_eq!(score_fraction(0, 4), 0);
        assert_eq!(score_fraction(1, 4), 1);
        assert_eq!(score_fraction(2, 4), 2);
        assert_eq!(score_fraction(3, 4), 3);
        assert_eq!(score_fraction(4, 4), 4);
        // Single mapped field, observed -> full visibility.
        assert_eq!(score_fraction(1, 1), 4);
    }

    #[test]
    fn no_observed_is_baseline_all_zero() {
        let a = analysis(RULE, Observed::default());
        let process = a
            .data_sources
            .iter()
            .find(|d| d.data_source == "Process")
            .expect("Process data source expected");
        assert_eq!(process.score, 0);
        assert!(process.blind_spot, "no observation => blind spot");
        assert!(!process.available());
        assert!(!a.has_observed);
    }

    #[test]
    fn all_fields_observed_scores_excellent() {
        // Observed signal present, nothing missing => every mapped field seen.
        let observed = Observed {
            present: true,
            missing: BTreeSet::new(),
            unknown: Vec::new(),
            events_observed: 100,
            unique_keys: 2,
        };
        let a = analysis(RULE, observed);
        let process = a
            .data_sources
            .iter()
            .find(|d| d.data_source == "Process")
            .unwrap();
        assert_eq!(process.score, 4);
        assert!(!process.blind_spot);
        assert!(process.available());
    }

    #[test]
    fn partial_observation_is_a_blind_spot_only_when_all_missing() {
        // CommandLine observed, Image missing => 1 of 2 mapped fields => score 2.
        let observed = Observed {
            present: true,
            missing: BTreeSet::from(["Image".to_string()]),
            unknown: Vec::new(),
            events_observed: 10,
            unique_keys: 1,
        };
        let a = analysis(RULE, observed);
        let process = a
            .data_sources
            .iter()
            .find(|d| d.data_source == "Process")
            .unwrap();
        assert_eq!(process.score, 2);
        assert!(!process.blind_spot);
    }

    #[test]
    fn unmapped_logsource_is_surfaced() {
        let yaml = r#"
title: Odd
id: 00000000-0000-0000-0000-0000000000b1
logsource: {category: totally_unknown_thing}
detection: {sel: {Foo: bar}, condition: sel}
"#;
        let a = analysis(yaml, Observed::default());
        assert!(
            a.unmapped_logsources
                .contains(&"totally_unknown_thing".to_string())
        );
    }

    #[test]
    fn techniques_roll_up_from_data_sources() {
        let observed = Observed {
            present: true,
            missing: BTreeSet::new(),
            unknown: Vec::new(),
            events_observed: 5,
            unique_keys: 2,
        };
        let a = analysis(RULE, observed);
        // Process Creation informs T1059; with full observation the technique
        // visibility rolls up to 4.
        let t = a
            .techniques
            .iter()
            .find(|t| t.technique_id == "T1059")
            .expect("T1059 reachable via Process Creation");
        assert_eq!(t.score, 4);
        assert!(t.data_sources.contains(&"Process".to_string()));
    }

    #[test]
    fn untapped_source_when_observed_but_unreferenced() {
        // A rule only on Process; an observed (unknown) registry field that no
        // rule references surfaces Windows Registry as untapped.
        let observed = Observed {
            present: true,
            missing: BTreeSet::new(),
            unknown: vec![ObservedField {
                field: "TargetObject".to_string(),
                count: 42,
            }],
            events_observed: 50,
            unique_keys: 3,
        };
        let a = analysis(RULE, observed);
        let untapped = a
            .untapped
            .iter()
            .find(|u| u.data_source == "Windows Registry")
            .expect("Windows Registry is untapped");
        assert_eq!(untapped.observed_fields[0].field, "TargetObject");
    }
}
