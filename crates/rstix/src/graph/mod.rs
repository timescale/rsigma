//! STIX property graph construction and traversal.

mod edge;
mod error;
mod expander;
mod traversal;

pub use edge::{Edge, EdgePredicate, PredicateFn, SroEdgePayload};
pub use error::GraphError;
pub use expander::{
    AttackPatternSummary, CampaignSummary, CoaSummary, ExpansionResult, IdentitySummary,
    IndicatorSummary, InfrastructureSummary, MalwareSummary, RelationshipExpander,
    ThreatActorSummary, VulnerabilitySummary,
};
pub use traversal::{EdgeTraversal, TraversalBuilder};

use std::collections::HashMap;

use crate::core::QueryableStixObject;
use crate::core::StixId;
use crate::model::ref_paths::collect_ref_paths;
use crate::model::sro::SroObject;
use crate::model::{Bundle, StixObject};

use edge::{InlinedEdgeStorage, SroEdgeStorage};

/// A typed property graph built from a STIX bundle.
///
/// All node and edge references are zero-copy borrows into the source [`Bundle`].
pub struct StixGraph<'b> {
    nodes: HashMap<&'b StixId, &'b StixObject>,
    sro_edges: Vec<SroEdgeStorage<'b>>,
    ref_edges: Vec<InlinedEdgeStorage<'b>>,
    out_sro: HashMap<&'b str, Vec<usize>>,
    in_sro: HashMap<&'b str, Vec<usize>>,
    out_refs: HashMap<&'b str, Vec<usize>>,
    in_refs: HashMap<String, Vec<usize>>,
}

impl<'b> StixGraph<'b> {
    /// Build a graph from `bundle`, indexing SRO edges and inlined `_ref` / `_refs` properties.
    pub fn from_bundle(bundle: &'b Bundle) -> Result<Self, GraphError> {
        let mut graph = Self {
            nodes: HashMap::new(),
            sro_edges: Vec::new(),
            ref_edges: Vec::new(),
            out_sro: HashMap::new(),
            in_sro: HashMap::new(),
            out_refs: HashMap::new(),
            in_refs: HashMap::new(),
        };

        for object in bundle.objects() {
            let id = object.id();
            if graph.nodes.insert(id, object).is_some() {
                return Err(GraphError::DuplicateObjectId(id.as_str().to_owned()));
            }
        }

        for object in bundle.objects() {
            match object {
                StixObject::Sro(SroObject::Relationship(relationship)) => {
                    let source_key = relationship.source_ref.as_str();
                    let target_key = relationship.target_ref.as_str();
                    let index = graph.sro_edges.len();
                    graph.sro_edges.push(SroEdgeStorage::Relationship {
                        source_id: &relationship.source_ref,
                        target_id: &relationship.target_ref,
                        relationship,
                    });
                    graph.out_sro.entry(source_key).or_default().push(index);
                    graph.in_sro.entry(target_key).or_default().push(index);
                }
                StixObject::Sro(SroObject::Sighting(sighting)) => {
                    let source_id = sighting.id();
                    let source_key = source_id.as_str();
                    let target_key = sighting.sighting_of_ref.as_str();
                    let index = graph.sro_edges.len();
                    graph.sro_edges.push(SroEdgeStorage::Sighting {
                        source_id,
                        target_id: &sighting.sighting_of_ref,
                        sighting,
                    });
                    graph.out_sro.entry(source_key).or_default().push(index);
                    graph.in_sro.entry(target_key).or_default().push(index);
                }
                _ => {}
            }

            let source_id = object.id();
            let mut ref_paths = Vec::new();
            collect_ref_paths(object, &mut ref_paths);
            for (property_path, target_id) in ref_paths {
                let index = graph.ref_edges.len();
                graph.ref_edges.push(InlinedEdgeStorage {
                    source_id,
                    property_path,
                    target_id: target_id.clone(),
                });
                graph
                    .out_refs
                    .entry(source_id.as_str())
                    .or_default()
                    .push(index);
                graph
                    .in_refs
                    .entry(target_id.as_str().to_owned())
                    .or_default()
                    .push(index);
            }
        }

        Ok(graph)
    }

    /// Begin a traversal from `id`.
    pub fn from(&self, id: &StixId) -> TraversalBuilder<'_> {
        TraversalBuilder::new(self, id)
    }

    /// All dangling references: `(source_id, property_path, missing_target_id)`.
    ///
    /// Scans inlined `_ref`/`_refs` edges and SRO endpoints missing from the bundle.
    pub fn unresolved_references(&self) -> impl Iterator<Item = (&StixId, &str, &StixId)> + '_ {
        let mut seen = std::collections::HashSet::new();
        self.ref_edges
            .iter()
            .filter_map(|edge| {
                if self.nodes.contains_key(&edge.target_id) {
                    None
                } else {
                    Some((edge.source_id, edge.property_path.as_str(), &edge.target_id))
                }
            })
            .chain(self.sro_edges.iter().flat_map(|edge| {
                let (source_id, target_id, path) = match edge {
                    SroEdgeStorage::Relationship {
                        source_id,
                        target_id,
                        ..
                    } => (*source_id, *target_id, "target_ref"),
                    SroEdgeStorage::Sighting {
                        source_id,
                        target_id,
                        ..
                    } => (*source_id, *target_id, "sighting_of_ref"),
                };
                if self.nodes.contains_key(target_id) {
                    None
                } else {
                    Some((source_id, path, target_id))
                }
            }))
            .filter(move |(source, path, target)| {
                seen.insert((source.as_str(), *path, target.as_str()))
            })
    }

    /// Number of indexed bundle nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of indexed SRO relationship edges.
    pub fn sro_edge_count(&self) -> usize {
        self.sro_edges.len()
    }

    /// Number of indexed inlined reference edges.
    pub fn ref_edge_count(&self) -> usize {
        self.ref_edges.len()
    }
}

#[cfg(test)]
mod from_bundle {
    use super::*;
    use crate::parse_bundle;

    #[test]
    fn indexes_sro_and_ref_edges() {
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/validation/bundle-relationship-matrix-invalid.json"
        ))
        .expect("parse bundle");
        let graph = StixGraph::from_bundle(&bundle).expect("graph");
        assert_eq!(graph.node_count(), 3);
        assert_eq!(graph.sro_edge_count(), 1);
        assert!(graph.ref_edge_count() >= 2);
    }

    #[test]
    fn indexes_sighting_sro_edge() {
        let json = r#"{
          "type": "bundle",
          "id": "bundle--00000000-0000-0000-0000-000000000099",
          "objects": [
            {
              "type": "indicator",
              "spec_version": "2.1",
              "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
              "created": "2016-05-12T08:17:27.000Z",
              "modified": "2016-05-12T08:17:27.000Z",
              "pattern": "[file:hashes.MD5 = '644bf17e482f443f763b0b7355b14372']",
              "pattern_type": "stix",
              "valid_from": "2016-05-12T08:17:27.000Z"
            },
            {
              "type": "sighting",
              "spec_version": "2.1",
              "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
              "created": "2016-04-06T20:08:31.000Z",
              "modified": "2016-04-06T20:08:31.000Z",
              "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
            }
          ]
        }"#;
        let bundle = parse_bundle(json).expect("parse");
        let graph = StixGraph::from_bundle(&bundle).expect("graph");
        assert_eq!(graph.sro_edge_count(), 1);
        let sighting_id = "sighting--ee20065d-2555-424f-ad9e-0f8428623c75"
            .parse()
            .expect("id");
        let edges: Vec<_> = graph
            .from(&sighting_id)
            .out_edges_matching(EdgePredicate::Type("sighting"))
            .into_iter()
            .collect();
        assert_eq!(edges.len(), 1);
        assert!(edges[0].sighting().is_some());
    }
}

#[cfg(test)]
mod traversal_tests {
    use super::*;
    use crate::model::cast::BundleObjectCast;
    use crate::model::sdo::Malware;
    use crate::parse_bundle;

    #[test]
    fn out_edges_matching_returns_relationship_targets() {
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/validation/bundle-relationship-matrix-invalid.json"
        ))
        .expect("parse bundle");
        let graph = StixGraph::from_bundle(&bundle).expect("graph");
        let malware_id = bundle
            .objects()
            .iter()
            .find_map(|object| Malware::cast_from(object).map(|malware| malware.id().clone()))
            .expect("malware");

        let targets: Vec<_> = graph
            .from(&malware_id)
            .out_edges_matching(EdgePredicate::Type("uses"))
            .targets()
            .collect();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].type_name(), "identity");
    }

    #[test]
    fn targets_as_skips_non_matching_types() {
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/validation/bundle-relationship-matrix-invalid.json"
        ))
        .expect("parse bundle");
        let graph = StixGraph::from_bundle(&bundle).expect("graph");
        let malware_id = bundle
            .objects()
            .iter()
            .find_map(|object| Malware::cast_from(object).map(|malware| malware.id().clone()))
            .expect("malware");

        let malware_targets: Vec<_> = graph
            .from(&malware_id)
            .out_edges_matching(EdgePredicate::Type("uses"))
            .targets_as::<Malware>()
            .collect();
        assert!(malware_targets.is_empty());

        let identity_targets: Vec<_> = graph
            .from(&malware_id)
            .out_edges_matching(EdgePredicate::Type("uses"))
            .targets_as::<crate::model::sdo::Identity>()
            .collect();
        assert_eq!(identity_targets.len(), 1);
    }
}

#[cfg(test)]
mod predicates {
    use super::*;
    use crate::core::Confidence;
    use crate::model::cast::BundleObjectCast;
    use crate::model::sdo::Malware;
    use crate::parse_bundle;

    #[test]
    fn compound_and_filters_edges() {
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/validation/bundle-relationship-matrix-invalid.json"
        ))
        .expect("parse bundle");
        let graph = StixGraph::from_bundle(&bundle).expect("graph");
        let malware_id = bundle
            .objects()
            .iter()
            .find_map(|object| Malware::cast_from(object).map(|malware| malware.id().clone()))
            .expect("malware");

        let pred = EdgePredicate::And(
            Box::new(EdgePredicate::Type("uses")),
            Box::new(EdgePredicate::Custom(Box::new(|edge: &Edge<'_>| {
                edge.relationship().is_none_or(|relationship| {
                    relationship
                        .common
                        .confidence
                        .is_none_or(|confidence| confidence.get() > 70)
                })
            }))),
        );

        let edges: Vec<_> = graph
            .from(&malware_id)
            .out_edges_matching(pred)
            .into_iter()
            .collect();
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn custom_predicate_reads_relationship_confidence() {
        let json = r#"{
          "type": "bundle",
          "id": "bundle--00000000-0000-0000-0000-000000000003",
          "objects": [
            {
              "type": "malware",
              "spec_version": "2.1",
              "id": "malware--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
              "created": "2016-05-12T08:17:27.000Z",
              "modified": "2016-05-12T08:17:27.000Z",
              "name": "test-malware",
              "is_family": false
            },
            {
              "type": "identity",
              "spec_version": "2.1",
              "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
              "created": "2016-04-06T20:03:00.000Z",
              "modified": "2016-04-06T20:03:00.000Z",
              "name": "John Smith"
            },
            {
              "type": "relationship",
              "spec_version": "2.1",
              "id": "relationship--a2216352-483a-4941-842c-5328ad08abfd",
              "created": "2016-05-12T08:17:27.000Z",
              "modified": "2016-05-12T08:17:27.000Z",
              "relationship_type": "uses",
              "confidence": 85,
              "source_ref": "malware--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
              "target_ref": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e"
            }
          ]
        }"#;
        let bundle = parse_bundle(json).expect("parse");
        let graph = StixGraph::from_bundle(&bundle).expect("graph");
        let malware_id = bundle
            .objects()
            .iter()
            .find_map(|object| Malware::cast_from(object).map(|malware| malware.id().clone()))
            .expect("malware");

        let pred = EdgePredicate::And(
            Box::new(EdgePredicate::Type("uses")),
            Box::new(EdgePredicate::Custom(Box::new(|edge: &Edge<'_>| {
                edge.relationship().is_some_and(|relationship| {
                    relationship
                        .common
                        .confidence
                        .is_some_and(|confidence| confidence.get() > 70)
                })
            }))),
        );
        let edges: Vec<_> = graph
            .from(&malware_id)
            .out_edges_matching(pred)
            .into_iter()
            .collect();
        assert_eq!(edges.len(), 1);
        assert_eq!(
            edges[0].relationship().unwrap().common.confidence,
            Some(Confidence::new(85).expect("confidence"))
        );
    }

    #[test]
    fn or_and_not_filter_edges() {
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/validation/bundle-relationship-matrix-invalid.json"
        ))
        .expect("parse bundle");
        let graph = StixGraph::from_bundle(&bundle).expect("graph");
        let malware_id = bundle
            .objects()
            .iter()
            .find_map(|object| Malware::cast_from(object).map(|malware| malware.id().clone()))
            .expect("malware");

        let uses_or_sighting = EdgePredicate::Or(
            Box::new(EdgePredicate::Type("uses")),
            Box::new(EdgePredicate::Type("sighting")),
        );
        assert_eq!(
            graph
                .from(&malware_id)
                .out_edges_matching(uses_or_sighting)
                .into_iter()
                .count(),
            1
        );

        let not_sighting = EdgePredicate::Not(Box::new(EdgePredicate::Type("sighting")));
        let edges: Vec<_> = graph
            .from(&malware_id)
            .out_edges_matching(not_sighting)
            .into_iter()
            .collect();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].relationship_type, "uses");
    }
}

#[cfg(test)]
mod unresolved {
    use super::*;
    use crate::model::sdo::SdoObject;
    use crate::model::{Bundle, StixObject};

    #[test]
    fn finds_dangling_targets() {
        let indicator: crate::model::sdo::Indicator =
            match serde_json::from_str::<serde_json::Value>(include_str!(
                "../../tests/fixtures/graph/dangling-created-by-ref.json"
            ))
            .expect("json")
            .get("objects")
            .and_then(|objects| objects.as_array())
            .and_then(|objects| objects.first())
            {
                Some(value) => serde_json::from_value(value.clone()).expect("indicator"),
                None => panic!("fixture missing objects"),
            };
        let bundle = Bundle::from_objects(
            "bundle--00000000-0000-0000-0000-000000000001"
                .parse()
                .expect("bundle id"),
            vec![StixObject::Sdo(SdoObject::Indicator(indicator))],
        );
        let graph = StixGraph::from_bundle(&bundle).expect("graph");
        let dangling: Vec<_> = graph.unresolved_references().collect();
        assert_eq!(dangling.len(), 1);
        assert_eq!(dangling[0].1, "created_by_ref");
        assert_eq!(
            dangling[0].2.as_str(),
            "identity--00000000-0000-0000-0000-000000000099"
        );
    }
}

#[cfg(test)]
mod expander_tests {
    use super::*;
    use crate::model::cast::BundleObjectCast;
    use crate::model::sdo::Indicator;
    use crate::parse_bundle;

    #[test]
    fn finds_depth_two_chain() {
        let json = r#"{
          "type": "bundle",
          "id": "bundle--00000000-0000-0000-0000-000000000002",
          "objects": [
            {
              "type": "indicator",
              "spec_version": "2.1",
              "id": "indicator--11111111-1111-1111-1111-111111111111",
              "created": "2016-05-12T08:17:27.000Z",
              "modified": "2016-05-12T08:17:27.000Z",
              "pattern": "[file:hashes.MD5 = '644bf17e482f443f763b0b7355b14372']",
              "pattern_type": "stix",
              "valid_from": "2016-05-12T08:17:27.000Z"
            },
            {
              "type": "malware",
              "spec_version": "2.1",
              "id": "malware--22222222-2222-2222-2222-222222222222",
              "created": "2016-05-12T08:17:27.000Z",
              "modified": "2016-05-12T08:17:27.000Z",
              "name": "Poison Ivy",
              "is_family": false
            },
            {
              "type": "threat-actor",
              "spec_version": "2.1",
              "id": "threat-actor--33333333-3333-3333-3333-333333333333",
              "created": "2016-05-12T08:17:27.000Z",
              "modified": "2016-05-12T08:17:27.000Z",
              "name": "APT1"
            },
            {
              "type": "relationship",
              "spec_version": "2.1",
              "id": "relationship--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
              "created": "2016-05-12T08:17:27.000Z",
              "modified": "2016-05-12T08:17:27.000Z",
              "relationship_type": "indicates",
              "source_ref": "indicator--11111111-1111-1111-1111-111111111111",
              "target_ref": "malware--22222222-2222-2222-2222-222222222222"
            },
            {
              "type": "relationship",
              "spec_version": "2.1",
              "id": "relationship--bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
              "created": "2016-05-12T08:17:27.000Z",
              "modified": "2016-05-12T08:17:27.000Z",
              "relationship_type": "attributed-to",
              "source_ref": "malware--22222222-2222-2222-2222-222222222222",
              "target_ref": "threat-actor--33333333-3333-3333-3333-333333333333"
            }
          ]
        }"#;
        let bundle = parse_bundle(json).expect("parse");
        let graph = StixGraph::from_bundle(&bundle).expect("graph");
        let indicator = bundle
            .objects()
            .iter()
            .find_map(|object| Indicator::cast_from(object))
            .expect("indicator");
        let indicator_id =
            crate::core::IndicatorId::from_stix_id(indicator.id().clone()).expect("indicator id");

        let depth_one = RelationshipExpander::new(&graph).expand_from_indicator(&indicator_id, 1);
        assert_eq!(depth_one.malware.len(), 1);
        assert!(depth_one.threat_actors.is_empty());

        let depth_two = RelationshipExpander::new(&graph).expand_from_indicator(&indicator_id, 2);
        assert_eq!(depth_two.malware.len(), 1);
        assert_eq!(depth_two.threat_actors.len(), 1);
        assert_eq!(depth_two.threat_actors[0].name.as_deref(), Some("APT1"));
    }
}
