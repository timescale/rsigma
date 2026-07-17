//! Integration tests for the `graph` feature.

use rstix::core::QueryableStixObject;
use rstix::graph::{EdgePredicate, RelationshipExpander, StixGraph};
use rstix::model::BundleObjectCast;
use rstix::model::sdo::{Indicator, Malware};
use rstix::parse_bundle;

#[test]
fn graph_from_bundle_indexes_relationship_fixture() {
    let bundle = parse_bundle(include_str!(
        "fixtures/validation/bundle-relationship-matrix-invalid.json"
    ))
    .expect("parse bundle");
    let graph = StixGraph::from_bundle(&bundle).expect("graph");
    assert_eq!(graph.node_count(), 3);
    assert_eq!(graph.sro_edge_count(), 1);
}

#[test]
fn graph_traversal_targets_as_resolves_identity() {
    let bundle = parse_bundle(include_str!(
        "fixtures/validation/bundle-relationship-matrix-invalid.json"
    ))
    .expect("parse bundle");
    let graph = StixGraph::from_bundle(&bundle).expect("graph");
    let malware_id = bundle
        .objects()
        .iter()
        .find_map(|object| Malware::cast_from(object).map(|malware| malware.id().clone()))
        .expect("malware");

    let identities: Vec<_> = graph
        .from(&malware_id)
        .out_edges_matching(EdgePredicate::Type("uses"))
        .targets_as::<rstix::model::sdo::Identity>()
        .collect();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].name, "John Smith");
}

#[test]
fn graph_expander_depth_two_chain() {
    let bundle = parse_bundle(include_str!(
        "fixtures/graph/indicator-malware-actor-chain.json"
    ))
    .expect("parse bundle");
    let graph = StixGraph::from_bundle(&bundle).expect("graph");
    let indicator = bundle
        .objects()
        .iter()
        .find_map(Indicator::cast_from)
        .expect("indicator");
    let indicator_id =
        rstix::core::IndicatorId::from_stix_id(indicator.id().clone()).expect("indicator id");

    let depth_two = RelationshipExpander::new(&graph).expand_from_indicator(&indicator_id, 2);
    assert_eq!(depth_two.malware.len(), 1);
    assert_eq!(depth_two.threat_actors.len(), 1);
}
