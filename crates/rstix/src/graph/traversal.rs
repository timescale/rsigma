//! Graph traversal builders.

use crate::core::StixId;
use crate::model::BundleObjectCast;
use crate::model::stix_object::StixObject;

use super::StixGraph;
use super::edge::{Edge, EdgePredicate, InlinedEdgeStorage};

/// Filtered SRO edge traversal (returned by [`TraversalBuilder::out_edges_matching`] /
/// [`TraversalBuilder::in_edges_matching`]).
pub struct EdgeTraversal<'g> {
    graph: &'g StixGraph<'g>,
    edges: Vec<Edge<'g>>,
}

impl<'g> EdgeTraversal<'g> {
    pub(crate) fn from_outgoing(
        graph: &'g StixGraph<'g>,
        source_id: &StixId,
        pred: EdgePredicate,
    ) -> Self {
        let edges = graph
            .outgoing_sro_edges(source_id)
            .filter(|edge| pred.matches(edge))
            .collect();
        Self { graph, edges }
    }

    pub(crate) fn from_incoming(
        graph: &'g StixGraph<'g>,
        target_id: &StixId,
        pred: EdgePredicate,
    ) -> Self {
        let edges = graph
            .incoming_sro_edges(target_id)
            .filter(|edge| pred.matches(edge))
            .collect();
        Self { graph, edges }
    }

    /// Iterate matching SRO edges.
    pub fn edges(&self) -> impl Iterator<Item = Edge<'g>> + '_ {
        self.edges.iter().copied()
    }

    /// Collect target ids from matching outgoing edges.
    pub fn targets(&self) -> impl Iterator<Item = &'g StixId> + '_ {
        self.edges().map(|edge| edge.target_id)
    }

    /// Collect source ids from matching incoming edges.
    pub fn sources(&self) -> impl Iterator<Item = &'g StixId> + '_ {
        self.edges().map(|edge| edge.source_id)
    }

    /// Collect targets resolved to concrete type `T`; skips non-matching types.
    pub fn targets_as<T: BundleObjectCast>(&self) -> impl Iterator<Item = &'g T> + '_ {
        let graph = self.graph;
        self.edges()
            .filter_map(move |edge| graph.node(edge.target_id).and_then(T::cast_from))
    }

    /// Collect sources resolved to concrete type `T`; skips non-matching types.
    pub fn sources_as<T: BundleObjectCast>(&self) -> impl Iterator<Item = &'g T> + '_ {
        let graph = self.graph;
        self.edges()
            .filter_map(move |edge| graph.node(edge.source_id).and_then(T::cast_from))
    }
}

impl<'g> IntoIterator for EdgeTraversal<'g> {
    type Item = Edge<'g>;
    type IntoIter = std::vec::IntoIter<Edge<'g>>;

    fn into_iter(self) -> Self::IntoIter {
        self.edges.into_iter()
    }
}

/// Begins a traversal from a bundle node.
pub struct TraversalBuilder<'g> {
    graph: &'g StixGraph<'g>,
    source_id: StixId,
}

impl<'g> TraversalBuilder<'g> {
    pub(crate) fn new(graph: &'g StixGraph<'g>, source_id: &StixId) -> Self {
        Self {
            graph,
            source_id: source_id.clone(),
        }
    }

    /// Filter outgoing SRO edges by predicate.
    pub fn out_edges_matching(self, pred: EdgePredicate) -> EdgeTraversal<'g> {
        EdgeTraversal::from_outgoing(self.graph, &self.source_id, pred)
    }

    /// Filter incoming SRO edges by predicate.
    pub fn in_edges_matching(self, pred: EdgePredicate) -> EdgeTraversal<'g> {
        EdgeTraversal::from_incoming(self.graph, &self.source_id, pred)
    }

    /// Follow all outgoing inlined `_ref` / `_refs` properties (including dangling targets).
    pub fn out_refs(self) -> Vec<(String, StixId)> {
        let source_id = self.source_id;
        self.graph
            .outgoing_ref_edges(&source_id)
            .map(|edge| (edge.property_path.clone(), edge.target_id.clone()))
            .collect()
    }

    /// Follow all incoming inlined `_ref` / `_refs` properties pointing at this node.
    pub fn in_refs(self) -> Vec<(StixId, String)> {
        let source_id = self.source_id;
        self.graph
            .incoming_ref_edges(&source_id)
            .map(|edge| (edge.source_id.clone(), edge.property_path.clone()))
            .collect()
    }

    /// Filter outgoing inlined reference edges by property path prefix.
    pub fn out_refs_matching(self, property_prefix: &str) -> Vec<(String, StixId)> {
        self.out_refs()
            .into_iter()
            .filter(|(path, _)| path.starts_with(property_prefix))
            .collect()
    }

    /// Filter incoming inlined reference edges by property path prefix.
    pub fn in_refs_matching(self, property_prefix: &str) -> Vec<(StixId, String)> {
        self.in_refs()
            .into_iter()
            .filter(|(_, path)| path.starts_with(property_prefix))
            .collect()
    }
}

impl<'g> StixGraph<'g> {
    pub(crate) fn outgoing_sro_edges(
        &self,
        source_id: &StixId,
    ) -> impl Iterator<Item = Edge<'g>> + '_ {
        let source_key = source_id.as_str();
        self.out_sro
            .get(source_key)
            .into_iter()
            .flat_map(|indices| indices.iter())
            .map(|&index| self.sro_edges[index].as_edge())
    }

    pub(crate) fn incoming_sro_edges(
        &self,
        target_id: &StixId,
    ) -> impl Iterator<Item = Edge<'g>> + '_ {
        let target_key = target_id.as_str();
        self.in_sro
            .get(target_key)
            .into_iter()
            .flat_map(|indices| indices.iter())
            .map(|&index| self.sro_edges[index].as_edge())
    }

    pub(crate) fn outgoing_ref_edges(
        &self,
        source_id: &StixId,
    ) -> impl Iterator<Item = &InlinedEdgeStorage<'g>> + '_ {
        let source_key = source_id.as_str();
        self.out_refs
            .get(source_key)
            .into_iter()
            .flat_map(|indices| indices.iter())
            .map(|&index| &self.ref_edges[index])
    }

    pub(crate) fn incoming_ref_edges(
        &self,
        target_id: &StixId,
    ) -> impl Iterator<Item = &InlinedEdgeStorage<'g>> + '_ {
        let target_key = target_id.as_str();
        self.in_refs
            .get(target_key)
            .into_iter()
            .flat_map(|indices| indices.iter())
            .map(|&index| &self.ref_edges[index])
    }

    pub(crate) fn node(&self, id: &StixId) -> Option<&'g StixObject> {
        self.nodes.get(id).copied()
    }
}
