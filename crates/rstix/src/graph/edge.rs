//! SRO edges and typed edge predicates.

use crate::core::StixId;
use crate::model::sro::{Relationship, Sighting};

/// Payload carried by an indexed SRO graph edge.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SroEdgePayload<'g> {
    /// Generic `relationship` SRO.
    Relationship(&'g Relationship),
    /// `sighting` SRO (primary edge: sighting → `sighting_of_ref`).
    Sighting(&'g Sighting),
}

/// An explicit STIX relationship graph edge (SRO `relationship` or `sighting`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Edge<'g> {
    /// Edge type label (`relationship_type` or `"sighting"`).
    pub relationship_type: &'g str,
    /// Source object id.
    pub source_id: &'g StixId,
    /// Target object id.
    pub target_id: &'g StixId,
    /// Full SRO payload in the source bundle.
    pub payload: SroEdgePayload<'g>,
}

impl<'g> Edge<'g> {
    /// Full `relationship` object when this edge is a generic relationship SRO.
    pub fn relationship(&self) -> Option<&'g Relationship> {
        match self.payload {
            SroEdgePayload::Relationship(relationship) => Some(relationship),
            SroEdgePayload::Sighting(_) => None,
        }
    }

    /// Full `sighting` object when this edge is a sighting SRO.
    pub fn sighting(&self) -> Option<&'g Sighting> {
        match self.payload {
            SroEdgePayload::Sighting(sighting) => Some(sighting),
            SroEdgePayload::Relationship(_) => None,
        }
    }
}

/// Internal storage for an indexed SRO edge.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SroEdgeStorage<'b> {
    Relationship {
        source_id: &'b StixId,
        target_id: &'b StixId,
        relationship: &'b Relationship,
    },
    Sighting {
        source_id: &'b StixId,
        target_id: &'b StixId,
        sighting: &'b Sighting,
    },
}

impl<'b> SroEdgeStorage<'b> {
    pub(crate) fn as_edge(&self) -> Edge<'b> {
        match self {
            Self::Relationship {
                source_id,
                target_id,
                relationship,
            } => Edge {
                relationship_type: relationship.relationship_type.as_str(),
                source_id,
                target_id,
                payload: SroEdgePayload::Relationship(relationship),
            },
            Self::Sighting {
                source_id,
                target_id,
                sighting,
            } => Edge {
                relationship_type: "sighting",
                source_id,
                target_id,
                payload: SroEdgePayload::Sighting(sighting),
            },
        }
    }
}

/// Internal storage for an inlined `_ref` / `_refs` edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InlinedEdgeStorage<'b> {
    pub(crate) source_id: &'b StixId,
    pub(crate) property_path: String,
    pub(crate) target_id: StixId,
}

/// Typed predicate for filtering SRO edges during traversal.
pub enum EdgePredicate {
    /// Match by edge type string (`relationship_type` or `"sighting"`).
    Type(&'static str),
    /// Compound AND.
    And(Box<EdgePredicate>, Box<EdgePredicate>),
    /// Compound OR.
    Or(Box<EdgePredicate>, Box<EdgePredicate>),
    /// Negation.
    Not(Box<EdgePredicate>),
    /// Custom closure — escape hatch for complex predicates.
    Custom(PredicateFn),
}

/// Object-safe custom predicate over SRO edges.
pub type PredicateFn = Box<dyn for<'g> Fn(&Edge<'g>) -> bool + Send + Sync>;

impl EdgePredicate {
    pub(crate) fn matches(&self, edge: &Edge<'_>) -> bool {
        match self {
            Self::Type(expected) => edge.relationship_type == *expected,
            Self::And(left, right) => left.matches(edge) && right.matches(edge),
            Self::Or(left, right) => left.matches(edge) || right.matches(edge),
            Self::Not(inner) => !inner.matches(edge),
            Self::Custom(predicate) => predicate(edge),
        }
    }
}

impl From<&'static str> for EdgePredicate {
    fn from(value: &'static str) -> Self {
        Self::Type(value)
    }
}
