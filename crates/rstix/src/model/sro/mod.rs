//! STIX Relationship Objects (`relationship`, `sighting`).

mod relationship;
mod sighting;

pub use relationship::{RelSourceRef, RelTargetRef, Relationship};
pub use sighting::{Sighting, SightingOfRef, WhereSightedRef};

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};

/// STIX SRO enum (2 variants).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum SroObject {
    /// A relationship between two STIX objects.
    Relationship(Relationship),
    /// A sighting of an SDO.
    Sighting(Sighting),
}

impl QueryableStixObject for SroObject {
    fn id(&self) -> &StixId {
        match self {
            Self::Relationship(inner) => inner.id(),
            Self::Sighting(inner) => inner.id(),
        }
    }

    fn type_name(&self) -> &'static str {
        match self {
            Self::Relationship(_) => Relationship::TYPE_NAME,
            Self::Sighting(_) => Sighting::TYPE_NAME,
        }
    }

    fn spec_version(&self) -> Option<SpecVersion> {
        match self {
            Self::Relationship(inner) => inner.spec_version(),
            Self::Sighting(inner) => inner.spec_version(),
        }
    }

    fn created(&self) -> Option<&StixTimestamp> {
        match self {
            Self::Relationship(inner) => inner.created(),
            Self::Sighting(inner) => inner.created(),
        }
    }

    fn modified(&self) -> Option<&StixTimestamp> {
        match self {
            Self::Relationship(inner) => inner.modified(),
            Self::Sighting(inner) => inner.modified(),
        }
    }

    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match self {
            Self::Relationship(inner) => inner.get_field(path),
            Self::Sighting(inner) => inner.get_field(path),
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::core::QueryableStixObject;

    #[test]
    fn sro_object_delegates_queryable_stix_object() {
        let raw = include_str!("../../../tests/fixtures/spec/sro/relationship.json");
        let relationship: Relationship = serde_json::from_str(raw).expect("parse");
        let sro = SroObject::Relationship(relationship.clone());
        assert_eq!(QueryableStixObject::id(&sro), relationship.id());
        assert_eq!(
            QueryableStixObject::type_name(&sro),
            Relationship::TYPE_NAME
        );
        assert_eq!(sro.spec_version(), Some(SpecVersion::V2_1));
        assert_eq!(
            sro.get_field(&["relationship_type"]),
            Some(QueryValue::Str("uses"))
        );
    }
}
