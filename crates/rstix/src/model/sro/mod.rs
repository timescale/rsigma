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

impl SroObject {
    /// Borrow shared SDO/SRO common properties.
    pub fn common_props(&self) -> &crate::model::common::SdoSroCommonProps {
        match self {
            Self::Relationship(inner) => &inner.common,
            Self::Sighting(inner) => &inner.common,
        }
    }

    pub(crate) fn common_props_mut(&mut self) -> &mut crate::model::common::SdoSroCommonProps {
        match self {
            Self::Relationship(inner) => &mut inner.common,
            Self::Sighting(inner) => &mut inner.common,
        }
    }
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

#[cfg(feature = "serde")]
impl serde::Serialize for SroObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Relationship(inner) => inner.serialize(serializer),
            Self::Sighting(inner) => inner.serialize(serializer),
        }
    }
}

#[cfg(feature = "serde")]
pub(crate) fn deserialize_sro_object_from_value(
    value: serde_json::Value,
) -> Result<SroObject, serde_json::Error> {
    let type_name = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SRO object missing type field",
            ))
        })?;
    match type_name {
        "relationship" => serde_json::from_value(value).map(SroObject::Relationship),
        "sighting" => serde_json::from_value(value).map(SroObject::Sighting),
        _ => Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown SRO type `{type_name}`"),
        ))),
    }
}

crate::impl_bundle_object_cast!(Sro, Relationship, Relationship);
crate::impl_bundle_object_cast!(Sro, Sighting, Sighting);

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
