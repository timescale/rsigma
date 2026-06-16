//! STIX Meta objects (marking-definition, extension-definition, language-content).

mod extension_def;
mod language_content;
mod marking_def;

pub use extension_def::ExtensionDefinition;
pub use language_content::LanguageContent;
pub use marking_def::{
    MarkingDefinition, TLP1_AMBER_ID, TLP1_GREEN_ID, TLP1_RED_ID, TLP1_WHITE_ID, TLP2_AMBER_ID,
    TLP2_AMBER_STRICT_ID, TLP2_CLEAR_ID, TLP2_GREEN_ID, TLP2_RED_ID,
};

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};

/// STIX Meta object enum (3 variants).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum MetaObject {
    /// A marking definition.
    MarkingDefinition(MarkingDefinition),
    /// An extension definition.
    ExtensionDefinition(ExtensionDefinition),
    /// A language-content object.
    LanguageContent(LanguageContent),
}

impl QueryableStixObject for MetaObject {
    fn id(&self) -> &StixId {
        match self {
            Self::MarkingDefinition(inner) => inner.id(),
            Self::ExtensionDefinition(inner) => inner.id(),
            Self::LanguageContent(inner) => inner.id(),
        }
    }

    fn type_name(&self) -> &'static str {
        match self {
            Self::MarkingDefinition(_) => MarkingDefinition::TYPE_NAME,
            Self::ExtensionDefinition(_) => ExtensionDefinition::TYPE_NAME,
            Self::LanguageContent(_) => LanguageContent::TYPE_NAME,
        }
    }

    fn spec_version(&self) -> Option<SpecVersion> {
        match self {
            Self::MarkingDefinition(inner) => inner.spec_version(),
            Self::ExtensionDefinition(inner) => inner.spec_version(),
            Self::LanguageContent(inner) => inner.spec_version(),
        }
    }

    fn created(&self) -> Option<&StixTimestamp> {
        match self {
            Self::MarkingDefinition(inner) => inner.created(),
            Self::ExtensionDefinition(inner) => inner.created(),
            Self::LanguageContent(inner) => inner.created(),
        }
    }

    fn modified(&self) -> Option<&StixTimestamp> {
        match self {
            Self::MarkingDefinition(inner) => inner.modified(),
            Self::ExtensionDefinition(inner) => inner.modified(),
            Self::LanguageContent(inner) => inner.modified(),
        }
    }

    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match self {
            Self::MarkingDefinition(inner) => inner.get_field(path),
            Self::ExtensionDefinition(inner) => inner.get_field(path),
            Self::LanguageContent(inner) => inner.get_field(path),
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::core::QueryableStixObject;

    #[test]
    fn meta_object_delegates_queryable_stix_object() {
        let raw = include_str!(
            "../../../tests/fixtures/spec/meta/marking-definition-tlp-v1-white-stix21.json"
        );
        let marking: MarkingDefinition = serde_json::from_str(raw).expect("parse");
        let meta = MetaObject::MarkingDefinition(marking.clone());
        assert_eq!(QueryableStixObject::id(&meta), marking.id());
        assert_eq!(
            QueryableStixObject::type_name(&meta),
            MarkingDefinition::TYPE_NAME
        );
        assert_eq!(meta.spec_version(), Some(SpecVersion::V2_1));
        assert_eq!(
            meta.get_field(&["name"]),
            Some(QueryValue::Str("TLP:WHITE"))
        );
    }
}
