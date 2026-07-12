//! STIX `extension-definition` objects (STIX §7.2.2).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::{ExtensionType, SdoSroCommonProps};

/// A STIX extension definition.
///
/// `created_by_ref` is required (STIX §7.2.2). The invariant is enforced on
/// deserialization when the `serde` feature is enabled.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::meta::ExtensionDefinition;
///
/// let json = r#"{
///   "type": "extension-definition",
///   "spec_version": "2.1",
///   "id": "extension-definition--04ee437a-1b58-4f6e-8b3e-6c0d0c7b9b21",
///   "created": "2016-05-12T08:17:27.000Z",
///   "modified": "2016-05-12T08:17:27.000Z",
///   "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
///   "name": "Custom Extension",
///   "schema": "https://example.org/schema/extension.json",
///   "version": "1.0.0",
///   "extension_types": ["property-extension"]
/// }"#;
/// let definition: ExtensionDefinition = serde_json::from_str(json)?;
/// assert!(definition.validate().is_ok());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ExtensionDefinition {
    /// STIX object type (`extension-definition`).
    #[cfg_attr(
        feature = "serde",
        serde(
            rename = "type",
            deserialize_with = "deserialize_extension_definition_type"
        )
    )]
    object_type: String,
    /// SDO/SRO common properties (`created_by_ref` required).
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Human-readable name.
    pub name: String,
    /// Human-readable description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// URL of the JSON schema for this extension.
    pub schema: String,
    /// Semver version string for this extension.
    pub version: String,
    /// Extension roles this definition may play.
    pub extension_types: Vec<ExtensionType>,
    /// Property names contributed by this extension, when applicable.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub extension_properties: Vec<String>,
}

impl ExtensionDefinition {
    /// STIX type name for extension definitions.
    pub const TYPE_NAME: &'static str = "extension-definition";

    /// Validate required `created_by_ref`.
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)?;
        if self.common.created_by_ref.is_none() {
            return Err(ModelError::ExtensionDefinitionMissingCreatedByRef);
        }
        if !self.common.extensions.is_empty() {
            return Err(ModelError::ExtensionDefinitionForbiddenCommonProperty {
                property: "extensions".to_owned(),
            });
        }
        if self.common.confidence.is_some() {
            return Err(ModelError::ExtensionDefinitionForbiddenCommonProperty {
                property: "confidence".to_owned(),
            });
        }
        if self.common.lang.is_some() {
            return Err(ModelError::ExtensionDefinitionForbiddenCommonProperty {
                property: "lang".to_owned(),
            });
        }
        Ok(())
    }
}

impl QueryableStixObject for ExtensionDefinition {
    fn id(&self) -> &StixId {
        &self.common.id
    }

    fn type_name(&self) -> &'static str {
        Self::TYPE_NAME
    }

    fn spec_version(&self) -> Option<SpecVersion> {
        Some(self.common.spec_version)
    }

    fn created(&self) -> Option<&StixTimestamp> {
        Some(&self.common.created)
    }

    fn modified(&self) -> Option<&StixTimestamp> {
        Some(&self.common.modified)
    }

    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match path {
            ["name"] => Some(QueryValue::Str(&self.name)),
            ["schema"] => Some(QueryValue::Str(&self.schema)),
            ["version"] => Some(QueryValue::Str(&self.version)),
            ["created_by_ref"] => self
                .common
                .created_by_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            _ => None,
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ExtensionDefinition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(
                rename = "type",
                deserialize_with = "deserialize_extension_definition_type"
            )]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            name: String,
            #[serde(default)]
            description: Option<String>,
            schema: String,
            version: String,
            extension_types: Vec<ExtensionType>,
            #[serde(default)]
            extension_properties: Vec<String>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let definition = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
            schema: raw.schema,
            version: raw.version,
            extension_types: raw.extension_types,
            extension_properties: raw.extension_properties,
        };
        definition
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(definition)
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::core::{StixId, StixTimestamp};
    use crate::model::ModelError;
    use crate::model::common::SdoSroCommonProps;

    #[test]
    fn validate_requires_created_by_ref() {
        let ts = StixTimestamp::parse("2016-05-12T08:17:27.000Z").expect("timestamp");
        let common =
            SdoSroCommonProps::new(StixId::generate("extension-definition"), ts.clone(), ts);
        let definition = ExtensionDefinition {
            object_type: ExtensionDefinition::TYPE_NAME.to_string(),
            common,
            name: "x".into(),
            description: None,
            schema: "https://example.org/schema.json".into(),
            version: "1.0.0".into(),
            extension_types: vec![ExtensionType::PropertyExtension],
            extension_properties: Vec::new(),
        };
        assert_eq!(
            definition.validate().unwrap_err(),
            ModelError::ExtensionDefinitionMissingCreatedByRef
        );
    }

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/meta/language-content.json");
        let msg = serde_json::from_str::<ExtensionDefinition>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `extension-definition`"));
        assert!(msg.contains("got `language-content`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/meta/extension-definition.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<ExtensionDefinition>(serde_json::Value::Object(obj))
            .unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}

#[cfg(feature = "serde")]
fn deserialize_extension_definition_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(
        deserializer,
        ExtensionDefinition::TYPE_NAME,
    )
}
