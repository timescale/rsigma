//! STIX `domain-name` objects (STIX §6.4).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;
use crate::model::sco::ref_types::DomainNameResolvesToRef;

/// A STIX domain name cyber-observable.
///
/// Per STIX §6.4, the required `value` holds the domain name string. Optional
/// `resolves_to_refs` links to IPv4, IPv6, or domain-name objects the name
/// resolved to.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sco::DomainName;
///
/// let json = r#"{
///   "type": "domain-name",
///   "spec_version": "2.1",
///   "id": "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7",
///   "value": "example.com",
///   "resolves_to_refs": ["ipv4-addr--28bb3599-77cd-5a82-a950-b5bc3caf07c4"]
/// }"#;
/// let domain: DomainName = serde_json::from_str(json)?;
/// assert_eq!(domain.value, "example.com");
/// assert_eq!(domain.resolves_to_refs.len(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct DomainName {
    /// STIX object type (`domain-name`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_domain_name_type")
    )]
    object_type: String,
    /// SCO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    /// Domain name (for example `example.com`).
    pub value: String,
    /// IPv4, IPv6, or domain-name objects this name resolved to.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub resolves_to_refs: Vec<DomainNameResolvesToRef>,
}

impl DomainName {
    /// STIX type name for domain names.
    pub const TYPE_NAME: &'static str = "domain-name";

    /// Rejects empty `value`.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.value.is_empty() {
            return Err(ModelError::DomainNameValueEmpty);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_domain_name_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, DomainName::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DomainName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_domain_name_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            value: String,
            #[serde(default)]
            resolves_to_refs: Vec<DomainNameResolvesToRef>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            value: raw.value,
            resolves_to_refs: raw.resolves_to_refs,
        };
        obj.validate().map_err(serde::de::Error::custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for DomainName {
    fn id(&self) -> &StixId {
        &self.common.id
    }

    fn type_name(&self) -> &'static str {
        DomainName::TYPE_NAME
    }

    fn spec_version(&self) -> Option<SpecVersion> {
        self.common.spec_version
    }

    fn created(&self) -> Option<&StixTimestamp> {
        None
    }

    fn modified(&self) -> Option<&StixTimestamp> {
        None
    }

    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match path {
            ["value"] => Some(QueryValue::Str(&self.value)),
            ["resolves_to_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.resolves_to_refs.get(i))
                .map(|id| QueryValue::Id(id.as_stix_id())),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::core::QueryValue;

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/url.json");
        let msg = serde_json::from_str::<DomainName>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `domain-name`"));
        assert!(msg.contains("got `url`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/domain-name-basic.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<DomainName>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn get_field_exposes_refs() {
        let json = include_str!("../../../tests/fixtures/spec/sco/domain-name-basic.json");
        let obj: DomainName = serde_json::from_str(json).expect("parse");
        assert!(matches!(
            obj.get_field(&["resolves_to_refs", "0"]),
            Some(QueryValue::Id(_))
        ));
    }
}
