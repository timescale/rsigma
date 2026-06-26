//! STIX `ipv6-addr` objects (STIX §6.9).

use crate::core::{AutonomousSystemId, MacAddrId};
use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;

/// A STIX IPv6 address cyber-observable.
///
/// Per STIX §6.9, the required `value` holds an IPv6 address or CIDR block.
/// Optional `resolves_to_refs` and `belongs_to_refs` link to related MAC
/// addresses and autonomous systems.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sco::Ipv6Addr;
///
/// let json = r#"{
///   "type": "ipv6-addr",
///   "spec_version": "2.1",
///   "id": "ipv6-addr--85a85a8c-ee99-5722-946d-3c3a3270fc6f",
///   "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
/// }"#;
/// let addr: Ipv6Addr = serde_json::from_str(json)?;
/// assert_eq!(addr.value, "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Ipv6Addr {
    /// STIX object type (`ipv6-addr`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_ipv6_addr_type")
    )]
    object_type: String,
    /// SCO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    /// IPv6 address or CIDR block.
    pub value: String,
    /// MAC addresses this IP address resolved to.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub resolves_to_refs: Vec<MacAddrId>,
    /// Autonomous systems this address belongs to.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub belongs_to_refs: Vec<AutonomousSystemId>,
}

impl Ipv6Addr {
    /// STIX type name for IPv6 addresses.
    pub const TYPE_NAME: &'static str = "ipv6-addr";

    /// Rejects empty `value`.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.value.is_empty() {
            return Err(ModelError::Ipv6AddrValueEmpty);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_ipv6_addr_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Ipv6Addr::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Ipv6Addr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_ipv6_addr_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            value: String,
            #[serde(default)]
            resolves_to_refs: Vec<MacAddrId>,
            #[serde(default)]
            belongs_to_refs: Vec<AutonomousSystemId>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            value: raw.value,
            resolves_to_refs: raw.resolves_to_refs,
            belongs_to_refs: raw.belongs_to_refs,
        };
        obj.validate().map_err(serde::de::Error::custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for Ipv6Addr {
    fn id(&self) -> &StixId {
        &self.common.id
    }

    fn type_name(&self) -> &'static str {
        Ipv6Addr::TYPE_NAME
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
            ["belongs_to_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.belongs_to_refs.get(i))
                .map(|id| QueryValue::Id(id.as_stix_id())),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/url.json");
        let msg = serde_json::from_str::<Ipv6Addr>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `ipv6-addr`"));
        assert!(msg.contains("got `"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/ipv6-addr-single.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Ipv6Addr>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
