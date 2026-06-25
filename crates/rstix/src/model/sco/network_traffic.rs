//! STIX `network-traffic` objects (STIX §6.12).

use std::collections::BTreeMap;

use crate::core::{
    ArtifactId, NetworkTrafficId, QueryValue, QueryableStixObject, SpecVersion, StixId,
    StixTimestamp,
};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;
use crate::model::sco::extensions::{HttpRequestExt, IcmpExt, SocketExt, TcpExt};
use crate::model::sco::ref_types::NetworkTrafficEndpointRef;

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct NetworkTraffic {
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_network_traffic_type")
    )]
    object_type: String,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub start: Option<StixTimestamp>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub end: Option<StixTimestamp>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub is_active: Option<bool>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub src_ref: Option<NetworkTrafficEndpointRef>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub dst_ref: Option<NetworkTrafficEndpointRef>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub src_port: Option<u16>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub dst_port: Option<u16>,
    pub protocols: Vec<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub src_byte_count: Option<u64>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub dst_byte_count: Option<u64>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub src_packets: Option<u64>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub dst_packets: Option<u64>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub ipfix: BTreeMap<String, serde_json::Value>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub src_payload_ref: Option<ArtifactId>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub dst_payload_ref: Option<ArtifactId>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub encapsulates_refs: Vec<NetworkTrafficId>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub encapsulated_by_ref: Option<NetworkTrafficId>,
}

impl NetworkTraffic {
    pub const TYPE_NAME: &'static str = "network-traffic";

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.protocols.is_empty() {
            return Err(ModelError::NetworkTrafficProtocolsRequired);
        }
        if self.src_ref.is_none() && self.dst_ref.is_none() {
            return Err(ModelError::NetworkTrafficSrcOrDstRequired);
        }
        if self.is_active == Some(true) && self.end.is_some() {
            return Err(ModelError::NetworkTrafficEndWithActive);
        }
        if let (Some(start), Some(end)) = (&self.start, &self.end)
            && end < start
        {
            return Err(ModelError::NetworkTrafficEndBeforeStart);
        }
        for port in [self.src_port, self.dst_port].into_iter().flatten() {
            // u16 is always 0-65535
            let _ = port;
        }
        HttpRequestExt::validate_in_map(&self.common.extensions)?;
        IcmpExt::validate_in_map(&self.common.extensions)?;
        SocketExt::validate_in_map(&self.common.extensions)?;
        TcpExt::validate_in_map(&self.common.extensions)?;
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_network_traffic_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, NetworkTraffic::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for NetworkTraffic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_network_traffic_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            #[serde(default)]
            start: Option<StixTimestamp>,
            #[serde(default)]
            end: Option<StixTimestamp>,
            #[serde(default)]
            is_active: Option<bool>,
            #[serde(default)]
            src_ref: Option<NetworkTrafficEndpointRef>,
            #[serde(default)]
            dst_ref: Option<NetworkTrafficEndpointRef>,
            #[serde(default)]
            src_port: Option<u16>,
            #[serde(default)]
            dst_port: Option<u16>,
            protocols: Vec<String>,
            #[serde(default)]
            src_byte_count: Option<u64>,
            #[serde(default)]
            dst_byte_count: Option<u64>,
            #[serde(default)]
            src_packets: Option<u64>,
            #[serde(default)]
            dst_packets: Option<u64>,
            #[serde(default)]
            ipfix: BTreeMap<String, serde_json::Value>,
            #[serde(default)]
            src_payload_ref: Option<ArtifactId>,
            #[serde(default)]
            dst_payload_ref: Option<ArtifactId>,
            #[serde(default)]
            encapsulates_refs: Vec<NetworkTrafficId>,
            #[serde(default)]
            encapsulated_by_ref: Option<NetworkTrafficId>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            start: raw.start,
            end: raw.end,
            is_active: raw.is_active,
            src_ref: raw.src_ref,
            dst_ref: raw.dst_ref,
            src_port: raw.src_port,
            dst_port: raw.dst_port,
            protocols: raw.protocols,
            src_byte_count: raw.src_byte_count,
            dst_byte_count: raw.dst_byte_count,
            src_packets: raw.src_packets,
            dst_packets: raw.dst_packets,
            ipfix: raw.ipfix,
            src_payload_ref: raw.src_payload_ref,
            dst_payload_ref: raw.dst_payload_ref,
            encapsulates_refs: raw.encapsulates_refs,
            encapsulated_by_ref: raw.encapsulated_by_ref,
        };
        obj.validate().map_err(serde::de::Error::custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for NetworkTraffic {
    fn id(&self) -> &StixId {
        &self.common.id
    }

    fn type_name(&self) -> &'static str {
        Self::TYPE_NAME
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
            ["protocols", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.protocols.get(i))
                .map(|p| QueryValue::Str(p.as_str())),
            ["src_ref"] => self
                .src_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["dst_ref"] => self
                .dst_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["encapsulates_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.encapsulates_refs.get(i))
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["encapsulated_by_ref"] => self
                .encapsulated_by_ref
                .as_ref()
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
        let msg = serde_json::from_str::<NetworkTraffic>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `network-traffic`"));
        assert!(msg.contains("got `url`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/network-traffic-tcp.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err =
            serde_json::from_value::<NetworkTraffic>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn get_field_exposes_refs() {
        let json = include_str!("../../../tests/fixtures/spec/sco/network-traffic-tcp.json");
        let obj: NetworkTraffic = serde_json::from_str(json).expect("parse");
        assert!(matches!(
            obj.get_field(&["src_ref"]),
            Some(QueryValue::Id(_))
        ));
        assert!(matches!(
            obj.get_field(&["dst_ref"]),
            Some(QueryValue::Id(_))
        ));
    }
}
