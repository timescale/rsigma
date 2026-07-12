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

/// Network traffic between one or more endpoints (STIX §6.12).
///
/// [`protocols`](Self::protocols) is required and at least one of
/// [`src_ref`](Self::src_ref) or [`dst_ref`](Self::dst_ref) must be set.
/// An active connection cannot have an `end` time, and `end` must not precede `start`.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sco::NetworkTraffic;
///
/// let json = include_str!("../../../tests/fixtures/spec/sco/network-traffic-tcp.json");
/// let traffic: NetworkTraffic = serde_json::from_str(json)?;
/// assert_eq!(traffic.protocols, vec!["tcp"]);
/// assert!(traffic.src_ref.is_some() && traffic.dst_ref.is_some());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct NetworkTraffic {
    /// STIX object type (`network-traffic`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_network_traffic_type")
    )]
    object_type: String,
    /// SCO common properties (STIX §3.2).
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    /// Start time of the traffic (STIX §6.12.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub start: Option<StixTimestamp>,
    /// End time of the traffic (STIX §6.12.2; incompatible with `is_active = true`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub end: Option<StixTimestamp>,
    /// Whether the traffic is still ongoing (STIX §6.12.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub is_active: Option<bool>,
    /// Source endpoint (STIX §6.12.2; at least one of `src_ref` or `dst_ref` required).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub src_ref: Option<NetworkTrafficEndpointRef>,
    /// Destination endpoint (STIX §6.12.2; at least one of `src_ref` or `dst_ref` required).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub dst_ref: Option<NetworkTrafficEndpointRef>,
    /// Source port number (STIX §6.12.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub src_port: Option<u16>,
    /// Destination port number (STIX §6.12.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub dst_port: Option<u16>,
    /// Ordered list of OSI layers and protocols observed (STIX §6.12.2; required).
    pub protocols: Vec<String>,
    /// Number of bytes sent from source to destination (STIX §6.12.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub src_byte_count: Option<u64>,
    /// Number of bytes sent from destination to source (STIX §6.12.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub dst_byte_count: Option<u64>,
    /// Number of packets sent from source to destination (STIX §6.12.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub src_packets: Option<u64>,
    /// Number of packets sent from destination to source (STIX §6.12.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub dst_packets: Option<u64>,
    /// IPFIX dictionary of additional flow attributes (STIX §6.12.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub ipfix: BTreeMap<String, serde_json::Value>,
    /// Artifact containing payload sent from source (STIX §6.12.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub src_payload_ref: Option<ArtifactId>,
    /// Artifact containing payload sent from destination (STIX §6.12.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub dst_payload_ref: Option<ArtifactId>,
    /// Network traffic objects encapsulated by this flow (STIX §6.12.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub encapsulates_refs: Vec<NetworkTrafficId>,
    /// Network traffic object that encapsulates this flow (STIX §6.12.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub encapsulated_by_ref: Option<NetworkTrafficId>,
}

impl NetworkTraffic {
    /// STIX type name for network traffic.
    pub const TYPE_NAME: &'static str = "network-traffic";

    /// Check network-traffic invariants (protocols, endpoints, timing, extensions).
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
        obj.validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
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
            ["start"] => self.start.as_ref().map(QueryValue::Timestamp),
            ["end"] => self.end.as_ref().map(QueryValue::Timestamp),
            ["is_active"] => self.is_active.map(QueryValue::Bool),
            ["src_port"] => self.src_port.map(|p| QueryValue::Int(i64::from(p))),
            ["dst_port"] => self.dst_port.map(|p| QueryValue::Int(i64::from(p))),
            ["protocols"] if !self.protocols.is_empty() => Some(QueryValue::Null),
            ["protocols", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.protocols.get(i))
                .map(|p| QueryValue::Str(p.as_str())),
            ["ipfix"] if !self.ipfix.is_empty() => Some(QueryValue::Null),
            ["ipfix", key] => self
                .ipfix
                .get(*key)
                .and_then(|v| v.as_str())
                .map(QueryValue::Str),
            ["src_byte_count"] => self
                .src_byte_count
                .map(|n| QueryValue::Int(i64::try_from(n).unwrap_or(i64::MAX))),
            ["dst_byte_count"] => self
                .dst_byte_count
                .map(|n| QueryValue::Int(i64::try_from(n).unwrap_or(i64::MAX))),
            ["src_packets"] => self
                .src_packets
                .map(|n| QueryValue::Int(i64::try_from(n).unwrap_or(i64::MAX))),
            ["dst_packets"] => self
                .dst_packets
                .map(|n| QueryValue::Int(i64::try_from(n).unwrap_or(i64::MAX))),
            ["src_ref"] => self
                .src_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["dst_ref"] => self
                .dst_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["src_payload_ref"] => self
                .src_payload_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["dst_payload_ref"] => self
                .dst_payload_ref
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
