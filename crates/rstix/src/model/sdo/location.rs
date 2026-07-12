//! STIX `location` objects (STIX §4.10).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;

/// A geographic location (STIX §4.10).
///
/// At least one identifying property is required: non-empty [`region`](Self::region),
/// non-empty [`country`](Self::country), or both [`latitude`](Self::latitude) and
/// [`longitude`](Self::longitude). Latitude and longitude must appear together; when
/// present they must fall within WGS-84 ranges. [`precision`](Self::precision) is
/// only valid when coordinates are present.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sdo::Location;
///
/// let json = r#"{
///   "type": "location",
///   "spec_version": "2.1",
///   "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
///   "created": "2016-04-06T20:03:00.000Z",
///   "modified": "2016-04-06T20:03:00.000Z",
///   "region": "northern-america"
/// }"#;
/// let location: Location = serde_json::from_str(json)?;
/// assert_eq!(location.region.as_deref(), Some("northern-america"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Location {
    /// STIX object type (`location`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_location_type")
    )]
    object_type: String,
    /// SDO common properties (STIX §3.2).
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// A name used to identify the location (STIX §4.10.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub name: Option<String>,
    /// A description of the location (STIX §4.10.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// The latitude of the location in decimal degrees (STIX §4.10.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub latitude: Option<f64>,
    /// The longitude of the location in decimal degrees (STIX §4.10.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub longitude: Option<f64>,
    /// Precision of the coordinates, in meters (STIX §4.10.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub precision: Option<f64>,
    /// Region that this location is in (STIX §4.10.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub region: Option<String>,
    /// Two-letter ISO 3166 country code (STIX §4.10.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub country: Option<String>,
    /// State, province, or other sub-national administrative area (STIX §4.10.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub administrative_area: Option<String>,
    /// City that this location is in (STIX §4.10.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub city: Option<String>,
    /// Street address (STIX §4.10.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub street_address: Option<String>,
    /// Postal/ZIP code (STIX §4.10.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub postal_code: Option<String>,
}

impl Location {
    /// STIX type name for location objects.
    pub const TYPE_NAME: &'static str = "location";

    /// Check location invariants (geo identity, coordinate pairing/ranges, precision).
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)?;
        let has_region = self.region.as_ref().is_some_and(|v| !v.is_empty());
        let has_country = self.country.as_ref().is_some_and(|v| !v.is_empty());
        let has_coordinates = self.latitude.is_some() && self.longitude.is_some();
        if !(has_region || has_country || has_coordinates) {
            return Err(ModelError::LocationMissingGeo);
        }
        match (self.latitude, self.longitude) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(ModelError::LocationLatitudeLongitudePairRequired);
            }
            (Some(lat), Some(_)) if !(-90.0..=90.0).contains(&lat) => {
                return Err(ModelError::LocationLatitudeOutOfRange);
            }
            (Some(_), Some(lon)) if !(-180.0..=180.0).contains(&lon) => {
                return Err(ModelError::LocationLongitudeOutOfRange);
            }
            _ => {}
        }
        if self.precision.is_some() && !has_coordinates {
            return Err(ModelError::LocationPrecisionRequiresCoordinates);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_location_type<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(d, Location::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Location {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_location_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            latitude: Option<f64>,
            #[serde(default)]
            longitude: Option<f64>,
            #[serde(default)]
            precision: Option<f64>,
            #[serde(default)]
            region: Option<String>,
            #[serde(default)]
            country: Option<String>,
            #[serde(default)]
            administrative_area: Option<String>,
            #[serde(default)]
            city: Option<String>,
            #[serde(default)]
            street_address: Option<String>,
            #[serde(default)]
            postal_code: Option<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let value = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
            latitude: raw.latitude,
            longitude: raw.longitude,
            precision: raw.precision,
            region: raw.region,
            country: raw.country,
            administrative_area: raw.administrative_area,
            city: raw.city,
            street_address: raw.street_address,
            postal_code: raw.postal_code,
        };
        value
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(value)
    }
}

impl QueryableStixObject for Location {
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
            ["name"] => self.name.as_deref().map(QueryValue::Str),
            ["country"] => self.country.as_deref().map(QueryValue::Str),
            ["region"] => self.region.as_deref().map(QueryValue::Str),
            ["latitude"] => self.latitude.map(QueryValue::Float),
            ["longitude"] => self.longitude.map(QueryValue::Float),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/infrastructure-minimal.json");
        let msg = serde_json::from_str::<Location>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `location`"));
        assert!(msg.contains("got `infrastructure`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/location-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Location>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
