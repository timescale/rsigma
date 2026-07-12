//! STIX `indicator` objects (STIX §4.7).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::{KillChainPhase, SdoSroCommonProps};
use crate::model::sdo::validate_kill_chain_phases;

#[cfg(feature = "pattern")]
use crate::model::Bundle;
#[cfg(feature = "pattern")]
use crate::model::sdo::ObservedData;
#[cfg(feature = "pattern")]
use crate::pattern::{ObservationContext, Pattern, PatternError, PatternMatchError};

/// Detection pattern representation for an [`Indicator`].
#[derive(Clone, Debug, PartialEq)]
pub enum IndicatorPattern {
    /// STIX patterning language (`pattern_type` = `stix` on the wire).
    Stix {
        /// Raw STIX pattern string.
        raw: String,
        /// STIX patterning version (wire field `pattern_version`).
        pattern_version: Option<String>,
        /// Parsed and type-checked pattern (`pattern` feature).
        #[cfg(feature = "pattern")]
        parsed: Pattern,
    },
    /// Non-STIX pattern language (YARA, Snort, etc.).
    Other {
        /// Pattern language identifier (wire field `pattern_type`).
        pattern_type: String,
        /// Version of the pattern language (wire field `pattern_version`).
        pattern_version: Option<String>,
        /// Raw pattern string (wire field `pattern`).
        raw: String,
    },
}

impl IndicatorPattern {
    /// Raw pattern string from the wire `pattern` field.
    pub fn raw(&self) -> &str {
        match self {
            Self::Stix { raw, .. } | Self::Other { raw, .. } => raw,
        }
    }

    /// Pattern language from the wire `pattern_type` field.
    pub fn pattern_type(&self) -> &str {
        match self {
            Self::Stix { .. } => "stix",
            Self::Other { pattern_type, .. } => pattern_type,
        }
    }

    /// Pattern language version from the wire `pattern_version` field.
    pub fn pattern_version(&self) -> Option<&str> {
        match self {
            Self::Stix {
                pattern_version, ..
            } => pattern_version.as_deref(),
            Self::Other {
                pattern_version, ..
            } => pattern_version.as_deref(),
        }
    }

    /// Parse and construct a STIX indicator pattern (`pattern` feature).
    #[cfg(feature = "pattern")]
    pub fn stix(
        raw: impl Into<String>,
        pattern_version: Option<String>,
    ) -> Result<Self, PatternError> {
        let raw = raw.into();
        let parsed = Pattern::parse(&raw)?;
        Ok(Self::Stix {
            raw,
            pattern_version,
            parsed,
        })
    }

    /// Parsed STIX pattern when `pattern_type` is `stix` (`pattern` feature).
    #[cfg(feature = "pattern")]
    pub fn parsed_pattern(&self) -> Result<&Pattern, PatternMatchError> {
        match self {
            Self::Stix { parsed, .. } => Ok(parsed),
            Self::Other { pattern_type, .. } => {
                Err(PatternMatchError::NonStixPattern(pattern_type.clone()))
            }
        }
    }

    /// Evaluate a STIX pattern against timestamped observations (`pattern` feature).
    #[cfg(feature = "pattern")]
    pub fn evaluate(&self, ctx: &ObservationContext<'_>) -> Result<bool, PatternMatchError> {
        self.parsed_pattern()?.evaluate(ctx)
    }

    /// Evaluate against observed-data and a bundle (`pattern` feature).
    #[cfg(feature = "pattern")]
    pub fn evaluate_observed_data(
        &self,
        observed_data: &ObservedData,
        bundle: &Bundle,
    ) -> Result<bool, PatternMatchError> {
        self.parsed_pattern()?
            .evaluate_observed_data(observed_data, bundle)
    }
}

/// A STIX indicator describing a detection pattern (STIX §4.7).
#[derive(Clone, Debug, PartialEq)]
pub struct Indicator {
    /// STIX object type (`indicator`).
    object_type: String,
    /// SDO/SRO common properties.
    pub common: SdoSroCommonProps,
    /// Name identifying the indicator.
    pub name: Option<String>,
    /// Human-readable description.
    pub description: Option<String>,
    /// Categorizations for this indicator.
    pub indicator_types: Vec<String>,
    /// Detection pattern (STIX patterning or other language).
    pub pattern: IndicatorPattern,
    /// Start of the validity window.
    pub valid_from: StixTimestamp,
    /// End of the validity window.
    pub valid_until: Option<StixTimestamp>,
    /// Kill chain phases this indicator detects.
    pub kill_chain_phases: Vec<KillChainPhase>,
}

impl Indicator {
    /// STIX type name for indicators.
    pub const TYPE_NAME: &'static str = "indicator";

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        common: SdoSroCommonProps,
        name: Option<String>,
        description: Option<String>,
        indicator_types: Vec<String>,
        pattern: IndicatorPattern,
        valid_from: StixTimestamp,
        valid_until: Option<StixTimestamp>,
        kill_chain_phases: Vec<KillChainPhase>,
    ) -> Self {
        Self {
            object_type: Self::TYPE_NAME.to_string(),
            common,
            name,
            description,
            indicator_types,
            pattern,
            valid_from,
            valid_until,
            kill_chain_phases,
        }
    }

    /// Check indicator-specific invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)?;
        validate_kill_chain_phases(&self.kill_chain_phases)?;
        if let Some(valid_until) = &self.valid_until
            && valid_until <= &self.valid_from
        {
            return Err(ModelError::IndicatorValidUntilBeforeValidFrom);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_indicator_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Indicator::TYPE_NAME)
}

#[cfg(all(feature = "serde", feature = "pattern"))]
fn indicator_pattern_from_wire(
    pattern: String,
    pattern_type: String,
    pattern_version: Option<String>,
) -> Result<IndicatorPattern, PatternError> {
    if pattern_type == "stix" {
        let parsed = Pattern::parse(&pattern)?;
        Ok(IndicatorPattern::Stix {
            raw: pattern,
            pattern_version,
            parsed,
        })
    } else {
        Ok(IndicatorPattern::Other {
            pattern_type,
            pattern_version,
            raw: pattern,
        })
    }
}

#[cfg(all(feature = "serde", not(feature = "pattern")))]
fn indicator_pattern_from_wire(
    pattern: String,
    pattern_type: String,
    pattern_version: Option<String>,
) -> IndicatorPattern {
    if pattern_type == "stix" {
        IndicatorPattern::Stix {
            raw: pattern,
            pattern_version,
        }
    } else {
        IndicatorPattern::Other {
            pattern_type,
            pattern_version,
            raw: pattern,
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Indicator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (pattern, pattern_type, pattern_version) = match &self.pattern {
            IndicatorPattern::Stix {
                raw,
                pattern_version,
                ..
            } => (raw.as_str(), "stix", pattern_version.as_deref()),
            IndicatorPattern::Other {
                pattern_type,
                pattern_version,
                raw,
            } => (
                raw.as_str(),
                pattern_type.as_str(),
                pattern_version.as_deref(),
            ),
        };

        #[derive(serde::Serialize)]
        struct Wire<'a> {
            #[serde(rename = "type")]
            object_type: &'a str,
            #[serde(flatten)]
            common: &'a SdoSroCommonProps,
            #[serde(skip_serializing_if = "Option::is_none")]
            name: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            description: &'a Option<String>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            indicator_types: &'a Vec<String>,
            pattern: &'a str,
            pattern_type: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            pattern_version: Option<&'a str>,
            valid_from: &'a StixTimestamp,
            #[serde(skip_serializing_if = "Option::is_none")]
            valid_until: &'a Option<StixTimestamp>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            kill_chain_phases: &'a Vec<KillChainPhase>,
        }

        Wire {
            object_type: &self.object_type,
            common: &self.common,
            name: &self.name,
            description: &self.description,
            indicator_types: &self.indicator_types,
            pattern,
            pattern_type,
            pattern_version,
            valid_from: &self.valid_from,
            valid_until: &self.valid_until,
            kill_chain_phases: &self.kill_chain_phases,
        }
        .serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Indicator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_indicator_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            indicator_types: Vec<String>,
            pattern: String,
            pattern_type: String,
            #[serde(default)]
            pattern_version: Option<String>,
            valid_from: StixTimestamp,
            #[serde(default)]
            valid_until: Option<StixTimestamp>,
            #[serde(default)]
            kill_chain_phases: Vec<KillChainPhase>,
        }

        let raw = Raw::deserialize(deserializer)?;
        #[cfg(feature = "pattern")]
        let pattern = indicator_pattern_from_wire(
            raw.pattern.clone(),
            raw.pattern_type.clone(),
            raw.pattern_version.clone(),
        )
        .map_err(serde::de::Error::custom)?;
        #[cfg(not(feature = "pattern"))]
        let pattern =
            indicator_pattern_from_wire(raw.pattern, raw.pattern_type, raw.pattern_version);
        let indicator = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
            indicator_types: raw.indicator_types,
            pattern,
            valid_from: raw.valid_from,
            valid_until: raw.valid_until,
            kill_chain_phases: raw.kill_chain_phases,
        };
        indicator
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(indicator)
    }
}

impl QueryableStixObject for Indicator {
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
            ["description"] => self.description.as_deref().map(QueryValue::Str),
            ["pattern"] => Some(QueryValue::Str(self.pattern.raw())),
            ["pattern_type"] => Some(QueryValue::Str(self.pattern.pattern_type())),
            ["valid_from"] => Some(QueryValue::Timestamp(&self.valid_from)),
            ["valid_until"] => self.valid_until.as_ref().map(QueryValue::Timestamp),
            ["created_by_ref"] => self
                .common
                .created_by_ref
                .as_ref()
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
        let json = include_str!("../../../tests/fixtures/spec/sdo/incident-minimal.json");
        let msg = serde_json::from_str::<Indicator>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `indicator`"));
        assert!(msg.contains("got `incident`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/indicator-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Indicator>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn validate_rejects_valid_until_before_valid_from() {
        let valid_from = StixTimestamp::parse("2016-05-01T00:00:00.000Z").expect("timestamp");
        let valid_until = StixTimestamp::parse("2016-04-01T00:00:00.000Z").expect("timestamp");
        let indicator = Indicator {
            object_type: Indicator::TYPE_NAME.to_string(),
            common: indicator_common(),
            name: None,
            description: None,
            indicator_types: Vec::new(),
            pattern: {
                #[cfg(feature = "pattern")]
                {
                    IndicatorPattern::stix("[ipv4-addr:value = '198.51.100.3']", None)
                        .expect("valid pattern")
                }
                #[cfg(not(feature = "pattern"))]
                {
                    IndicatorPattern::Stix {
                        raw: "[ipv4-addr:value = '198.51.100.3']".into(),
                        pattern_version: None,
                    }
                }
            },
            valid_from,
            valid_until: Some(valid_until),
            kill_chain_phases: Vec::new(),
        };
        assert_eq!(
            indicator.validate().unwrap_err(),
            ModelError::IndicatorValidUntilBeforeValidFrom
        );
    }

    fn indicator_common() -> SdoSroCommonProps {
        let ts = StixTimestamp::parse("2016-05-12T08:17:27.000Z").expect("timestamp");
        SdoSroCommonProps::new(StixId::generate("indicator"), ts.clone(), ts)
    }
}
