//! Programmatic construction of [`Indicator`] objects (STIX §4.7).

use crate::core::{StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::{KillChainPhase, SdoSroCommonProps};

use super::{Indicator, IndicatorPattern};

/// Errors when building an [`Indicator`] with [`IndicatorBuilder`].
#[derive(Debug, thiserror::Error)]
pub enum IndicatorBuilderError {
    /// `build()` was called without [`IndicatorBuilder::new`] or [`IndicatorBuilder::with_timestamps`].
    #[error("SDO common properties are required")]
    MissingCommon,
    /// `build()` was called without `stix_pattern`, `external_pattern`, or `pattern`.
    #[error("indicator pattern is required")]
    MissingPattern,
    /// `build()` was called without `valid_from`.
    #[error("valid_from is required")]
    MissingValidFrom,
    /// Indicator invariants failed ([`Indicator::validate`]).
    #[error(transparent)]
    Model(#[from] ModelError),
    /// STIX pattern parse/type-check failed (`pattern` feature).
    #[cfg(feature = "pattern")]
    #[error(transparent)]
    Pattern(#[from] crate::pattern::PatternError),
}

#[derive(Clone, Debug)]
enum PendingPattern {
    Stix {
        raw: String,
        pattern_version: Option<String>,
    },
    External {
        pattern_type: String,
        pattern_version: Option<String>,
        raw: String,
    },
    Built(IndicatorPattern),
}

/// Fluent builder for [`Indicator`] with STIX or external detection patterns.
///
/// Setters (`stix_pattern`, `name`, `valid_from`, …) only store configuration and return
/// `Self` so the chain stays fluent. All validation runs in [`build`](Self::build):
///
/// - required fields (`pattern`, `valid_from`, SDO common props)
/// - STIX pattern parse and type-check when the `pattern` feature is enabled
/// - [`Indicator::validate`] (time window, kill-chain phases, etc.)
///
/// This matches JSON deserialization: the wire `pattern` string is accepted during
/// configuration, then parsed when the [`Indicator`] is materialized (deserialize or
/// `build()`), not when each field setter runs.
///
/// Design decision **DD-PE-001** (rationale, alternatives, consequences):
/// [Pattern Engine design decisions](https://github.com/timescale/rsigma/blob/main/docs/library/rstix.md#dd-pe-001--indicatorbuilder-validates-at-build-not-in-setters).
///
/// # Examples
///
/// ```
/// use rstix::core::{StixId, StixTimestamp};
/// use rstix::model::common::SdoSroCommonProps;
/// use rstix::model::sdo::{IndicatorBuilder, IndicatorPattern};
///
/// let ts = StixTimestamp::parse("2016-05-12T08:17:27.000Z").expect("timestamp");
/// let valid_from = StixTimestamp::parse("2016-01-01T00:00:00.000Z").expect("valid_from");
/// let indicator = IndicatorBuilder::new(SdoSroCommonProps::new(
///     StixId::generate("indicator"),
///     ts.clone(),
///     ts,
/// ))
/// .name("Example")
/// .stix_pattern("[ipv4-addr:value = '198.51.100.3']", None)
/// .valid_from(valid_from)
/// .build()
/// .expect("indicator");
/// assert!(matches!(indicator.pattern, IndicatorPattern::Stix { .. }));
/// ```
#[derive(Clone, Debug)]
pub struct IndicatorBuilder {
    common: Option<SdoSroCommonProps>,
    name: Option<String>,
    description: Option<String>,
    indicator_types: Vec<String>,
    pattern: Option<PendingPattern>,
    valid_from: Option<StixTimestamp>,
    valid_until: Option<StixTimestamp>,
    kill_chain_phases: Vec<KillChainPhase>,
}

impl IndicatorBuilder {
    /// Start from SDO common properties (`id`, `created`, `modified`, …).
    pub fn new(common: SdoSroCommonProps) -> Self {
        Self {
            common: Some(common),
            name: None,
            description: None,
            indicator_types: Vec::new(),
            pattern: None,
            valid_from: None,
            valid_until: None,
            kill_chain_phases: Vec::new(),
        }
    }

    /// Generate a new indicator id and attach `created` / `modified` timestamps.
    pub fn with_timestamps(created: StixTimestamp, modified: StixTimestamp) -> Self {
        Self::new(SdoSroCommonProps::new(
            StixId::generate(Indicator::TYPE_NAME),
            created,
            modified,
        ))
    }

    /// Replace SDO common properties.
    pub fn common(mut self, common: SdoSroCommonProps) -> Self {
        self.common = Some(common);
        self
    }

    /// Mutate SDO common properties in place.
    pub fn with_common(mut self, f: impl FnOnce(&mut SdoSroCommonProps)) -> Self {
        let common = self.common.get_or_insert_with(|| {
            let ts = StixTimestamp::parse("1970-01-01T00:00:00.000Z").expect("epoch");
            SdoSroCommonProps::new(StixId::generate(Indicator::TYPE_NAME), ts.clone(), ts)
        });
        f(common);
        self
    }

    /// Set the indicator name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the indicator description.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Append one entry to `indicator_types`.
    pub fn indicator_type(mut self, indicator_type: impl Into<String>) -> Self {
        self.indicator_types.push(indicator_type.into());
        self
    }

    /// Replace `indicator_types`.
    pub fn indicator_types(
        mut self,
        indicator_types: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.indicator_types = indicator_types.into_iter().map(Into::into).collect();
        self
    }

    /// STIX patterning language (`pattern_type = stix` on the wire).
    ///
    /// Stores the raw pattern string; does not parse here. With the `pattern` feature,
    /// parse and type-check run in [`build`](Self::build) (same boundary as deserialize).
    pub fn stix_pattern(mut self, raw: impl Into<String>, pattern_version: Option<String>) -> Self {
        self.pattern = Some(PendingPattern::Stix {
            raw: raw.into(),
            pattern_version,
        });
        self
    }

    /// Non-STIX pattern language (YARA, Snort, etc.).
    pub fn external_pattern(
        mut self,
        pattern_type: impl Into<String>,
        raw: impl Into<String>,
        pattern_version: Option<String>,
    ) -> Self {
        self.pattern = Some(PendingPattern::External {
            pattern_type: pattern_type.into(),
            pattern_version,
            raw: raw.into(),
        });
        self
    }

    /// Supply a fully built [`IndicatorPattern`].
    pub fn pattern(mut self, pattern: IndicatorPattern) -> Self {
        self.pattern = Some(PendingPattern::Built(pattern));
        self
    }

    /// Required validity start ([`Indicator::valid_from`]).
    pub fn valid_from(mut self, valid_from: StixTimestamp) -> Self {
        self.valid_from = Some(valid_from);
        self
    }

    /// Optional validity end ([`Indicator::valid_until`]).
    pub fn valid_until(mut self, valid_until: StixTimestamp) -> Self {
        self.valid_until = Some(valid_until);
        self
    }

    /// Append a kill-chain phase.
    pub fn kill_chain_phase(mut self, phase: KillChainPhase) -> Self {
        self.kill_chain_phases.push(phase);
        self
    }

    /// Construct the indicator: parse STIX patterns (when `pattern` is enabled), then
    /// run [`Indicator::validate`].
    ///
    /// Returns [`IndicatorBuilderError::MissingPattern`] if no pattern was set,
    /// [`IndicatorBuilderError::MissingValidFrom`] if `valid_from` is absent, and
    /// [`IndicatorBuilderError::Pattern`] if a STIX pattern fails parse or type-check.
    pub fn build(self) -> Result<Indicator, IndicatorBuilderError> {
        let common = self.common.ok_or(IndicatorBuilderError::MissingCommon)?;
        let valid_from = self
            .valid_from
            .ok_or(IndicatorBuilderError::MissingValidFrom)?;
        let pattern = match self.pattern.ok_or(IndicatorBuilderError::MissingPattern)? {
            PendingPattern::Stix {
                raw,
                pattern_version,
            } => build_stix_pattern(raw, pattern_version)?,
            PendingPattern::External {
                pattern_type,
                pattern_version,
                raw,
            } => IndicatorPattern::Other {
                pattern_type,
                pattern_version,
                raw,
            },
            PendingPattern::Built(pattern) => pattern,
        };
        let indicator = Indicator::from_parts(
            common,
            self.name,
            self.description,
            self.indicator_types,
            pattern,
            valid_from,
            self.valid_until,
            self.kill_chain_phases,
        );
        indicator.validate()?;
        Ok(indicator)
    }
}

#[cfg(feature = "pattern")]
fn build_stix_pattern(
    raw: String,
    pattern_version: Option<String>,
) -> Result<IndicatorPattern, IndicatorBuilderError> {
    Ok(IndicatorPattern::stix(raw, pattern_version)?)
}

#[cfg(not(feature = "pattern"))]
fn build_stix_pattern(
    raw: String,
    pattern_version: Option<String>,
) -> Result<IndicatorPattern, IndicatorBuilderError> {
    Ok(IndicatorPattern::Stix {
        raw,
        pattern_version,
    })
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::model::sdo::IndicatorPattern;

    fn ts(s: &str) -> StixTimestamp {
        StixTimestamp::parse(s).expect("timestamp")
    }

    #[test]
    fn builds_stix_indicator_and_round_trips() {
        let indicator = IndicatorBuilder::with_timestamps(ts("2016-04-06T20:03:48.000Z"), ts(
            "2016-04-06T20:03:48.000Z",
        ))
        .name("Poison Ivy Malware")
        .indicator_type("malicious-activity")
        .stix_pattern(
            "[ file:hashes.'SHA-256' = '4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877' ]",
            None,
        )
        .valid_from(ts("2016-01-01T00:00:00.000Z"))
        .build()
        .expect("build");

        let json = serde_json::to_string(&indicator).expect("serialize");
        let restored: Indicator = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.name, indicator.name);
        assert!(matches!(restored.pattern, IndicatorPattern::Stix { .. }));
    }

    #[test]
    fn builds_external_pattern() {
        let indicator = IndicatorBuilder::with_timestamps(
            ts("2016-04-06T20:03:48.000Z"),
            ts("2016-04-06T20:03:48.000Z"),
        )
        .external_pattern("yara", "rule test { condition: true }", None)
        .valid_from(ts("2016-01-01T00:00:00.000Z"))
        .build()
        .expect("build");
        assert_eq!(indicator.pattern.pattern_type(), "yara");
    }

    #[test]
    fn missing_pattern_is_error() {
        let err = IndicatorBuilder::with_timestamps(
            ts("2016-04-06T20:03:48.000Z"),
            ts("2016-04-06T20:03:48.000Z"),
        )
        .valid_from(ts("2016-01-01T00:00:00.000Z"))
        .build()
        .unwrap_err();
        assert!(matches!(err, IndicatorBuilderError::MissingPattern));
    }

    #[test]
    fn missing_valid_from_is_error() {
        let err = IndicatorBuilder::with_timestamps(
            ts("2016-04-06T20:03:48.000Z"),
            ts("2016-04-06T20:03:48.000Z"),
        )
        .stix_pattern("[ipv4-addr:value = '198.51.100.3']", None)
        .build()
        .unwrap_err();
        assert!(matches!(err, IndicatorBuilderError::MissingValidFrom));
    }

    #[cfg(feature = "pattern")]
    #[test]
    fn invalid_stix_pattern_is_error() {
        let err = IndicatorBuilder::with_timestamps(
            ts("2016-04-06T20:03:48.000Z"),
            ts("2016-04-06T20:03:48.000Z"),
        )
        .stix_pattern("[not-valid", None)
        .valid_from(ts("2016-01-01T00:00:00.000Z"))
        .build()
        .unwrap_err();
        assert!(matches!(err, IndicatorBuilderError::Pattern(_)));
    }
}
