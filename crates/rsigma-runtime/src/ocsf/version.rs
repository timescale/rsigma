//! Pinned OCSF schema versions for finding serializers.

use std::fmt;
use std::str::FromStr;

/// Closed set of OCSF schema versions rsigma can emit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OcsfVersion {
    /// Default; matches the committed `1.1.0` conformance fixtures.
    #[default]
    V1_1_0,
    /// Additional pinned minor (field inventory identical to `1.1.0` for class 2004 today).
    V1_3_0,
}

impl OcsfVersion {
    /// Wire string recorded in every finding's `metadata.version`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1_1_0 => "1.1.0",
            Self::V1_3_0 => "1.3.0",
        }
    }

    /// Directory name under `tests/fixtures/ocsf/` for conformance schemas.
    pub fn fixture_dir(self) -> &'static str {
        match self {
            Self::V1_1_0 => "1.1.0",
            Self::V1_3_0 => "1.3.0",
        }
    }
}

impl FromStr for OcsfVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1.1.0" => Ok(Self::V1_1_0),
            "1.3.0" => Ok(Self::V1_3_0),
            other => Err(format!(
                "unsupported OCSF version '{other}' (supported: 1.1.0, 1.3.0)"
            )),
        }
    }
}

impl fmt::Display for OcsfVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The OCSF class alert-pipeline and risk incidents serialize into.
///
/// Detections, correlations, dedup summaries, and risk events are always
/// Detection Findings; only the two incident shapes can be Incident Findings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OcsfIncidentClass {
    /// Detection Finding (2004), the default.
    #[default]
    DetectionFinding,
    /// Incident Finding (2005), referencing contributing Detection Findings.
    IncidentFinding,
}

impl OcsfIncidentClass {
    /// The OCSF `class_uid`, as written in a sink spec.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DetectionFinding => "2004",
            Self::IncidentFinding => "2005",
        }
    }
}

impl FromStr for OcsfIncidentClass {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "2004" => Ok(Self::DetectionFinding),
            "2005" => Ok(Self::IncidentFinding),
            other => Err(format!(
                "unsupported OCSF incident class '{other}' (supported: 2004, 2005)"
            )),
        }
    }
}

impl fmt::Display for OcsfIncidentClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-sink OCSF serializer options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct OcsfOptions {
    /// Schema version recorded in `metadata.version`.
    pub version: OcsfVersion,
    /// Class the incident shapes serialize into.
    pub incident_class: OcsfIncidentClass,
    /// Group name required on class-2005 findings (`assignee_group.name`).
    ///
    /// Process-lifetime: the daemon leaks the sink-spec value so options stay `Copy`.
    pub assignee_group: Option<&'static str>,
}

impl OcsfOptions {
    /// Options for `version` with the default incident class.
    pub fn new(version: OcsfVersion) -> Self {
        Self {
            version,
            incident_class: OcsfIncidentClass::default(),
            assignee_group: None,
        }
    }

    /// Select the class incidents serialize into.
    #[must_use]
    pub fn with_incident_class(mut self, incident_class: OcsfIncidentClass) -> Self {
        self.incident_class = incident_class;
        self
    }

    /// Name the `assignee_group` class 2005 requires.
    ///
    /// `name` must already be `'static` (the daemon leaks the sink-spec value).
    #[must_use]
    pub fn with_assignee_group(mut self, name: &'static str) -> Self {
        self.assignee_group = Some(name);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_versions() {
        assert_eq!("1.1.0".parse::<OcsfVersion>().unwrap(), OcsfVersion::V1_1_0);
        assert_eq!("1.3.0".parse::<OcsfVersion>().unwrap(), OcsfVersion::V1_3_0);
    }

    #[test]
    fn parses_incident_classes_and_rejects_others() {
        assert_eq!(
            "2004".parse::<OcsfIncidentClass>().unwrap(),
            OcsfIncidentClass::DetectionFinding
        );
        assert_eq!(
            "2005".parse::<OcsfIncidentClass>().unwrap(),
            OcsfIncidentClass::IncidentFinding
        );
        let err = "2003".parse::<OcsfIncidentClass>().unwrap_err();
        assert!(err.contains("2004, 2005"), "{err}");
        assert_eq!(
            OcsfOptions::default().incident_class,
            OcsfIncidentClass::DetectionFinding
        );
    }

    #[test]
    fn rejects_unknown_versions() {
        let err = "9.9.9".parse::<OcsfVersion>().unwrap_err();
        assert!(err.contains("unsupported OCSF version"));
        assert!(err.contains("1.1.0"));
        assert!(err.contains("1.3.0"));
    }
}
