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

/// Why [`OcsfOptions`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcsfOptionsError {
    message: &'static str,
}

impl fmt::Display for OcsfOptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for OcsfOptionsError {}

/// Per-sink OCSF serializer options.
///
/// Class 2005 is only representable through [`OcsfOptions::with_incident_finding`],
/// which requires a non-empty assignee group. Fields stay private so a later
/// option is not a breaking change.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct OcsfOptions {
    version: OcsfVersion,
    incident_class: OcsfIncidentClass,
    assignee_group: Option<String>,
}

impl Default for OcsfOptions {
    fn default() -> Self {
        Self::new(OcsfVersion::default())
    }
}

impl OcsfOptions {
    /// Class 2004 options for `version`, with no assignee group.
    pub fn new(version: OcsfVersion) -> Self {
        Self {
            version,
            incident_class: OcsfIncidentClass::DetectionFinding,
            assignee_group: None,
        }
    }

    /// Schema version recorded in `metadata.version`.
    pub fn version(&self) -> OcsfVersion {
        self.version
    }

    /// Class the incident shapes serialize into.
    pub fn incident_class(&self) -> OcsfIncidentClass {
        self.incident_class
    }

    /// `assignee_group.name` when these options select class 2005.
    pub fn assignee_group(&self) -> Option<&str> {
        self.assignee_group.as_deref()
    }

    /// The group name class 2005 requires, or an error when these options have none.
    pub(crate) fn require_assignee_group(&self) -> Result<&str, OcsfOptionsError> {
        self.assignee_group.as_deref().ok_or(OcsfOptionsError {
            message: "class 2005 requires an assignee group",
        })
    }

    /// Keep class 2004. Passing class 2005 is rejected: use [`Self::with_incident_finding`].
    pub fn with_incident_class(
        self,
        incident_class: OcsfIncidentClass,
    ) -> Result<Self, OcsfOptionsError> {
        match incident_class {
            OcsfIncidentClass::DetectionFinding => Ok(Self {
                incident_class: OcsfIncidentClass::DetectionFinding,
                assignee_group: None,
                ..self
            }),
            OcsfIncidentClass::IncidentFinding => Err(OcsfOptionsError {
                message: "class 2005 requires with_incident_finding(<non-empty group>)",
            }),
        }
    }

    /// Select class 2005 and name its `assignee_group`.
    ///
    /// An empty or whitespace-only name is rejected, so a class-2005 finding
    /// built from these options always has a group.
    pub fn with_incident_finding(self, name: impl AsRef<str>) -> Result<Self, OcsfOptionsError> {
        let name = name.as_ref().trim();
        if name.is_empty() {
            return Err(OcsfOptionsError {
                message: "assignee group name must not be empty",
            });
        }
        Ok(Self {
            incident_class: OcsfIncidentClass::IncidentFinding,
            assignee_group: Some(name.to_string()),
            ..self
        })
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
            OcsfOptions::default().incident_class(),
            OcsfIncidentClass::DetectionFinding
        );
    }

    #[test]
    fn class_2005_requires_a_non_empty_assignee_group() {
        let err = OcsfOptions::default()
            .with_incident_class(OcsfIncidentClass::IncidentFinding)
            .unwrap_err();
        assert!(err.to_string().contains("with_incident_finding"));
        assert!(OcsfOptions::default().with_incident_finding("   ").is_err());
        let opts = OcsfOptions::default().with_incident_finding("soc").unwrap();
        assert_eq!(opts.incident_class(), OcsfIncidentClass::IncidentFinding);
        assert_eq!(opts.assignee_group(), Some("soc"));
    }

    #[test]
    fn rejects_unknown_versions() {
        let err = "9.9.9".parse::<OcsfVersion>().unwrap_err();
        assert!(err.contains("unsupported OCSF version"));
        assert!(err.contains("1.1.0"));
        assert!(err.contains("1.3.0"));
    }
}
