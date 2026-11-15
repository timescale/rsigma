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

/// Per-sink OCSF serializer options (version today; incident class lands in Task 4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct OcsfOptions {
    pub version: OcsfVersion,
}

impl OcsfOptions {
    pub fn new(version: OcsfVersion) -> Self {
        Self { version }
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
    fn rejects_unknown_versions() {
        let err = "9.9.9".parse::<OcsfVersion>().unwrap_err();
        assert!(err.contains("unsupported OCSF version"));
        assert!(err.contains("1.1.0"));
        assert!(err.contains("1.3.0"));
    }
}
