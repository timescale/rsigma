use std::fmt;

use thiserror::Error;

/// Source location within a Sigma document.
///
/// Attached to parse errors when position information is available
/// (e.g. from pest parse failures). Line and column are 1-indexed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceLocation {
    pub line: u32,
    pub col: u32,
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.col)
    }
}

/// Errors that can occur during Sigma rule parsing.
#[derive(Debug, Error)]
pub enum SigmaParserError {
    #[error("YAML parsing error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("{}", format_with_location(.0, .1))]
    Condition(String, Option<SourceLocation>),

    #[error("Unknown modifier '{0}'")]
    UnknownModifier(String),

    #[error("Invalid field specification: {0}")]
    InvalidFieldSpec(String),

    #[error("Invalid rule: {0}")]
    InvalidRule(String),

    #[error("Missing required field '{0}'")]
    MissingField(String),

    #[error("Invalid detection: {0}")]
    InvalidDetection(String),

    #[error("Invalid correlation rule: {0}")]
    InvalidCorrelation(String),

    #[error("Invalid timespan '{0}'")]
    InvalidTimespan(String),

    #[error("Invalid value: {0}")]
    InvalidValue(String),

    #[error("Invalid collection action '{0}'")]
    InvalidAction(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl SigmaParserError {
    /// Returns the source location if this error variant carries one.
    pub fn location(&self) -> Option<SourceLocation> {
        match self {
            SigmaParserError::Condition(_, loc) => *loc,
            _ => None,
        }
    }
}

fn format_with_location(msg: &str, loc: &Option<SourceLocation>) -> String {
    match loc {
        Some(loc) => format!("Condition parse error at {loc}: {msg}"),
        None => format!("Condition parse error: {msg}"),
    }
}

pub type Result<T> = std::result::Result<T, SigmaParserError>;
