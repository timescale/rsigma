use thiserror::Error;

/// Errors that can occur during Sigma rule parsing.
#[derive(Debug, Error)]
pub enum SigmaParserError {
    #[error("YAML parsing error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Condition parse error: {0}")]
    Condition(String),

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

pub type Result<T> = std::result::Result<T, SigmaParserError>;
