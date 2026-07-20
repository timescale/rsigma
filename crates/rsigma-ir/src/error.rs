//! Error types for the lowering pipeline.

#[derive(Debug, thiserror::Error)]
pub enum IrError {
    #[error("lowering error: {0}")]
    Lowering(String),

    #[error("invalid regex pattern: {0}")]
    InvalidRegex(#[from] regex::Error),

    #[error("invalid CIDR: {0}")]
    InvalidCidr(#[from] ipnet::AddrParseError),

    #[error("unknown detection identifier: {0}")]
    UnknownDetection(String),

    #[error("invalid modifier combination: {0}")]
    InvalidModifiers(String),

    #[error("incompatible value for modifier: {0}")]
    IncompatibleValue(String),

    #[error("expected numeric value: {0}")]
    ExpectedNumeric(String),

    #[error("selector resolved zero matches but condition required at least one: {0:?}")]
    NoSelectorMatches(Vec<String>),

    #[error("custom attribute {0:?} could not be projected: {1}")]
    CustomAttribute(String, String),

    #[error("parser error in IR context: {0}")]
    Parser(#[from] rsigma_parser::SigmaParserError),
}
