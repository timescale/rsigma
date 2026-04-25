use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConvertError {
    #[error("backend does not support modifier: {0}")]
    UnsupportedModifier(String),

    #[error("backend does not support keyword/unbound detection")]
    UnsupportedKeyword,

    #[error("backend does not support correlation type: {0}")]
    UnsupportedCorrelation(String),

    #[error("backend requires a processing pipeline")]
    PipelineRequired,

    #[error("field name is required but missing")]
    MissingFieldName,

    #[error("unsupported value type: {0}")]
    UnsupportedValue(String),

    #[error("CIDR parse error: {0}")]
    CidrParse(String),

    #[error("regex error: {0}")]
    Regex(String),

    #[error("rule conversion failed: {0}")]
    RuleConversion(String),

    #[error("pipeline error: {0}")]
    Pipeline(#[from] rsigma_eval::error::EvalError),
}

pub type Result<T> = std::result::Result<T, ConvertError>;
