use crate::error::ConvertError;

/// Output from converting a single Sigma rule.
#[derive(Debug)]
pub struct ConversionResult {
    pub rule_title: String,
    pub rule_id: Option<String>,
    pub queries: Vec<String>,
}

/// Aggregated output from converting a collection of rules.
#[derive(Debug)]
pub struct ConversionOutput {
    pub queries: Vec<ConversionResult>,
    pub errors: Vec<(String, ConvertError)>,
}

impl ConversionOutput {
    pub fn new() -> Self {
        Self {
            queries: Vec::new(),
            errors: Vec::new(),
        }
    }
}

impl Default for ConversionOutput {
    fn default() -> Self {
        Self::new()
    }
}
