use crate::error::ConvertError;

/// Output from converting a single Sigma rule.
#[derive(Debug)]
pub struct ConversionResult {
    pub rule_title: String,
    pub rule_id: Option<String>,
    pub queries: Vec<String>,
    /// Non-fatal diagnostics for this rule. Populated when a backend can only
    /// approximate a requested feature (the Sigma "should warn, still convert"
    /// case), as opposed to a hard [`ConvertError`] which fails the rule.
    pub warnings: Vec<String>,
}

/// Aggregated output from converting a collection of rules.
#[derive(Debug)]
pub struct ConversionOutput {
    pub queries: Vec<ConversionResult>,
    pub errors: Vec<(String, ConvertError)>,
}

impl ConversionOutput {
    /// Iterate over every non-fatal warning as `(rule_title, message)` pairs.
    pub fn warnings(&self) -> impl Iterator<Item = (&str, &str)> {
        self.queries.iter().flat_map(|r| {
            r.warnings
                .iter()
                .map(move |w| (r.rule_title.as_str(), w.as_str()))
        })
    }

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
