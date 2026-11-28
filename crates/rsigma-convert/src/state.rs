use std::collections::HashMap;

/// Trait for deferred query expressions that are finalized after main condition conversion.
///
/// In pySigma, deferred expressions postpone part of the query (e.g. Splunk `| regex`,
/// `| where`) to the `finish_query` phase. Each backend can define custom deferred types.
pub trait DeferredExpression: std::fmt::Debug + Send + Sync {
    fn finalize(&self) -> String;
    fn negate(&mut self);
    fn is_negated(&self) -> bool;
}

/// Simple template-based deferred expression (covers most text-backend cases).
#[derive(Debug, Clone)]
pub struct DeferredTextExpression {
    pub template: String,
    pub field: String,
    pub value: String,
    pub negated: bool,
    /// `(positive_op, negated_op)` substituted into `{op}` in the template.
    pub operators: (&'static str, &'static str),
}

impl DeferredExpression for DeferredTextExpression {
    fn finalize(&self) -> String {
        let op = if self.negated {
            self.operators.1
        } else {
            self.operators.0
        };
        crate::backend::fill_placeholders(
            &self.template,
            &[("field", &self.field), ("value", &self.value), ("op", op)],
        )
    }

    fn negate(&mut self) {
        self.negated = !self.negated;
    }

    fn is_negated(&self) -> bool {
        self.negated
    }
}

/// Return type for conversion methods that may produce a direct string or a deferred expression.
#[derive(Debug)]
pub enum ConvertResult {
    Query(String),
    Deferred(Box<dyn DeferredExpression>),
}

/// Per-condition conversion state carried through the conversion of a single rule condition.
#[derive(Debug, Default)]
pub struct ConversionState {
    /// Key-value state inherited from pipeline `SetState` transformations.
    pub processing_state: HashMap<String, serde_json::Value>,
    /// Deferred query parts to be appended after the main condition.
    pub deferred: Vec<Box<dyn DeferredExpression>>,
}

impl ConversionState {
    pub fn new(processing_state: HashMap<String, serde_json::Value>) -> Self {
        Self {
            processing_state,
            deferred: Vec::new(),
        }
    }

    pub fn add_deferred(&mut self, expr: Box<dyn DeferredExpression>) {
        self.deferred.push(expr);
    }

    pub fn has_deferred(&self) -> bool {
        !self.deferred.is_empty()
    }

    pub fn get_state_str(&self, key: &str) -> Option<&str> {
        self.processing_state.get(key)?.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_placeholders_are_filled_in_one_pass() {
        let mut expr = DeferredTextExpression {
            template: "| where {field} {op} \"{value}\"".to_string(),
            field: "a{value}".to_string(),
            value: "{op}{field}".to_string(),
            negated: false,
            operators: ("=", "!="),
        };
        assert_eq!(expr.finalize(), "| where a{value} = \"{op}{field}\"");
        expr.negate();
        assert_eq!(expr.finalize(), "| where a{value} != \"{op}{field}\"");
    }
}
