//! Event logsource extraction for opt-in, conflict-based logsource pruning.
//!
//! A [`LogSourceExtractor`] derives a [`LogSource`] from an event by reading
//! configurable field names (defaulting to the literals `product`, `service`,
//! and `category`), falling back to optional static defaults. The result feeds
//! the engine's conflict-based pruning: an event tagged `product: windows`
//! skips `product: linux` rules without dropping Windows-category or
//! logsource-less rules.
//!
//! Extraction is fail-open per dimension: a field that is absent, null, or
//! blank leaves that dimension unset (after the static default is consulted),
//! so a missing tag never prunes anything.

use rsigma_parser::LogSource;

use crate::event::Event;

/// Derives an event [`LogSource`] from configurable fields plus static
/// defaults, for conflict-based logsource pruning on the evaluation hot path.
///
/// Each dimension is resolved independently in precedence order: the value of
/// the configured event field, then the static default, then unset (`None`).
/// A present-but-blank field value is treated as unset.
///
/// # Example
///
/// ```rust
/// use rsigma_eval::LogSourceExtractor;
/// use rsigma_eval::event::JsonEvent;
/// use serde_json::json;
///
/// let extractor = LogSourceExtractor::new();
/// let ev = json!({"product": "windows"});
/// let event = JsonEvent::borrow(&ev);
///
/// let ls = extractor.extract(&event);
/// assert_eq!(ls.product.as_deref(), Some("windows"));
/// assert_eq!(ls.category, None); // absent fields stay unset (fail-open)
/// ```
#[derive(Debug, Clone)]
pub struct LogSourceExtractor {
    product_field: String,
    service_field: String,
    category_field: String,
    defaults: LogSource,
}

impl LogSourceExtractor {
    /// Create an extractor that reads the literal `product`, `service`, and
    /// `category` fields with no static defaults.
    pub fn new() -> Self {
        LogSourceExtractor {
            product_field: "product".to_string(),
            service_field: "service".to_string(),
            category_field: "category".to_string(),
            defaults: LogSource::default(),
        }
    }

    /// Override the event field names read for each dimension.
    #[must_use]
    pub fn with_field_names(
        mut self,
        product_field: impl Into<String>,
        service_field: impl Into<String>,
        category_field: impl Into<String>,
    ) -> Self {
        self.product_field = product_field.into();
        self.service_field = service_field.into();
        self.category_field = category_field.into();
        self
    }

    /// Set the static per-dimension defaults applied when a field is absent.
    /// Only `product`, `service`, and `category` are consulted.
    #[must_use]
    pub fn with_defaults(mut self, defaults: LogSource) -> Self {
        self.defaults = defaults;
        self
    }

    /// Extract the event's logsource. Each dimension resolves to the configured
    /// field value, then the static default, then `None` (fail-open).
    pub fn extract<E: Event>(&self, event: &E) -> LogSource {
        LogSource {
            product: self.resolve(event, &self.product_field, &self.defaults.product),
            service: self.resolve(event, &self.service_field, &self.defaults.service),
            category: self.resolve(event, &self.category_field, &self.defaults.category),
            ..LogSource::default()
        }
    }

    fn resolve<E: Event>(
        &self,
        event: &E,
        field: &str,
        default: &Option<String>,
    ) -> Option<String> {
        if let Some(value) = event.get_field(field)
            && let Some(s) = value.as_str()
        {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        default.clone()
    }
}

impl Default for LogSourceExtractor {
    fn default() -> Self {
        Self::new()
    }
}
