//! Granular marking selector matching (STIX §7.2.3).

use crate::model::validate::{resolve_selector_value, validate_granular_selector_syntax};

/// Returns true when `selector` applies to `property` on an object.
pub fn selector_applies_to_property(selector: &str, property: &str) -> bool {
    if validate_granular_selector_syntax(selector).is_err() {
        return false;
    }
    if selector == property {
        return true;
    }
    property.starts_with(&format!("{selector}."))
        || selector.starts_with(&format!("{property}."))
        || property.starts_with(&format!("{selector}["))
        || selector.starts_with(&format!("{property}["))
}

/// Returns true when `selector` resolves on the wire JSON for `object`.
pub fn selector_resolves_on_object(object: &serde_json::Value, selector: &str) -> bool {
    validate_granular_selector_syntax(selector).is_ok()
        && resolve_selector_value(object, selector).is_some()
}

/// Returns true when `granular_selector` marks content selected by `target_selector`.
pub fn selector_matches_target(
    object: &serde_json::Value,
    granular_selector: &str,
    target_selector: &str,
) -> bool {
    if !selector_resolves_on_object(object, granular_selector) {
        return false;
    }
    if granular_selector == target_selector {
        return true;
    }
    selector_applies_to_property(granular_selector, target_selector)
        || selector_applies_to_property(target_selector, granular_selector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_prefix_matching() {
        assert!(selector_applies_to_property("name", "name"));
        assert!(selector_applies_to_property("labels", "labels.[0]"));
        assert!(!selector_applies_to_property("name", "description"));
    }

    #[test]
    fn selector_must_resolve_on_object() {
        let wire = serde_json::json!({
            "type": "indicator",
            "name": "test",
            "labels": ["a", "b"]
        });
        assert!(selector_matches_target(&wire, "name", "name"));
        assert!(selector_matches_target(&wire, "labels", "labels.[0]"));
        assert!(!selector_matches_target(&wire, "pattern", "name"));
    }
}
