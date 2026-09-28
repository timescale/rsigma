//! Shared parsing and construction for the `--logsource-*` flags and the
//! `logsource_routing` config block, used by `engine eval` and `engine daemon`.

use std::collections::{BTreeMap, HashMap};

use rsigma_eval::FieldLogSourceExtractor;
use rsigma_parser::LogSource;

/// A parsed logsource option: the three standard dimensions plus any custom
/// dimensions written as `custom.<name>=<value>`.
///
/// For `--logsource-field-map` the values are event field names; for
/// `--event-logsource` they are literal logsource values. The parser is the
/// same for both; the caller interprets the meaning.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ParsedLogsource {
    pub product: Option<String>,
    pub service: Option<String>,
    pub category: Option<String>,
    /// `(custom dimension name, value)` pairs in input order.
    pub custom: Vec<(String, String)>,
}

/// Parse a `product=...,service=...,category=...,custom.<name>=...` option.
/// Bare keys other than the three standard dimensions are an error (typo
/// protection); custom dimensions must use the explicit `custom.` prefix.
/// Absent dimensions stay unset; blank values are ignored.
pub(crate) fn parse_logsource_kv(input: &str) -> Result<ParsedLogsource, String> {
    let mut out = ParsedLogsource::default();

    for pair in input.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| format!("expected key=value, got '{pair}'"))?;
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key {
            "product" => out.product = Some(value.to_string()),
            "service" => out.service = Some(value.to_string()),
            "category" => out.category = Some(value.to_string()),
            other => {
                if let Some(dimension) = other.strip_prefix("custom.") {
                    if dimension.is_empty() {
                        return Err(format!("empty custom dimension name in '{pair}'"));
                    }
                    out.custom.push((dimension.to_string(), value.to_string()));
                } else {
                    return Err(format!(
                        "unknown logsource key '{other}' (expected product, service, category, or custom.<name>)"
                    ));
                }
            }
        }
    }

    Ok(out)
}

/// Serialize a config-side dimensions block back into the `key=value,...` form
/// the flag parser accepts, so the overlay can feed config values through the
/// same build path. Returns `None` when nothing is set. Custom dimensions are
/// emitted in sorted order for deterministic output.
pub(crate) fn dims_to_kv(
    product: Option<&str>,
    service: Option<&str>,
    category: Option<&str>,
    custom: Option<&HashMap<String, String>>,
) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(p) = product {
        parts.push(format!("product={p}"));
    }
    if let Some(s) = service {
        parts.push(format!("service={s}"));
    }
    if let Some(c) = category {
        parts.push(format!("category={c}"));
    }
    if let Some(custom) = custom {
        for (key, value) in custom.iter().collect::<BTreeMap<_, _>>() {
            parts.push(format!("custom.{key}={value}"));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(","))
    }
}

/// Build a [`FieldLogSourceExtractor`] from the resolved flags. Returns `Ok(None)`
/// when routing is disabled. `evtx_default_product` supplies the EVTX-only
/// format default (`product: windows`) when no explicit or static product is
/// configured.
pub(crate) fn build_logsource_extractor(
    enabled: bool,
    field_map: Option<&str>,
    event_logsource: Option<&str>,
    evtx_default_product: bool,
) -> Result<Option<FieldLogSourceExtractor>, String> {
    if !enabled {
        return Ok(None);
    }

    let mut extractor = FieldLogSourceExtractor::new();

    if let Some(map) = field_map {
        let parsed =
            parse_logsource_kv(map).map_err(|e| format!("invalid --logsource-field-map: {e}"))?;
        extractor = extractor.with_field_names(
            parsed.product.unwrap_or_else(|| "product".to_string()),
            parsed.service.unwrap_or_else(|| "service".to_string()),
            parsed.category.unwrap_or_else(|| "category".to_string()),
        );
        if !parsed.custom.is_empty() {
            extractor = extractor.with_custom_fields(parsed.custom);
        }
    }

    let mut defaults = LogSource::default();
    if let Some(static_ls) = event_logsource {
        let parsed =
            parse_logsource_kv(static_ls).map_err(|e| format!("invalid --event-logsource: {e}"))?;
        defaults.product = parsed.product;
        defaults.service = parsed.service;
        defaults.category = parsed.category;
        for (dimension, value) in parsed.custom {
            defaults.custom.insert(dimension, value);
        }
    }
    // EVTX-only guardrail: only a platform-locked format may set a default
    // product, and only when none is already configured.
    if evtx_default_product && defaults.product.is_none() {
        defaults.product = Some("windows".to_string());
    }
    if defaults.product.is_some()
        || defaults.service.is_some()
        || defaults.category.is_some()
        || !defaults.custom.is_empty()
    {
        extractor = extractor.with_defaults(defaults);
    }

    Ok(Some(extractor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::LogSourceExtractor;

    #[test]
    fn parses_known_keys() {
        let parsed = parse_logsource_kv("product=windows,service=sysmon").unwrap();
        assert_eq!(parsed.product.as_deref(), Some("windows"));
        assert_eq!(parsed.service.as_deref(), Some("sysmon"));
        assert_eq!(parsed.category, None);
        assert!(parsed.custom.is_empty());
    }

    #[test]
    fn parses_custom_dimensions() {
        let parsed =
            parse_logsource_kv("product=windows,custom.tenant=acme,custom.region=eu").unwrap();
        assert_eq!(parsed.product.as_deref(), Some("windows"));
        assert_eq!(
            parsed.custom,
            vec![
                ("tenant".to_string(), "acme".to_string()),
                ("region".to_string(), "eu".to_string()),
            ]
        );
    }

    #[test]
    fn rejects_unknown_bare_keys() {
        let err = parse_logsource_kv("product=windows,os=linux").unwrap_err();
        assert!(err.contains("unknown logsource key 'os'"), "got: {err}");
    }

    #[test]
    fn rejects_empty_custom_name() {
        let err = parse_logsource_kv("custom.=x").unwrap_err();
        assert!(err.contains("empty custom dimension name"), "got: {err}");
    }

    #[test]
    fn dims_to_kv_emits_sorted_custom() {
        let mut custom = HashMap::new();
        custom.insert("tenant".to_string(), "acme".to_string());
        custom.insert("region".to_string(), "eu".to_string());
        let kv = dims_to_kv(Some("windows"), None, None, Some(&custom)).unwrap();
        assert_eq!(kv, "product=windows,custom.region=eu,custom.tenant=acme");
    }

    #[test]
    fn disabled_returns_none() {
        assert!(
            build_logsource_extractor(false, None, None, false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn evtx_default_supplies_windows_when_unset() {
        let extractor = build_logsource_extractor(true, None, None, true)
            .unwrap()
            .expect("routing enabled");
        let ev = serde_json::json!({"CommandLine": "whoami"});
        let event = rsigma_eval::event::JsonEvent::borrow(&ev);
        assert_eq!(
            extractor.extract(&event).product.as_deref(),
            Some("windows")
        );
    }

    #[test]
    fn explicit_product_overrides_evtx_default() {
        let extractor = build_logsource_extractor(true, None, Some("product=linux"), true)
            .unwrap()
            .expect("routing enabled");
        let ev = serde_json::json!({});
        let event = rsigma_eval::event::JsonEvent::borrow(&ev);
        assert_eq!(extractor.extract(&event).product.as_deref(), Some("linux"));
    }

    #[test]
    fn custom_field_map_and_static_default_resolve() {
        // Field map reads custom dimension `tenant` from event field `org`;
        // static default supplies `region`.
        let extractor = build_logsource_extractor(
            true,
            Some("custom.tenant=org"),
            Some("custom.region=eu"),
            false,
        )
        .unwrap()
        .expect("routing enabled");
        let ev = serde_json::json!({"org": "acme"});
        let event = rsigma_eval::event::JsonEvent::borrow(&ev);
        let ls = extractor.extract(&event);
        assert_eq!(ls.custom.get("tenant").map(String::as_str), Some("acme"));
        assert_eq!(ls.custom.get("region").map(String::as_str), Some("eu"));
    }
}
