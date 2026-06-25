//! Shared parsing and construction for the `--logsource-*` flags and the
//! `logsource_routing` config block, used by `engine eval` and `engine daemon`.

use rsigma_eval::LogSourceExtractor;
use rsigma_parser::LogSource;

/// A parsed `(product, service, category)` triple, each dimension optional.
type LogsourceTriple = (Option<String>, Option<String>, Option<String>);

/// Parse a `product=...,service=...,category=...` option into a
/// `(product, service, category)` triple. Unknown keys are an error; absent
/// dimensions stay `None`; blank values are ignored.
pub(crate) fn parse_logsource_kv(input: &str) -> Result<LogsourceTriple, String> {
    let mut product = None;
    let mut service = None;
    let mut category = None;

    for pair in input.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| format!("expected key=value, got '{pair}'"))?;
        let value = value.trim();
        let slot = match key.trim() {
            "product" => &mut product,
            "service" => &mut service,
            "category" => &mut category,
            other => {
                return Err(format!(
                    "unknown logsource key '{other}' (expected product, service, or category)"
                ));
            }
        };
        if !value.is_empty() {
            *slot = Some(value.to_string());
        }
    }

    Ok((product, service, category))
}

/// Serialize a config-side dimensions block back into the `key=value,...` form
/// the flag parser accepts, so the overlay can feed config values through the
/// same build path. Returns `None` when no dimension is set.
pub(crate) fn dims_to_kv(
    product: Option<&str>,
    service: Option<&str>,
    category: Option<&str>,
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
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(","))
    }
}

/// Build a [`LogSourceExtractor`] from the resolved flags. Returns `Ok(None)`
/// when routing is disabled. `evtx_default_product` supplies the EVTX-only
/// format default (`product: windows`) when no explicit or static product is
/// configured.
pub(crate) fn build_logsource_extractor(
    enabled: bool,
    field_map: Option<&str>,
    event_logsource: Option<&str>,
    evtx_default_product: bool,
) -> Result<Option<LogSourceExtractor>, String> {
    if !enabled {
        return Ok(None);
    }

    let mut extractor = LogSourceExtractor::new();

    if let Some(map) = field_map {
        let (product, service, category) =
            parse_logsource_kv(map).map_err(|e| format!("invalid --logsource-field-map: {e}"))?;
        extractor = extractor.with_field_names(
            product.unwrap_or_else(|| "product".to_string()),
            service.unwrap_or_else(|| "service".to_string()),
            category.unwrap_or_else(|| "category".to_string()),
        );
    }

    let mut defaults = LogSource::default();
    if let Some(static_ls) = event_logsource {
        let (product, service, category) =
            parse_logsource_kv(static_ls).map_err(|e| format!("invalid --event-logsource: {e}"))?;
        defaults.product = product;
        defaults.service = service;
        defaults.category = category;
    }
    // EVTX-only guardrail: only a platform-locked format may set a default
    // product, and only when none is already configured.
    if evtx_default_product && defaults.product.is_none() {
        defaults.product = Some("windows".to_string());
    }
    if defaults.product.is_some() || defaults.service.is_some() || defaults.category.is_some() {
        extractor = extractor.with_defaults(defaults);
    }

    Ok(Some(extractor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_keys() {
        let (p, s, c) = parse_logsource_kv("product=windows,service=sysmon").unwrap();
        assert_eq!(p.as_deref(), Some("windows"));
        assert_eq!(s.as_deref(), Some("sysmon"));
        assert_eq!(c, None);
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = parse_logsource_kv("product=windows,os=linux").unwrap_err();
        assert!(err.contains("unknown logsource key 'os'"), "got: {err}");
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
}
