//! The logsource/field to ATT&CK data-source mapping table.
//!
//! A curated, overridable table that resolves three relationships used by the
//! visibility join:
//!
//! * `logsource (category/product/service) -> {data_source, data_component, products}`
//! * `field -> data_component`
//! * `data_component -> {data_source, technique[]}`
//!
//! The bundled default ([`mapping_default.json`](./mapping_default.json)) ships
//! in-repo so the default invocation needs no network. `--mapping[=<path|url>]`
//! overrides it: a local path is read directly, a URL is fetched through the
//! same 7-day on-disk cache the lint schema download and the coverage
//! cross-references use.

use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rsigma_parser::LogSource;
use serde::Deserialize;

/// Curated default mapping table URL, used by a bare `--mapping` flag. The
/// in-repo bundled copy is the offline default; this URL only matters when the
/// operator explicitly asks for the upstream copy.
pub(crate) const DEFAULT_MAPPING_URL: &str = "https://raw.githubusercontent.com/timescale/rsigma/main/crates/rsigma-cli/src/commands/visibility/mapping_default.json";

/// The bundled default table, compiled into the binary.
const BUNDLED_MAPPING: &str = include_str!("mapping_default.json");

/// Cache freshness for a downloaded `--mapping` table: 7 days, matching the
/// lint schema cache and the coverage cross-references.
const CACHE_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// The deserialized mapping table.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MappingTable {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub provenance: Option<String>,
    #[serde(default)]
    pub logsources: Vec<LogsourceMapping>,
    #[serde(default)]
    pub fields: Vec<FieldMapping>,
    #[serde(default)]
    pub data_components: Vec<DataComponentMapping>,
}

/// One logsource pattern and the ATT&CK data source/component it implies. A
/// `None` field is a wildcard; a logsource matches when every specified field
/// equals the rule's corresponding field.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LogsourceMapping {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    pub data_source: String,
    pub data_component: String,
    #[serde(default)]
    pub products: Vec<String>,
}

/// One field name and the data component its presence attributes to.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct FieldMapping {
    pub field: String,
    pub data_component: String,
}

/// One data component, its parent data source, and the techniques it informs.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DataComponentMapping {
    pub name: String,
    pub data_source: String,
    #[serde(default)]
    pub techniques: Vec<String>,
}

impl MappingTable {
    /// The bundled default table. Panics only if the committed JSON is
    /// malformed, which a unit test guards against.
    pub(crate) fn bundled() -> Self {
        serde_json::from_str(BUNDLED_MAPPING)
            .expect("bundled mapping_default.json is valid (guarded by a unit test)")
    }

    /// Parse a mapping table from raw JSON.
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        serde_json::from_str(raw).map_err(|e| format!("parsing mapping table: {e}"))
    }

    /// Every [`LogsourceMapping`] that matches `ls`. A table entry matches when
    /// each field it specifies (non-`None`) equals the rule logsource's
    /// corresponding field; unspecified fields are wildcards.
    pub(crate) fn logsource_matches(&self, ls: &LogSource) -> Vec<&LogsourceMapping> {
        self.logsources
            .iter()
            .filter(|entry| {
                field_matches(&entry.category, &ls.category)
                    && field_matches(&entry.product, &ls.product)
                    && field_matches(&entry.service, &ls.service)
                    // An all-wildcard entry would match everything; ignore it.
                    && (entry.category.is_some()
                        || entry.product.is_some()
                        || entry.service.is_some())
            })
            .collect()
    }

    /// The data component a field name attributes to, if the table maps it.
    pub(crate) fn field_component(&self, field: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.field == field)
            .map(|f| f.data_component.as_str())
    }

    /// The data source a component belongs to, if known.
    pub(crate) fn component_source(&self, component: &str) -> Option<&str> {
        self.data_components
            .iter()
            .find(|c| c.name == component)
            .map(|c| c.data_source.as_str())
    }

    /// The techniques a data component informs.
    pub(crate) fn component_techniques(&self, component: &str) -> &[String] {
        self.data_components
            .iter()
            .find(|c| c.name == component)
            .map(|c| c.techniques.as_slice())
            .unwrap_or(&[])
    }
}

/// A table field matches the rule's field when the table left it unset
/// (wildcard) or both equal.
fn field_matches(entry: &Option<String>, rule: &Option<String>) -> bool {
    match entry {
        None => true,
        Some(e) => rule.as_deref() == Some(e.as_str()),
    }
}

/// Resolve the mapping table from the `--mapping` spec.
///
/// * `None`: the bundled default table.
/// * `Some("")` or the sentinel default URL: fetch the curated default URL
///   through the cache (a bare `--mapping` flag).
/// * `Some(path)`: read a local JSON file.
/// * `Some(url)`: fetch and cache an `http(s)` URL.
pub(crate) fn resolve(spec: Option<&str>) -> Result<MappingTable, String> {
    match spec {
        None => Ok(MappingTable::bundled()),
        Some("") => {
            let raw = fetch_cached(DEFAULT_MAPPING_URL)?;
            MappingTable::parse(&raw)
        }
        Some(spec) if spec.starts_with("http://") || spec.starts_with("https://") => {
            let raw = fetch_cached(spec)?;
            MappingTable::parse(&raw)
        }
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("could not read mapping table {path}: {e}"))?;
            MappingTable::parse(&raw)
        }
    }
}

/// Resolve the cache path for a URL: `<cache>/rsigma/visibility/<hash>.json`.
fn cache_path(url: &str) -> Option<PathBuf> {
    let dir = dirs::cache_dir()?.join("rsigma").join("visibility");
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    url.hash(&mut hasher);
    let hash = hasher.finish();
    Some(dir.join(format!("{hash:016x}.json")))
}

fn is_fresh(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .map(|age| age.as_secs() < CACHE_MAX_AGE_SECS)
        .unwrap_or(false)
}

/// Download `url`, caching the body under the XDG cache dir. Falls back to a
/// stale cache copy when the network is unavailable; errors only when there is
/// neither a successful download nor any cached copy.
fn fetch_cached(url: &str) -> Result<String, String> {
    let cache = cache_path(url);

    if let Some(path) = &cache
        && is_fresh(path)
        && let Ok(body) = std::fs::read_to_string(path)
    {
        return Ok(body);
    }

    match ureq::get(url).call() {
        Ok(response) => {
            let body = response
                .into_body()
                .read_to_string()
                .map_err(|e| format!("reading response from {url}: {e}"))?;
            if let Some(path) = &cache {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(path, &body);
            }
            Ok(body)
        }
        Err(e) => {
            if let Some(path) = &cache
                && let Ok(body) = std::fs::read_to_string(path)
            {
                eprintln!("warning: download of {url} failed ({e}); using stale cache");
                return Ok(body);
            }
            Err(format!("downloading {url}: {e}"))
        }
    }
}

/// Title-case a logsource product token (`windows` -> `Windows`) for the
/// DeTT&CT `products` field. Multi-segment products keep their separators.
pub(crate) fn humanize_product(product: &str) -> String {
    let mut chars = product.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Collect the data-source `products` hint for a logsource: the rule's own
/// product (title-cased) plus the table entry's product hints, deduplicated.
pub(crate) fn entry_products(ls: &LogSource, entry: &LogsourceMapping) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = entry.products.iter().cloned().collect();
    if let Some(product) = &ls.product {
        out.insert(humanize_product(product));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ls(category: Option<&str>, product: Option<&str>, service: Option<&str>) -> LogSource {
        LogSource {
            category: category.map(String::from),
            product: product.map(String::from),
            service: service.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn bundled_table_parses_and_is_consistent() {
        let t = MappingTable::bundled();
        assert!(!t.logsources.is_empty());
        assert!(!t.fields.is_empty());
        assert!(!t.data_components.is_empty());
        // Every logsource and field data_component resolves to a known
        // data_component, and every component resolves to a data source.
        for entry in &t.logsources {
            assert!(
                t.component_source(&entry.data_component).is_some(),
                "logsource component {} has no data source",
                entry.data_component
            );
        }
        for f in &t.fields {
            assert!(
                t.component_source(&f.data_component).is_some(),
                "field {} component {} has no data source",
                f.field,
                f.data_component
            );
        }
    }

    #[test]
    fn logsource_matches_on_category_wildcard_product() {
        let t = MappingTable::bundled();
        let m = t.logsource_matches(&ls(Some("process_creation"), Some("windows"), None));
        assert!(m.iter().any(|e| e.data_source == "Process"));
        // The category-only entry still matches a product-bearing rule.
        let m2 = t.logsource_matches(&ls(Some("process_creation"), None, None));
        assert!(m2.iter().any(|e| e.data_component == "Process Creation"));
    }

    #[test]
    fn logsource_no_match_returns_empty() {
        let t = MappingTable::bundled();
        let m = t.logsource_matches(&ls(Some("totally_unknown_category"), None, None));
        assert!(m.is_empty());
    }

    #[test]
    fn field_attributes_to_component_and_source() {
        let t = MappingTable::bundled();
        assert_eq!(t.field_component("Image"), Some("Process Creation"));
        assert_eq!(t.component_source("Process Creation"), Some("Process"));
        assert!(t.field_component("DefinitelyNotAField").is_none());
    }

    #[test]
    fn component_techniques_present_and_absent() {
        let t = MappingTable::bundled();
        assert!(
            t.component_techniques("Process Creation")
                .contains(&"T1059".to_string())
        );
        assert!(t.component_techniques("Nonexistent Component").is_empty());
    }

    #[test]
    fn products_combine_rule_and_table_hints() {
        let entry = LogsourceMapping {
            category: Some("process_creation".into()),
            product: None,
            service: None,
            data_source: "Process".into(),
            data_component: "Process Creation".into(),
            products: vec!["Linux".into()],
        };
        let products = entry_products(&ls(Some("process_creation"), Some("windows"), None), &entry);
        assert!(products.contains("Windows"));
        assert!(products.contains("Linux"));
    }

    #[test]
    fn parse_rejects_malformed_json() {
        assert!(MappingTable::parse("{ not json").is_err());
    }
}
