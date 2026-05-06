//! File source resolver: reads data from local files.

use std::path::Path;
use std::time::Instant;

use rsigma_eval::pipeline::sources::{DataFormat, ExtractExpr};

use super::extract::apply_extract;
use super::{ResolvedValue, SourceError, SourceErrorKind};

/// Resolve a file source by reading and parsing the file at `path`.
pub async fn resolve_file(
    path: &Path,
    format: DataFormat,
    extract_expr: Option<&ExtractExpr>,
) -> Result<ResolvedValue, SourceError> {
    let contents = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!("failed to read {}: {e}", path.display())),
        })?;

    let parsed = parse_data(&contents, format)?;

    let data = if let Some(expr) = extract_expr {
        apply_extract(&parsed, expr)?
    } else {
        parsed
    };

    Ok(ResolvedValue {
        data,
        resolved_at: Instant::now(),
        from_cache: false,
    })
}

/// Parse raw string data according to the specified format.
pub fn parse_data(raw: &str, format: DataFormat) -> Result<serde_json::Value, SourceError> {
    match format {
        DataFormat::Json => serde_json::from_str(raw).map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Parse(format!("invalid JSON: {e}")),
        }),
        DataFormat::Yaml => {
            let yaml: serde_yaml::Value = serde_yaml::from_str(raw).map_err(|e| SourceError {
                source_id: String::new(),
                kind: SourceErrorKind::Parse(format!("invalid YAML: {e}")),
            })?;
            Ok(super::yaml_value_to_json(&yaml))
        }
        DataFormat::Lines => {
            let lines: Vec<serde_json::Value> = raw
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::Value::String(l.to_string()))
                .collect();
            Ok(serde_json::Value::Array(lines))
        }
        DataFormat::Csv => {
            let mut reader = csv::ReaderBuilder::new()
                .has_headers(true)
                .from_reader(raw.as_bytes());
            let headers: Vec<String> = reader
                .headers()
                .map_err(|e| SourceError {
                    source_id: String::new(),
                    kind: SourceErrorKind::Parse(format!("CSV header error: {e}")),
                })?
                .iter()
                .map(|h| h.to_string())
                .collect();

            let mut rows = Vec::new();
            for result in reader.records() {
                let record = result.map_err(|e| SourceError {
                    source_id: String::new(),
                    kind: SourceErrorKind::Parse(format!("CSV row error: {e}")),
                })?;
                let obj: serde_json::Map<String, serde_json::Value> = headers
                    .iter()
                    .zip(record.iter())
                    .map(|(h, v)| (h.clone(), serde_json::Value::String(v.to_string())))
                    .collect();
                rows.push(serde_json::Value::Object(obj));
            }
            Ok(serde_json::Value::Array(rows))
        }
    }
}
