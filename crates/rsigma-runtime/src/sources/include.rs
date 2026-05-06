//! Include expansion for dynamic pipelines.
//!
//! Expands `Transformation::Include { template }` directives by fetching the
//! referenced source and parsing it as a list of transformation YAML objects,
//! then splicing them into the transformations list.

use std::collections::HashMap;

use rsigma_eval::pipeline::sources::SourceType;
use rsigma_eval::pipeline::transformations::Transformation;
use rsigma_eval::{Pipeline, TransformationItem};

/// Expand all `Include` transformations in a pipeline.
///
/// For each `Include { template }`, the template references a source ID.
/// The resolved source data is expected to be a YAML array of transformation
/// objects. These are parsed and spliced into the pipeline at the include position.
///
/// Security: if `allow_remote_include` is false, includes referencing HTTP or NATS
/// sources produce an error.
pub fn expand_includes(
    pipeline: &mut Pipeline,
    resolved: &HashMap<String, serde_json::Value>,
    allow_remote_include: bool,
) -> Result<(), String> {
    let mut expanded_transformations = Vec::new();
    let mut had_include = false;

    for item in &pipeline.transformations {
        if let Transformation::Include { template } = &item.transformation {
            had_include = true;
            let source_id = extract_source_id(template);

            // Security check: block remote includes if not allowed
            if !allow_remote_include
                && let Some(source) = pipeline.sources.iter().find(|s| s.id == source_id)
            {
                match &source.source_type {
                    SourceType::Http { .. } | SourceType::Nats { .. } => {
                        return Err(format!(
                            "include references remote source '{}'; use --allow-remote-include to permit",
                            source_id
                        ));
                    }
                    _ => {}
                }
            }

            if let Some(data) = resolved.get(&source_id) {
                let items = parse_transformation_array(data)?;
                expanded_transformations.extend(items);
            } else {
                return Err(format!(
                    "include references unresolved source '{source_id}'"
                ));
            }
        } else {
            expanded_transformations.push(item.clone());
        }
    }

    if had_include {
        pipeline.transformations = expanded_transformations;
    }

    Ok(())
}

/// Extract the source ID from a template string like `${source.my_transforms}`.
fn extract_source_id(template: &str) -> String {
    let trimmed = template.trim();
    if let Some(inner) = trimmed.strip_prefix("${source.")
        && let Some(id) = inner.strip_suffix('}')
    {
        return id.split('.').next().unwrap_or(id).to_string();
    }
    trimmed.to_string()
}

/// Parse a JSON value as an array of transformation objects.
///
/// Each element should be a JSON object with at minimum a "type" field.
/// Uses rsigma-eval's `parse_transformation_items` to handle the full
/// transformation grammar.
fn parse_transformation_array(data: &serde_json::Value) -> Result<Vec<TransformationItem>, String> {
    if !data.is_array() {
        return Err("include source data must be an array of transformation objects".to_string());
    }

    // Convert JSON -> YAML string -> serde_yaml::Value, then use the eval parser
    let yaml_str =
        serde_json::to_string(data).map_err(|e| format!("include serialization: {e}"))?;
    let yaml_val: serde_yaml::Value = serde_yaml::from_str(&yaml_str)
        .map_err(|e| format!("include data is not valid YAML: {e}"))?;

    rsigma_eval::parse_transformation_items(&yaml_val)
        .map_err(|e| format!("include parse error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_source_id_simple() {
        assert_eq!(
            extract_source_id("${source.my_transforms}"),
            "my_transforms"
        );
    }

    #[test]
    fn extract_source_id_with_path() {
        assert_eq!(extract_source_id("${source.config.transforms}"), "config");
    }

    #[test]
    fn extract_source_id_plain_string() {
        assert_eq!(extract_source_id("my_source"), "my_source");
    }
}
