//! Include expansion for dynamic pipelines.
//!
//! Expands `Transformation::Include { template }` directives by fetching the
//! referenced source and parsing it as a list of transformation YAML objects,
//! then splicing them into the transformations list.

use std::collections::HashMap;

use rsigma_eval::pipeline::sources::{DynamicSource, SourceType};
use rsigma_eval::pipeline::transformations::Transformation;
use rsigma_eval::{Pipeline, TransformationItem};

/// Maximum include nesting depth (prevents cycles).
const MAX_INCLUDE_DEPTH: usize = 1;

/// Expand all `Include` transformations in a pipeline.
///
/// For each `Include { template }`, the template references a source ID.
/// The resolved source data is expected to be a YAML array of transformation
/// objects. These are parsed and spliced into the pipeline at the include position.
///
/// Security: if `allow_remote_include` is false, includes referencing HTTP or NATS
/// sources produce an error. `sources` holds the external source declarations
/// (loaded via `--source`) used to look up the referenced source's type.
///
/// Recursive includes are not allowed (max depth 1). If an included fragment
/// itself contains `Include` directives, expansion fails with an error.
pub fn expand_includes(
    pipeline: &mut Pipeline,
    resolved: &HashMap<String, serde_json::Value>,
    sources: &[DynamicSource],
    allow_remote_include: bool,
) -> Result<(), String> {
    expand_includes_with_depth(pipeline, resolved, sources, allow_remote_include, 0)
}

fn expand_includes_with_depth(
    pipeline: &mut Pipeline,
    resolved: &HashMap<String, serde_json::Value>,
    sources: &[DynamicSource],
    allow_remote_include: bool,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(
            "recursive includes are not allowed (max depth 1); included content cannot itself contain include directives".to_string()
        );
    }

    let mut expanded_transformations = Vec::new();
    let mut had_include = false;

    for item in &pipeline.transformations {
        if let Transformation::Include { template } = &item.transformation {
            had_include = true;
            let source_id = extract_source_id(template);

            // Security check: block remote includes if not allowed
            if !allow_remote_include
                && let Some(source) = sources.iter().find(|s| s.id == source_id)
            {
                match &source.source_type {
                    SourceType::Http { .. } | SourceType::Nats { .. } => {
                        return Err(format!(
                            "include references remote source '{source_id}'; use --allow-remote-include to permit"
                        ));
                    }
                    _ => {}
                }
            }

            if let Some(data) = resolved.get(&source_id) {
                let items = parse_transformation_array(data)?;

                // Check for nested includes (depth enforcement)
                for parsed_item in &items {
                    if matches!(parsed_item.transformation, Transformation::Include { .. }) {
                        return Err(format!(
                            "included content from source '{source_id}' contains nested include directives; recursive includes are not allowed (max depth 1)"
                        ));
                    }
                }

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

    // Convert JSON -> YAML string -> yaml_serde::Value, then use the eval parser
    let yaml_str =
        serde_json::to_string(data).map_err(|e| format!("include serialization: {e}"))?;
    let yaml_val: yaml_serde::Value = yaml_serde::from_str(&yaml_str)
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

    #[test]
    fn nested_include_rejected() {
        let mut pipeline = Pipeline {
            name: "test".to_string(),
            priority: 0,
            vars: HashMap::new(),
            transformations: vec![TransformationItem {
                id: None,
                transformation: Transformation::Include {
                    template: "${source.transforms}".to_string(),
                },
                rule_conditions: vec![],
                rule_cond_expr: None,
                detection_item_conditions: vec![],
                field_name_conditions: vec![],
                field_name_cond_not: false,
            }],
            finalizers: vec![],
            source_refs: vec![],
        };

        // The resolved source data contains an include directive itself
        let nested_yaml = serde_json::json!([
            {"type": "include", "include": "${source.other}"}
        ]);
        let mut resolved = HashMap::new();
        resolved.insert("transforms".to_string(), nested_yaml);

        let result = expand_includes(&mut pipeline, &resolved, &[], true);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("nested include") || err.contains("recursive"),
            "error should mention nesting: {err}"
        );
    }
}
