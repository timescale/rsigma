//! Template expansion for dynamic pipeline sources.
//!
//! Walks a pipeline's fields and replaces `${source.X}` and `${source.X.path.to.field}`
//! references with resolved data from the source resolution map.

use std::collections::HashMap;

use regex::Regex;
use rsigma_eval::Pipeline;
use std::sync::LazyLock;

static SOURCE_TEMPLATE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{source\.([a-zA-Z0-9_]+)(?:\.([a-zA-Z0-9_.]+))?\}").unwrap());

/// Expands `${source.*}` template references in a pipeline using resolved source data.
pub struct TemplateExpander;

impl TemplateExpander {
    /// Expand all `${source.*}` references in the pipeline's vars and return an updated pipeline.
    ///
    /// The pipeline's `vars` values are expanded by replacing template expressions
    /// with data from the `resolved` map. Transformation fields containing templates
    /// are left in place (they are handled at apply-time, not here) since transformations
    /// use typed structures rather than raw strings.
    pub fn expand(pipeline: &Pipeline, resolved: &HashMap<String, serde_json::Value>) -> Pipeline {
        let mut expanded = pipeline.clone();

        // Expand vars
        for (_var_name, values) in expanded.vars.iter_mut() {
            let mut new_values = Vec::new();
            for val in values.iter() {
                if let Some(expanded_vals) = Self::expand_string_value(val, resolved) {
                    new_values.extend(expanded_vals);
                } else {
                    new_values.push(val.clone());
                }
            }
            *values = new_values;
        }

        expanded
    }

    /// Try to expand a single string value containing `${source.*}` templates.
    ///
    /// Returns `None` if the string contains no templates.
    /// Returns `Some(vec)` with the expanded values if templates were found.
    fn expand_string_value(
        value: &str,
        resolved: &HashMap<String, serde_json::Value>,
    ) -> Option<Vec<String>> {
        if !value.contains("${source.") {
            return None;
        }

        // If the entire value is a single template reference, replace it directly
        if let Some(caps) = SOURCE_TEMPLATE_RE.captures(value)
            && caps.get(0).unwrap().as_str() == value
        {
            let source_id = caps.get(1).unwrap().as_str();
            let sub_path = caps.get(2).map(|m| m.as_str());

            if let Some(data) = resolved.get(source_id) {
                let target = if let Some(path) = sub_path {
                    navigate_path(data, path)
                } else {
                    Some(data)
                };

                if let Some(val) = target {
                    return Some(json_to_string_vec(val));
                }
            }

            return None;
        }

        // Otherwise, do substring replacement (inline templates within larger strings)
        let result = SOURCE_TEMPLATE_RE
            .replace_all(value, |caps: &regex::Captures| {
                let source_id = caps.get(1).unwrap().as_str();
                let sub_path = caps.get(2).map(|m| m.as_str());

                if let Some(data) = resolved.get(source_id) {
                    let target = if let Some(path) = sub_path {
                        navigate_path(data, path)
                    } else {
                        Some(data)
                    };

                    if let Some(val) = target {
                        return json_to_single_string(val);
                    }
                }

                caps.get(0).unwrap().as_str().to_string()
            })
            .to_string();

        Some(vec![result])
    }
}

/// Navigate a dot-separated path into a JSON value.
///
/// E.g., `"field_mapping.sysmon"` navigates `data["field_mapping"]["sysmon"]`.
fn navigate_path<'a>(data: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = data;
    for segment in path.split('.') {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(segment)?;
            }
            serde_json::Value::Array(arr) => {
                let idx: usize = segment.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

/// Convert a JSON value to a vector of strings for use in pipeline vars.
///
/// Arrays are flattened into multiple string entries.
/// Objects are serialized as JSON strings.
/// Scalars become single-element vectors.
fn json_to_string_vec(val: &serde_json::Value) -> Vec<String> {
    match val {
        serde_json::Value::Array(arr) => arr.iter().map(json_to_single_string).collect(),
        serde_json::Value::Null => vec![],
        other => vec![json_to_single_string(other)],
    }
}

/// Convert a single JSON value to a string representation.
fn json_to_single_string(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_simple_var() {
        let mut vars = HashMap::new();
        vars.insert(
            "admin_emails".to_string(),
            vec!["${source.admin_emails}".to_string()],
        );

        let pipeline = Pipeline {
            name: "test".to_string(),
            priority: 0,
            vars,
            transformations: vec![],
            finalizers: vec![],
            source_refs: vec![],
        };

        let mut resolved = HashMap::new();
        resolved.insert(
            "admin_emails".to_string(),
            serde_json::json!(["admin@corp.com", "root@corp.com"]),
        );

        let expanded = TemplateExpander::expand(&pipeline, &resolved);
        assert_eq!(
            expanded.vars.get("admin_emails").unwrap(),
            &vec!["admin@corp.com".to_string(), "root@corp.com".to_string()]
        );
    }

    #[test]
    fn expand_nested_path() {
        let mut vars = HashMap::new();
        vars.insert(
            "log_index".to_string(),
            vec!["${source.env_config.log_index}".to_string()],
        );

        let pipeline = Pipeline {
            name: "test".to_string(),
            priority: 0,
            vars,
            transformations: vec![],
            finalizers: vec![],
            source_refs: vec![],
        };

        let mut resolved = HashMap::new();
        resolved.insert(
            "env_config".to_string(),
            serde_json::json!({"log_index": "security-events", "retention": "30d"}),
        );

        let expanded = TemplateExpander::expand(&pipeline, &resolved);
        assert_eq!(
            expanded.vars.get("log_index").unwrap(),
            &vec!["security-events".to_string()]
        );
    }

    #[test]
    fn expand_inline_template() {
        let mut vars = HashMap::new();
        vars.insert(
            "index_pattern".to_string(),
            vec!["logs-${source.env_config.env}-*".to_string()],
        );

        let pipeline = Pipeline {
            name: "test".to_string(),
            priority: 0,
            vars,
            transformations: vec![],
            finalizers: vec![],
            source_refs: vec![],
        };

        let mut resolved = HashMap::new();
        resolved.insert(
            "env_config".to_string(),
            serde_json::json!({"env": "production"}),
        );

        let expanded = TemplateExpander::expand(&pipeline, &resolved);
        assert_eq!(
            expanded.vars.get("index_pattern").unwrap(),
            &vec!["logs-production-*".to_string()]
        );
    }

    #[test]
    fn static_vars_unchanged() {
        let mut vars = HashMap::new();
        vars.insert("static".to_string(), vec!["no_template_here".to_string()]);

        let pipeline = Pipeline {
            name: "test".to_string(),
            priority: 0,
            vars,
            transformations: vec![],
            finalizers: vec![],
            source_refs: vec![],
        };

        let resolved = HashMap::new();
        let expanded = TemplateExpander::expand(&pipeline, &resolved);
        assert_eq!(
            expanded.vars.get("static").unwrap(),
            &vec!["no_template_here".to_string()]
        );
    }

    #[test]
    fn unresolved_template_kept_as_is() {
        let mut vars = HashMap::new();
        vars.insert(
            "missing".to_string(),
            vec!["${source.nonexistent}".to_string()],
        );

        let pipeline = Pipeline {
            name: "test".to_string(),
            priority: 0,
            vars,
            transformations: vec![],
            finalizers: vec![],
            source_refs: vec![],
        };

        let resolved = HashMap::new();
        let expanded = TemplateExpander::expand(&pipeline, &resolved);
        assert_eq!(
            expanded.vars.get("missing").unwrap(),
            &vec!["${source.nonexistent}".to_string()]
        );
    }
}
