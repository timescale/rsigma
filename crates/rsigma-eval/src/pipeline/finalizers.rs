//! Pipeline finalizers for query-output use cases.
//!
//! Finalizers are the last step in a pySigma pipeline. They transform the
//! generated query string (e.g., concatenating multiple conditions, wrapping
//! in JSON). For eval-mode, these are stored for YAML compatibility but not
//! executed — they only matter for query-conversion backends.

/// A pipeline finalizer that post-processes generated query strings.
///
/// Stored in the `Pipeline` struct for YAML round-tripping and backend
/// compatibility. Eval-mode ignores these.
#[derive(Debug, Clone)]
pub enum Finalizer {
    /// Concatenate query parts with a separator.
    Concat {
        separator: String,
        prefix: String,
        suffix: String,
    },

    /// Wrap the query in JSON format.
    Json { indent: Option<usize> },

    /// Apply a template string to the query.
    Template { template: String },
}

impl Finalizer {
    /// Parse a finalizer from a YAML mapping.
    pub fn from_yaml(mapping: &serde_yaml::Value) -> Option<Self> {
        let obj = mapping.as_mapping()?;
        let type_val = obj.get(serde_yaml::Value::String("type".to_string()))?;
        let type_str = type_val.as_str()?;

        match type_str {
            "concat" => {
                let separator = obj
                    .get(serde_yaml::Value::String("separator".to_string()))
                    .and_then(|v| v.as_str())
                    .unwrap_or(" ")
                    .to_string();
                let prefix = obj
                    .get(serde_yaml::Value::String("prefix".to_string()))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let suffix = obj
                    .get(serde_yaml::Value::String("suffix".to_string()))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Some(Finalizer::Concat {
                    separator,
                    prefix,
                    suffix,
                })
            }

            "json" => {
                let indent = obj
                    .get(serde_yaml::Value::String("indent".to_string()))
                    .and_then(|v| v.as_u64())
                    .map(|n| n as usize);
                Some(Finalizer::Json { indent })
            }

            "template" => {
                let template = obj
                    .get(serde_yaml::Value::String("template".to_string()))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Some(Finalizer::Template { template })
            }

            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_concat_finalizer() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
type: concat
separator: " OR "
prefix: "("
suffix: ")"
"#,
        )
        .unwrap();

        let f = Finalizer::from_yaml(&yaml).unwrap();
        if let Finalizer::Concat {
            separator,
            prefix,
            suffix,
        } = f
        {
            assert_eq!(separator, " OR ");
            assert_eq!(prefix, "(");
            assert_eq!(suffix, ")");
        } else {
            panic!("Expected Concat");
        }
    }

    #[test]
    fn test_parse_json_finalizer() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
type: json
indent: 2
"#,
        )
        .unwrap();

        let f = Finalizer::from_yaml(&yaml).unwrap();
        if let Finalizer::Json { indent } = f {
            assert_eq!(indent, Some(2));
        } else {
            panic!("Expected Json");
        }
    }

    #[test]
    fn test_parse_template_finalizer() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
type: template
template: "source={source} ({query})"
"#,
        )
        .unwrap();

        let f = Finalizer::from_yaml(&yaml).unwrap();
        if let Finalizer::Template { template } = f {
            assert_eq!(template, "source={source} ({query})");
        } else {
            panic!("Expected Template");
        }
    }
}
