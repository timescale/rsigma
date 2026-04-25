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
    /// Apply this finalizer to a list of query strings, producing a single output string.
    ///
    /// - `Concat`: joins queries with a separator and wraps in prefix/suffix.
    /// - `Json`: serializes as a JSON array, optionally pretty-printed.
    /// - `Template`: applies a template per query, replacing `{query}` and `{index}`.
    pub fn apply(&self, queries: Vec<String>) -> String {
        match self {
            Finalizer::Concat {
                separator,
                prefix,
                suffix,
            } => {
                format!("{prefix}{}{suffix}", queries.join(separator))
            }
            Finalizer::Json { indent } => match indent {
                Some(n) => {
                    let indent_str = " ".repeat(*n);
                    let items: Vec<String> = queries
                        .iter()
                        .map(|q| {
                            format!(
                                "{indent_str}{}",
                                serde_json::to_string(q).unwrap_or_default()
                            )
                        })
                        .collect();
                    format!("[\n{}\n]", items.join(",\n"))
                }
                None => serde_json::to_string(&queries).unwrap_or_else(|_| "[]".to_string()),
            },
            Finalizer::Template { template } => queries
                .iter()
                .enumerate()
                .map(|(i, q)| {
                    template
                        .replace("{query}", q)
                        .replace("{index}", &i.to_string())
                })
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

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

    #[test]
    fn test_concat_apply() {
        let f = Finalizer::Concat {
            separator: " OR ".to_string(),
            prefix: "(".to_string(),
            suffix: ")".to_string(),
        };
        let result = f.apply(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(result, "(a OR b)");
    }

    #[test]
    fn test_concat_apply_single() {
        let f = Finalizer::Concat {
            separator: " OR ".to_string(),
            prefix: String::new(),
            suffix: String::new(),
        };
        let result = f.apply(vec!["only".to_string()]);
        assert_eq!(result, "only");
    }

    #[test]
    fn test_concat_apply_empty() {
        let f = Finalizer::Concat {
            separator: ", ".to_string(),
            prefix: "[".to_string(),
            suffix: "]".to_string(),
        };
        let result = f.apply(vec![]);
        assert_eq!(result, "[]");
    }

    #[test]
    fn test_json_apply_no_indent() {
        let f = Finalizer::Json { indent: None };
        let result = f.apply(vec!["query1".to_string(), "query2".to_string()]);
        assert_eq!(result, r#"["query1","query2"]"#);
    }

    #[test]
    fn test_json_apply_with_indent() {
        let f = Finalizer::Json { indent: Some(2) };
        let result = f.apply(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(result, "[\n  \"a\",\n  \"b\"\n]");
    }

    #[test]
    fn test_template_apply() {
        let f = Finalizer::Template {
            template: "search {query}".to_string(),
        };
        let result = f.apply(vec!["x=1".to_string(), "y=2".to_string()]);
        assert_eq!(result, "search x=1\nsearch y=2");
    }

    #[test]
    fn test_template_apply_with_index() {
        let f = Finalizer::Template {
            template: "[{index}] {query}".to_string(),
        };
        let result = f.apply(vec!["first".to_string(), "second".to_string()]);
        assert_eq!(result, "[0] first\n[1] second");
    }
}
