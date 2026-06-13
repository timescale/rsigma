//! String-level auto-fix applier shared by the CLI, LSP, and MCP server.
//!
//! The linter attaches an optional [`Fix`](super::Fix) to each
//! [`LintWarning`](super::LintWarning). This module turns those fixes into
//! concrete edits on a YAML source string using the `yamlpath`/`yamlpatch`
//! crates, preserving comments and formatting outside the edited spans.
//!
//! Only [`FixDisposition::Safe`] fixes are applied; unsafe fixes are skipped so
//! a batch fixer never makes a change that needs human judgement.
//!
//! # Usage
//!
//! ```rust
//! use rsigma_parser::lint::{lint_yaml_str, fix::apply_fixes_to_source};
//!
//! let source = "title: Test\nStatus: test\nlogsource:\n    category: test\ndetection:\n    sel:\n        field: value\n    condition: sel\n";
//! let warnings = lint_yaml_str(source);
//! let fixable: Vec<_> = warnings.iter().filter(|w| w.fix.is_some()).collect();
//! let outcome = apply_fixes_to_source(source, &fixable);
//! assert!(outcome.fixed_source.contains("status: test"));
//! ```

use std::borrow::Cow;

use yamlpath::{Component, Route};

use super::{FixDisposition, FixPatch, LintWarning};

/// Outcome of applying fixes to a single YAML source string.
#[derive(Debug, Clone)]
pub struct SourceFixOutcome {
    /// The (possibly) rewritten source. Equal to the input when nothing
    /// applied (no safe fixes, all conflicts, or an unparseable document).
    pub fixed_source: String,
    /// Number of safe fixes that applied cleanly.
    pub applied: usize,
    /// Number of safe fixes that could not be applied (patch conflicts or an
    /// unparseable document).
    pub failed: usize,
}

/// Convert an rsigma JSON-pointer path (e.g. "/tags/2", "/detection/sel/CommandLine|contains")
/// into a `yamlpath::Route` with owned components.
///
/// JSON-pointer segments that parse as `usize` become `Index`, others become `Key`.
/// Leading "/" is stripped; an empty/root path returns an empty route.
pub fn json_pointer_to_route(path: &str) -> Route<'static> {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if trimmed.is_empty() {
        return Route::default();
    }

    let components: Vec<Component<'static>> = trimmed
        .split('/')
        .map(|segment| {
            if let Ok(idx) = segment.parse::<usize>() {
                Component::Index(idx)
            } else {
                Component::Key(Cow::Owned(segment.to_string()))
            }
        })
        .collect();

    Route::from(components)
}

/// Apply a single [`FixPatch`] to a `yamlpath::Document`, returning a new Document.
///
/// `ReplaceValue` and `Remove` delegate to yamlpatch.
/// `ReplaceKey` is handled with a custom string-level rename since yamlpatch
/// has no native "rename key" operation.
pub fn apply_single_fix_patch(
    doc: &yamlpath::Document,
    patch: &FixPatch,
) -> Result<yamlpath::Document, String> {
    match patch {
        FixPatch::ReplaceValue { path, new_value } => {
            let yp = yamlpatch::Patch {
                route: json_pointer_to_route(path),
                operation: yamlpatch::Op::Replace(yaml_serde::Value::String(new_value.clone())),
            };
            yamlpatch::apply_yaml_patches(doc, &[yp]).map_err(|e| e.to_string())
        }
        FixPatch::ReplaceKey { path, new_key } => apply_rename_key(doc, path, new_key),
        FixPatch::Remove { path } => {
            let yp = yamlpatch::Patch {
                route: json_pointer_to_route(path),
                operation: yamlpatch::Op::Remove,
            };
            yamlpatch::apply_yaml_patches(doc, &[yp]).map_err(|e| e.to_string())
        }
    }
}

/// Rename a YAML key in-place using `query_key_only` to get the exact
/// byte span of the key, then replacing it in the document source.
pub fn apply_rename_key(
    doc: &yamlpath::Document,
    path: &str,
    new_key: &str,
) -> Result<yamlpath::Document, String> {
    let route = json_pointer_to_route(path);

    let key_feature = doc
        .query_key_only(&route)
        .map_err(|e| format!("route query failed for key rename: {e}"))?;

    let (start, end) = key_feature.location.byte_span;
    let mut patched = doc.source().to_string();
    patched.replace_range(start..end, new_key);

    yamlpath::Document::new(patched).map_err(|e| format!("re-parse after key rename failed: {e}"))
}

/// Apply every safe fix from `warnings` to `source`, returning the rewritten
/// source plus applied/failed counts.
///
/// Each warning's patches are applied sequentially against a running document
/// (so routes stay valid as the source mutates). A fix counts as `applied`
/// only when all of its patches land; the first conflicting patch aborts that
/// fix and counts it as `failed`. Unsafe fixes and warnings without a fix are
/// ignored. An unparseable document fails every safe fix and returns the
/// source unchanged.
pub fn apply_fixes_to_source(source: &str, warnings: &[&LintWarning]) -> SourceFixOutcome {
    let safe_fixes = || {
        warnings.iter().filter(|w| {
            w.fix
                .as_ref()
                .is_some_and(|f| f.disposition == FixDisposition::Safe)
        })
    };

    let mut current_doc = match yamlpath::Document::new(source.to_string()) {
        Ok(d) => d,
        Err(_) => {
            return SourceFixOutcome {
                fixed_source: source.to_string(),
                applied: 0,
                failed: safe_fixes().count(),
            };
        }
    };

    let mut applied = 0usize;
    let mut failed = 0usize;

    for w in safe_fixes() {
        let fix = w.fix.as_ref().expect("filtered to fixes above");
        let mut ok = true;
        for patch in &fix.patches {
            match apply_single_fix_patch(&current_doc, patch) {
                Ok(new_doc) => current_doc = new_doc,
                Err(_) => {
                    failed += 1;
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            applied += 1;
        }
    }

    SourceFixOutcome {
        fixed_source: current_doc.source().to_string(),
        applied,
        failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::lint_yaml_str;
    use insta::assert_snapshot;

    #[test]
    fn json_pointer_root() {
        let route = json_pointer_to_route("/");
        assert!(route.is_empty());
    }

    #[test]
    fn json_pointer_empty() {
        let route = json_pointer_to_route("");
        assert!(route.is_empty());
    }

    #[test]
    fn json_pointer_simple_key() {
        let route = json_pointer_to_route("/status");
        assert_snapshot!(format!("{route:?}"), @r#"Route { route: [Key("status")] }"#);
    }

    #[test]
    fn json_pointer_nested() {
        let route = json_pointer_to_route("/logsource/category");
        assert_snapshot!(format!("{route:?}"), @r#"Route { route: [Key("logsource"), Key("category")] }"#);
    }

    #[test]
    fn json_pointer_with_index() {
        let route = json_pointer_to_route("/tags/2");
        assert_snapshot!(format!("{route:?}"), @r#"Route { route: [Key("tags"), Index(2)] }"#);
    }

    #[test]
    fn json_pointer_detection_path() {
        let route = json_pointer_to_route("/detection/selection/CommandLine|contains");
        assert_snapshot!(format!("{route:?}"), @r#"Route { route: [Key("detection"), Key("selection"), Key("CommandLine|contains")] }"#);
    }

    #[test]
    fn fix_replace_value_on_file() {
        let yaml = "title: Test\nstatus: experimetal\nlevel: medium\n";
        let doc = yamlpath::Document::new(yaml.to_string()).unwrap();
        let route = json_pointer_to_route("/status");
        let patch = yamlpatch::Patch {
            route,
            operation: yamlpatch::Op::Replace(yaml_serde::Value::String(
                "experimental".to_string(),
            )),
        };
        let result = yamlpatch::apply_yaml_patches(&doc, &[patch]).unwrap();
        assert_snapshot!(result.source(), @r"
        title: Test
        status: experimental
        level: medium
        ");
    }

    #[test]
    fn fix_remove_on_file() {
        let yaml = "title: Test\ntags:\n  - attack.execution\n  - attack.execution\n  - attack.defense_evasion\n";
        let doc = yamlpath::Document::new(yaml.to_string()).unwrap();
        let route = json_pointer_to_route("/tags/1");
        let patch = yamlpatch::Patch {
            route,
            operation: yamlpatch::Op::Remove,
        };
        let result = yamlpatch::apply_yaml_patches(&doc, &[patch]).unwrap();
        assert_snapshot!(result.source(), @r"
        title: Test
        tags:
          - attack.execution
          - attack.defense_evasion
        ");
    }

    #[test]
    fn fix_rename_key_top_level() {
        let yaml = "title: Test\nStatus: experimental\nlevel: medium\n";
        let doc = yamlpath::Document::new(yaml.to_string()).unwrap();
        let result = apply_rename_key(&doc, "/Status", "status").unwrap();
        assert_snapshot!(result.source(), @r"
        title: Test
        status: experimental
        level: medium
        ");
    }

    #[test]
    fn fix_rename_key_nested() {
        let yaml = "title: Test\nlogsource:\n    Category: test\n    product: windows\n";
        let doc = yamlpath::Document::new(yaml.to_string()).unwrap();
        let result = apply_rename_key(&doc, "/logsource/Category", "category").unwrap();
        assert_snapshot!(result.source(), @r"
        title: Test
        logsource:
            category: test
            product: windows
        ");
    }

    #[test]
    fn fix_rename_detection_key_with_modifiers() {
        let yaml = "title: Test\nlogsource:\n    category: test\ndetection:\n    sel:\n        Cmd|all|re:\n            - foo\n            - bar\n    condition: sel\n";
        let doc = yamlpath::Document::new(yaml.to_string()).unwrap();
        let result = apply_rename_key(&doc, "/detection/sel/Cmd|all|re", "Cmd|re").unwrap();
        assert_snapshot!(result.source(), @r"
        title: Test
        logsource:
            category: test
        detection:
            sel:
                Cmd|re:
                    - foo
                    - bar
            condition: sel
        ");
    }

    #[test]
    fn sequential_patches_reparse_correctly() {
        let yaml = "title: Test\ntags:\n  - a\n  - a\n  - b\n  - b\n  - c\n";
        let doc = yamlpath::Document::new(yaml.to_string()).unwrap();

        let patch1 = yamlpatch::Patch {
            route: json_pointer_to_route("/tags/1"),
            operation: yamlpatch::Op::Remove,
        };
        let doc = yamlpatch::apply_yaml_patches(&doc, &[patch1]).unwrap();

        // After removing index 1, the array is [a, b, b, c].
        let patch2 = yamlpatch::Patch {
            route: json_pointer_to_route("/tags/2"),
            operation: yamlpatch::Op::Remove,
        };
        let doc = yamlpatch::apply_yaml_patches(&doc, &[patch2]).unwrap();

        assert_snapshot!(doc.source(), @r"
        title: Test
        tags:
          - a
          - b
          - c
        ");
    }

    #[test]
    fn apply_fixes_to_source_corrects_invalid_status() {
        let source = "title: Test\nstatus: expreimental\nlogsource:\n    category: test\ndetection:\n    sel:\n        field: value\n    condition: sel\n";
        let warnings = lint_yaml_str(source);
        let fixable: Vec<&LintWarning> = warnings.iter().filter(|w| w.fix.is_some()).collect();
        let outcome = apply_fixes_to_source(source, &fixable);
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.failed, 0);
        assert!(outcome.fixed_source.contains("status: experimental"));
        assert!(!outcome.fixed_source.contains("expreimental"));
    }

    #[test]
    fn apply_fixes_to_source_no_fixes_returns_input() {
        let source = "title: Test\nstatus: test\nlogsource:\n    category: test\ndetection:\n    sel:\n        field: value\n    condition: sel\n";
        let outcome = apply_fixes_to_source(source, &[]);
        assert_eq!(outcome.applied, 0);
        assert_eq!(outcome.failed, 0);
        assert_eq!(outcome.fixed_source, source);
    }

    #[test]
    fn apply_fixes_to_source_skips_unparseable() {
        let warning_src = "title: Test\nStatus: test\n";
        let warnings = lint_yaml_str(warning_src);
        let fixable: Vec<&LintWarning> = warnings.iter().filter(|w| w.fix.is_some()).collect();
        // An unparseable YAML document fails every safe fix and is returned as-is.
        let broken = "title: [unterminated\n";
        let outcome = apply_fixes_to_source(broken, &fixable);
        assert_eq!(outcome.applied, 0);
        assert_eq!(outcome.fixed_source, broken);
    }
}
