use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;

use rsigma_parser::lint::{self, FileLintResult, FixPatch, LintWarning};
use yamlpath::{Component, Route};

/// Result of applying fixes to a set of files.
pub struct FixResult {
    pub applied: usize,
    pub failed: usize,
    pub files_modified: usize,
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

/// Apply a single `FixPatch` to a `yamlpath::Document`, returning a new Document.
///
/// `ReplaceValue` and `Remove` delegate to yamlpatch.
/// `ReplaceKey` is handled with a custom string-level rename since yamlpatch
/// has no native "rename key" operation.
fn apply_single_fix_patch(
    doc: &yamlpath::Document,
    patch: &FixPatch,
) -> Result<yamlpath::Document, String> {
    match patch {
        FixPatch::ReplaceValue { path, new_value } => {
            let yp = yamlpatch::Patch {
                route: json_pointer_to_route(path),
                operation: yamlpatch::Op::Replace(serde_yaml::Value::String(new_value.clone())),
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
fn apply_rename_key(
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

/// Collect fixable warnings from lint results, grouped by file path.
fn collect_fixable_warnings(results: &[FileLintResult]) -> HashMap<&Path, Vec<&LintWarning>> {
    let mut by_file: HashMap<&Path, Vec<&LintWarning>> = HashMap::new();
    for result in results {
        for w in &result.warnings {
            if w.fix.is_some() {
                by_file.entry(&result.path).or_default().push(w);
            }
        }
    }
    by_file
}

/// Apply all safe fixes from lint results to the files on disk.
///
/// For each file with fixable warnings:
/// 1. Loads the file as a `yamlpath::Document`
/// 2. Applies each fix's patches sequentially (each producing a fresh Document)
/// 3. Gracefully records conflicts when a patch fails
/// 4. Writes the modified source back only if it actually changed
pub fn apply_fixes(results: &[FileLintResult]) -> FixResult {
    let by_file = collect_fixable_warnings(results);

    let mut total_applied = 0usize;
    let mut total_failed = 0usize;
    let mut files_modified = 0usize;

    for (file_path, warnings) in &by_file {
        let source = match std::fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  cannot read {}: {e}", file_path.display());
                total_failed += warnings.len();
                continue;
            }
        };

        let mut current_doc = match yamlpath::Document::new(source.clone()) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("  cannot parse {}: {e}", file_path.display());
                total_failed += warnings.len();
                continue;
            }
        };

        let mut file_applied = 0usize;

        for w in warnings {
            let fix = w.fix.as_ref().unwrap();

            if fix.disposition != lint::FixDisposition::Safe {
                continue;
            }

            // Apply each patch in the fix sequentially.
            // Each produces a fresh Document so routes stay valid.
            let mut ok = true;
            for patch in &fix.patches {
                match apply_single_fix_patch(&current_doc, patch) {
                    Ok(new_doc) => current_doc = new_doc,
                    Err(e) => {
                        eprintln!(
                            "  fix conflict in {}: [{}] {e}",
                            file_path.display(),
                            w.rule
                        );
                        total_failed += 1;
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                file_applied += 1;
            }
        }

        if current_doc.source() != source {
            if let Err(e) = std::fs::write(file_path, current_doc.source()) {
                eprintln!("  cannot write {}: {e}", file_path.display());
                total_failed += file_applied;
            } else {
                total_applied += file_applied;
                files_modified += 1;
            }
        }
    }

    FixResult {
        applied: total_applied,
        failed: total_failed,
        files_modified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            operation: yamlpatch::Op::Replace(serde_yaml::Value::String(
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
}
