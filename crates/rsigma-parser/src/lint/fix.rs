//! String-level auto-fix applier shared by the CLI, LSP, and MCP server.
//!
//! The linter attaches an optional [`Fix`](super::Fix) to each
//! [`LintWarning`]. This module turns those fixes into
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
/// JSON-pointer segments that parse as `usize` become `Index`, others become
/// `Key`, with `~1` and `~0` unescaped to `/` and `~`. Leading "/" is stripped;
/// an empty/root path returns an empty route.
pub fn json_pointer_to_route(path: &str) -> Route<'static> {
    Route::from(
        pointer_segments(path)
            .into_iter()
            .map(|segment| match segment {
                Segment::Index(idx) => Component::Index(idx),
                Segment::Key(key) => Component::Key(Cow::Owned(key)),
            })
            .collect::<Vec<_>>(),
    )
}

enum Segment {
    Index(usize),
    Key(String),
}

fn pointer_segments(path: &str) -> Vec<Segment> {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if trimmed.is_empty() {
        return Vec::new();
    }
    trimmed
        .split('/')
        .map(|segment| match segment.parse::<usize>() {
            Ok(idx) => Segment::Index(idx),
            Err(_) => Segment::Key(segment.replace("~1", "/").replace("~0", "~")),
        })
        .collect()
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
        FixPatch::ReplaceBool { path, new_value } => {
            let yp = yamlpatch::Patch {
                route: json_pointer_to_route(path),
                operation: yamlpatch::Op::Replace(yaml_serde::Value::Bool(*new_value)),
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
/// byte span of the key, then replacing it in the document source. The new
/// key is quoted when YAML would not read it back plain.
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
    patched.replace_range(
        start..end,
        &crate::style::encode_key(new_key, crate::style::KeyCtx::FieldKey),
    );

    yamlpath::Document::new(patched).map_err(|e| format!("re-parse after key rename failed: {e}"))
}

/// Apply every safe fix from `warnings` to `source`, returning the rewritten
/// source plus applied/failed counts.
///
/// Each fix lands on the first YAML document of `source` it changes, in
/// document order, so identical findings in several documents of one file are
/// fixed once each. A fix counts as `applied` only when all of its patches
/// land, the document then reads back as exactly the requested edit, and the
/// edit adds no Sigma parse error; otherwise the document is left as it was
/// and the fix counts as `failed`. Unsafe fixes and warnings without a fix are
/// ignored. An unparseable document fails every safe fix and returns the
/// source unchanged.
pub fn apply_fixes_to_source(source: &str, warnings: &[&LintWarning]) -> SourceFixOutcome {
    let mut documents = split_documents(source);
    let mut applied = 0usize;
    let mut failed = 0usize;

    let safe_fixes = warnings
        .iter()
        .filter_map(|w| w.fix.as_ref())
        .filter(|f| f.disposition == FixDisposition::Safe);
    for fix in safe_fixes {
        let landed = documents.iter_mut().any(|document| {
            match apply_fix_to_document(document, &fix.patches) {
                Some(fixed) => {
                    *document = fixed;
                    true
                }
                None => false,
            }
        });
        if landed {
            applied += 1;
        } else {
            failed += 1;
        }
    }

    SourceFixOutcome {
        fixed_source: documents.concat(),
        applied,
        failed,
    }
}

/// Apply `patches` to one YAML document's text and check the result, returning
/// the fixed text, or `None` when a patch does not land, the text does not
/// change, or the result is not the requested edit.
fn apply_fix_to_document(text: &str, patches: &[FixPatch]) -> Option<String> {
    let mut expected: yaml_serde::Value = yaml_serde::from_str(text).ok()?;
    for patch in patches {
        apply_to_value(&mut expected, patch)?;
    }
    let mut document = yamlpath::Document::new(text.to_string()).ok()?;
    for patch in patches {
        document = apply_single_fix_patch(&document, patch).ok()?;
    }
    let fixed = document.source();
    if fixed == text {
        return None;
    }
    let actual: yaml_serde::Value = yaml_serde::from_str(fixed).ok()?;
    if actual != expected || sigma_errors(fixed) > sigma_errors(text) {
        return None;
    }
    Some(fixed.to_string())
}

fn sigma_errors(text: &str) -> usize {
    crate::parse_sigma_yaml(text).map_or(usize::MAX, |collection| collection.error_count())
}

/// Apply one patch to a parsed value, the way the source edit should change it.
fn apply_to_value(root: &mut yaml_serde::Value, patch: &FixPatch) -> Option<()> {
    let (path, edit) = match patch {
        FixPatch::ReplaceValue { path, new_value } => (
            path,
            Edit::Replace(yaml_serde::Value::String(new_value.clone())),
        ),
        FixPatch::ReplaceBool { path, new_value } => {
            (path, Edit::Replace(yaml_serde::Value::Bool(*new_value)))
        }
        FixPatch::ReplaceKey { path, new_key } => (path, Edit::Rename(new_key)),
        FixPatch::Remove { path } => (path, Edit::Remove),
    };
    let mut segments = pointer_segments(path);
    let last = segments.pop()?;
    let mut parent = root;
    for segment in segments {
        parent = match (segment, parent) {
            (Segment::Index(idx), yaml_serde::Value::Sequence(seq)) => seq.get_mut(idx)?,
            (Segment::Key(key), yaml_serde::Value::Mapping(map)) => map.get_mut(key.as_str())?,
            _ => return None,
        };
    }
    match (last, parent, edit) {
        (Segment::Index(idx), yaml_serde::Value::Sequence(seq), Edit::Replace(value)) => {
            *seq.get_mut(idx)? = value;
        }
        (Segment::Index(idx), yaml_serde::Value::Sequence(seq), Edit::Remove) => {
            if idx >= seq.len() {
                return None;
            }
            seq.remove(idx);
        }
        (Segment::Key(key), yaml_serde::Value::Mapping(map), Edit::Replace(value)) => {
            *map.get_mut(key.as_str())? = value;
        }
        (Segment::Key(key), yaml_serde::Value::Mapping(map), Edit::Remove) => {
            map.shift_remove(key.as_str())?;
        }
        (Segment::Key(key), yaml_serde::Value::Mapping(map), Edit::Rename(new_key)) => {
            if key != new_key && map.contains_key(new_key) {
                return None;
            }
            map.get(key.as_str())?;
            let renamed: yaml_serde::Mapping = std::mem::take(map)
                .into_iter()
                .map(|(k, v)| {
                    if k.as_str() == Some(key.as_str()) {
                        (yaml_serde::Value::String(new_key.to_string()), v)
                    } else {
                        (k, v)
                    }
                })
                .collect();
            *map = renamed;
        }
        _ => return None,
    }
    Some(())
}

enum Edit<'a> {
    Replace(yaml_serde::Value),
    Rename(&'a str),
    Remove,
}

/// Split a YAML stream into its documents' exact text, so the pieces
/// concatenate back to `source`. A document starts at a `---` marker line,
/// unless nothing but comments, blank lines, and directives came before it in
/// the current piece, and after a `...` end marker line.
fn split_documents(source: &str) -> Vec<String> {
    let mut documents: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut has_content = false;
    let mut ended = false;
    for line in source.split_inclusive('\n') {
        let bare = line.trim_end_matches(['\n', '\r']);
        let is_marker = |marker: &str| {
            bare.strip_prefix(marker)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '\t']))
        };
        let blank = bare.trim().is_empty() || bare.starts_with('#');
        if (is_marker("---") && has_content) || (ended && !blank && !bare.starts_with('%')) {
            documents.push(std::mem::take(&mut current));
            has_content = false;
            ended = false;
        }
        current.push_str(line);
        if is_marker("...") {
            ended = true;
        } else if !blank && !bare.starts_with('%') && !is_marker("---") {
            has_content = true;
        }
    }
    documents.push(current);
    documents
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

    fn fix_all(source: &str) -> SourceFixOutcome {
        let warnings = lint_yaml_str(source);
        let fixable: Vec<&LintWarning> = warnings.iter().filter(|w| w.fix.is_some()).collect();
        apply_fixes_to_source(source, &fixable)
    }

    fn field_names(source: &str) -> Vec<String> {
        let collection = crate::parse_sigma_yaml(source).unwrap();
        assert!(!collection.has_errors(), "{:?}", collection.diagnostics);
        let mut names = Vec::new();
        for rule in &collection.rules {
            for detection in rule.detection.named.values() {
                if let crate::ast::Detection::AllOf(items) = detection {
                    for item in items {
                        names.push(format!(
                            "{}|{:?}",
                            item.field.name.as_deref().unwrap_or(""),
                            item.field.modifiers
                        ));
                    }
                }
            }
        }
        names
    }

    #[test]
    fn wildcard_only_fix_writes_a_boolean() {
        let source = "title: Test\nlogsource:\n    category: test\ndetection:\n    sel:\n        CommandLine: '*'\n    condition: sel\n";
        let outcome = fix_all(source);
        assert_eq!(outcome.applied, 1, "{}", outcome.fixed_source);
        assert!(
            outcome.fixed_source.contains("CommandLine|exists: true\n"),
            "{}",
            outcome.fixed_source
        );
        assert_eq!(field_names(&outcome.fixed_source), ["CommandLine|[Exists]"]);
    }

    #[test]
    fn renamed_keys_stay_quoted_when_yaml_needs_it() {
        for key in [
            "x: y",
            "#hash",
            "a #b",
            "- dash",
            "tab\there",
            "{flow}",
            "\"dq\"",
        ] {
            let source = format!(
                "title: Test\nlogsource:\n    category: test\ndetection:\n    sel:\n        {}: v\n    condition: sel\n",
                crate::style::encode_key(&format!("{key}|all"), crate::style::KeyCtx::FieldKey)
            );
            let outcome = fix_all(&source);
            assert_eq!(outcome.applied, 1, "{key:?}: {}", outcome.fixed_source);
            assert_eq!(field_names(&outcome.fixed_source), [format!("{key}|[]")]);
        }
    }

    #[test]
    fn fixes_land_on_the_document_they_came_from() {
        let source = "title: One\nstatus: test\nlogsource:\n    category: test\ndetection:\n    sel:\n        a: b\n    condition: sel\n---\ntitle: Two\nStatus: test\nlogsource:\n    category: test\ndetection:\n    sel:\n        a: b\n    condition: sel\n";
        let outcome = fix_all(source);
        assert_eq!(outcome.applied, 1);
        let (first, second) = outcome.fixed_source.split_once("---\n").unwrap();
        assert!(first.contains("status: test") && !first.contains("Status"));
        assert!(second.contains("status: test") && !second.contains("Status"));
    }

    #[test]
    fn identical_findings_in_two_documents_are_fixed_once_each() {
        let doc = "title: T\nStatus: test\nlogsource:\n    category: test\ndetection:\n    sel:\n        a: b\n    condition: sel\n";
        let source = format!("{doc}---\n{doc}");
        let outcome = fix_all(&source);
        assert_eq!(outcome.applied, 2);
        assert!(!outcome.fixed_source.contains("Status"));
        assert_eq!(outcome.fixed_source.matches("status: test").count(), 2);
    }

    #[test]
    fn documents_split_back_into_the_same_text() {
        for source in [
            "",
            "a: 1\n",
            "# c\n---\na: 1\n---\nb: 2\n",
            "%YAML 1.2\n---\na: 1\n...\n---\nb: 2\n",
            "a: 1\n...\nb: 2\n",
            "a: |\n    --- not a marker\nb: 2\r\n---\r\nc: 3",
        ] {
            assert_eq!(split_documents(source).concat(), source);
        }
        assert_eq!(split_documents("a: 1\n---\nb: 2\n").len(), 2);
        assert_eq!(split_documents("---\na: 1\n").len(), 1);
        assert_eq!(split_documents("a: 1\n...\nb: 2\n").len(), 2);
    }

    #[test]
    fn a_patch_with_the_wrong_result_is_not_applied() {
        let source = "title: Test\nStatus: test\nstatus: stable\n";
        let rename = FixPatch::ReplaceKey {
            path: "/Status".into(),
            new_key: "status".into(),
        };
        assert!(apply_fix_to_document(source, &[rename]).is_none());

        let missing = FixPatch::ReplaceValue {
            path: "/level".into(),
            new_value: "high".into(),
        };
        assert!(apply_fix_to_document(source, &[missing]).is_none());
    }

    #[test]
    fn json_pointer_unescapes_slash_and_tilde() {
        let route = json_pointer_to_route("/detection/a~1b/c~0d~01");
        assert_snapshot!(format!("{route:?}"), @r#"Route { route: [Key("detection"), Key("a/b"), Key("c~d~1")] }"#);
    }
}
