//! Every documented enrichers, webhooks, risk, alert-pipeline, and sources
//! example must load under the same rules the daemon applies, so a doc
//! cannot show a key or value the loader rejects.
//!
//! Examples are fenced `yaml` or `yml` blocks in `docs/content`, the crate
//! READMEs, the root README, and `skills/`. Each block is classified by its
//! top-level keys. Blocks that hold a schema placeholder (a `<name>` value
//! or an `a | b` alternation) are skipped.

use std::path::{Path, PathBuf};

/// Pages that describe how to add a new source type, so their examples use
/// a type the parser does not know yet.
const HYPOTHETICAL_SOURCE_PAGES: &[&str] = &["docs/content/developers/adding-sources.md"];

fn repo_root() -> Option<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if root.join("docs/content").is_dir() {
        Some(root)
    } else {
        eprintln!("docs/content not found, skipping documented config checks");
        None
    }
}

fn markdown_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "node_modules") {
                    continue;
                }
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "md") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&root.join("docs/content"), &mut files);
    walk(&root.join("skills"), &mut files);
    files.push(root.join("README.md"));
    if let Ok(crates) = std::fs::read_dir(root.join("crates")) {
        for entry in crates.flatten() {
            let readme = entry.path().join("README.md");
            if readme.is_file() {
                files.push(readme);
            }
        }
    }
    files.sort();
    files
}

struct Block {
    /// `path:line` of the opening fence.
    location: String,
    file: String,
    text: String,
    value: yaml_serde::Value,
}

impl Block {
    fn has(&self, key: &str) -> bool {
        self.value
            .as_mapping()
            .is_some_and(|m| m.contains_key(yaml_serde::Value::String(key.to_string())))
    }

    fn keys(&self) -> Vec<&str> {
        self.value
            .as_mapping()
            .map(|m| m.keys().filter_map(|k| k.as_str()).collect())
            .unwrap_or_default()
    }

    fn is_placeholder(&self) -> bool {
        has_placeholder(&self.value)
    }
}

/// A schema placeholder is a `<name>` scalar or a bare `a | b` alternation
/// of identifiers. A jq pipe such as `.a[] | .b` is not one.
fn is_placeholder_scalar(s: &str) -> bool {
    let s = s.trim();
    let word = |w: &str| {
        !w.is_empty()
            && w.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    };
    (s.starts_with('<') && s.contains('>')) || (s.contains(" | ") && s.split(" | ").all(word))
}

fn has_placeholder(value: &yaml_serde::Value) -> bool {
    match value {
        yaml_serde::Value::String(s) => is_placeholder_scalar(s),
        yaml_serde::Value::Sequence(items) => items.iter().any(has_placeholder),
        yaml_serde::Value::Mapping(map) => map
            .iter()
            .any(|(k, v)| has_placeholder(k) || has_placeholder(v)),
        yaml_serde::Value::Tagged(tagged) => has_placeholder(&tagged.value),
        _ => false,
    }
}

/// Every fenced YAML block that parses as a single YAML document.
fn yaml_blocks(root: &Path) -> Vec<Block> {
    let mut blocks = Vec::new();
    for path in markdown_files(root) {
        let text = std::fs::read_to_string(&path).unwrap();
        let file = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string()
            .replace('\\', "/");
        let mut open: Option<(usize, String, String)> = None;
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            match &mut open {
                None if trimmed == "```yaml" || trimmed == "```yml" => {
                    let indent = " ".repeat(line.len() - trimmed.len());
                    open = Some((index + 1, indent, String::new()));
                }
                None => {}
                Some((start, indent, body)) => {
                    if trimmed.starts_with("```") {
                        let body = std::mem::take(body);
                        if let Ok(value) = yaml_serde::from_str(&body) {
                            blocks.push(Block {
                                location: format!("{file}:{start}"),
                                file: file.clone(),
                                text: body,
                                value,
                            });
                        }
                        open = None;
                    } else {
                        body.push_str(line.strip_prefix(indent.as_str()).unwrap_or(line));
                        body.push('\n');
                    }
                }
            }
        }
    }
    blocks
}

/// Check every block `select` picks with `check`, and assert there are at
/// least `minimum` of them and no failures.
fn check_family(
    family: &str,
    minimum: usize,
    select: impl Fn(&Block) -> bool,
    check: impl Fn(&Block) -> Result<(), String>,
) {
    let Some(root) = repo_root() else {
        return;
    };
    let mut checked = 0;
    let mut failures = Vec::new();
    for block in yaml_blocks(&root).iter().filter(|b| select(b)) {
        if block.is_placeholder() {
            continue;
        }
        checked += 1;
        if let Err(e) = check(block) {
            let first = block.text.lines().next().unwrap_or_default();
            failures.push(format!("{} (`{first}`): {e}", block.location));
        }
    }
    assert!(
        failures.is_empty(),
        "documented {family} examples fail to load:\n{}",
        failures.join("\n")
    );
    assert!(
        checked >= minimum,
        "expected at least {minimum} documented {family} examples, found {checked}"
    );
}

fn is_enrichers(block: &Block) -> bool {
    block.has("enrichers") || (block.value.is_sequence() && block.text.contains("inject_field:"))
}

#[test]
fn documented_enrichers_examples_load() {
    check_family("enrichers", 39, is_enrichers, |block| {
        let text = if block.value.is_sequence() {
            let indented: String = block.text.lines().map(|l| format!("  {l}\n")).collect();
            format!("enrichers:\n{indented}")
        } else {
            block.text.clone()
        };
        rsigma_runtime::parse_enrichers_config(&text)
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
}

#[test]
fn documented_webhooks_examples_load() {
    check_family(
        "webhooks",
        11,
        |block| block.has("webhooks"),
        |block| {
            yaml_serde::from_str::<rsigma_runtime::WebhooksFile>(&block.text)
                .map(|_| ())
                .map_err(|e| e.to_string())
        },
    );
}

#[test]
fn documented_risk_examples_load() {
    check_family(
        "risk",
        1,
        |block| block.has("objects") && !block.has("sources"),
        |block| {
            rsigma_runtime::parse_risk_config(&block.text)
                .map(|_| ())
                .map_err(|e| e.to_string())
        },
    );
}

#[test]
fn documented_alert_pipeline_examples_load() {
    check_family(
        "alert pipeline",
        3,
        |block| {
            ["dedup", "group", "silences", "inhibit_rules"]
                .iter()
                .any(|key| block.has(key))
        },
        |block| {
            rsigma_runtime::parse_alert_pipeline_config(&block.text)
                .map(|_| ())
                .map_err(|e| e.to_string())
        },
    );
}

#[test]
fn documented_sources_examples_load() {
    check_family(
        "sources",
        18,
        |block| {
            block.keys() == ["sources"] && !HYPOTHETICAL_SOURCE_PAGES.contains(&block.file.as_str())
        },
        |block| {
            let items = block
                .value
                .get("sources")
                .expect("selected blocks have sources");
            rsigma_eval::parse_sources(items)
                .map(|_| ())
                .map_err(|e| e.to_string())
        },
    );
}
