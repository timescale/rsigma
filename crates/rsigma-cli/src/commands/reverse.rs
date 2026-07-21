//! `rule reverse`: convert one or more SIEM queries into draft Sigma rules.
//!
//! Reads queries in the dialect chosen by `--from`, parses each into the
//! intermediate representation, raises a Sigma rule, and prints them as Sigma
//! YAML. A query can come from an inline argument, from `--file` (repeatable,
//! files or directories: each file is one query, a directory contributes every
//! file it holds), or from stdin. A query carries no rule metadata, so the
//! title, id, level, status, and logsource come from flags; for file inputs the
//! title defaults to the file name. This is the inverse of
//! `rsigma backend convert` and the query sibling of `rule draft`.
//!
//! Each emitted rule is parsed back before it is written, so a rule that would
//! not round-trip never reaches the operator.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process;

use clap::{Args, ValueEnum};
use rsigma_convert::{Frontend, LuceneFrontend, ReverseCtx, reverse_collection};
use rsigma_parser::{Level, Status};

use crate::output::OutputCtx;

/// The query dialect to reverse-convert from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Default)]
pub(crate) enum Dialect {
    /// Elastic Lucene / Elasticsearch `query_string`.
    #[default]
    Lucene,
}

impl Dialect {
    /// File extensions treated as query files when walking a directory
    /// (case-insensitive). An explicitly named file is read regardless of
    /// extension; this filter only applies to directory contents, mirroring how
    /// `parse_sigma_directory` restricts to `.yml`/`.yaml`.
    fn query_extensions(self) -> &'static [&'static str] {
        match self {
            Dialect::Lucene => &["lucene", "txt", "query"],
        }
    }
}

/// Arguments for `rsigma rule reverse`.
#[derive(Args, Debug)]
pub(crate) struct ReverseArgs {
    /// An inline query. Omit to read from `--file` or stdin.
    pub query: Option<String>,

    /// Source query dialect.
    #[arg(long, value_enum, default_value_t = Dialect::Lucene)]
    pub from: Dialect,

    /// Read queries from files or directories (repeatable). Each file is one
    /// query; a directory contributes every file it holds (recursively).
    /// Mutually exclusive with an inline query.
    #[arg(short = 'f', long)]
    pub file: Vec<PathBuf>,

    /// Rule title. For a single query only; multi-query runs title each rule
    /// from its file name.
    #[arg(long)]
    pub title: Option<String>,

    /// Rule id (UUID). For a single query only.
    #[arg(long)]
    pub id: Option<String>,

    /// Rule level: informational, low, medium, high, or critical.
    #[arg(long)]
    pub level: Option<String>,

    /// Rule status: stable, test, experimental, deprecated, or unsupported.
    #[arg(long)]
    pub status: Option<String>,

    /// Logsource product (e.g. windows).
    #[arg(long)]
    pub logsource_product: Option<String>,

    /// Logsource category (e.g. process_creation).
    #[arg(long)]
    pub logsource_category: Option<String>,

    /// Logsource service (e.g. sysmon).
    #[arg(long)]
    pub logsource_service: Option<String>,

    /// Write output instead of stdout. With multiple rules, an existing
    /// directory receives one `<name>.yml` per query; any other path receives a
    /// single multi-document bundle.
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}

/// A query plus an optional source name used to title the rule.
#[derive(Debug, PartialEq, Eq)]
struct GatheredQuery {
    text: String,
    /// The source file stem, when the query came from a file.
    name: Option<String>,
}

pub(crate) fn cmd_reverse(args: ReverseArgs, _ctx: OutputCtx) {
    let mut queries = collect_queries(
        args.query.as_deref(),
        &args.file,
        args.from.query_extensions(),
    )
    .unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(crate::exit_code::CONFIG_ERROR);
    });
    if queries.is_empty() {
        queries = vec![read_stdin_query()];
    }

    if queries.len() > 1 && (args.title.is_some() || args.id.is_some()) {
        eprintln!(
            "--title/--id apply to a single query; with multiple queries the title comes from each file name"
        );
        process::exit(crate::exit_code::CONFIG_ERROR);
    }

    let level = parse_enum::<Level>(args.level.as_deref(), "level");
    let status = parse_enum::<Status>(args.status.as_deref(), "status");
    let single = queries.len() == 1;

    let frontend: &dyn Frontend = match args.from {
        Dialect::Lucene => &LuceneFrontend,
    };

    let mut rules: Vec<(Option<String>, String)> = Vec::new();
    let mut failures: Vec<(String, String)> = Vec::new();

    for gathered in &queries {
        let title = if single {
            args.title.clone().or_else(|| gathered.name.clone())
        } else {
            gathered.name.clone()
        };
        let ctx = ReverseCtx {
            title,
            id: if single { args.id.clone() } else { None },
            level,
            status,
            product: args.logsource_product.clone(),
            category: args.logsource_category.clone(),
            service: args.logsource_service.clone(),
            strict: false,
        };

        let source = gathered
            .name
            .clone()
            .unwrap_or_else(|| truncate(&gathered.text));
        let mut output = reverse_collection(frontend, std::slice::from_ref(&gathered.text), &ctx);

        if let Some((_, err)) = output.errors.first() {
            failures.push((source, err.to_string()));
            continue;
        }
        let Some(result) = output.rules.pop() else {
            failures.push((source, "no rule was produced".to_string()));
            continue;
        };
        if !reparses(&result.yaml) {
            failures.push((source, "the converted rule did not round-trip".to_string()));
            continue;
        }
        rules.push((gathered.name.clone(), result.yaml));
    }

    if !rules.is_empty()
        && let Err(e) = write_rules(&rules, args.output.as_deref())
    {
        eprintln!("{e}");
        process::exit(crate::exit_code::CONFIG_ERROR);
    }

    for (source, err) in &failures {
        eprintln!("Error converting {source}: {err}");
    }
    if !failures.is_empty() {
        process::exit(crate::exit_code::RULE_ERROR);
    }
}

// ---------------------------------------------------------------------------
// Query gathering
// ---------------------------------------------------------------------------

/// Gather queries from an inline argument or `--file` paths. Returns an empty
/// vec (meaning "read stdin") when neither is given. Directory contents are
/// filtered to `extensions`; explicitly named files are read regardless.
fn collect_queries(
    inline: Option<&str>,
    files: &[PathBuf],
    extensions: &[&str],
) -> Result<Vec<GatheredQuery>, String> {
    match (inline, files.is_empty()) {
        (Some(_), false) => Err("Provide an inline query or --file, not both".to_string()),
        (Some(q), true) => {
            let text = q.trim();
            if text.is_empty() {
                return Err("Empty query".to_string());
            }
            Ok(vec![GatheredQuery {
                text: text.to_string(),
                name: None,
            }])
        }
        (None, false) => {
            let mut out = Vec::new();
            for path in files {
                collect_path(path, extensions, &mut out)?;
            }
            if out.is_empty() {
                return Err("No non-empty query files found in the given paths".to_string());
            }
            Ok(out)
        }
        (None, true) => Ok(Vec::new()),
    }
}

fn collect_path(
    path: &Path,
    extensions: &[&str],
    out: &mut Vec<GatheredQuery>,
) -> Result<(), String> {
    if path.is_dir() {
        let mut files = Vec::new();
        walk_dir(path, &mut files)?;
        files.retain(|f| has_query_extension(f, extensions));
        files.sort();
        for file in &files {
            read_query_file(file, out)?;
        }
        Ok(())
    } else if path.is_file() {
        read_query_file(path, out)
    } else {
        Err(format!("Path not found: {}", path.display()))
    }
}

fn has_query_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| extensions.iter().any(|want| ext.eq_ignore_ascii_case(want)))
}

/// Recursively collect regular files under `dir`, skipping dotfiles/dotdirs.
fn walk_dir(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        fs::read_dir(dir).map_err(|e| format!("Error reading directory {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("Error reading directory {}: {e}", dir.display()))?;
        let path = entry.path();
        let hidden = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with('.'));
        if hidden {
            continue;
        }
        if path.is_dir() {
            walk_dir(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn read_query_file(path: &Path, out: &mut Vec<GatheredQuery>) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("Error reading query file '{}': {e}", path.display()))?;
    let text = text.trim();
    if text.is_empty() {
        return Ok(());
    }
    out.push(GatheredQuery {
        text: text.to_string(),
        name: path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string()),
    });
    Ok(())
}

fn read_stdin_query() -> GatheredQuery {
    let mut buf = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buf) {
        eprintln!("Error reading stdin: {e}");
        process::exit(crate::exit_code::CONFIG_ERROR);
    }
    let text = buf.trim();
    if text.is_empty() {
        eprintln!("Empty query; pass a query as an argument, via --file, or on stdin");
        process::exit(crate::exit_code::CONFIG_ERROR);
    }
    GatheredQuery {
        text: text.to_string(),
        name: None,
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn write_rules(rules: &[(Option<String>, String)], output: Option<&Path>) -> Result<(), String> {
    match output {
        None => {
            print!("{}", bundle(rules));
            Ok(())
        }
        Some(path) if rules.len() > 1 && path.is_dir() => {
            for (index, (name, yaml)) in rules.iter().enumerate() {
                let stem = name
                    .clone()
                    .unwrap_or_else(|| format!("rule_{}", index + 1));
                let file = path.join(format!("{stem}.yml"));
                fs::write(&file, yaml)
                    .map_err(|e| format!("Error writing to {}: {e}", file.display()))?;
            }
            Ok(())
        }
        Some(path) => fs::write(path, bundle(rules))
            .map_err(|e| format!("Error writing to {}: {e}", path.display())),
    }
}

/// Join emitted rules into a single (possibly multi-document) YAML string. Each
/// rule already ends with a newline, so `---\n` separators land on their own line.
fn bundle(rules: &[(Option<String>, String)]) -> String {
    rules
        .iter()
        .map(|(_, yaml)| yaml.as_str())
        .collect::<Vec<_>>()
        .join("---\n")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn reparses(yaml: &str) -> bool {
    matches!(
        rsigma_parser::parse_sigma_yaml(yaml),
        Ok(collection) if collection.rules.len() == 1 && !collection.has_errors()
    )
}

fn truncate(query: &str) -> String {
    const MAX: usize = 60;
    if query.chars().count() > MAX {
        format!("query '{}...'", query.chars().take(MAX).collect::<String>())
    } else {
        format!("query '{query}'")
    }
}

fn parse_enum<T: std::str::FromStr>(value: Option<&str>, label: &str) -> Option<T> {
    value.map(|v| {
        v.parse::<T>().unwrap_or_else(|_| {
            eprintln!("Invalid {label}: '{v}'");
            process::exit(crate::exit_code::CONFIG_ERROR);
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXTS: &[&str] = &["lucene", "txt", "query"];

    #[test]
    fn inline_query_is_a_single_gathered_query() {
        let got = collect_queries(Some("  EventID:1  "), &[], EXTS).unwrap();
        assert_eq!(
            got,
            vec![GatheredQuery {
                text: "EventID:1".into(),
                name: None
            }]
        );
    }

    #[test]
    fn inline_and_file_together_is_rejected() {
        let err = collect_queries(Some("x"), &[PathBuf::from("q.lucene")], EXTS).unwrap_err();
        assert!(err.contains("not both"));
    }

    #[test]
    fn no_input_signals_stdin() {
        assert!(collect_queries(None, &[], EXTS).unwrap().is_empty());
    }

    #[test]
    fn files_and_directories_expand_to_one_query_each() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.lucene"), "EventID:1\n").unwrap();
        let sub = dir.path().join("nested");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("b.lucene"), "EventID:2").unwrap();
        std::fs::write(dir.path().join(".hidden"), "ignored").unwrap();
        std::fs::write(dir.path().join("empty.lucene"), "  \n").unwrap();
        // A non-query file next to the fixtures must be filtered out.
        std::fs::write(dir.path().join("a.yml"), "title: not a query").unwrap();

        let got = collect_queries(None, &[dir.path().to_path_buf()], EXTS).unwrap();
        // Sorted, dotfiles / empty / non-query files skipped, directory recursed.
        assert_eq!(
            got,
            vec![
                GatheredQuery {
                    text: "EventID:1".into(),
                    name: Some("a".into())
                },
                GatheredQuery {
                    text: "EventID:2".into(),
                    name: Some("b".into())
                },
            ]
        );
    }

    #[test]
    fn explicitly_named_file_ignores_the_extension_filter() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("query.spl");
        std::fs::write(&file, "EventID:1").unwrap();
        let got = collect_queries(None, &[file], EXTS).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name.as_deref(), Some("query"));
    }

    #[test]
    fn missing_path_is_an_error() {
        let err = collect_queries(None, &[PathBuf::from("/no/such/dir")], EXTS).unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn bundle_separates_documents() {
        let rules = vec![
            (Some("a".into()), "title: A\n".to_string()),
            (Some("b".into()), "title: B\n".to_string()),
        ];
        assert_eq!(bundle(&rules), "title: A\n---\ntitle: B\n");
    }
}
