//! `rsigma rule migrate-sources`: extract pipeline-embedded `sources:`
//! blocks into standalone source files.

use std::collections::HashMap;
use std::path::PathBuf;

use clap::Args;
use rsigma_eval::parse_sources;

use crate::output::OutputCtx;

/// Arguments for `rsigma rule migrate-sources`.
#[derive(Args, Debug)]
pub(crate) struct MigrateSourcesArgs {
    /// Pipeline file or directory of pipeline files to migrate
    #[arg(short = 'p', long = "pipeline", required = true)]
    pub pipelines: Vec<PathBuf>,

    /// Output file or directory for extracted sources
    #[arg(short, long = "output", required = true)]
    pub output: PathBuf,

    /// Consolidation strategy: 'single' writes one file (default),
    /// 'per-pipeline' writes one file per pipeline
    #[arg(long, default_value = "single", value_parser = ["single", "per-pipeline"])]
    pub strategy: String,

    /// Perform extraction without writing files
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

pub(crate) fn cmd_migrate_sources(args: MigrateSourcesArgs, ctx: OutputCtx) {
    if ctx.explicit_format {
        ctx.warn_unsupported("rule migrate-sources", "source YAML / file writes");
    }
    let MigrateSourcesArgs {
        pipelines: pipeline_paths,
        output,
        strategy,
        dry_run,
    } = args;

    let mut pipeline_files: Vec<PathBuf> = Vec::new();
    for path in &pipeline_paths {
        if path.is_dir() {
            let options = crate::walk_options().max_depth(0);
            let walk = match rsigma_parser::walk::walk_files(path, &options) {
                Ok(walk) => walk,
                Err(e) => {
                    eprintln!("Error reading directory {}: {e}", path.display());
                    std::process::exit(crate::exit_code::CONFIG_ERROR);
                }
            };
            for skipped in &walk.skipped {
                eprintln!("Warning: {skipped}");
            }
            pipeline_files.extend(walk.files.into_iter().map(|file| file.path));
        } else {
            pipeline_files.push(path.clone());
        }
    }

    if pipeline_files.is_empty() {
        eprintln!("No pipeline files found.");
        std::process::exit(crate::exit_code::CONFIG_ERROR);
    }

    // Collected sources keyed by source ID for deduplication
    let mut consolidated: Vec<ExtractedSource> = Vec::new();
    let mut seen_ids: HashMap<String, String> = HashMap::new(); // id -> first pipeline name
    let mut per_pipeline: Vec<(String, Vec<ExtractedSource>)> = Vec::new();
    let mut pipelines_with_sources = 0;
    let mut pipelines_without_sources = 0;

    for path in &pipeline_files {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error reading {}: {e}", path.display());
                std::process::exit(crate::exit_code::RULE_ERROR);
            }
        };

        // The pipeline parser rejects inline `sources:` blocks, so read the
        // block straight out of the raw YAML instead. A pipeline that no
        // longer declares sources is simply skipped.
        let (sources, values) = match extract_inline_sources(&content) {
            Ok(sources) => sources,
            Err(e) => {
                eprintln!("Error parsing sources in {}: {e}", path.display());
                std::process::exit(crate::exit_code::RULE_ERROR);
            }
        };

        if sources.is_empty() {
            pipelines_without_sources += 1;
            continue;
        }

        pipelines_with_sources += 1;

        let mut extracted = Vec::new();
        for (source, value) in sources.iter().zip(values) {
            if let Some(prev_pipeline) = seen_ids.get(&source.id) {
                eprintln!(
                    "Error: source ID '{}' declared in both '{}' and '{}'. \
                     Resolve the conflict before migrating.",
                    source.id,
                    prev_pipeline,
                    path.display()
                );
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
            seen_ids.insert(source.id.clone(), path.display().to_string());
            extracted.push(ExtractedSource {
                raw_yaml: extract_source_yaml(&content, &source.id),
                value,
            });
        }

        consolidated.extend(extracted.iter().cloned());
        per_pipeline.push((path.display().to_string(), extracted));
    }

    if consolidated.is_empty() {
        eprintln!("No sources found in any pipeline file.");
        return;
    }

    eprintln!(
        "Found {} source(s) across {} pipeline(s) ({} without sources).",
        consolidated.len(),
        pipelines_with_sources,
        pipelines_without_sources
    );

    if dry_run {
        eprintln!("Dry run: would write the following sources:");
        let yaml_content = build_sources_yaml(&consolidated);
        println!("{yaml_content}");
        return;
    }

    match strategy.as_str() {
        "single" => {
            let yaml_content = build_sources_yaml(&consolidated);
            if let Err(e) = std::fs::write(&output, &yaml_content) {
                eprintln!("Error writing {}: {e}", output.display());
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
            eprintln!(
                "Wrote {} source(s) to {}",
                consolidated.len(),
                output.display()
            );
        }
        "per-pipeline" => {
            if !output.exists()
                && let Err(e) = std::fs::create_dir_all(&output)
            {
                eprintln!("Error creating directory {}: {e}", output.display());
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
            for (pipeline_path, sources) in &per_pipeline {
                if sources.is_empty() {
                    continue;
                }
                let stem = std::path::Path::new(pipeline_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("sources");
                let out_file = output.join(format!("{stem}-sources.yml"));
                let yaml_content = build_sources_yaml(sources);
                if let Err(e) = std::fs::write(&out_file, &yaml_content) {
                    eprintln!("Error writing {}: {e}", out_file.display());
                    std::process::exit(crate::exit_code::CONFIG_ERROR);
                }
                eprintln!(
                    "Wrote {} source(s) from {pipeline_path} to {}",
                    sources.len(),
                    out_file.display()
                );
            }
        }
        _ => unreachable!(),
    }

    // Rewrite pipeline files with sources: block removed. A read failure
    // here (file deleted between scan and rewrite, permission flip, …)
    // used to panic the CLI; report the failure on stderr and keep
    // processing the remaining pipelines, matching the soft-error
    // behaviour the rewrite step itself already uses.
    for path in &pipeline_files {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "warning: could not re-read {} to strip sources: {e}",
                    path.display()
                );
                continue;
            }
        };
        let stripped = remove_sources_block(&content);
        if stripped != content && !strips_only_sources(&content, &stripped) {
            eprintln!(
                "warning: could not remove the sources: block from {} without changing the rest of the file; remove it by hand",
                path.display()
            );
            continue;
        }
        if stripped != content {
            if let Err(e) = std::fs::write(path, &stripped) {
                eprintln!("warning: could not rewrite {}: {e}", path.display());
            } else {
                eprintln!("Removed sources: block from {}", path.display());
            }
        }
    }
}

#[derive(Clone)]
struct ExtractedSource {
    raw_yaml: String,
    /// The parsed source entry the written YAML must read back as.
    value: yaml_serde::Value,
}

/// Whether `stripped` reads back as `original` without its `sources` key.
fn strips_only_sources(original: &str, stripped: &str) -> bool {
    let Ok(yaml_serde::Value::Mapping(mut expected)) = yaml_serde::from_str(original) else {
        return false;
    };
    expected.shift_remove("sources");
    matches!(
        yaml_serde::from_str::<yaml_serde::Value>(stripped),
        Ok(yaml_serde::Value::Mapping(actual)) if actual == expected
    )
}

/// Parse a pipeline file's raw YAML and return its inline `sources:`
/// declarations, or an empty vector when the file declares none. Errors only
/// on a malformed `sources:` block (an unknown source type, a missing `id`,
/// etc.), so a clean, already-migrated pipeline is a no-op.
type InlineSources = (
    Vec<rsigma_eval::pipeline::sources::DynamicSource>,
    Vec<yaml_serde::Value>,
);

fn extract_inline_sources(content: &str) -> Result<InlineSources, rsigma_eval::EvalError> {
    let value: yaml_serde::Value = yaml_serde::from_str(content)
        .map_err(|e| rsigma_eval::EvalError::Pipeline(format!("YAML parse error: {e}")))?;
    let Some(node) = value
        .as_mapping()
        .and_then(|m| m.get(yaml_serde::Value::String("sources".to_string())))
    else {
        return Ok((Vec::new(), Vec::new()));
    };
    let sources = parse_sources(node)?;
    let values = node.as_sequence().cloned().unwrap_or_default();
    Ok((sources, values))
}

/// Extract the raw YAML text for a single source entry from a pipeline file.
/// Falls back to a simple serialization if the source can't be found by ID.
fn extract_source_yaml(content: &str, source_id: &str) -> String {
    // Try to find the source block by scanning for the id field
    let lines: Vec<&str> = content.lines().collect();
    let mut in_sources = false;
    let mut source_start: Option<usize> = None;
    let mut source_end: Option<usize> = None;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed == "sources:" {
            in_sources = true;
            continue;
        }
        if !in_sources {
            continue;
        }

        // Detect end of sources block (a non-indented, non-empty line that
        // isn't a list item or continuation)
        if !trimmed.is_empty()
            && !line.starts_with(' ')
            && !line.starts_with('\t')
            && !trimmed.starts_with('-')
        {
            if source_start.is_some() && source_end.is_none() {
                source_end = Some(i);
            }
            break;
        }

        // Detect start of our source by looking for `- id: <source_id>`
        if trimmed.starts_with("- id:") || trimmed.starts_with("-  id:") {
            let id_val = trimmed
                .trim_start_matches("- id:")
                .trim_start_matches("-  id:")
                .trim();
            if id_val == source_id || id_val == format!("\"{source_id}\"") {
                // Close any previously open source before starting ours
                source_start = Some(i);
                source_end = None;
                continue;
            } else if source_start.is_some() && source_end.is_none() {
                source_end = Some(i);
            }
        }
    }

    if source_start.is_none() {
        // Fallback: generate minimal YAML
        return format!("  - id: {source_id}\n");
    }

    let start = source_start.unwrap();
    let end = source_end.unwrap_or(lines.len());

    lines[start..end].iter().map(|l| format!("{l}\n")).collect()
}

/// Build a complete sources YAML file from extracted entries: each entry's
/// original text re-indented as a whole, so nested keys keep their structure.
/// When that text does not read back as exactly the extracted entries (an
/// entry the line scan could not isolate), the entries are serialized instead.
fn build_sources_yaml(sources: &[ExtractedSource]) -> String {
    let mut out = String::from("sources:\n");
    for src in sources {
        let spaces = |line: &str| line.len() - line.trim_start_matches(' ').len();
        let base = src
            .raw_yaml
            .lines()
            .find(|line| !line.trim().is_empty())
            .map(spaces)
            .unwrap_or(0);
        for line in src.raw_yaml.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let indent = spaces(line);
            out.push_str("  ");
            out.push_str(&line[base.min(indent)..]);
            out.push('\n');
        }
    }
    let values: Vec<yaml_serde::Value> = sources.iter().map(|src| src.value.clone()).collect();
    if reads_back_as(&out, &values) {
        return out;
    }
    let mut file = yaml_serde::Mapping::new();
    file.insert("sources".into(), yaml_serde::Value::Sequence(values));
    yaml_serde::to_string(&file).unwrap_or_default()
}

/// Whether `yaml` holds a `sources:` list equal to `values`.
fn reads_back_as(yaml: &str, values: &[yaml_serde::Value]) -> bool {
    let Ok(yaml_serde::Value::Mapping(file)) = yaml_serde::from_str(yaml) else {
        return false;
    };
    file.len() == 1 && file.get("sources").and_then(|s| s.as_sequence()) == Some(&values.to_vec())
}

/// Remove the `sources:` block from a pipeline YAML string.
fn remove_sources_block(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::new();
    let mut in_sources = false;
    let mut sources_indent: Option<usize> = None;

    for line in &lines {
        let trimmed = line.trim();

        if trimmed == "sources:" && !in_sources {
            in_sources = true;
            sources_indent = Some(line.len() - line.trim_start().len());
            continue;
        }

        if in_sources {
            if trimmed.is_empty() {
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            if indent > sources_indent.unwrap_or(0)
                || trimmed.starts_with('-') && indent >= sources_indent.unwrap_or(0)
            {
                continue;
            }
            in_sources = false;
        }

        result.push(*line);
    }

    let mut out: String = result.join("\n");
    if content.ends_with('\n') {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_sources_block() {
        let input = r#"name: my_pipeline
priority: 50
sources:
  - id: threat_feed
    type: http
    url: https://example.com/feed
    format: json
  - id: local_data
    type: file
    path: /tmp/data.json
    format: json
transformations:
  - type: value_placeholders
"#;
        let output = remove_sources_block(input);
        assert!(!output.contains("sources:"));
        assert!(!output.contains("threat_feed"));
        assert!(!output.contains("local_data"));
        assert!(output.contains("name: my_pipeline"));
        assert!(output.contains("transformations:"));
    }

    #[test]
    fn test_remove_sources_block_no_sources() {
        let input = "name: simple\ntransformations:\n  - type: field_name_mapping\n";
        let output = remove_sources_block(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_build_sources_yaml() {
        let source = |raw: &str| ExtractedSource {
            raw_yaml: raw.to_string(),
            value: yaml_serde::from_str::<Vec<yaml_serde::Value>>(raw).unwrap()[0].clone(),
        };
        let sources = vec![
            source("  - id: feed_a\n    type: http\n    url: https://example.com\n"),
            source("  - id: feed_b\n    type: file\n    path: /tmp/data.json\n"),
        ];
        let yaml = build_sources_yaml(&sources);
        assert!(yaml.starts_with("sources:\n"));
        assert!(yaml.contains("feed_a"));
        assert!(yaml.contains("feed_b"));

        // Must be valid YAML
        let parsed: yaml_serde::Value = yaml_serde::from_str(&yaml).unwrap();
        assert!(
            parsed
                .as_mapping()
                .unwrap()
                .contains_key(yaml_serde::Value::String("sources".to_string()))
        );
    }

    #[test]
    fn test_extract_source_yaml() {
        let content = r#"name: test
sources:
  - id: alpha
    type: file
    path: /tmp/a.json
    format: json
  - id: beta
    type: http
    url: https://example.com
    format: json
transformations:
  - type: value_placeholders
"#;
        let extracted = extract_source_yaml(content, "alpha");
        assert!(extracted.contains("alpha"));
        assert!(extracted.contains("file"));
        assert!(!extracted.contains("beta"));
    }

    #[test]
    fn nested_source_keys_keep_their_structure() {
        let content = r#"name: test
sources:
    -   id: alpha
        type: http
        url: https://example.com
        format: json
        extract:
            type: jq
            expr: '.items[] | {ip: .addr}'
        headers:
            X-Key: "a: b # c"
# trailing comment at column 0
    -   id: 'beta'
        type: file
        path: /tmp/b.json
        format: json
transformations:
    - type: value_placeholders
"#;
        let (sources, values) = extract_inline_sources(content).unwrap();
        let extracted: Vec<ExtractedSource> = sources
            .iter()
            .zip(values.clone())
            .map(|(source, value)| ExtractedSource {
                raw_yaml: extract_source_yaml(content, &source.id),
                value,
            })
            .collect();
        let yaml = build_sources_yaml(&extracted);
        assert!(reads_back_as(&yaml, &values), "{yaml}");
        let (reparsed, _) = extract_inline_sources(&yaml).unwrap();
        assert_eq!(reparsed.len(), 2);
    }

    #[test]
    fn stripping_sources_is_checked() {
        let content = "name: test\nsources:\n  - id: a\n    type: file\n    path: /tmp/a\n    format: json\n# note\n  - id: b\n    type: file\n    path: /tmp/b\n    format: json\ntransformations: []\n";
        let stripped = remove_sources_block(content);
        assert!(!strips_only_sources(content, &stripped), "{stripped}");
        let clean = "name: test\nsources:\n  - id: a\n    type: file\n    path: /tmp/a\n    format: json\ntransformations: []\n";
        assert!(strips_only_sources(clean, &remove_sources_block(clean)));
    }
}
