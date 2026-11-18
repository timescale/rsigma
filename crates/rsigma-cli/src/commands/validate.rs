use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::process;

use clap::Args;
use rsigma_eval::Engine;
use rsigma_parser::{
    CollectionDiagnostic, SigmaCollection, SigmaParserError, parse_sigma_directory,
    parse_sigma_file,
};
use serde::Serialize;

use crate::output::{OutputCtx, OutputFormat, Tabular, render_report};

/// Arguments for `rsigma rule validate` (and the deprecated `rsigma validate`).
#[derive(Args, Debug)]
pub(crate) struct ValidateArgs {
    /// Sigma YAML file, or directory searched recursively for .yml and .yaml files
    #[arg(required_unless_present = "ruleset", conflicts_with = "ruleset")]
    pub path: Option<PathBuf>,

    /// Named ruleset from the configuration to validate instead of `PATH`.
    #[arg(long, value_name = "NAME")]
    pub ruleset: Option<String>,

    /// Path to an rsigma config file. Overrides config-file discovery.
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Show details for each file (not just summary)
    #[arg(short, long)]
    pub verbose: bool,

    /// Processing pipeline(s) to apply. Accepts builtin names (ecs_windows, sysmon) or YAML file paths
    #[arg(short = 'p', long = "pipeline")]
    pub pipelines: Vec<PathBuf>,

    /// Also resolve dynamic pipeline sources during validation.
    /// Sources must be reachable (file/command/HTTP) for validation to pass.
    #[arg(long = "resolve-sources")]
    pub resolve_sources: bool,

    /// External source file(s) or directory of source files
    #[arg(long = "source", value_name = "FILE_OR_DIR")]
    pub source_files: Vec<PathBuf>,

    /// Minimum parse diagnostic severity that causes exit code 2.
    /// 'error' (default): exit 2 on parse errors and compile errors.
    /// 'warning': also exit 2 on parse warnings, such as an invalid status or level.
    #[arg(long = "fail-level", default_value = "error",
           value_parser = ["error", "warning"])]
    pub fail_level: String,
}

#[derive(Debug, Serialize)]
struct ValidateSummary {
    path: String,
    total: usize,
    detection_rules: usize,
    correlation_rules: usize,
    filter_rules: usize,
    parse_errors: usize,
    parse_warnings: usize,
    compile_ok: usize,
    compile_errors: usize,
    pipelines: usize,
}

#[derive(Debug, Serialize)]
struct ValidateRow {
    path: String,
    status: String,
    errors: String,
}

impl Tabular for ValidateRow {
    fn headers() -> &'static [&'static str] {
        &["PATH", "STATUS", "ERRORS"]
    }
    fn row(&self) -> Vec<String> {
        vec![self.path.clone(), self.status.clone(), self.errors.clone()]
    }
}

pub(crate) fn cmd_validate(args: ValidateArgs, ctx: OutputCtx) {
    let ValidateArgs {
        path,
        ruleset,
        config,
        verbose,
        pipelines: pipeline_paths,
        resolve_sources,
        source_files,
        fail_level,
    } = args;
    let rules: Vec<PathBuf> = path.iter().cloned().collect();
    let input = crate::ruleset::RuleInput {
        rules: &rules,
        ruleset: ruleset.as_deref(),
        config: config.as_deref(),
    };
    let label = input.label();
    let pipeline_paths = input.pipelines(&pipeline_paths);
    // Dynamic source resolution (`--resolve-sources` / `--source`) needs the
    // async runtime + source resolver, which ship with the `daemon` feature.
    #[cfg(feature = "daemon")]
    let pipelines = resolve_validate_sources(
        crate::load_pipelines(&pipeline_paths),
        resolve_sources,
        &source_files,
        !ctx.explicit_format,
    );
    #[cfg(not(feature = "daemon"))]
    let pipelines = {
        let loaded = crate::load_pipelines(&pipeline_paths);
        if resolve_sources || !source_files.is_empty() {
            eprintln!(
                "error: --resolve-sources/--source require the `daemon` feature; \
                 rebuild with `--features daemon`"
            );
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
        loaded
    };

    let (parsed, origins) = if let Some(resolved) = input.resolved(&ctx) {
        (Ok(resolved.collection), Some(resolved.entries))
    } else {
        let path = path
            .as_ref()
            .expect("clap requires a path when no ruleset is selected");
        let parsed = if path.is_dir() {
            parse_sigma_directory(path)
        } else {
            match parse_sigma_file(path) {
                Err(SigmaParserError::Io(e)) => Err(SigmaParserError::Io(e)),
                Err(e) => {
                    let mut collection = SigmaCollection::new();
                    collection
                        .diagnostics
                        .push(CollectionDiagnostic::file(path, &e));
                    Ok(collection)
                }
                ok => ok,
            }
        };
        (parsed, None)
    };

    match parsed {
        Ok(collection) => {
            let total = collection.len();
            let rules = collection.rules.len();
            let correlations = collection.correlations.len();
            let filters = collection.filters.len();
            let parse_errors = collection.error_count();
            let parse_warnings = collection.warning_count();

            let mut engine = Engine::new();
            for p in &pipelines {
                engine.add_pipeline(p.clone());
            }

            // Batch all rules through `add_rules` so the inverted index and
            // bloom filter rebuild exactly once for the whole corpus instead
            // of once per rule (the latter is O(N²) and turns 3K-rule loads
            // into a multi-minute stall).
            let batch_errors = engine.add_rules(&collection.rules);
            let compile_ok = collection.rules.len() - batch_errors.len();
            let mut compile_errors: Vec<String> = batch_errors
                .into_iter()
                .map(|(idx, e)| {
                    let rule = &collection.rules[idx];
                    let id = rule.id.as_deref().unwrap_or(&rule.title);
                    format!("{id}: {e}")
                })
                .collect();
            compile_errors.extend(validate_correlation_references(&collection));

            let parse_error_msgs: Vec<String> =
                collection.errors().map(ToString::to_string).collect();
            let parse_warning_msgs: Vec<String> =
                collection.warnings().map(ToString::to_string).collect();

            let summary = ValidateSummary {
                path: label.clone(),
                total,
                detection_rules: rules,
                correlation_rules: correlations,
                filter_rules: filters,
                parse_errors,
                parse_warnings,
                compile_ok,
                compile_errors: compile_errors.len(),
                pipelines: pipelines.len(),
            };

            if ctx.explicit_format {
                let mut rows = Vec::new();
                for err in &parse_error_msgs {
                    rows.push(ValidateRow {
                        path: label.clone(),
                        status: "parse_error".into(),
                        errors: err.clone(),
                    });
                }
                for warning in &parse_warning_msgs {
                    rows.push(ValidateRow {
                        path: label.clone(),
                        status: "parse_warning".into(),
                        errors: warning.clone(),
                    });
                }
                for err in &compile_errors {
                    rows.push(ValidateRow {
                        path: label.clone(),
                        status: "compile_error".into(),
                        errors: err.clone(),
                    });
                }
                if rows.is_empty() {
                    rows.push(ValidateRow {
                        path: label.clone(),
                        status: "ok".into(),
                        errors: String::new(),
                    });
                }
                let envelope = serde_json::json!({
                    "summary": summary,
                    "parse_errors": parse_error_msgs,
                    "parse_warnings": parse_warning_msgs,
                    "compile_errors": compile_errors,
                });
                // NDJSON: one row per finding (or a single ok row). JSON: envelope.
                let format = ctx.format;
                match format {
                    OutputFormat::Ndjson
                    | OutputFormat::Table
                    | OutputFormat::Csv
                    | OutputFormat::Tsv => render_report(&ctx, &envelope, &rows),
                    OutputFormat::Json => {
                        crate::output::render_json(&envelope, ctx.pretty_json());
                    }
                }
            } else {
                println!("Parsed {total} documents from {label}");
                println!("  Detection rules:   {rules}");
                println!("  Correlation rules: {correlations}");
                println!("  Filter rules:      {filters}");
                println!("  Parse errors:      {parse_errors}");
                println!("  Parse warnings:    {parse_warnings}");
                tracing::info!(
                    total,
                    detection_rules = rules,
                    correlation_rules = correlations,
                    filter_rules = filters,
                    parse_errors,
                    parse_warnings,
                    rules_path = %label,
                    "Validation parsed",
                );

                if !pipelines.is_empty() {
                    println!("  Pipeline applied:  {} pipeline(s)", pipelines.len(),);
                }
                println!("  Compiled OK:       {compile_ok}");
                println!("  Compile errors:    {}", compile_errors.len());

                if verbose {
                    if !parse_error_msgs.is_empty() {
                        println!("\nParse errors:");
                        for err in &parse_error_msgs {
                            println!("  - {err}");
                        }
                    }
                    if !parse_warning_msgs.is_empty() {
                        println!("\nParse warnings:");
                        for warning in &parse_warning_msgs {
                            println!("  - {warning}");
                        }
                    }
                    if !compile_errors.is_empty() {
                        println!("\nCompile errors:");
                        for err in &compile_errors {
                            println!("  - {err}");
                        }
                    }
                    if let Some(entries) = &origins {
                        println!("\nDocuments by origin:");
                        for entry in entries.iter().filter(|entry| {
                            matches!(
                                entry.decision,
                                rsigma_parser::ruleset::Decision::Included { .. }
                                    | rsigma_parser::ruleset::Decision::PulledIn { .. }
                                    | rsigma_parser::ruleset::Decision::FilterKept
                            )
                        }) {
                            println!(
                                "  {} ({}/{}#{})",
                                entry.title,
                                entry.origin.root.display(),
                                entry.origin.file.display(),
                                entry.origin.ordinal
                            );
                        }
                    }
                }
            }

            let warnings_fail = fail_level == "warning" && parse_warnings > 0;
            if parse_errors > 0 || warnings_fail || !compile_errors.is_empty() {
                process::exit(crate::exit_code::RULE_ERROR);
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

fn validate_correlation_references(collection: &rsigma_parser::SigmaCollection) -> Vec<String> {
    let mut errors = validate_reference_identities(collection);
    let mut known = HashSet::new();
    for rule in &collection.rules {
        known.extend(rule.id.iter().map(String::as_str));
        known.extend(rule.name.iter().map(String::as_str));
    }
    for correlation in &collection.correlations {
        known.extend(correlation.id.iter().map(String::as_str));
        known.extend(correlation.name.iter().map(String::as_str));
    }

    errors.extend(collection.correlations.iter().flat_map(|correlation| {
        correlation
            .rules
            .iter()
            .filter(|rule_ref| !known.contains(rule_ref.as_str()))
            .map(|rule_ref| {
                let identity = correlation
                    .id
                    .as_deref()
                    .or(correlation.name.as_deref())
                    .unwrap_or(&correlation.title);
                format!("{identity}: unknown rule reference: {rule_ref}")
            })
    }));
    errors
}

/// Report correlation references that resolve to more than one detection or
/// correlation rule, through a duplicate id, a duplicate name, or a name that
/// equals another rule's id.
fn validate_reference_identities(collection: &rsigma_parser::SigmaCollection) -> Vec<String> {
    let rules: Vec<(Option<&str>, Option<&str>, &str)> = collection
        .rules
        .iter()
        .map(|rule| {
            (
                rule.id.as_deref(),
                rule.name.as_deref(),
                rule.title.as_str(),
            )
        })
        .chain(collection.correlations.iter().map(|correlation| {
            (
                correlation.id.as_deref(),
                correlation.name.as_deref(),
                correlation.title.as_str(),
            )
        }))
        .collect();

    let referenced: BTreeSet<&str> = collection
        .correlations
        .iter()
        .flat_map(|correlation| correlation.rules.iter().map(String::as_str))
        .collect();

    referenced
        .into_iter()
        .filter_map(|rule_ref| {
            let matches: Vec<String> = rules
                .iter()
                .filter(|(id, name, _)| *id == Some(rule_ref) || *name == Some(rule_ref))
                .map(|(_, _, title)| format!("'{title}'"))
                .collect();
            (matches.len() > 1).then(|| {
                format!(
                    "{rule_ref}: ambiguous rule reference matches {}",
                    matches.join(", ")
                )
            })
        })
        .collect()
}

/// Load external sources and, when `--resolve-sources` is set, resolve every
/// dynamic pipeline and external source, returning the expanded pipelines.
/// Exits with `CONFIG_ERROR` on a load or resolution failure.
#[cfg(feature = "daemon")]
fn resolve_validate_sources(
    mut pipelines: Vec<rsigma_eval::Pipeline>,
    resolve_sources: bool,
    source_files: &[PathBuf],
    print_human_ok: bool,
) -> Vec<rsigma_eval::Pipeline> {
    // Load external sources alongside pipeline-embedded ones (validating that
    // the source files parse, regardless of whether we resolve them).
    let external_sources = if !source_files.is_empty() {
        match rsigma_runtime::sources::registry::load_external_sources(source_files) {
            Ok(ext) => ext.into_iter().map(|(s, _)| s).collect::<Vec<_>>(),
            Err(e) => {
                eprintln!("Error loading external sources: {e}");
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
        }
    } else {
        Vec::new()
    };

    if resolve_sources {
        let has_dynamic = pipelines.iter().any(|p| p.is_dynamic()) || !external_sources.is_empty();
        if has_dynamic {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|e| {
                    eprintln!("Failed to create async runtime for source resolution: {e}");
                    process::exit(crate::exit_code::CONFIG_ERROR);
                });

            let mut resolver = rsigma_runtime::DefaultSourceResolver::new();
            if let Err(err) = resolver.prepare_taxii(&external_sources) {
                eprintln!("Error preparing TAXII sources: {err}");
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
            let mut resolved_pipelines = Vec::with_capacity(pipelines.len());
            let mut source_errors: Vec<String> = Vec::new();

            // Resolve the external sources once into a shared data map that
            // every dynamic pipeline's `${source.*}` references expand against.
            let resolved_data = match rt.block_on(rsigma_runtime::sources::resolve_all(
                &resolver,
                &external_sources,
            )) {
                Ok(data) => data,
                Err(e) => {
                    source_errors.push(format!("external sources: {e}"));
                    std::collections::HashMap::new()
                }
            };

            for pipeline in &pipelines {
                if pipeline.is_dynamic() {
                    let mut expanded = rsigma_runtime::sources::template::TemplateExpander::expand(
                        pipeline,
                        &resolved_data,
                    );
                    if let Err(e) = rsigma_runtime::sources::include::expand_includes(
                        &mut expanded,
                        &resolved_data,
                        &external_sources,
                        false,
                    ) {
                        source_errors.push(format!("pipeline '{}': {e}", pipeline.name));
                    }
                    resolved_pipelines.push(expanded);
                } else {
                    resolved_pipelines.push(pipeline.clone());
                }
            }

            if !source_errors.is_empty() {
                eprintln!("Source resolution errors:");
                for err in &source_errors {
                    eprintln!("  - {err}");
                }
                process::exit(crate::exit_code::CONFIG_ERROR);
            }

            pipelines = resolved_pipelines;
            if print_human_ok {
                println!("  Sources resolved:  OK");
            }
        }
    }

    pipelines
}
