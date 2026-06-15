use std::path::PathBuf;
use std::process;

use clap::Args;
use rsigma_eval::Engine;
use rsigma_parser::parse_sigma_directory;

/// Arguments for `rsigma rule validate` (and the deprecated `rsigma validate`).
#[derive(Args, Debug)]
pub(crate) struct ValidateArgs {
    /// Path to a directory containing Sigma YAML files
    pub path: PathBuf,

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
}

pub(crate) fn cmd_validate(args: ValidateArgs) {
    let ValidateArgs {
        path,
        verbose,
        pipelines: pipeline_paths,
        resolve_sources,
        source_files,
    } = args;
    // Dynamic source resolution (`--resolve-sources` / `--source`) needs the
    // async runtime + source resolver, which ship with the `daemon` feature.
    #[cfg(feature = "daemon")]
    let pipelines = resolve_validate_sources(
        crate::load_pipelines(&pipeline_paths),
        resolve_sources,
        &source_files,
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

    match parse_sigma_directory(&path) {
        Ok(collection) => {
            let total = collection.len();
            let rules = collection.rules.len();
            let correlations = collection.correlations.len();
            let filters = collection.filters.len();
            let parse_errors = collection.errors.len();

            println!("Parsed {total} documents from {}", path.display());
            println!("  Detection rules:   {rules}");
            println!("  Correlation rules: {correlations}");
            println!("  Filter rules:      {filters}");
            println!("  Parse errors:      {parse_errors}");
            tracing::info!(
                total,
                detection_rules = rules,
                correlation_rules = correlations,
                filter_rules = filters,
                parse_errors,
                rules_path = %path.display(),
                "Validation parsed",
            );

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
            let compile_errors: Vec<String> = batch_errors
                .into_iter()
                .map(|(idx, e)| {
                    let rule = &collection.rules[idx];
                    let id = rule.id.as_deref().unwrap_or(&rule.title);
                    format!("{id}: {e}")
                })
                .collect();

            if !pipelines.is_empty() {
                println!("  Pipeline applied:  {} pipeline(s)", pipelines.len(),);
            }
            println!("  Compiled OK:       {compile_ok}");
            println!("  Compile errors:    {}", compile_errors.len());

            if verbose {
                if !collection.errors.is_empty() {
                    println!("\nParse errors:");
                    for err in &collection.errors {
                        println!("  - {err}");
                    }
                }
                if !compile_errors.is_empty() {
                    println!("\nCompile errors:");
                    for err in &compile_errors {
                        println!("  - {err}");
                    }
                }
            }

            if parse_errors > 0 || !compile_errors.is_empty() {
                process::exit(crate::exit_code::RULE_ERROR);
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

/// Load external sources and, when `--resolve-sources` is set, resolve every
/// dynamic pipeline and external source, returning the expanded pipelines.
/// Exits with `CONFIG_ERROR` on a load or resolution failure.
#[cfg(feature = "daemon")]
fn resolve_validate_sources(
    mut pipelines: Vec<rsigma_eval::Pipeline>,
    resolve_sources: bool,
    source_files: &[PathBuf],
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

            let resolver = rsigma_runtime::DefaultSourceResolver::new();
            let mut resolved_pipelines = Vec::with_capacity(pipelines.len());
            let mut source_errors: Vec<String> = Vec::new();

            // Resolve external sources first so they populate the cache
            if !external_sources.is_empty()
                && let Err(e) = rt.block_on(rsigma_runtime::sources::resolve_all(
                    &resolver,
                    &external_sources,
                ))
            {
                source_errors.push(format!("external sources: {e}"));
            }

            for pipeline in &pipelines {
                if pipeline.is_dynamic() {
                    match rt.block_on(rsigma_runtime::sources::resolve_all(
                        &resolver,
                        &pipeline.sources,
                    )) {
                        Ok(resolved_data) => {
                            let expanded =
                                rsigma_runtime::sources::template::TemplateExpander::expand(
                                    pipeline,
                                    &resolved_data,
                                );
                            resolved_pipelines.push(expanded);
                        }
                        Err(e) => {
                            source_errors.push(format!("pipeline '{}': {e}", pipeline.name));
                            resolved_pipelines.push(pipeline.clone());
                        }
                    }
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
            println!("  Sources resolved:  OK");
        }
    }

    pipelines
}
