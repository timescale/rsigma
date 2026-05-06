use std::path::PathBuf;
use std::process;

use rsigma_eval::Engine;
use rsigma_parser::parse_sigma_directory;

pub(crate) fn cmd_validate(
    path: PathBuf,
    verbose: bool,
    pipeline_paths: Vec<PathBuf>,
    resolve_sources: bool,
) {
    let mut pipelines = crate::load_pipelines(&pipeline_paths);

    if resolve_sources {
        let has_dynamic = pipelines.iter().any(|p| p.is_dynamic());
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

            let mut engine = Engine::new();
            for p in &pipelines {
                engine.add_pipeline(p.clone());
            }

            let mut compile_ok = 0usize;
            let mut compile_errors: Vec<String> = Vec::new();
            for rule in &collection.rules {
                match engine.add_rule(rule) {
                    Ok(()) => compile_ok += 1,
                    Err(e) => {
                        let id = rule.id.as_deref().unwrap_or(&rule.title);
                        compile_errors.push(format!("{id}: {e}"));
                    }
                }
            }

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
