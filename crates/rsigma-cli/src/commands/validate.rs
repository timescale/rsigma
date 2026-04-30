use std::path::PathBuf;
use std::process;

use rsigma_eval::Engine;
use rsigma_parser::parse_sigma_directory;

pub(crate) fn cmd_validate(path: PathBuf, verbose: bool, pipeline_paths: Vec<PathBuf>) {
    let pipelines = crate::load_pipelines(&pipeline_paths);

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
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}
