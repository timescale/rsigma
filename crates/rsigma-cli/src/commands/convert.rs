use std::path::PathBuf;
use std::process;

use clap::Args;

use crate::output::{OutputCtx, OutputFormat, render_json};

/// Arguments for `rsigma backend convert` (and the deprecated `rsigma convert`).
#[derive(Args, Debug)]
pub(crate) struct ConvertArgs {
    /// Path(s) to Sigma rule file(s) or directory
    pub rules: Vec<PathBuf>,

    /// Target backend (e.g. postgres, lynxdb, fibratus, test)
    #[arg(short, long)]
    pub target: String,

    /// Output format (backend-specific, default: "default")
    #[arg(short, long, default_value = "default")]
    pub format: String,

    /// Processing pipeline(s) (repeatable). Accepts builtin names (ecs_windows, sysmon) or YAML file paths
    #[arg(short = 'p', long = "pipeline")]
    pub pipeline: Vec<PathBuf>,

    /// Skip pipeline requirement check
    #[arg(long)]
    pub without_pipeline: bool,

    /// Skip unsupported rules instead of failing
    #[arg(short, long)]
    pub skip_unsupported: bool,

    /// Output file (default: stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Backend options as key=value pairs (repeatable)
    #[arg(short = 'O', long = "option")]
    pub backend_options: Vec<String>,
}

/// Canonical names of the targets rsigma converts natively, for listings and
/// error messages. Aliases (`postgresql`, `pg`) and the internal test backends
/// are accepted by [`try_native_backend`] but intentionally not advertised.
const NATIVE_TARGETS: &[&str] = &["postgres", "lynxdb", "fibratus"];

/// Return the native backend for `target`, or `None` when rsigma has no native
/// backend for it, in which case `backend convert` delegates to sigma-cli.
fn try_native_backend(
    target: &str,
    options: &std::collections::HashMap<String, String>,
) -> Option<Box<dyn rsigma_convert::Backend>> {
    match target {
        "postgres" | "postgresql" | "pg" => Some(Box::new(
            rsigma_convert::backends::postgres::PostgresBackend::from_options(options),
        )),
        "lynxdb" => Some(Box::new(
            rsigma_convert::backends::lynxdb::LynxDbBackend::new(),
        )),
        "fibratus" => Some(Box::new(
            rsigma_convert::backends::fibratus::FibratusBackend::from_options(options),
        )),
        "test" => Some(Box::new(
            rsigma_convert::backends::test::TextQueryTestBackend::new(),
        )),
        "test_mandatory_pipeline" => Some(Box::new(
            rsigma_convert::backends::test::MandatoryPipelineTestBackend::new(),
        )),
        _ => None,
    }
}

pub(crate) fn cmd_convert(args: ConvertArgs, ctx: OutputCtx) {
    let options: std::collections::HashMap<String, String> = args
        .backend_options
        .iter()
        .filter_map(|opt| {
            opt.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();

    // Native-first dispatch: convert with a native rsigma backend when one
    // exists, otherwise delegate the whole conversion to a discovered
    // sigma-cli (or fail with install guidance when neither is available).
    let Some(backend) = try_native_backend(&args.target, &options) else {
        run_delegated(&args, &ctx);
        return;
    };

    let ConvertArgs {
        rules,
        target,
        format,
        pipeline: pipeline_paths,
        without_pipeline,
        skip_unsupported,
        output,
        backend_options: _,
    } = args;

    let collection = crate::load_collection_multi(&rules);
    let pipelines = crate::load_pipelines(&pipeline_paths);

    if pipelines.iter().any(|p| p.is_dynamic()) {
        eprintln!(
            "  note: dynamic sources are not resolved by `rsigma backend convert`. \
             Use `rsigma pipeline resolve` to inspect sources or `rsigma engine daemon` to evaluate \
             events with dynamic pipelines."
        );
    }

    if backend.requires_pipeline() && pipelines.is_empty() && !without_pipeline {
        eprintln!("Backend '{target}' requires a pipeline. Use -p or --without-pipeline.");
        process::exit(crate::exit_code::CONFIG_ERROR);
    }

    if !backend.formats().iter().any(|(f, _)| *f == format) {
        eprintln!("Unknown format '{format}' for backend '{target}'");
        eprintln!(
            "Available: {}",
            backend
                .formats()
                .iter()
                .map(|(f, d)| format!("{f} ({d})"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        process::exit(crate::exit_code::CONFIG_ERROR);
    }

    if let Some(method) = options.get("correlation_method") {
        let methods = backend.correlation_methods();
        if !methods.iter().any(|(n, _)| n == method) {
            eprintln!("Unknown correlation_method '{method}' for backend '{target}'");
            if methods.is_empty() {
                eprintln!("Backend '{target}' does not support selectable correlation methods.");
            } else {
                eprintln!(
                    "Available: {}",
                    methods
                        .iter()
                        .map(|(n, d)| format!("{n} ({d})"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
    }

    if let Some(gap) = options.get("gap")
        && rsigma_parser::Timespan::parse(gap).is_err()
    {
        eprintln!("Invalid gap '{gap}': expected a duration like 30s, 5m, 1h, 7d");
        process::exit(crate::exit_code::CONFIG_ERROR);
    }

    let result =
        rsigma_convert::convert_collection(backend.as_ref(), &collection, &pipelines, &format);
    match result {
        Ok(output_data) => {
            for (rule_title, error) in &output_data.errors {
                if skip_unsupported {
                    eprintln!("Warning: rule '{rule_title}' skipped: {error}");
                } else {
                    eprintln!("Error: rule '{rule_title}' failed: {error}");
                }
            }
            for (rule_title, warning) in output_data.warnings() {
                eprintln!("Warning: rule '{rule_title}': {warning}");
            }
            if !skip_unsupported && !output_data.errors.is_empty() {
                process::exit(crate::exit_code::RULE_ERROR);
            }
            // When `--output` points at a directory (an existing directory or a
            // path with a trailing separator), write one file per converted
            // rule into it instead of a single concatenated stream. This lets
            // operators drop the result straight into a target rules directory
            // (e.g. a Fibratus `Rules/` folder) without splitting the output by
            // hand.
            if let Some(dir) = output.as_deref().filter(|p| is_directory_target(p)) {
                write_split_output(backend.as_ref(), &output_data, &format, dir, &ctx);
                return;
            }
            // `--output-format json` wraps the queries in a JSON envelope.
            // The other structured formats (`ndjson`/`csv`/`tsv`/`table`)
            // make no sense for free-form query text -- warn once on stderr
            // and fall back to the raw text path.
            if ctx.format == OutputFormat::Json && output.is_none() {
                let queries: Vec<serde_json::Value> = output_data
                    .queries
                    .iter()
                    .flat_map(|r| {
                        r.queries.iter().map(move |q| {
                            serde_json::json!({
                                "rule_title": r.rule_title,
                                "rule_id": r.rule_id,
                                "query": q,
                            })
                        })
                    })
                    .collect();
                render_json(
                    &serde_json::json!({
                        "target": target,
                        "format": format,
                        "queries": queries,
                    }),
                    ctx.pretty_json(),
                );
                return;
            }
            if ctx.explicit_format
                && !matches!(ctx.format, OutputFormat::Json | OutputFormat::Ndjson)
                && ctx.show_progress()
            {
                eprintln!(
                    "warning: `--output-format {}` is not supported by `backend convert`; falling back to raw query text.",
                    ctx.format.as_str(),
                );
            }
            let all_queries: Vec<String> = output_data
                .queries
                .iter()
                .flat_map(|r| r.queries.iter().cloned())
                .collect();
            // Defer to the backend so format-aware separators land in
            // the joined output (e.g. `---\n` between YAML rule
            // documents for the Fibratus backend, `;\n\n` between
            // PostgreSQL `view`/`continuous_aggregate` statements).
            let output_str = backend
                .finalize_output(all_queries, &format)
                .unwrap_or_else(|e| {
                    eprintln!("Output finalization failed: {e}");
                    process::exit(crate::exit_code::RULE_ERROR);
                });
            write_output(&output_str, output.as_deref());
        }
        Err(e) => {
            eprintln!("Conversion failed: {e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

/// Convert via an external sigma-cli for a target rsigma has no native backend
/// for. The original rule files and a near 1:1 flag mapping are passed straight
/// through, and sigma-cli's stdout is relayed through rsigma's output handling,
/// so the result is identical to running sigma-cli directly.
fn run_delegated(args: &ConvertArgs, ctx: &OutputCtx) {
    use super::sigma_cli::{self, SigmaCli};

    let target = args.target.as_str();
    let format = args.format.as_str();
    let output = args.output.as_deref();

    // Per-rule directory splitting reuses a native backend's finalizer, which a
    // delegated stream has no equivalent of; fail clearly rather than write a
    // single concatenated file into the directory.
    if let Some(dir) = output.filter(|p| is_directory_target(p)) {
        eprintln!(
            "Per-rule directory output ('-o {}') is only supported by native backends; \
             the delegated target '{target}' produces a single stream. Use a file path or stdout.",
            dir.display()
        );
        process::exit(crate::exit_code::CONFIG_ERROR);
    }

    let cli = SigmaCli::configured();
    let argv = sigma_cli::build_convert_args(
        target,
        format,
        &args.pipeline,
        args.without_pipeline,
        args.skip_unsupported,
        &args.backend_options,
        &args.rules,
    );

    let result = match cli.run(&argv) {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "{}",
                sigma_cli::install_hint(target, cli.program(), cli.is_override(), NATIVE_TARGETS)
            );
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
        Err(e) => {
            eprintln!(
                "Failed to launch sigma-cli ('{}'): {e}",
                cli.program().display()
            );
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
    };

    // Relay sigma-cli diagnostics verbatim (warnings, skipped-rule notes, errors).
    if !result.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&result.stderr));
    }
    if !result.status.success() {
        process::exit(crate::exit_code::RULE_ERROR);
    }

    let stdout = String::from_utf8_lossy(&result.stdout);
    let queries = stdout.trim_end_matches('\n');

    // `--output-format json` wraps the delegated queries in the same envelope
    // shape the native path emits. sigma-cli text backends emit one query per
    // line, so each non-empty line becomes a query object.
    if ctx.format == OutputFormat::Json && output.is_none() {
        let query_objs: Vec<serde_json::Value> = queries
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|q| serde_json::json!({ "query": q }))
            .collect();
        render_json(
            &serde_json::json!({
                "target": target,
                "format": format,
                "engine": "sigma-cli",
                "queries": query_objs,
            }),
            ctx.pretty_json(),
        );
        return;
    }

    if ctx.explicit_format
        && !matches!(ctx.format, OutputFormat::Json | OutputFormat::Ndjson)
        && ctx.show_progress()
    {
        eprintln!(
            "warning: `--output-format {}` is not supported by `backend convert`; falling back to raw query text.",
            ctx.format.as_str(),
        );
    }

    write_output(queries, output);
}

pub(crate) fn cmd_list_targets() {
    println!("Available conversion targets:");
    println!("  postgres  - PostgreSQL/TimescaleDB (aliases: postgresql, pg)");
    println!("  lynxdb    - LynxDB log analytics engine");
    println!("  fibratus  - Fibratus kernel-event detection engine");
    println!("  test      - Backend-neutral test backend");

    // Any other target is delegated to sigma-cli when it is installed; list its
    // targets too so the user sees the full set available from this machine.
    let cli = super::sigma_cli::SigmaCli::configured();
    match cli.run(["list", "targets"]) {
        Ok(out) if out.status.success() && !out.stdout.is_empty() => {
            println!(
                "\nAdditional targets via sigma-cli ('{}'):",
                cli.program().display()
            );
            print!("{}", String::from_utf8_lossy(&out.stdout));
        }
        _ => {
            println!(
                "\nInstall sigma-cli for more targets (splunk, elasticsearch, kusto, qradar, loki, ...):"
            );
            println!("  pipx install sigma-cli && sigma plugin install <target>");
        }
    }
}

pub(crate) fn cmd_list_formats(target: String) {
    if let Some(backend) = try_native_backend(&target, &std::collections::HashMap::new()) {
        println!("Available formats for '{target}':");
        for (name, desc) in backend.formats() {
            println!("  {name}  - {desc}");
        }
        let methods = backend.correlation_methods();
        if !methods.is_empty() {
            println!(
                "\nCorrelation methods for '{target}' (select with -O correlation_method=NAME, default: {}):",
                backend.default_correlation_method()
            );
            for (name, desc) in methods {
                println!("  {name}  - {desc}");
            }
        }
        return;
    }

    // Delegated target: ask sigma-cli for the formats it supports.
    let cli = super::sigma_cli::SigmaCli::configured();
    match cli.run(["list", "formats", target.as_str()]) {
        Ok(out) => {
            if !out.stdout.is_empty() {
                print!("{}", String::from_utf8_lossy(&out.stdout));
            }
            if !out.stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(&out.stderr));
            }
            if !out.status.success() {
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "{}",
                super::sigma_cli::install_hint(
                    &target,
                    cli.program(),
                    cli.is_override(),
                    NATIVE_TARGETS
                )
            );
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
        Err(e) => {
            eprintln!(
                "Failed to launch sigma-cli ('{}'): {e}",
                cli.program().display()
            );
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
    }
}

/// Wrapper for the deprecated flat `rsigma list-formats TARGET` form so the
/// outer dispatch can pull the positional argument off a clap variant uniformly.
#[derive(Args, Debug)]
pub(crate) struct ListFormatsArgs {
    /// Target backend name
    pub target: String,
}

fn write_output(content: &str, output: Option<&std::path::Path>) {
    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, content) {
                eprintln!("Error writing to {}: {e}", path.display());
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
        }
        None => println!("{content}"),
    }
}

/// True when the `--output` target should be treated as a directory to fill
/// with one file per rule rather than a single file to write the whole stream
/// to.
///
/// An existing directory always qualifies. A path with a trailing separator
/// signals directory intent even before the directory exists (rsync-style), so
/// `-o rules/` splits while `-o rules.yml` writes a single file.
fn is_directory_target(path: &std::path::Path) -> bool {
    if path.is_dir() {
        return true;
    }
    let s = path.as_os_str().to_string_lossy();
    s.ends_with('/') || s.ends_with(std::path::MAIN_SEPARATOR)
}

/// Write one file per converted rule into `dir`, naming each file after the
/// rule and giving it the backend's per-rule extension (`.yml` for Fibratus,
/// `.sql` for PostgreSQL, ...). Each rule's own conversion result (which may
/// itself be several documents, e.g. correlation permutations) is finalized
/// through the backend so format-aware separators land inside the file.
fn write_split_output(
    backend: &dyn rsigma_convert::Backend,
    output_data: &rsigma_convert::ConversionOutput,
    format: &str,
    dir: &std::path::Path,
    ctx: &OutputCtx,
) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("Error creating output directory {}: {e}", dir.display());
        process::exit(crate::exit_code::CONFIG_ERROR);
    }

    let ext = backend.output_file_extension(format);
    let mut used_names = std::collections::HashSet::new();
    let mut written = 0usize;

    for result in &output_data.queries {
        let content = backend
            .finalize_output(result.queries.clone(), format)
            .unwrap_or_else(|e| {
                eprintln!(
                    "Output finalization failed for rule '{}': {e}",
                    result.rule_title
                );
                process::exit(crate::exit_code::RULE_ERROR);
            });
        if content.trim().is_empty() {
            continue;
        }

        let filename = rule_filename(
            &result.rule_title,
            result.rule_id.as_deref(),
            ext,
            &mut used_names,
        );
        let path = dir.join(&filename);
        let content = if content.ends_with('\n') {
            content
        } else {
            format!("{content}\n")
        };
        if let Err(e) = std::fs::write(&path, &content) {
            eprintln!("Error writing to {}: {e}", path.display());
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
        written += 1;
    }

    if ctx.show_progress() {
        eprintln!("Wrote {written} rule file(s) to {}", dir.display());
    }
}

/// Build a unique, filesystem-safe file name for a converted rule.
///
/// The base name is a slug of the rule title (the human-readable key the
/// upstream Fibratus rules library names its files after); the rule id, then a
/// `rule` literal, are fallbacks when the title slugifies to nothing. Names
/// already taken in this run get a numeric suffix so two rules with the same
/// title never overwrite each other.
fn rule_filename(
    title: &str,
    id: Option<&str>,
    ext: &str,
    used: &mut std::collections::HashSet<String>,
) -> String {
    let mut base = slugify(title);
    if base.is_empty() {
        base = id
            .map(slugify)
            .filter(|s| !s.is_empty())
            .unwrap_or_default();
    }
    if base.is_empty() {
        base = "rule".to_string();
    }

    let mut candidate = format!("{base}.{ext}");
    let mut counter = 2usize;
    while !used.insert(candidate.clone()) {
        candidate = format!("{base}_{counter}.{ext}");
        counter += 1;
    }
    candidate
}

/// Lowercase a string and collapse every run of non-alphanumeric characters
/// into a single `_`, trimming leading and trailing underscores. Produces the
/// snake_case file stems the upstream Fibratus rules library uses.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_underscore = false;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_underscore = false;
        } else if !prev_underscore {
            out.push('_');
            prev_underscore = true;
        }
    }
    out.trim_matches('_').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn slugify_makes_snake_case_stems() {
        assert_eq!(slugify("Detect Whoami"), "detect_whoami");
        assert_eq!(
            slugify("Suspicious cmd.exe via Explorer!"),
            "suspicious_cmd_exe_via_explorer"
        );
        assert_eq!(slugify("  leading/trailing  "), "leading_trailing");
        assert_eq!(slugify("---"), "");
    }

    #[test]
    fn rule_filename_uses_title_slug_and_extension() {
        let mut used = HashSet::new();
        assert_eq!(
            rule_filename("Detect Whoami", Some("abc"), "yml", &mut used),
            "detect_whoami.yml"
        );
    }

    #[test]
    fn rule_filename_falls_back_to_id_then_rule() {
        let mut used = HashSet::new();
        assert_eq!(
            rule_filename(
                "!!!",
                Some("00000000-0000-0000-0000-000000000100"),
                "yml",
                &mut used
            ),
            "00000000_0000_0000_0000_000000000100.yml"
        );
        assert_eq!(rule_filename("???", None, "sql", &mut used), "rule.sql");
    }

    #[test]
    fn rule_filename_dedupes_collisions() {
        let mut used = HashSet::new();
        assert_eq!(rule_filename("Same", None, "yml", &mut used), "same.yml");
        assert_eq!(rule_filename("Same", None, "yml", &mut used), "same_2.yml");
        assert_eq!(rule_filename("Same", None, "yml", &mut used), "same_3.yml");
    }

    #[test]
    fn directory_target_detects_trailing_separator() {
        assert!(is_directory_target(std::path::Path::new("rules/")));
        assert!(!is_directory_target(std::path::Path::new("rules.yml")));
    }
}
