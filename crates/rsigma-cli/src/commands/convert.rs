use std::path::PathBuf;
use std::process;

use clap::Args;

use serde::Serialize;

use crate::output::{OutputCtx, OutputFormat, Tabular, render_json, render_report};

/// Arguments for `rsigma backend convert` (and the deprecated `rsigma convert`).
#[derive(Args, Debug)]
pub(crate) struct ConvertArgs {
    /// Path(s) to Sigma rule file(s) or directory
    #[arg(required_unless_present = "ruleset", conflicts_with = "ruleset")]
    pub rules: Vec<PathBuf>,

    /// Named ruleset from the configuration to convert instead of rule paths.
    #[arg(long, value_name = "NAME")]
    pub ruleset: Option<String>,

    /// Path to an rsigma config file. Overrides config-file discovery.
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

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
pub(crate) const NATIVE_TARGETS: &[&str] = &["postgres", "lynxdb", "fibratus"];

/// Return the native backend for `target`, or `None` when rsigma has no native
/// backend for it, in which case `backend convert` delegates to sigma-cli.
pub(crate) fn try_native_backend(
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

/// One rule-loading request for the shared conversion core.
pub(crate) struct ConvertRequest<'a> {
    pub collection: &'a rsigma_parser::SigmaCollection,
    pub target: &'a str,
    pub format: &'a str,
    pub pipelines: Vec<rsigma_eval::Pipeline>,
    pub options: std::collections::HashMap<String, String>,
    pub skip_unsupported: bool,
    pub without_pipeline: bool,
}

/// Per-rule conversion status for a build manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuleStatus {
    Converted,
    Skipped,
    Failed,
}

/// Per-rule outcome from the shared conversion core.
#[derive(Debug, Clone)]
pub(crate) struct RuleOutcome {
    pub id: Option<String>,
    pub title: String,
    pub status: RuleStatus,
    pub error: Option<String>,
}

/// Rendered conversion output and per-rule outcomes.
#[derive(Debug)]
pub(crate) struct ConvertOutput {
    pub text: String,
    pub results: Vec<rsigma_convert::ConversionResult>,
    pub rules: Vec<RuleOutcome>,
    pub queries: usize,
    pub warnings: Vec<(String, String)>,
}

/// A conversion failure with the exit-code class it maps to.
#[derive(Debug)]
pub(crate) enum ConvertFailure {
    Config(String),
    Rule(String),
}

/// A delegated sigma-cli conversion.
#[derive(Debug)]
pub(crate) struct DelegatedOutput {
    pub raw: String,
    pub queries: Vec<String>,
    pub stderr: String,
}

/// Convert a collection with a native backend.
pub(crate) fn convert_native(req: &ConvertRequest<'_>) -> Result<ConvertOutput, ConvertFailure> {
    let Some(backend) = try_native_backend(req.target, &req.options) else {
        return Err(ConvertFailure::Config(format!(
            "unknown target '{}'; available: {}",
            req.target,
            NATIVE_TARGETS.join(", ")
        )));
    };

    if backend.requires_pipeline() && req.pipelines.is_empty() && !req.without_pipeline {
        return Err(ConvertFailure::Config(format!(
            "Backend '{}' requires a pipeline. Use -p or --without-pipeline.",
            req.target
        )));
    }

    if !backend.formats().iter().any(|(f, _)| *f == req.format) {
        let available = backend
            .formats()
            .iter()
            .map(|(f, d)| format!("{f} ({d})"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ConvertFailure::Config(format!(
            "Unknown format '{}' for backend '{}'\nAvailable: {available}",
            req.format, req.target
        )));
    }

    if let Some(method) = req.options.get("correlation_method") {
        let methods = backend.correlation_methods();
        if !methods.iter().any(|(n, _)| n == method) {
            let available = methods
                .iter()
                .map(|(n, d)| format!("{n} ({d})"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(ConvertFailure::Config(if methods.is_empty() {
                format!(
                    "Unknown correlation_method '{method}' for backend '{}'\nBackend '{}' does not support selectable correlation methods.",
                    req.target, req.target
                )
            } else {
                format!(
                    "Unknown correlation_method '{method}' for backend '{}'\nAvailable: {available}",
                    req.target
                )
            }));
        }
    }

    if let Some(gap) = req.options.get("gap")
        && rsigma_parser::Timespan::parse(gap).is_err()
    {
        return Err(ConvertFailure::Config(format!(
            "Invalid gap '{gap}': expected a duration like 30s, 5m, 1h, 7d"
        )));
    }

    let output_data = rsigma_convert::convert_collection(
        backend.as_ref(),
        req.collection,
        &req.pipelines,
        req.format,
    )
    .map_err(|e| ConvertFailure::Rule(format!("Conversion failed: {e}")))?;

    let mut rules = Vec::new();
    for result in &output_data.queries {
        rules.push(RuleOutcome {
            id: result.rule_id.clone(),
            title: result.rule_title.clone(),
            status: RuleStatus::Converted,
            error: None,
        });
    }
    for (title, error) in &output_data.errors {
        let (id, status, message) = if req.skip_unsupported {
            (None, RuleStatus::Skipped, Some(error.to_string()))
        } else {
            (None, RuleStatus::Failed, Some(error.to_string()))
        };
        rules.push(RuleOutcome {
            id,
            title: title.clone(),
            status,
            error: message,
        });
    }

    let warnings = output_data
        .warnings()
        .map(|(title, message)| (title.to_string(), message.to_string()))
        .collect::<Vec<_>>();

    let all_queries: Vec<String> = output_data
        .queries
        .iter()
        .flat_map(|r| r.queries.iter().cloned())
        .collect();
    let queries = all_queries.len();
    let text = backend
        .finalize_output(all_queries, req.format)
        .map_err(|e| ConvertFailure::Rule(format!("Output finalization failed: {e}")))?;

    Ok(ConvertOutput {
        text,
        results: output_data.queries,
        rules,
        queries,
        warnings,
    })
}

/// Convert via an external sigma-cli for a target rsigma has no native backend.
pub(crate) fn convert_delegated(
    paths: &[PathBuf],
    target: &str,
    format: &str,
    pipelines: &[PathBuf],
    options: &[String],
    skip_unsupported: bool,
    without_pipeline: bool,
) -> Result<DelegatedOutput, ConvertFailure> {
    use rsigma_convert::sigma_cli::{self, DelegateError, SigmaCli};

    let cli = SigmaCli::configured();
    let argv = sigma_cli::build_convert_args(
        target,
        format,
        pipelines,
        without_pipeline,
        skip_unsupported,
        options,
        paths,
    );

    let result = match cli.run(&argv) {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConvertFailure::Config(sigma_cli::install_hint(
                target,
                cli.program(),
                cli.is_override(),
                NATIVE_TARGETS,
            )));
        }
        Err(e) => {
            return Err(ConvertFailure::Config(format!(
                "Failed to launch sigma-cli ('{}'): {e}",
                cli.program().display()
            )));
        }
    };

    let conversion = match sigma_cli::classify_output(&result) {
        Ok(conversion) => conversion,
        Err(DelegateError::NonZero { stderr, .. }) => {
            return Err(ConvertFailure::Rule(stderr));
        }
        Err(DelegateError::NotInstalled { .. }) => {
            return Err(ConvertFailure::Config(sigma_cli::install_hint(
                target,
                cli.program(),
                cli.is_override(),
                NATIVE_TARGETS,
            )));
        }
    };

    Ok(DelegatedOutput {
        raw: conversion.raw.trim_end_matches('\n').to_string(),
        queries: conversion.queries,
        stderr: conversion.stderr,
    })
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

    if ctx.explicit_format && args.output.is_some() {
        ctx.warn_ignored("backend convert", "--output always writes raw query text");
    }

    let Some(backend) = try_native_backend(&args.target, &options) else {
        let tempdir = args.ruleset.as_deref().map(|name| {
            let (name, spec) = crate::ruleset::load_named(name, args.config.as_deref());
            let resolved = crate::ruleset::resolve_or_exit(&name, &spec, &ctx);
            crate::ruleset::build::materialize_temp(&resolved, &spec).unwrap_or_else(|error| {
                eprintln!("error: {error}");
                process::exit(crate::exit_code::CONFIG_ERROR);
            })
        });
        let rules = match &tempdir {
            Some(dir) => vec![dir.path().to_path_buf()],
            None => args.rules.clone(),
        };
        run_delegated(&args, &ctx, &rules, tempdir);
        return;
    };

    let ConvertArgs {
        rules,
        ruleset,
        config,
        target,
        format,
        pipeline: pipeline_paths,
        without_pipeline,
        skip_unsupported,
        output,
        backend_options: _,
    } = args;

    let input = crate::ruleset::RuleInput {
        rules: &rules,
        ruleset: ruleset.as_deref(),
        config: config.as_deref(),
    };
    let collection = input.collection(&ctx);
    let pipelines = crate::load_pipelines(&pipeline_paths);

    if pipelines.iter().any(|p| p.is_dynamic()) {
        eprintln!(
            "  note: dynamic sources are not resolved by `rsigma backend convert`. \
             Use `rsigma pipeline resolve` to inspect sources or `rsigma engine daemon` to evaluate \
             events with dynamic pipelines."
        );
    }

    let request = ConvertRequest {
        collection: &collection,
        target: &target,
        format: &format,
        pipelines,
        options,
        skip_unsupported,
        without_pipeline,
    };
    let output_data = match convert_native(&request) {
        Ok(output) => output,
        Err(ConvertFailure::Config(message)) => {
            eprintln!("{message}");
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
        Err(ConvertFailure::Rule(message)) => {
            eprintln!("{message}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    };

    for rule in &output_data.rules {
        if let Some(error) = &rule.error {
            if rule.status == RuleStatus::Skipped {
                eprintln!("Warning: rule '{}' skipped: {error}", rule.title);
            } else {
                eprintln!("Error: rule '{}' failed: {error}", rule.title);
            }
        }
    }
    for (rule_title, warning) in &output_data.warnings {
        eprintln!("Warning: rule '{rule_title}': {warning}");
    }
    if !skip_unsupported
        && output_data
            .rules
            .iter()
            .any(|rule| rule.status == RuleStatus::Failed)
    {
        process::exit(crate::exit_code::RULE_ERROR);
    }

    if let Some(dir) = output.as_deref().filter(|p| is_directory_target(p)) {
        write_split_output(backend.as_ref(), &output_data.results, &format, dir, &ctx);
        return;
    }

    if ctx.explicit_format && output.is_none() {
        let out_format = ctx.format;
        match out_format {
            OutputFormat::Json => {
                let queries: Vec<serde_json::Value> = output_data
                    .results
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
            OutputFormat::Ndjson => {
                for r in &output_data.results {
                    for q in &r.queries {
                        render_json(
                            &serde_json::json!({
                                "target": target,
                                "format": format,
                                "rule_title": r.rule_title,
                                "rule_id": r.rule_id,
                                "query": q,
                            }),
                            false,
                        );
                    }
                }
                return;
            }
            OutputFormat::Table | OutputFormat::Csv | OutputFormat::Tsv => {
                ctx.warn_unsupported("backend convert", "raw query text");
            }
        }
    }

    write_output(&output_data.text, output.as_deref());
}

/// Convert via an external sigma-cli for a target rsigma has no native backend.
fn run_delegated(
    args: &ConvertArgs,
    ctx: &OutputCtx,
    rules: &[PathBuf],
    materialized: Option<tempfile::TempDir>,
) {
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
        drop(materialized);
        process::exit(crate::exit_code::CONFIG_ERROR);
    }

    let converted = convert_delegated(
        rules,
        target,
        format,
        &args.pipeline,
        &args.backend_options,
        args.skip_unsupported,
        args.without_pipeline,
    );
    drop(materialized);

    let converted = match converted {
        Ok(converted) => converted,
        Err(ConvertFailure::Config(message)) => {
            eprintln!("{message}");
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
        Err(ConvertFailure::Rule(stderr)) => {
            // Relay sigma-cli's error text verbatim.
            if !stderr.is_empty() {
                eprint!("{stderr}");
            }
            process::exit(crate::exit_code::RULE_ERROR);
        }
    };

    // Relay sigma-cli diagnostics verbatim (warnings, skipped-rule notes).
    if !converted.stderr.is_empty() {
        eprint!("{}", converted.stderr);
    }

    // Explicit `--output-format json|ndjson` wraps the delegated queries in
    // the same envelope shape the native path emits. sigma-cli text backends
    // emit one query per line, so each non-empty line becomes a query object.
    if ctx.explicit_format && output.is_none() {
        let out_format = ctx.format;
        match out_format {
            OutputFormat::Json => {
                let query_objs: Vec<serde_json::Value> = converted
                    .queries
                    .iter()
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
            OutputFormat::Ndjson => {
                for q in &converted.queries {
                    render_json(
                        &serde_json::json!({
                            "target": target,
                            "format": format,
                            "engine": "sigma-cli",
                            "query": q,
                        }),
                        false,
                    );
                }
                return;
            }
            OutputFormat::Table | OutputFormat::Csv | OutputFormat::Tsv => {
                ctx.warn_unsupported("backend convert", "raw query text");
            }
        }
    }

    write_output(&converted.raw, output);
}

#[derive(Debug, Serialize)]
struct TargetRow {
    provider: String,
    name: String,
    description: String,
}

impl Tabular for TargetRow {
    fn headers() -> &'static [&'static str] {
        &["PROVIDER", "NAME", "DESCRIPTION"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.provider.clone(),
            self.name.clone(),
            self.description.clone(),
        ]
    }
}

#[derive(Debug, Serialize)]
struct FormatRow {
    target: String,
    kind: String,
    name: String,
    description: String,
}

impl Tabular for FormatRow {
    fn headers() -> &'static [&'static str] {
        &["TARGET", "KIND", "NAME", "DESCRIPTION"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.target.clone(),
            self.kind.clone(),
            self.name.clone(),
            self.description.clone(),
        ]
    }
}

fn native_target_rows() -> Vec<TargetRow> {
    vec![
        TargetRow {
            provider: "native".into(),
            name: "postgres".into(),
            description: "PostgreSQL/TimescaleDB (aliases: postgresql, pg)".into(),
        },
        TargetRow {
            provider: "native".into(),
            name: "lynxdb".into(),
            description: "LynxDB log analytics engine".into(),
        },
        TargetRow {
            provider: "native".into(),
            name: "fibratus".into(),
            description: "Fibratus kernel-event detection engine".into(),
        },
        TargetRow {
            provider: "native".into(),
            name: "test".into(),
            description: "Backend-neutral test backend".into(),
        },
    ]
}

/// Parse a sigma-cli ASCII table into data rows, skipping border lines and the
/// header row. Each returned row is the list of trimmed cell strings.
///
/// sigma-cli (`list targets`, `list formats`, …) renders pretty tables like:
///
/// ```text
/// +------------+-----------------------+
/// | Identifier | Target Query Language |
/// +------------+-----------------------+
/// | loki       | Grafana Loki          |
/// +------------+-----------------------+
/// ```
fn parse_sigma_cli_table(raw: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut saw_header = false;
    for line in raw.lines() {
        let line = line.trim();
        // Borders (`+---+`) and non-table prose are ignored.
        if line.is_empty() || line.starts_with('+') || !line.starts_with('|') {
            continue;
        }
        let cells: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_string())
            .collect();
        if cells.iter().all(|c| c.is_empty()) {
            continue;
        }
        if !saw_header {
            saw_header = true;
            continue;
        }
        rows.push(cells);
    }
    rows
}

fn sigma_cli_target_rows(raw: &str) -> Vec<TargetRow> {
    parse_sigma_cli_table(raw)
        .into_iter()
        .filter_map(|cells| {
            let name = cells.first()?.trim();
            if name.is_empty() {
                return None;
            }
            // Column 1 is the query language / description; column 2 (when
            // present) notes whether a processing pipeline is required.
            let language = cells.get(1).map(|s| s.trim()).unwrap_or("");
            let pipeline = cells.get(2).map(|s| s.trim()).unwrap_or("");
            let description = match (language.is_empty(), pipeline.is_empty()) {
                (true, true) => String::new(),
                (false, true) => language.to_string(),
                (true, false) => format!("pipeline required: {pipeline}"),
                (false, false) => format!("{language} (pipeline required: {pipeline})"),
            };
            Some(TargetRow {
                provider: "sigma-cli".into(),
                name: name.to_string(),
                description,
            })
        })
        .collect()
}

fn sigma_cli_format_rows(target: &str, raw: &str) -> Vec<FormatRow> {
    parse_sigma_cli_table(raw)
        .into_iter()
        .filter_map(|cells| {
            let name = cells.first()?.trim();
            if name.is_empty() {
                return None;
            }
            let description = cells
                .get(1..)
                .map(|rest| {
                    rest.iter()
                        .map(|c| c.trim())
                        .filter(|c| !c.is_empty())
                        .collect::<Vec<_>>()
                        .join(" — ")
                })
                .unwrap_or_default();
            Some(FormatRow {
                target: target.to_string(),
                kind: "format".into(),
                name: name.to_string(),
                description,
            })
        })
        .collect()
}

pub(crate) fn cmd_list_targets(ctx: OutputCtx) {
    let mut rows = native_target_rows();

    // Any other target is delegated to sigma-cli when it is installed; list its
    // targets too so the user sees the full set available from this machine.
    let cli = rsigma_convert::sigma_cli::SigmaCli::configured();
    let listing = cli
        .run(["list", "targets"])
        .ok()
        .and_then(|out| rsigma_convert::sigma_cli::classify_output(&out).ok())
        .filter(|conversion| !conversion.raw.is_empty());

    if ctx.explicit_format {
        if let Some(conversion) = &listing {
            rows.extend(sigma_cli_target_rows(&conversion.raw));
        }
        let envelope = serde_json::json!({
            "targets": rows,
            "sigma_cli": listing.as_ref().map(|_| cli.program().display().to_string()),
        });
        render_report(&ctx, &envelope, &rows);
        return;
    }

    println!("Available conversion targets:");
    for row in &rows {
        println!("  {:<9} - {}", row.name, row.description);
    }
    match listing {
        Some(conversion) => {
            println!(
                "\nAdditional targets via sigma-cli ('{}'):",
                cli.program().display()
            );
            print!("{}", conversion.raw);
        }
        None => {
            println!(
                "\nInstall sigma-cli for more targets (splunk, elasticsearch, kusto, qradar, loki, ...):"
            );
            println!("  pipx install sigma-cli && sigma plugin install <target>");
        }
    }
}

pub(crate) fn cmd_list_formats(target: String, ctx: OutputCtx) {
    if let Some(backend) = try_native_backend(&target, &std::collections::HashMap::new()) {
        let mut rows = Vec::new();
        for (name, desc) in backend.formats() {
            rows.push(FormatRow {
                target: target.clone(),
                kind: "format".into(),
                name: name.to_string(),
                description: desc.to_string(),
            });
        }
        let methods = backend.correlation_methods();
        for (name, desc) in methods {
            rows.push(FormatRow {
                target: target.clone(),
                kind: "correlation_method".into(),
                name: name.to_string(),
                description: desc.to_string(),
            });
        }

        if ctx.explicit_format {
            let envelope = serde_json::json!({
                "target": target,
                "default_correlation_method": backend.default_correlation_method(),
                "items": rows,
            });
            render_report(&ctx, &envelope, &rows);
            return;
        }

        println!("Available formats for '{target}':");
        for row in rows.iter().filter(|r| r.kind == "format") {
            println!("  {}  - {}", row.name, row.description);
        }
        let has_methods = rows.iter().any(|r| r.kind == "correlation_method");
        if has_methods {
            println!(
                "\nCorrelation methods for '{target}' (select with -O correlation_method=NAME, default: {}):",
                backend.default_correlation_method()
            );
            for row in rows.iter().filter(|r| r.kind == "correlation_method") {
                println!("  {}  - {}", row.name, row.description);
            }
        }
        return;
    }

    // Delegated target: ask sigma-cli for the formats it supports.
    use rsigma_convert::sigma_cli::{self, DelegateError, SigmaCli};
    let cli = SigmaCli::configured();
    match cli.run(["list", "formats", target.as_str()]) {
        Ok(out) => match sigma_cli::classify_output(&out) {
            Ok(conversion) => {
                if ctx.explicit_format {
                    let rows = sigma_cli_format_rows(&target, &conversion.raw);
                    let envelope = serde_json::json!({
                        "target": target,
                        "engine": "sigma-cli",
                        "items": rows,
                    });
                    render_report(&ctx, &envelope, &rows);
                } else {
                    if !conversion.raw.is_empty() {
                        print!("{}", conversion.raw);
                    }
                    if !conversion.stderr.is_empty() {
                        eprint!("{}", conversion.stderr);
                    }
                }
            }
            Err(DelegateError::NonZero { stdout, stderr, .. }) => {
                if !stdout.is_empty() {
                    print!("{stdout}");
                }
                if !stderr.is_empty() {
                    eprint!("{stderr}");
                }
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
            Err(DelegateError::NotInstalled { .. }) => {
                // Unreachable: spawn errors are handled below.
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "{}",
                sigma_cli::install_hint(&target, cli.program(), cli.is_override(), NATIVE_TARGETS)
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
    results: &[rsigma_convert::ConversionResult],
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

    for result in results {
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

    #[test]
    fn parse_sigma_cli_table_skips_borders_and_header() {
        let raw = "\
+------------+-----------------------+------------------------------+
| Identifier | Target Query Language | Processing Pipeline Required |
+------------+-----------------------+------------------------------+
| loki       | Grafana Loki          | No                           |
| splunk     | Splunk SPL            | Yes                          |
+------------+-----------------------+------------------------------+
";
        let rows = parse_sigma_cli_table(raw);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], vec!["loki", "Grafana Loki", "No"]);
        assert_eq!(rows[1], vec!["splunk", "Splunk SPL", "Yes"]);
    }

    #[test]
    fn sigma_cli_target_rows_ignore_ascii_chrome() {
        let raw = "\
+------------+-----------------------+------------------------------+
| Identifier | Target Query Language | Processing Pipeline Required |
+------------+-----------------------+------------------------------+
| loki       | Grafana Loki          | No                           |
+------------+-----------------------+------------------------------+
";
        let rows = sigma_cli_target_rows(raw);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].provider, "sigma-cli");
        assert_eq!(rows[0].name, "loki");
        assert_eq!(rows[0].description, "Grafana Loki (pipeline required: No)");
        // No border or header fragments leaked into the name column.
        assert!(
            !rows
                .iter()
                .any(|r| r.name.starts_with('+') || r.name == "|")
        );
    }

    #[test]
    fn sigma_cli_format_rows_parse_format_table() {
        let raw = "\
+---------+--------------------------------------------------+
| Format  | Description                                      |
+---------+--------------------------------------------------+
| default | Plain Loki queries                               |
| ruler   | Loki 'ruler' output format for generating alerts |
+---------+--------------------------------------------------+
";
        let rows = sigma_cli_format_rows("loki", raw);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "default");
        assert_eq!(rows[0].description, "Plain Loki queries");
        assert_eq!(rows[1].name, "ruler");
    }
}
