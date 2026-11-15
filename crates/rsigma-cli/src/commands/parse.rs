use std::io::{self, Read};
use std::path::PathBuf;
use std::process;

use clap::Args;
use rsigma_parser::{parse_sigma_file, parse_sigma_yaml};

use crate::output::{OutputCtx, OutputFormat, render_json};

/// Arguments for `rsigma rule parse` (and the deprecated `rsigma parse`).
#[derive(Args, Debug)]
pub(crate) struct ParseArgs {
    /// Path to a Sigma YAML file
    pub path: PathBuf,

    /// Pretty-print JSON output (default; pass `--no-pretty` for compact).
    ///
    /// Forced on when `--output-format json` is set on a TTY. Mostly here
    /// for backwards compatibility -- new code should rely on
    /// `--output-format`.
    #[arg(short, long, default_value_t = true)]
    pub pretty: bool,
}

/// Arguments for `rsigma rule condition` (and the deprecated `rsigma condition`).
#[derive(Args, Debug)]
pub(crate) struct ConditionArgs {
    /// The condition expression to parse
    pub expr: String,
}

/// Arguments for `rsigma rule stdin` (and the deprecated `rsigma stdin`).
#[derive(Args, Debug)]
pub(crate) struct StdinArgs {
    /// Pretty-print JSON output (default; pass `--no-pretty` for compact).
    #[arg(short, long, default_value_t = true)]
    pub pretty: bool,
}

pub(crate) fn cmd_parse(args: ParseArgs, ctx: OutputCtx) {
    let ParseArgs { path, pretty } = args;
    match parse_sigma_file(&path) {
        Ok(collection) => {
            crate::print_warnings(&collection.diagnostics);
            emit_ast("rule parse", &ctx, &collection, pretty);
        }
        Err(e) => {
            eprintln!("Error parsing {}: {e}", path.display());
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

pub(crate) fn cmd_condition(args: ConditionArgs, ctx: OutputCtx) {
    let ConditionArgs { expr } = args;
    match rsigma_parser::parse_condition(&expr) {
        // `--pretty` is implied for condition output; the AST is small and
        // human-friendly is the default. `--output-format ndjson` overrides
        // to compact via [`emit_ast`].
        Ok(ast) => emit_ast("rule condition", &ctx, &ast, true),
        Err(e) => {
            eprintln!("{e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

pub(crate) fn cmd_stdin(args: StdinArgs, ctx: OutputCtx) {
    let StdinArgs { pretty } = args;
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("Error reading stdin: {e}");
        process::exit(crate::exit_code::RULE_ERROR);
    }

    match parse_sigma_yaml(&input) {
        Ok(collection) => {
            crate::print_warnings(&collection.diagnostics);
            emit_ast("rule stdin", &ctx, &collection, pretty);
        }
        Err(e) => {
            eprintln!("Parse error: {e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

/// Emit a parsed AST. Honors json/ndjson; warns and falls back to JSON for
/// table/csv/tsv. The legacy `--pretty` flag still controls pretty-printing
/// when the format is JSON (or the JSON fallback).
fn emit_ast<T: serde::Serialize>(command: &str, ctx: &OutputCtx, value: &T, pretty_flag: bool) {
    match ctx.format {
        OutputFormat::Ndjson => render_json(value, false),
        OutputFormat::Json => render_json(value, pretty_flag || ctx.pretty_json()),
        OutputFormat::Table | OutputFormat::Csv | OutputFormat::Tsv => {
            // Preserve the caller's pretty preference on the JSON fallback.
            ctx.warn_unsupported(command, "json");
            render_json(value, pretty_flag);
        }
    }
}
