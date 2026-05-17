use std::io::{self, Read};
use std::path::PathBuf;
use std::process;

use clap::Args;
use rsigma_parser::{parse_sigma_file, parse_sigma_yaml};

/// Arguments for `rsigma rule parse` (and the deprecated `rsigma parse`).
#[derive(Args, Debug)]
pub(crate) struct ParseArgs {
    /// Path to a Sigma YAML file
    pub path: PathBuf,

    /// Pretty-print JSON output
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
    /// Pretty-print JSON output
    #[arg(short, long, default_value_t = true)]
    pub pretty: bool,
}

pub(crate) fn cmd_parse(args: ParseArgs) {
    let ParseArgs { path, pretty } = args;
    match parse_sigma_file(&path) {
        Ok(collection) => {
            crate::print_warnings(&collection.errors);
            crate::print_json(&collection, pretty);
        }
        Err(e) => {
            eprintln!("Error parsing {}: {e}", path.display());
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

pub(crate) fn cmd_condition(args: ConditionArgs) {
    let ConditionArgs { expr } = args;
    match rsigma_parser::parse_condition(&expr) {
        Ok(ast) => crate::print_json(&ast, true),
        Err(e) => {
            eprintln!("Condition parse error: {e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

pub(crate) fn cmd_stdin(args: StdinArgs) {
    let StdinArgs { pretty } = args;
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("Error reading stdin: {e}");
        process::exit(crate::exit_code::RULE_ERROR);
    }

    match parse_sigma_yaml(&input) {
        Ok(collection) => {
            crate::print_warnings(&collection.errors);
            crate::print_json(&collection, pretty);
        }
        Err(e) => {
            eprintln!("Parse error: {e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}
