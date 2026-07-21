//! `rule from-lucene`: convert an Elastic Lucene query into a draft Sigma rule.
//!
//! Reads a Lucene / Elasticsearch `query_string` (from a positional argument,
//! `--file`, or stdin), parses it into the intermediate representation, raises a
//! Sigma rule, and prints it as Sigma YAML. A query carries no rule metadata, so
//! the title, id, level, status, and logsource come from flags; the rest is a
//! best-effort skeleton for a human to review.
//!
//! The emitted YAML is parsed back before it is printed, so a rule that would
//! not round-trip never reaches the operator. This is the query sibling of
//! `rule draft` (events to Sigma) and `rule discover-schemas`.

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;

use clap::Args;
use rsigma_convert::{LuceneFrontend, ReverseCtx, reverse_collection};
use rsigma_parser::{Level, Status};

use crate::output::OutputCtx;

/// Arguments for `rsigma rule from-lucene`.
#[derive(Args, Debug)]
pub(crate) struct FromLuceneArgs {
    /// The Lucene query. Omit to read from `--file` or stdin.
    pub query: Option<String>,

    /// Read the query from a file instead of the positional argument.
    #[arg(short = 'f', long)]
    pub file: Option<PathBuf>,

    /// Rule title (recommended; a query has no title of its own).
    #[arg(long)]
    pub title: Option<String>,

    /// Rule id (UUID).
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

    /// Write the rule to a file instead of stdout.
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}

pub(crate) fn cmd_from_lucene(args: FromLuceneArgs, _ctx: OutputCtx) {
    let query = read_query(&args);

    let level = parse_enum::<Level>(args.level.as_deref(), "level");
    let status = parse_enum::<Status>(args.status.as_deref(), "status");

    let ctx = ReverseCtx {
        title: args.title,
        id: args.id,
        level,
        status,
        product: args.logsource_product,
        category: args.logsource_category,
        service: args.logsource_service,
        strict: false,
    };

    let frontend = LuceneFrontend;
    let mut output = reverse_collection(&frontend, std::slice::from_ref(&query), &ctx);
    if let Some((_, err)) = output.errors.first() {
        eprintln!("Error converting query: {err}");
        process::exit(crate::exit_code::RULE_ERROR);
    }
    let yaml = output.rules.pop().map(|r| r.yaml).unwrap_or_else(|| {
        eprintln!("Error converting query: no rule was produced");
        process::exit(crate::exit_code::RULE_ERROR);
    });

    // Self-verify: the emitted rule must parse back to exactly one rule.
    match rsigma_parser::parse_sigma_yaml(&yaml) {
        Ok(collection) if collection.rules.len() == 1 && !collection.has_errors() => {}
        Ok(_) => {
            eprintln!("Error: the converted rule did not round-trip through the parser");
            process::exit(crate::exit_code::RULE_ERROR);
        }
        Err(e) => {
            eprintln!("Error: the converted rule failed to re-parse: {e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }

    match &args.output {
        Some(path) => {
            if let Err(e) = fs::write(path, &yaml) {
                eprintln!("Error writing to {}: {e}", path.display());
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
        }
        None => print!("{yaml}"),
    }
}

fn read_query(args: &FromLuceneArgs) -> String {
    let raw = match (&args.query, &args.file) {
        (Some(_), Some(_)) => {
            eprintln!("Provide the query as an argument or --file, not both");
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
        (Some(q), None) => q.clone(),
        (None, Some(path)) => fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("Error reading query file '{}': {e}", path.display());
            process::exit(crate::exit_code::CONFIG_ERROR);
        }),
        (None, None) => {
            let mut buf = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut buf) {
                eprintln!("Error reading stdin: {e}");
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
            buf
        }
    };
    let query = raw.trim().to_string();
    if query.is_empty() {
        eprintln!("Empty query; pass a Lucene query as an argument, via --file, or on stdin");
        process::exit(crate::exit_code::CONFIG_ERROR);
    }
    query
}

fn parse_enum<T: std::str::FromStr>(value: Option<&str>, label: &str) -> Option<T> {
    value.map(|v| {
        v.parse::<T>().unwrap_or_else(|_| {
            eprintln!("Invalid {label}: '{v}'");
            process::exit(crate::exit_code::CONFIG_ERROR);
        })
    })
}
