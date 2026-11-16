//! `rsigma ruleset`: curate named rule sets declared in `rsigma.yaml`.

mod build;
mod diff;
mod list;
mod show;

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::output::OutputCtx;

#[derive(Subcommand)]
pub(crate) enum RulesetCommands {
    /// List declared rulesets and their resolution status
    List(ListArgs),
    /// Show the documents a ruleset resolves to
    Show(ShowArgs),
    /// Materialize a ruleset into a directory with a lockfile
    Build(BuildArgs),
    /// Compare a ruleset with its lockfile
    Diff(DiffArgs),
}

#[derive(Args, Debug)]
pub(crate) struct ListArgs {
    /// Configuration file to read rulesets from
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct ShowArgs {
    /// Ruleset name
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Configuration file to read rulesets from
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Show every candidate, including excluded and dropped documents
    #[arg(long)]
    pub all: bool,

    /// Show one document by id
    #[arg(long, value_name = "ID")]
    pub id: Option<String>,

    /// Print the canonical emitted YAML of the document selected by --id
    #[arg(long, requires = "id")]
    pub yaml: bool,
}

#[derive(Args, Debug)]
pub(crate) struct BuildArgs {
    /// Ruleset name
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Configuration file to read rulesets from
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Output directory (defaults to the ruleset's `output`)
    #[arg(short = 'o', long, value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// Write into a non-empty directory that has no lockfile
    #[arg(long)]
    pub force: bool,

    /// Report drift and exit 1 instead of writing
    #[arg(long)]
    pub check: bool,
}

#[derive(Args, Debug)]
pub(crate) struct DiffArgs {
    /// Ruleset name
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Configuration file to read rulesets from
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Lockfile to compare against (defaults to the ruleset's `output`)
    #[arg(long, value_name = "PATH")]
    pub lock: Option<PathBuf>,

    /// Exit 1 when the ruleset differs from the lockfile
    #[arg(long)]
    pub fail_on_change: bool,
}

pub(crate) fn dispatch(cmd: RulesetCommands, ctx: OutputCtx) {
    match cmd {
        RulesetCommands::List(args) => list::cmd_list(args, ctx),
        RulesetCommands::Show(args) => show::cmd_show(args, ctx),
        RulesetCommands::Build(args) => build::cmd_build(args, ctx),
        RulesetCommands::Diff(args) => diff::cmd_diff(args, ctx),
    }
}
