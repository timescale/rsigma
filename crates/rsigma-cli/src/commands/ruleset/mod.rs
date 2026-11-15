//! `rsigma ruleset`: curate named rule sets declared in `rsigma.yaml`.

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

pub(crate) fn dispatch(cmd: RulesetCommands, ctx: OutputCtx) {
    match cmd {
        RulesetCommands::List(args) => list::cmd_list(args, ctx),
        RulesetCommands::Show(args) => show::cmd_show(args, ctx),
    }
}
