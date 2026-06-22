mod backtest;
mod convert;
mod coverage;
#[cfg(feature = "daemon")]
mod daemon;
mod eval;
mod eval_stream;
mod fields;
mod lint;
#[cfg(feature = "mcp")]
mod mcp;
mod migrate_sources;
mod navigator;
mod parse;
// `pipeline resolve` needs the async runtime + source resolver, which only
// ship with the `daemon` feature.
#[cfg(feature = "daemon")]
mod resolve;
// Delegation to an external sigma-cli for non-native conversion targets.
mod sigma_cli;
mod status;
mod tail;
mod tap;
mod validate;
mod visibility;

pub(crate) use backtest::{BacktestArgs, apply_backtest_config, cmd_backtest};
pub(crate) use convert::{
    ConvertArgs, ListFormatsArgs, cmd_convert, cmd_list_formats, cmd_list_targets,
};
pub(crate) use coverage::{CoverageArgs, apply_coverage_config, cmd_coverage};
#[cfg(feature = "daemon")]
pub(crate) use daemon::{DaemonArgs, cmd_daemon, parse_input_format};
pub(crate) use eval::{EvalArgs, apply_eval_config, cmd_eval};
pub(crate) use fields::{FieldsArgs, cmd_fields};
pub(crate) use lint::{LintArgs, LintCounts, cmd_lint};
#[cfg(feature = "mcp")]
pub(crate) use mcp::{McpCommands, dispatch_mcp};
pub(crate) use migrate_sources::{MigrateSourcesArgs, cmd_migrate_sources};
pub(crate) use parse::{ConditionArgs, ParseArgs, StdinArgs, cmd_condition, cmd_parse, cmd_stdin};
#[cfg(feature = "daemon")]
pub(crate) use resolve::{ResolveArgs, cmd_resolve};
pub(crate) use status::{StatusArgs, cmd_status};
pub(crate) use tail::{TailArgs, cmd_tail};
pub(crate) use tap::{TapArgs, cmd_tap};
pub(crate) use validate::{ValidateArgs, cmd_validate};
pub(crate) use visibility::{VisibilityArgs, apply_visibility_config, cmd_visibility};
