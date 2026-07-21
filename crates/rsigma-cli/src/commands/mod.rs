mod backtest;
mod classify;
mod convert;
mod coverage;
#[cfg(feature = "daemon")]
mod daemon;
mod discover;
mod doc;
mod draft;
mod eval;
mod eval_stream;
mod explain;
mod fields;
mod from_lucene;
mod hygiene;
mod lint;
#[cfg(feature = "mcp")]
mod mcp;
mod migrate_sources;
mod navigator;
mod parse;
mod pipeline_diff;
// Shared serializable report shapes for the detection-as-code `rule` commands:
// `backtest`/`coverage` produce them, `scorecard` consumes them.
pub(crate) mod reports;
// `pipeline resolve` needs the async runtime + source resolver, which only
// ship with the `daemon` feature.
#[cfg(feature = "daemon")]
mod resolve;
mod scorecard;
// Delegation to an external sigma-cli for non-native conversion targets.
mod status;
mod tail;
mod tap;
mod validate;
mod visibility;

pub(crate) use backtest::{BacktestArgs, apply_backtest_config, cmd_backtest};
pub(crate) use classify::{ClassifyArgs, cmd_classify};
pub(crate) use convert::{
    ConvertArgs, ListFormatsArgs, cmd_convert, cmd_list_formats, cmd_list_targets,
};
pub(crate) use coverage::{CoverageArgs, apply_coverage_config, cmd_coverage};
#[cfg(feature = "daemon")]
pub(crate) use daemon::{DaemonArgs, cmd_daemon, parse_input_format};
pub(crate) use discover::{DiscoverArgs, cmd_discover};
pub(crate) use doc::{DocArgs, apply_doc_config, cmd_doc};
pub(crate) use draft::{DraftArgs, cmd_draft};
pub(crate) use eval::{EvalArgs, apply_eval_config, cmd_eval};
pub(crate) use explain::{ExplainArgs, cmd_explain};
pub(crate) use fields::{FieldsArgs, cmd_fields};
pub(crate) use from_lucene::{FromLuceneArgs, cmd_from_lucene};
pub(crate) use hygiene::{HygieneArgs, apply_hygiene_config, cmd_hygiene};
pub(crate) use lint::{LintArgs, LintCounts, cmd_lint};
#[cfg(feature = "mcp")]
pub(crate) use mcp::{McpCommands, dispatch_mcp};
pub(crate) use migrate_sources::{MigrateSourcesArgs, cmd_migrate_sources};
pub(crate) use parse::{ConditionArgs, ParseArgs, StdinArgs, cmd_condition, cmd_parse, cmd_stdin};
pub(crate) use pipeline_diff::{PipelineDiffArgs, cmd_pipeline_diff};
#[cfg(feature = "daemon")]
pub(crate) use resolve::{ResolveArgs, cmd_resolve};
pub(crate) use scorecard::{ScorecardArgs, apply_scorecard_config, cmd_scorecard};
pub(crate) use status::{StatusArgs, cmd_status};
pub(crate) use tail::{TailArgs, cmd_tail};
pub(crate) use tap::{TapArgs, cmd_tap};
pub(crate) use validate::{ValidateArgs, cmd_validate};
pub(crate) use visibility::{VisibilityArgs, apply_visibility_config, cmd_visibility};
