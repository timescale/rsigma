//! `rsigma rule doc`: assemble, report, and scaffold the ADS (Alerting and
//! Detection Strategy) document for one or more rules.
//!
//! Render mode (the default) reports which required ADS sections each rule
//! carries and which it is missing, through the global `--output-format` layer
//! or as a canonical Markdown ADS document with `--format markdown`. Scaffold
//! mode (`--scaffold`) emits a `rsigma.ads.*` template prefilled from the
//! reused fields, to stdout or merged into the rule file with `--in-place`.

use std::path::{Path, PathBuf};
use std::process;

use clap::parser::ValueSource;
use clap::{ArgMatches, Args, ValueEnum};
use rsigma_parser::ads::{is_exempt, scaffold_missing};
use rsigma_parser::{AdsContent, AdsSection, LintConfig, SigmaRule, Status};
use serde::Serialize;

use crate::config;
use crate::exit_code;
use crate::output::{DelimitedWriter, OutputCtx, OutputFormat, Tabular, render_json};

/// Arguments for `rsigma rule doc`.
#[derive(Args, Debug)]
pub(crate) struct DocArgs {
    /// One or more Sigma rule files or directories of rules.
    #[arg(value_name = "RULES", required = true)]
    pub rules: Vec<PathBuf>,

    /// Emit a scaffolded ADS template for a single rule instead of a report.
    #[arg(long, conflicts_with_all = ["missing_only", "fail_on_missing"])]
    pub scaffold: bool,

    /// With `--scaffold`, merge the template into the rule file's
    /// `custom_attributes:` block instead of printing it to stdout.
    #[arg(long, requires = "scaffold")]
    pub in_place: bool,

    /// Render format. `auto` (the default) renders through the global
    /// `--output-format` layer; `markdown` emits the canonical ADS document
    /// per rule.
    #[arg(long, value_enum, default_value_t = DocFormat::Auto)]
    pub format: DocFormat,

    /// Report only rules that fall below the configured ADS bar. Filters the
    /// output only; the exit code is unchanged.
    #[arg(long)]
    pub missing_only: bool,

    /// Exit 1 if any requested rule falls below the configured ADS bar. Makes
    /// `rule doc` a standalone CI gate.
    #[arg(long)]
    pub fail_on_missing: bool,

    /// Path to a `.rsigma-lint.yml` whose `ads:` block sets the ADS bar.
    /// Without it, the bar is auto-discovered from the rule path, then the
    /// built-in defaults (enforce `stable`, require every section).
    #[arg(long = "lint-config", value_name = "PATH")]
    pub lint_config: Option<PathBuf>,

    /// Path to an rsigma config file. Overrides config-file discovery.
    /// CLI flags still take precedence over config-file values.
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Print the effective `doc` config (defaults < file < env) and exit.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

/// Apply the layered `doc` config (file < env) under the CLI flags, then run.
/// `--dry-run` prints the resolved config and exits.
pub(crate) fn apply_doc_config(args: &mut DocArgs, matches: &ArgMatches) {
    let base = config::load_and_merge(args.config.as_deref());
    if args.dry_run {
        config::print_dry_run("doc", &base);
        process::exit(exit_code::SUCCESS);
    }
    overlay_doc_config(args, matches, base);
}

/// Pure overlay of the resolved `doc` section onto `args` (no disk access),
/// split out so it can be unit-tested.
fn overlay_doc_config(args: &mut DocArgs, matches: &ArgMatches, base: config::RsigmaConfigPartial) {
    let explicit = |id: &str| {
        matches!(
            matches.value_source(id),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        )
    };

    if let Some(doc) = base.doc
        && !explicit("fail_on_missing")
        && let Some(v) = doc.fail_on_missing
    {
        args.fail_on_missing = v;
    }
}

/// Render format for `rule doc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum DocFormat {
    /// Render through the global `--output-format` layer.
    Auto,
    /// Emit a canonical Markdown ADS document per rule.
    Markdown,
}

/// Run `rule doc`, returning the process exit code.
pub(crate) fn cmd_doc(args: DocArgs, ctx: OutputCtx) -> i32 {
    let bar = load_ads_bar(&args);

    if args.scaffold {
        return run_scaffold(&args, &ctx);
    }

    let mut rules = Vec::new();
    for path in &args.rules {
        let collection = crate::load_collection(path);
        for rule in collection.rules {
            rules.push(RuleDoc::build(rule, path, &bar));
        }
    }

    if rules.is_empty() {
        if ctx.show_progress() {
            eprintln!("No detection rules found.");
        }
        return exit_code::SUCCESS;
    }

    let below = rules.iter().filter(|r| r.below_bar).count();

    let shown: Vec<&RuleDoc> = if args.missing_only {
        rules.iter().filter(|r| r.below_bar).collect()
    } else {
        rules.iter().collect()
    };

    match args.format {
        DocFormat::Markdown => render_markdown(&shown, &ctx),
        DocFormat::Auto => render_auto(&rules, &shown, below, &ctx),
    }

    if args.fail_on_missing && below > 0 {
        exit_code::FINDINGS
    } else {
        exit_code::SUCCESS
    }
}

/// The resolved ADS bar: which statuses are enforced, which sections are
/// required, and which extra tag namespaces satisfy the categorization check.
struct AdsBar {
    enforce_status: Vec<String>,
    required: Vec<AdsSection>,
    tag_namespaces: Vec<String>,
}

impl AdsBar {
    fn enforces(&self, status: Option<Status>) -> bool {
        match status {
            Some(s) => self.enforce_status.iter().any(|e| e == status_str(s)),
            None => false,
        }
    }

    /// Whether a section's content is present on the rule. Categorization is
    /// namespace-aware (matching the linter), so a tag in a configured
    /// `tag_namespaces` namespace satisfies it; every other section delegates to
    /// the parser's presence check.
    fn section_present(&self, section: AdsSection, rule: &SigmaRule) -> bool {
        if section == AdsSection::Categorization {
            rsigma_parser::ads::has_categorization(rule, &self.tag_namespaces)
        } else {
            section.is_present(rule)
        }
    }
}

/// Load the ADS bar from an explicit `--lint-config`, an auto-discovered
/// `.rsigma-lint.yml`, or the built-in defaults.
fn load_ads_bar(args: &DocArgs) -> AdsBar {
    let loaded = if let Some(explicit) = &args.lint_config {
        // An explicit --lint-config that cannot be read or parsed is a hard
        // error (exit 3), matching `rule lint`; a silently-default ADS bar
        // would let CI apply the wrong bar without noticing.
        match LintConfig::load(explicit) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("Error loading lint config '{}': {e}", explicit.display());
                process::exit(exit_code::CONFIG_ERROR);
            }
        }
    } else if let Some(first) = args.rules.first() {
        // Auto-discovery stays best-effort: a malformed discovered file falls
        // back to defaults rather than failing an unrelated invocation.
        LintConfig::find_in_ancestors(first).and_then(|p| LintConfig::load(&p).ok())
    } else {
        None
    };

    let tag_namespaces = loaded
        .as_ref()
        .map(|c| c.tag_namespaces.clone())
        .unwrap_or_default();
    let ads = loaded.and_then(|c| c.ads).unwrap_or_default();
    let required = AdsSection::all()
        .iter()
        .copied()
        .filter(|s| ads.required.iter().any(|r| r == s.id()))
        .collect();
    AdsBar {
        enforce_status: ads.enforce_status,
        required,
        tag_namespaces,
    }
}

/// The lowercase wire form of a status.
fn status_str(s: Status) -> &'static str {
    match s {
        Status::Stable => "stable",
        Status::Test => "test",
        Status::Experimental => "experimental",
        Status::Deprecated => "deprecated",
        Status::Unsupported => "unsupported",
    }
}

/// The display heading for an ADS section in the Markdown document.
fn heading(section: AdsSection) -> &'static str {
    match section {
        AdsSection::Goal => "Goal",
        AdsSection::Categorization => "Categorization",
        AdsSection::Strategy => "Strategy Abstract",
        AdsSection::TechnicalContext => "Technical Context",
        AdsSection::BlindSpots => "Blind Spots and Assumptions",
        AdsSection::FalsePositives => "False Positives",
        AdsSection::Validation => "Validation",
        AdsSection::Priority => "Priority",
        AdsSection::Response => "Response",
    }
}

// ---------------------------------------------------------------------------
// Report shape
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct RuleDoc {
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    /// Whether the rule's status is in the enforce set (the bar applies).
    enforced: bool,
    /// Whether the rule opted out via `rsigma.ads.exempt: true`.
    exempt: bool,
    sections: Vec<SectionEntry>,
    missing_required: Vec<&'static str>,
    /// True when the rule is enforced, not exempt, and missing a required section.
    below_bar: bool,
    #[serde(skip)]
    rule: SigmaRule,
}

#[derive(Debug, Serialize)]
struct SectionEntry {
    id: &'static str,
    required: bool,
    present: bool,
    carrier: &'static str,
}

impl RuleDoc {
    fn build(rule: SigmaRule, source: &Path, bar: &AdsBar) -> Self {
        let exempt = is_exempt(&rule);
        let enforced = bar.enforces(rule.status);

        let sections: Vec<SectionEntry> = AdsSection::all()
            .iter()
            .map(|&s| SectionEntry {
                id: s.id(),
                required: bar.required.contains(&s),
                present: bar.section_present(s, &rule),
                carrier: s.carrier_field(),
            })
            .collect();

        let missing_required: Vec<&'static str> = bar
            .required
            .iter()
            .filter(|s| !bar.section_present(**s, &rule))
            .map(|s| s.id())
            .collect();

        let below_bar = enforced && !exempt && !missing_required.is_empty();

        RuleDoc {
            title: rule.title.clone(),
            id: rule.id.clone(),
            source: source.display().to_string(),
            status: rule.status.map(|s| status_str(s).to_string()),
            enforced,
            exempt,
            sections,
            missing_required,
            below_bar,
            rule,
        }
    }
}

#[derive(Debug, Serialize)]
struct DocReport<'a> {
    summary: DocSummary,
    rules: Vec<&'a RuleDoc>,
}

#[derive(Debug, Serialize)]
struct DocSummary {
    total_rules: usize,
    below_bar: usize,
}

// ---------------------------------------------------------------------------
// Render: global output-format layer
// ---------------------------------------------------------------------------

fn render_auto(all: &[RuleDoc], shown: &[&RuleDoc], below: usize, ctx: &OutputCtx) {
    let format = if ctx.explicit_format {
        ctx.format
    } else {
        OutputFormat::Table
    };

    match format {
        OutputFormat::Json => {
            let report = DocReport {
                summary: DocSummary {
                    total_rules: all.len(),
                    below_bar: below,
                },
                rules: shown.to_vec(),
            };
            render_json(&report, ctx.pretty_json());
        }
        OutputFormat::Ndjson => {
            for r in shown {
                render_json(r, false);
            }
        }
        OutputFormat::Csv => render_delimited(shown, ',', ctx),
        OutputFormat::Tsv => render_delimited(shown, '\t', ctx),
        OutputFormat::Table => print_table(all, shown, below, ctx),
    }
}

/// One row per rule for the table and delimited renderers.
struct DocRow<'a>(&'a RuleDoc);

impl Tabular for DocRow<'_> {
    fn headers() -> &'static [&'static str] {
        &["RULE", "STATUS", "MISSING", "VERDICT"]
    }
    fn row(&self) -> Vec<String> {
        let r = self.0;
        let missing = if r.missing_required.is_empty() {
            "-".to_string()
        } else {
            r.missing_required.join(",")
        };
        let verdict = if r.exempt {
            "exempt"
        } else if !r.enforced {
            "not-enforced"
        } else if r.below_bar {
            "below-bar"
        } else {
            "complete"
        };
        vec![
            r.title.clone(),
            r.status.clone().unwrap_or_else(|| "-".to_string()),
            missing,
            verdict.to_string(),
        ]
    }
}

fn render_delimited(shown: &[&RuleDoc], sep: char, ctx: &OutputCtx) {
    if ctx.show_stats() {
        eprintln!("Rules: {}", shown.len());
    }
    let mut writer = DelimitedWriter::new(sep, DocRow::headers());
    for &r in shown {
        writer.push(&DocRow(r).row());
    }
}

fn print_table(all: &[RuleDoc], shown: &[&RuleDoc], below: usize, ctx: &OutputCtx) {
    if ctx.show_stats() {
        eprintln!(
            "Rules: {} | below ADS bar: {} | shown: {}",
            all.len(),
            below,
            shown.len()
        );
        eprintln!();
    }
    if shown.is_empty() {
        if ctx.show_progress() {
            eprintln!("No rules to show.");
        }
        return;
    }
    let rows: Vec<DocRow> = shown.iter().map(|&r| DocRow(r)).collect();
    crate::output::render_table(&rows);
}

// ---------------------------------------------------------------------------
// Render: Markdown ADS document
// ---------------------------------------------------------------------------

fn render_markdown(shown: &[&RuleDoc], ctx: &OutputCtx) {
    if shown.is_empty() {
        if ctx.show_progress() {
            eprintln!("No rules to show.");
        }
        return;
    }
    let mut out = String::new();
    for (i, &r) in shown.iter().enumerate() {
        if i > 0 {
            out.push_str("\n---\n\n");
        }
        out.push_str(&markdown_for(r));
    }
    print!("{out}");
}

fn markdown_for(doc: &RuleDoc) -> String {
    use std::fmt::Write;
    let rule = &doc.rule;
    let mut s = String::new();
    let _ = writeln!(s, "# {}\n", rule.title);
    if let Some(status) = &doc.status {
        let _ = writeln!(s, "- **Status:** {status}");
    }
    if let Some(level) = rule.level {
        let _ = writeln!(s, "- **Level:** {}", level.as_str());
    }
    s.push('\n');

    for &section in AdsSection::all() {
        let _ = writeln!(s, "## {}\n", heading(section));
        if section == AdsSection::Priority
            && let Some(level) = rule.level
        {
            let _ = writeln!(s, "**Level:** {}\n", level.as_str());
        }
        match section.content(rule) {
            Some(content) => {
                s.push_str(&render_content_md(&content));
                s.push('\n');
            }
            None => {
                let _ = writeln!(s, "_Not documented._\n");
            }
        }
    }
    s
}

fn render_content_md(content: &AdsContent) -> String {
    use std::fmt::Write;
    match content {
        AdsContent::Text(t) => format!("{t}\n"),
        AdsContent::List(items) => {
            let mut s = String::new();
            for item in items {
                let _ = writeln!(s, "- {item}");
            }
            s
        }
    }
}

// ---------------------------------------------------------------------------
// Scaffold
// ---------------------------------------------------------------------------

fn run_scaffold(args: &DocArgs, ctx: &OutputCtx) -> i32 {
    if args.rules.len() != 1 {
        eprintln!("error: --scaffold takes exactly one rule file");
        return exit_code::CONFIG_ERROR;
    }
    let path = &args.rules[0];
    if !path.is_file() {
        eprintln!("error: --scaffold takes a single rule file, not a directory");
        return exit_code::CONFIG_ERROR;
    }

    let collection = crate::load_collection(path);
    if collection.rules.len() != 1 {
        eprintln!(
            "error: --scaffold needs a file with exactly one detection rule (found {})",
            collection.rules.len()
        );
        return exit_code::CONFIG_ERROR;
    }
    let rule = &collection.rules[0];

    let entries = scaffold_missing(rule);
    if entries.is_empty() {
        if ctx.show_progress() {
            eprintln!("Rule already documents every rsigma.ads.* section.");
        }
        return exit_code::SUCCESS;
    }

    let block = scaffold_yaml(&entries, 4);

    if args.in_place {
        match merge_in_place(path, &entries) {
            Ok(0) => {
                if ctx.show_progress() {
                    eprintln!(
                        "No sections merged into {}: every scaffolded key already exists \
                         (fill any blank values in place).",
                        path.display()
                    );
                }
                exit_code::SUCCESS
            }
            Ok(n) => {
                if ctx.show_progress() {
                    eprintln!("Merged {n} ADS section(s) into {}", path.display());
                }
                exit_code::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                exit_code::CONFIG_ERROR
            }
        }
    } else {
        print!("custom_attributes:\n{block}");
        exit_code::SUCCESS
    }
}

/// Render scaffold entries as YAML keys at `indent` spaces (list items two
/// deeper).
fn scaffold_yaml(entries: &[rsigma_parser::AdsScaffoldEntry], indent: usize) -> String {
    use std::fmt::Write;
    let pad = " ".repeat(indent);
    let item_pad = " ".repeat(indent + 2);
    let mut s = String::new();
    for entry in entries {
        match &entry.placeholder {
            AdsContent::Text(t) => {
                let _ = writeln!(s, "{pad}{}: {}", entry.key, yaml_quote(t));
            }
            AdsContent::List(items) => {
                let _ = writeln!(s, "{pad}{}:", entry.key);
                for item in items {
                    let _ = writeln!(s, "{item_pad}- {}", yaml_quote(item));
                }
            }
        }
    }
    s
}

/// Double-quote a YAML scalar, escaping backslashes and double quotes.
fn yaml_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Merge the scaffold entries into the rule file's `custom_attributes:` block,
/// appending a new block when none exists. Returns the number of sections
/// actually written.
///
/// Entries whose key already appears in the file are skipped so the merge never
/// introduces a duplicate YAML key (a blank `rsigma.ads.strategy: ""` counts as
/// missing for the scaffold, but its key is still present, and a prepended
/// duplicate would be silently overridden by the existing empty value).
fn merge_in_place(
    path: &Path,
    entries: &[rsigma_parser::AdsScaffoldEntry],
) -> Result<usize, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let to_add: Vec<rsigma_parser::AdsScaffoldEntry> = entries
        .iter()
        .filter(|e| !file_has_key(&content, e.key))
        .cloned()
        .collect();
    if to_add.is_empty() {
        return Ok(0);
    }

    let lines: Vec<&str> = content.lines().collect();
    let header = lines.iter().position(|l| {
        let t = l.trim_end();
        t == "custom_attributes:" || t.starts_with("custom_attributes:")
    });

    let new_text = match header {
        Some(idx) => {
            let after = lines[idx].trim_end();
            if after != "custom_attributes:" {
                return Err(
                    "the rule's `custom_attributes` is inline; add the sections manually".into(),
                );
            }
            // Child indent: the indent of the first key under the block, or 2.
            let child_indent = lines
                .get(idx + 1)
                .map(|l| l.len() - l.trim_start().len())
                .filter(|n| *n > 0)
                .unwrap_or(2);
            let block = scaffold_yaml(&to_add, child_indent);
            let mut out: Vec<String> = lines[..=idx].iter().map(|s| s.to_string()).collect();
            for l in block.lines() {
                out.push(l.to_string());
            }
            for l in &lines[idx + 1..] {
                out.push(l.to_string());
            }
            let mut joined = out.join("\n");
            if content.ends_with('\n') {
                joined.push('\n');
            }
            joined
        }
        None => {
            let block = scaffold_yaml(&to_add, 4);
            let mut text = content.trim_end().to_string();
            text.push_str("\ncustom_attributes:\n");
            text.push_str(&block);
            text
        }
    };

    std::fs::write(path, new_text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(to_add.len())
}

/// Whether `content` already declares the dotted key `<key>:` on some line
/// (under `custom_attributes:` or as a top-level flat key).
fn file_has_key(content: &str, key: &str) -> bool {
    let needle = format!("{key}:");
    content.lines().any(|l| l.trim_start().starts_with(&needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Command, FromArgMatches};

    fn parse(argv: &[&str]) -> (DocArgs, ArgMatches) {
        let cmd = DocArgs::augment_args(Command::new("doc"));
        let matches = cmd.get_matches_from(argv);
        let args = DocArgs::from_arg_matches(&matches).expect("valid args");
        (args, matches)
    }

    fn partial(yaml: &str) -> config::RsigmaConfigPartial {
        yaml_serde::from_str(yaml).expect("valid partial")
    }

    fn parse_rule(yaml: &str) -> SigmaRule {
        rsigma_parser::parse_sigma_yaml(yaml)
            .unwrap()
            .rules
            .pop()
            .unwrap()
    }

    const PRIVATE_NS_RULE: &str = r#"
title: Private taxonomy
status: stable
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
tags:
    - myorg.technique
"#;

    #[test]
    fn categorization_uses_configured_namespaces() {
        let rule = parse_rule(PRIVATE_NS_RULE);
        // Without a configured namespace, a private-taxonomy tag does not
        // satisfy categorization, matching attack.*-only.
        let strict = AdsBar {
            enforce_status: vec!["stable".to_string()],
            required: AdsSection::all().to_vec(),
            tag_namespaces: vec![],
        };
        assert!(!strict.section_present(AdsSection::Categorization, &rule));

        // With `myorg` recognised, it does, matching `rule lint`.
        let lenient = AdsBar {
            enforce_status: vec!["stable".to_string()],
            required: AdsSection::all().to_vec(),
            tag_namespaces: vec!["myorg".to_string()],
        };
        assert!(lenient.section_present(AdsSection::Categorization, &rule));
    }

    #[test]
    fn yaml_quote_escapes() {
        assert_eq!(yaml_quote("a: b"), "\"a: b\"");
        assert_eq!(yaml_quote("say \"hi\""), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn status_strings() {
        assert_eq!(status_str(Status::Stable), "stable");
        assert_eq!(status_str(Status::Experimental), "experimental");
    }

    #[test]
    fn defaults_match_config_defaults() {
        let (args, _) = parse(&["doc", "rule.yml"]);
        assert_eq!(args.fail_on_missing, config::defaults::DOC_FAIL_ON_MISSING);
    }

    #[test]
    fn config_fills_unset_fail_on_missing() {
        let (mut args, matches) = parse(&["doc", "rule.yml"]);
        let base = partial("doc:\n  fail_on_missing: true\n");
        overlay_doc_config(&mut args, &matches, base);
        assert!(args.fail_on_missing);
    }

    #[test]
    fn cli_flag_wins_over_config() {
        let (mut args, matches) = parse(&["doc", "rule.yml", "--fail-on-missing"]);
        let base = partial("doc:\n  fail_on_missing: false\n");
        overlay_doc_config(&mut args, &matches, base);
        assert!(args.fail_on_missing);
    }
}
