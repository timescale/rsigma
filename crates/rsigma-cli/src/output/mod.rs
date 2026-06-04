//! Shared, TTY-aware output rendering for every rsigma CLI command.
//!
//! Two global, command-agnostic switches drive every renderer:
//!
//! * `--output-format <json|ndjson|table|csv|tsv>` selects the wire format
//!   for any tabular data the command emits. The default is TTY-aware: when
//!   stdout is a terminal it prints pretty JSON, when piped it prints
//!   newline-delimited JSON (NDJSON).
//! * `--color auto|always|never` controls ANSI color on the human-friendly
//!   paths (lint findings, summaries, …). Honours `NO_COLOR` when `auto`.
//!
//! Two more reduce noise: `--quiet`/`-q` and `--no-stats`.
//!
//! Commands compose these knobs through [`OutputCtx`], built once in `main`
//! after the existing flag + config resolution.

use std::io::{self, Write};

use serde::Serialize;

/// Selector for the wire format of structured CLI output.
///
/// `Json` and `Ndjson` mean what they say; `Table` is a width-aligned text
/// table for human consumption; `Csv` and `Tsv` are stream-friendly delimited
/// formats with embedded-quote handling for spreadsheets and data tools.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum OutputFormat {
    Json,
    Ndjson,
    Table,
    Csv,
    Tsv,
}

impl OutputFormat {
    /// Parse the value clap stores for `--output-format` (or the YAML
    /// `global.output_format` key, or the `RSIGMA_GLOBAL__OUTPUT_FORMAT` env
    /// var, which all coerce to a lowercase string).
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "ndjson" => Some(Self::Ndjson),
            "table" => Some(Self::Table),
            "csv" => Some(Self::Csv),
            "tsv" => Some(Self::Tsv),
            _ => None,
        }
    }

    /// Lowercase wire name, used for diagnostics and `config show`.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Ndjson => "ndjson",
            Self::Table => "table",
            Self::Csv => "csv",
            Self::Tsv => "tsv",
        }
    }
}

/// Whether ANSI color should be emitted on stdout/stderr.
///
/// The wire values match the lint command's existing `--color` value parser
/// and the `global.color` config key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ColorChoice {
    /// On when stdout is a TTY and `NO_COLOR` is not set.
    #[default]
    Auto,
    /// Always on.
    Always,
    /// Always off.
    Never,
}

impl ColorChoice {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "always" => Some(Self::Always),
            "never" => Some(Self::Never),
            _ => None,
        }
    }

    /// Resolve the choice to a concrete on/off decision.
    ///
    /// `stdout_is_tty` is taken as a parameter (rather than queried inline)
    /// so the resolution is unit-testable and so [`OutputCtx`] can decide
    /// once and re-use the answer for the rest of the run.
    pub(crate) fn resolve(self, stdout_is_tty: bool) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => stdout_is_tty && std::env::var_os("NO_COLOR").is_none(),
        }
    }
}

/// Everything a command needs to render its output, resolved once up front.
///
/// `explicit_format` is `true` when the operator passed `--output-format`
/// (or set the env / config key); commands use it to decide whether to fall
/// back to a TTY-aware default (`Json` when stdout is a terminal, `Ndjson`
/// when piped).
#[derive(Clone, Copy, Debug)]
pub(crate) struct OutputCtx {
    pub format: OutputFormat,
    pub color: bool,
    pub quiet: bool,
    pub no_stats: bool,
    pub stdout_is_tty: bool,
    pub explicit_format: bool,
}

impl Default for OutputCtx {
    fn default() -> Self {
        // The fallback when nothing is configured: NDJSON, no color, no
        // suppression. Used by tests and any code path that builds a renderer
        // before the global context is wired up.
        Self {
            format: OutputFormat::Ndjson,
            color: false,
            quiet: false,
            no_stats: false,
            stdout_is_tty: false,
            explicit_format: false,
        }
    }
}

/// Sanitize the raw `global.output_format` and `global.color` values
/// pulled from a config file before they reach [`OutputCtx::resolve`].
///
/// Both values previously round-tripped through
/// `OutputFormat::parse` / `ColorChoice::parse`, with a `None` from
/// the parser silently falling through to the default. That meant a
/// typo such as `output_format: xml` was silently ignored: the
/// effective format reverted to the TTY-aware default and the
/// operator had no way to discover the mistake short of reading the
/// source. This wrapper warns on stderr for each unrecognized value
/// and strips it from the return so callers fall through cleanly.
///
/// Returns the sanitized strings: any input that does not parse is
/// replaced with `None`. The original strings are accepted by value
/// so the call site can pass `cfg_format` directly without an extra
/// clone.
pub(crate) fn warn_invalid_global_output(
    output_format: Option<String>,
    color: Option<String>,
) -> (Option<String>, Option<String>) {
    let format = output_format.and_then(|s| match OutputFormat::parse(&s) {
        Some(_) => Some(s),
        None => {
            eprintln!(
                "warning: invalid global.output_format '{s}' \
                 (expected one of: json, ndjson, table, csv, tsv); \
                 falling back to default"
            );
            None
        }
    });
    let color = color.and_then(|s| match ColorChoice::parse(&s) {
        Some(_) => Some(s),
        None => {
            eprintln!(
                "warning: invalid global.color '{s}' \
                 (expected one of: auto, always, never); \
                 falling back to default"
            );
            None
        }
    });
    (format, color)
}

impl OutputCtx {
    /// Resolve the effective `OutputCtx` from layered inputs.
    ///
    /// Precedence (high to low) per knob:
    ///
    /// * `--output-format` flag > `RSIGMA_GLOBAL__OUTPUT_FORMAT` env >
    ///   `global.output_format` config > TTY-aware default
    ///   (`Json` when stdout is a TTY, `Ndjson` when piped).
    /// * `--color` flag > `global.color` config > `Auto`.
    /// * `--quiet`, `--no-stats` are flag-only.
    ///
    /// The exact provenance of each value is decided by the caller (which
    /// has the clap `ArgMatches` and the loaded config). This function takes
    /// the already-resolved values to keep it pure and testable.
    pub(crate) fn resolve(
        flag_format: Option<OutputFormat>,
        config_format: Option<&str>,
        flag_color: Option<ColorChoice>,
        config_color: Option<&str>,
        quiet: bool,
        no_stats: bool,
        stdout_is_tty: bool,
    ) -> Self {
        let explicit_format = flag_format.is_some()
            || config_format.is_some_and(|s| OutputFormat::parse(s).is_some());

        let format = flag_format
            .or_else(|| config_format.and_then(OutputFormat::parse))
            .unwrap_or(if stdout_is_tty {
                OutputFormat::Json
            } else {
                OutputFormat::Ndjson
            });

        let color_choice = flag_color
            .or_else(|| config_color.and_then(ColorChoice::parse))
            .unwrap_or_default();
        let color = color_choice.resolve(stdout_is_tty);

        Self {
            format,
            color,
            quiet,
            no_stats,
            stdout_is_tty,
            explicit_format,
        }
    }

    /// Should a `stats` line on stderr be emitted? Suppressed by `--quiet`
    /// and `--no-stats` alike; `--no-stats` is a narrower way to keep
    /// progress logs but drop the summary.
    pub(crate) fn show_stats(&self) -> bool {
        !self.quiet && !self.no_stats
    }

    /// Should non-data progress / informational lines be emitted on stderr?
    /// Only suppressed by `--quiet`. (`--no-stats` keeps progress but drops
    /// the final stats line.)
    pub(crate) fn show_progress(&self) -> bool {
        !self.quiet
    }

    /// True when JSON output should be pretty-printed: explicit `--pretty`,
    /// `--output-format json` with a TTY, or an implicit TTY default. For
    /// `ndjson` this is always false.
    pub(crate) fn pretty_json(&self) -> bool {
        match self.format {
            OutputFormat::Ndjson => false,
            OutputFormat::Json => self.stdout_is_tty || !self.explicit_format,
            // The other formats do not emit JSON.
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Tabular trait + renderers
// ---------------------------------------------------------------------------

/// A row source for the width-aligning text table and the streaming
/// delimited (`csv`/`tsv`) renderers.
///
/// Implementors expose a fixed column header list and convert themselves to
/// a row of cells. Cells are stringified up front so the renderer never has
/// to call back into the value.
pub(crate) trait Tabular {
    fn headers() -> &'static [&'static str];
    fn row(&self) -> Vec<String>;
}

/// Render `value` as JSON to stdout (pretty when `pretty` is `true`). Exits
/// the process with `CONFIG_ERROR` on serialization failure -- the same
/// behaviour the previous `print_json` had.
pub(crate) fn render_json<T: Serialize>(value: &T, pretty: bool) {
    let json = if pretty {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    };
    match json {
        Ok(j) => println!("{j}"),
        Err(e) => {
            eprintln!("JSON serialization error: {e}");
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }
    }
}

/// Render `value` as a single NDJSON line on stdout. Same error semantics as
/// [`render_json`].
pub(crate) fn render_ndjson<T: Serialize>(value: &T) {
    render_json(value, false);
}

/// Render a slice of `Tabular` rows as a width-aligned text table on stdout.
///
/// Width-buffering: we walk the rows once to compute per-column widths, then
/// print the header, a dashed separator, and each row. Columns whose body
/// cells all parse as integers are right-aligned (numeric); everything else
/// is left-aligned. `table` is not a streaming format; for piping to other
/// tools prefer `ndjson`, `csv`, or `tsv`.
pub(crate) fn render_table<T: Tabular>(rows: &[T]) {
    let headers = T::headers();
    if headers.is_empty() {
        return;
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    let stringified: Vec<Vec<String>> = rows.iter().map(|r| r.row()).collect();
    for row in &stringified {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() && cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }
    let right_align: Vec<bool> = (0..widths.len())
        .map(|i| {
            !stringified.is_empty()
                && stringified
                    .iter()
                    .all(|r| r.get(i).is_some_and(|c| c.parse::<i64>().is_ok()))
        })
        .collect();

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let _ = write_row(&mut out, headers.iter().copied(), &widths, &right_align);
    let dashes: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    let _ = write_row(
        &mut out,
        dashes.iter().map(String::as_str),
        &widths,
        &right_align,
    );
    for row in &stringified {
        let _ = write_row(
            &mut out,
            row.iter().map(String::as_str),
            &widths,
            &right_align,
        );
    }
}

fn write_row<'a, I, W>(
    out: &mut W,
    cells: I,
    widths: &[usize],
    right_align: &[bool],
) -> io::Result<()>
where
    I: Iterator<Item = &'a str>,
    W: Write,
{
    let mut first = true;
    for (i, cell) in cells.enumerate() {
        if !first {
            write!(out, "  ")?;
        }
        first = false;
        let w = widths.get(i).copied().unwrap_or(0);
        if right_align.get(i).copied().unwrap_or(false) {
            write!(out, "{cell:>w$}")?;
        } else {
            write!(out, "{cell:<w$}")?;
        }
    }
    writeln!(out)
}

/// Streaming writer for `csv`/`tsv`: header first, then one row per `push`.
///
/// Created once per command via [`DelimitedWriter::new`]. Calling
/// [`DelimitedWriter::push`] streams a row immediately, so the format scales
/// to large match counts without buffering.
pub(crate) struct DelimitedWriter {
    sep: char,
    headers: &'static [&'static str],
    wrote_header: bool,
}

impl DelimitedWriter {
    pub(crate) fn new(sep: char, headers: &'static [&'static str]) -> Self {
        Self {
            sep,
            headers,
            wrote_header: false,
        }
    }

    /// Write the header row (if it has not been written) and one data row.
    /// Cells are escaped according to RFC 4180-style rules: a field that
    /// contains the separator, a double-quote, a CR, or an LF is wrapped in
    /// double quotes, and embedded double-quotes are doubled.
    pub(crate) fn push(&mut self, cells: &[String]) {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        if !self.wrote_header {
            let _ = write_delimited_row(&mut out, self.headers.iter().copied(), self.sep);
            self.wrote_header = true;
        }
        let _ = write_delimited_row(&mut out, cells.iter().map(String::as_str), self.sep);
    }
}

fn write_delimited_row<'a, I, W>(out: &mut W, cells: I, sep: char) -> io::Result<()>
where
    I: Iterator<Item = &'a str>,
    W: Write,
{
    let mut first = true;
    for cell in cells {
        if !first {
            write!(out, "{sep}")?;
        }
        first = false;
        write!(out, "{}", escape_delimited(cell, sep))?;
    }
    writeln!(out)
}

/// Quote `cell` for `csv`/`tsv` output when it carries the separator, a
/// double-quote, or a CR/LF. Embedded double-quotes are doubled.
///
/// Returned as `String` (not `Cow`) for clarity at the cost of a single
/// allocation per cell; this is well below the cost of writing the row.
pub(crate) fn escape_delimited(cell: &str, sep: char) -> String {
    let needs_quote = cell
        .chars()
        .any(|c| c == sep || c == '"' || c == '\n' || c == '\r');
    if !needs_quote {
        return cell.to_string();
    }
    let mut buf = String::with_capacity(cell.len() + 2);
    buf.push('"');
    for c in cell.chars() {
        if c == '"' {
            buf.push('"');
        }
        buf.push(c);
    }
    buf.push('"');
    buf
}

// ---------------------------------------------------------------------------
// ANSI color painter
// ---------------------------------------------------------------------------

/// ANSI color painter shared by every command that emits coloured text.
///
/// `enabled` is decided once by [`OutputCtx::resolve`] (which honours
/// `--color` / `NO_COLOR` / TTY detection), so this struct only carries the
/// final on/off bit. Method names are intentionally short because they are
/// called inline inside larger format strings.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Painter {
    enabled: bool,
}

impl Painter {
    pub(crate) fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    pub(crate) fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub(crate) fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    pub(crate) fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    pub(crate) fn red(&self, s: &str) -> String {
        self.paint("31", s)
    }
    pub(crate) fn red_bold(&self, s: &str) -> String {
        self.paint("1;31", s)
    }
    pub(crate) fn green(&self, s: &str) -> String {
        self.paint("32", s)
    }
    pub(crate) fn green_bold(&self, s: &str) -> String {
        self.paint("1;32", s)
    }
    pub(crate) fn yellow(&self, s: &str) -> String {
        self.paint("33", s)
    }
    pub(crate) fn yellow_bold(&self, s: &str) -> String {
        self.paint("1;33", s)
    }
    pub(crate) fn blue(&self, s: &str) -> String {
        self.paint("34", s)
    }
    pub(crate) fn cyan(&self, s: &str) -> String {
        self.paint("36", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_format_parses_known_values() {
        assert_eq!(OutputFormat::parse("json"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::parse("NDJSON"), Some(OutputFormat::Ndjson));
        assert_eq!(OutputFormat::parse("Table"), Some(OutputFormat::Table));
        assert_eq!(OutputFormat::parse("csv"), Some(OutputFormat::Csv));
        assert_eq!(OutputFormat::parse("tsv"), Some(OutputFormat::Tsv));
        assert_eq!(OutputFormat::parse("xml"), None);
    }

    #[test]
    fn color_choice_parses_known_values() {
        assert_eq!(ColorChoice::parse("auto"), Some(ColorChoice::Auto));
        assert_eq!(ColorChoice::parse("Always"), Some(ColorChoice::Always));
        assert_eq!(ColorChoice::parse("NEVER"), Some(ColorChoice::Never));
        assert_eq!(ColorChoice::parse("bold"), None);
    }

    #[test]
    fn color_resolve_honors_no_color_only_under_auto() {
        // Save and clear NO_COLOR for the duration of the test.
        // SAFETY: This module's tests are run by `cargo test`, which is
        // single-threaded by default within a test binary unless the test
        // explicitly opts into a thread pool.
        let prior = std::env::var_os("NO_COLOR");
        // SAFETY: see note above.
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
        assert!(!ColorChoice::Auto.resolve(true));
        assert!(ColorChoice::Always.resolve(false));
        assert!(!ColorChoice::Never.resolve(true));
        match prior {
            Some(v) => unsafe { std::env::set_var("NO_COLOR", v) },
            None => unsafe { std::env::remove_var("NO_COLOR") },
        }
    }

    #[test]
    fn tty_default_falls_through_to_json_on_tty_ndjson_otherwise() {
        let on_tty =
            OutputCtx::resolve(None, None, None, None, false, false, /* tty = */ true);
        assert_eq!(on_tty.format, OutputFormat::Json);
        assert!(!on_tty.explicit_format);
        assert!(on_tty.pretty_json());

        let piped =
            OutputCtx::resolve(None, None, None, None, false, false, /* tty = */ false);
        assert_eq!(piped.format, OutputFormat::Ndjson);
        assert!(!piped.explicit_format);
        assert!(!piped.pretty_json());
    }

    #[test]
    fn explicit_flag_beats_config_and_default() {
        let ctx = OutputCtx::resolve(
            Some(OutputFormat::Csv),
            Some("table"),
            None,
            None,
            false,
            false,
            true,
        );
        assert_eq!(ctx.format, OutputFormat::Csv);
        assert!(ctx.explicit_format);
    }

    #[test]
    fn config_fills_when_flag_unset() {
        let ctx = OutputCtx::resolve(None, Some("ndjson"), None, None, false, false, true);
        assert_eq!(ctx.format, OutputFormat::Ndjson);
        assert!(ctx.explicit_format);
    }

    #[test]
    fn quiet_disables_stats_and_progress() {
        let ctx = OutputCtx::resolve(None, None, None, None, true, false, false);
        assert!(!ctx.show_stats());
        assert!(!ctx.show_progress());
    }

    #[test]
    fn no_stats_keeps_progress_drops_stats() {
        let ctx = OutputCtx::resolve(None, None, None, None, false, true, false);
        assert!(!ctx.show_stats());
        assert!(ctx.show_progress());
    }

    #[test]
    fn escape_delimited_quotes_only_when_needed() {
        assert_eq!(escape_delimited("hello", ','), "hello");
        assert_eq!(escape_delimited("a,b", ','), "\"a,b\"");
        // Tabs are not quoted by the comma escaper but are quoted by the tab
        // escaper.
        assert_eq!(escape_delimited("a\tb", ','), "a\tb");
        assert_eq!(escape_delimited("a\tb", '\t'), "\"a\tb\"");
        assert_eq!(
            escape_delimited("she said \"hi\"", ','),
            "\"she said \"\"hi\"\"\""
        );
        assert_eq!(escape_delimited("line1\nline2", ','), "\"line1\nline2\"");
    }

    struct Row {
        name: &'static str,
        n: u32,
    }

    impl Tabular for Row {
        fn headers() -> &'static [&'static str] {
            &["NAME", "N"]
        }
        fn row(&self) -> Vec<String> {
            vec![self.name.to_string(), self.n.to_string()]
        }
    }

    #[test]
    fn tabular_headers_and_row_shape() {
        let r = Row { name: "rule", n: 3 };
        assert_eq!(Row::headers(), &["NAME", "N"]);
        assert_eq!(r.row(), vec!["rule".to_string(), "3".to_string()]);
    }

    #[test]
    fn warn_invalid_global_output_keeps_recognized_values() {
        // Valid strings pass through untouched. The function is only
        // responsible for filtering out unrecognized values; the actual
        // parsing happens later in `OutputCtx::resolve`.
        let (f, c) = warn_invalid_global_output(Some("ndjson".into()), Some("always".into()));
        assert_eq!(f.as_deref(), Some("ndjson"));
        assert_eq!(c.as_deref(), Some("always"));
    }

    #[test]
    fn warn_invalid_global_output_strips_unrecognized_format() {
        // An invalid format string is replaced with `None` so the
        // downstream resolver falls back to its TTY-aware default
        // instead of silently keeping the misconfigured value.
        let (f, c) = warn_invalid_global_output(Some("xml".into()), None);
        assert!(f.is_none());
        assert!(c.is_none());
    }

    #[test]
    fn warn_invalid_global_output_strips_unrecognized_color() {
        let (f, c) = warn_invalid_global_output(None, Some("rainbow".into()));
        assert!(f.is_none());
        assert!(c.is_none());
    }

    #[test]
    fn warn_invalid_global_output_passes_through_none() {
        // The common case (no global override in the config file) must
        // not introduce a phantom warning. With both inputs `None`
        // there is nothing to validate and both outputs are `None`.
        let (f, c) = warn_invalid_global_output(None, None);
        assert!(f.is_none());
        assert!(c.is_none());
    }
}
