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

mod file;
pub(crate) use file::{OutputFile, output_path_is_inside, same_output_path};

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
                 ignoring value"
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
                 ignoring value"
            );
            None
        }
    });
    (format, color)
}

/// Resolve file and environment output settings after validating each layer.
///
/// Environment values have higher precedence, but an invalid environment
/// value is treated as absent so a valid file value can still win.
pub(crate) fn resolve_global_output_layers(
    file_format: Option<String>,
    file_color: Option<String>,
    env_format: Option<String>,
    env_color: Option<String>,
) -> (Option<String>, Option<String>) {
    let (env_format, env_color) = warn_invalid_global_output(env_format, env_color);
    let file_format = env_format.is_none().then_some(file_format).flatten();
    let file_color = env_color.is_none().then_some(file_color).flatten();
    let (file_format, file_color) = warn_invalid_global_output(file_format, file_color);
    (env_format.or(file_format), env_color.or(file_color))
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

    /// Reject `--finding-format ocsf` when this build has no OCSF serializer.
    pub(crate) fn ensure_finding_ocsf_available(&self, command: &str, finding_ocsf: bool) {
        if !finding_ocsf {
            return;
        }
        #[cfg(feature = "ocsf")]
        let _ = (self, command);
        #[cfg(not(feature = "ocsf"))]
        {
            let _ = self;
            eprintln!(
                "error: `--finding-format ocsf` is not available for `{command}` \
                 in this build (enable default features or the `ocsf` feature)"
            );
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }
    }

    /// Emit a single stderr warning when an explicit `--output-format` is not
    /// supported by `command`. Suppressed by `--quiet`.
    pub(crate) fn warn_unsupported(&self, command: &str, fallback: &str) {
        if self.explicit_format && self.show_progress() {
            eprintln!(
                "warning: `--output-format {}` is not supported by `{command}`; falling back to {fallback}.",
                self.format.as_str(),
            );
        }
    }

    /// Emit a single stderr warning that a global selector was ignored for
    /// `command` for `reason`. Suppressed by `--quiet`.
    pub(crate) fn warn_ignored(&self, command: &str, reason: &str) {
        if self.show_progress() {
            eprintln!("warning: `{command}` ignored `--output-format`: {reason}");
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

/// Serialize one [`EvaluationResult`](rsigma_eval::EvaluationResult) as an
/// OCSF class-2004 finding.
#[cfg(feature = "ocsf")]
pub(crate) fn write_ocsf_finding<W: Write>(
    writer: &mut W,
    result: &rsigma_eval::EvaluationResult,
    pretty: bool,
    version: rsigma_runtime::ocsf::OcsfVersion,
) -> io::Result<()> {
    let finding = rsigma_runtime::ocsf::detection_finding_opts(
        result,
        rsigma_runtime::ocsf::OcsfOptions::new(version),
    );
    let line = if pretty {
        serde_json::to_string_pretty(&finding)?
    } else {
        serde_json::to_string(&finding)?
    };
    writeln!(writer, "{line}")
}

/// Write one OCSF finding to stdout (compact NDJSON unless `pretty`).
#[cfg(feature = "ocsf")]
pub(crate) fn render_ocsf_finding(
    result: &rsigma_eval::EvaluationResult,
    pretty: bool,
    version: rsigma_runtime::ocsf::OcsfVersion,
) {
    let mut out = io::stdout().lock();
    if let Err(e) = write_ocsf_finding(&mut out, result, pretty, version) {
        eprintln!("OCSF serialization error: {e}");
        std::process::exit(crate::exit_code::CONFIG_ERROR);
    }
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

/// Write `value` as one JSON document followed by a newline to `out`.
///
/// Serialization and I/O failures are both returned as [`io::Error`] so the
/// caller can report them against its destination.
pub(crate) fn write_json<T: Serialize, W: Write>(
    out: &mut W,
    value: &T,
    pretty: bool,
) -> io::Result<()> {
    if pretty {
        serde_json::to_writer_pretty(&mut *out, value)?;
    } else {
        serde_json::to_writer(&mut *out, value)?;
    }
    out.write_all(b"\n")
}

/// Render `value` as a single NDJSON line on stdout. Same error semantics as
/// [`render_json`].
pub(crate) fn render_ndjson<T: Serialize>(value: &T) {
    render_json(value, false);
}

/// Render a structured report for every supported wire format.
///
/// `envelope` is used for `json` (one document). Each row in `rows` is used
/// for `ndjson` (one logical record per line) and for the shared
/// table/csv/tsv projection.
pub(crate) fn render_report<T, R>(ctx: &OutputCtx, envelope: &T, rows: &[R])
where
    T: Serialize,
    R: Serialize + Tabular,
{
    match ctx.format {
        OutputFormat::Json => render_json(envelope, ctx.pretty_json()),
        OutputFormat::Ndjson => {
            for row in rows {
                render_ndjson(row);
            }
        }
        OutputFormat::Table => render_table(rows),
        OutputFormat::Csv => render_delimited(rows, ','),
        OutputFormat::Tsv => render_delimited(rows, '\t'),
    }
}

/// Render a value that only has a meaningful JSON shape.
///
/// Honors `json` / `ndjson`. For table/csv/tsv, warns once and falls back to
/// JSON so the operator still gets machine-readable data.
pub(crate) fn render_json_only<T: Serialize>(command: &str, ctx: &OutputCtx, value: &T) {
    match ctx.format {
        OutputFormat::Ndjson => render_ndjson(value),
        OutputFormat::Json => render_json(value, ctx.pretty_json()),
        OutputFormat::Table | OutputFormat::Csv | OutputFormat::Tsv => {
            ctx.warn_unsupported(command, "json");
            render_json(value, ctx.pretty_json() || ctx.stdout_is_tty);
        }
    }
}

fn render_delimited<T: Tabular>(rows: &[T], sep: char) {
    let mut writer = DelimitedWriter::new(sep, T::headers());
    for row in rows {
        writer.push(&row.row());
    }
    writer.finish();
}

/// Render a slice of `Tabular` rows as a width-aligned text table on stdout.
///
/// Width-buffering: we walk the rows once to compute per-column widths, then
/// print the header, a dashed separator, and each row. Columns whose body
/// cells all parse as integers are right-aligned (numeric); everything else
/// is left-aligned. `table` is not a streaming format; for piping to other
/// tools prefer `ndjson`, `csv`, or `tsv`.
pub(crate) fn render_table<T: Tabular>(rows: &[T]) {
    let stdout = io::stdout();
    let _ = write_table(&mut stdout.lock(), rows);
}

/// Write a slice of `Tabular` rows as a width-aligned text table to `out`.
/// Layout is identical to [`render_table`].
pub(crate) fn write_table<T: Tabular, W: Write>(out: &mut W, rows: &[T]) -> io::Result<()> {
    let headers = T::headers();
    if headers.is_empty() {
        return Ok(());
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

    write_row(out, headers.iter().copied(), &widths, &right_align)?;
    let dashes: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    write_row(
        out,
        dashes.iter().map(String::as_str),
        &widths,
        &right_align,
    )?;
    for row in &stringified {
        write_row(out, row.iter().map(String::as_str), &widths, &right_align)?;
    }
    Ok(())
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
/// to large match counts without buffering. Backed by the `csv` crate with an
/// explicit LF terminator so CLI output stays platform-stable.
pub(crate) struct DelimitedWriter {
    inner: Option<csv::Writer<Box<dyn Write>>>,
    headers: &'static [&'static str],
    wrote_header: bool,
}

impl DelimitedWriter {
    pub(crate) fn new(sep: char, headers: &'static [&'static str]) -> Self {
        Self::with_writer(sep, headers, Box::new(io::stdout()))
    }

    /// Like [`DelimitedWriter::new`], but streams rows to `out` instead of
    /// stdout.
    pub(crate) fn with_writer(
        sep: char,
        headers: &'static [&'static str],
        out: Box<dyn Write>,
    ) -> Self {
        let writer = csv::WriterBuilder::new()
            .delimiter(sep as u8)
            .terminator(csv::Terminator::Any(b'\n'))
            .from_writer(out);
        Self {
            inner: Some(writer),
            headers,
            wrote_header: false,
        }
    }

    /// Write the header row (if it has not been written) and one data row.
    pub(crate) fn push(&mut self, cells: &[String]) {
        let Some(writer) = self.inner.as_mut() else {
            return;
        };
        if !self.wrote_header {
            if let Err(e) = writer.write_record(self.headers.iter().copied()) {
                eprintln!("CSV write error: {e}");
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
            self.wrote_header = true;
        }
        if let Err(e) = writer.write_record(cells.iter().map(String::as_str)) {
            eprintln!("CSV write error: {e}");
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }
    }

    /// Flush buffered delimited output. Called automatically on drop.
    ///
    /// When no data rows were pushed, still emit the header so empty reports
    /// (for example `discover-schemas` with zero candidates) remain valid CSV/TSV.
    pub(crate) fn finish(&mut self) {
        let Some(mut writer) = self.inner.take() else {
            return;
        };
        if !self.wrote_header {
            if let Err(e) = writer.write_record(self.headers.iter().copied()) {
                eprintln!("CSV write error: {e}");
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
            self.wrote_header = true;
        }
        if let Err(e) = writer.flush() {
            eprintln!("CSV flush error: {e}");
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }
    }
}

impl Drop for DelimitedWriter {
    fn drop(&mut self) {
        // Mirror `finish` without exiting: emit a header for empty reports,
        // then flush. Callers that need hard failure semantics should call
        // `finish` explicitly.
        if let Some(mut writer) = self.inner.take() {
            if !self.wrote_header {
                let _ = writer.write_record(self.headers.iter().copied());
                self.wrote_header = true;
            }
            let _ = writer.flush();
        }
    }
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
        assert_eq!(OutputFormat::parse("ocsf"), None);
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

    fn write_delimited_to_string(sep: u8, headers: &[&str], rows: &[&[&str]]) -> String {
        let mut buf = Vec::new();
        {
            let mut writer = csv::WriterBuilder::new()
                .delimiter(sep)
                .terminator(csv::Terminator::Any(b'\n'))
                .from_writer(&mut buf);
            writer.write_record(headers).unwrap();
            for row in rows {
                writer.write_record(*row).unwrap();
            }
            writer.flush().unwrap();
        }
        String::from_utf8(buf).unwrap()
    }

    fn read_delimited(sep: u8, input: &str) -> (Vec<String>, Vec<Vec<String>>) {
        let mut reader = csv::ReaderBuilder::new()
            .delimiter(sep)
            .from_reader(input.as_bytes());
        let headers = reader
            .headers()
            .unwrap()
            .iter()
            .map(str::to_string)
            .collect();
        let rows = reader
            .records()
            .map(|r| r.unwrap().iter().map(str::to_string).collect::<Vec<_>>())
            .collect();
        (headers, rows)
    }

    #[test]
    fn csv_round_trip_quotes_separators_and_newlines() {
        let raw = write_delimited_to_string(
            b',',
            &["NAME", "NOTE"],
            &[
                &["hello", "plain"],
                &["a,b", "has comma"],
                &["she said \"hi\"", "quotes"],
                &["line1\nline2", "newline"],
                &["", "empty"],
                &["café", "unicode"],
            ],
        );
        let (headers, rows) = read_delimited(b',', &raw);
        assert_eq!(headers, vec!["NAME", "NOTE"]);
        assert_eq!(rows[0], vec!["hello", "plain"]);
        assert_eq!(rows[1], vec!["a,b", "has comma"]);
        assert_eq!(rows[2], vec!["she said \"hi\"", "quotes"]);
        assert_eq!(rows[3], vec!["line1\nline2", "newline"]);
        assert_eq!(rows[4], vec!["", "empty"]);
        assert_eq!(rows[5], vec!["café", "unicode"]);
    }

    #[test]
    fn tsv_round_trip_quotes_tabs() {
        let raw = write_delimited_to_string(b'\t', &["A", "B"], &[&["a\tb", "plain"], &["x", "y"]]);
        let (headers, rows) = read_delimited(b'\t', &raw);
        assert_eq!(headers, vec!["A", "B"]);
        assert_eq!(rows[0], vec!["a\tb", "plain"]);
        assert_eq!(rows[1], vec!["x", "y"]);
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

    #[test]
    fn invalid_environment_output_falls_back_to_file_layer() {
        let (f, c) = resolve_global_output_layers(
            Some("csv".into()),
            Some("never".into()),
            Some("xml".into()),
            Some("rainbow".into()),
        );
        assert_eq!(f.as_deref(), Some("csv"));
        assert_eq!(c.as_deref(), Some("never"));
    }

    #[test]
    fn valid_environment_output_wins_over_file_layer() {
        let (f, c) = resolve_global_output_layers(
            Some("csv".into()),
            Some("never".into()),
            Some("ndjson".into()),
            Some("always".into()),
        );
        assert_eq!(f.as_deref(), Some("ndjson"));
        assert_eq!(c.as_deref(), Some("always"));
    }
}
