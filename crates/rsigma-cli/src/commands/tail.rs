//! `rsigma engine tail`: stream a running daemon's live detections to the
//! terminal.
//!
//! This is a read-only client over `GET /api/v1/detections/stream`. Like
//! `engine status` / `engine tap` it reuses the shared `--addr` resolution and
//! the synchronous `ureq` transport, so it builds without the `daemon`
//! feature. Each streamed result is rendered through the global output layer
//! (the same `EvaluationResult` shape `engine eval` and the sinks emit), and
//! the trailing summary record drives the stderr stats line.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process;

use clap::Args;

use crate::config;
use crate::exit_code;
use crate::output::{self, DelimitedWriter, OutputCtx, OutputFormat, Tabular};

#[derive(Args, Debug)]
pub(crate) struct TailArgs {
    /// Daemon API address as `host:port` or a full URL.
    /// Defaults to `daemon.api.addr` from the resolved config.
    #[arg(long)]
    pub addr: Option<String>,

    /// Explicit config file used to resolve the daemon address.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Capture window (humantime, e.g. `5m`).
    /// Unset streams until interrupted or `--limit` is reached.
    #[arg(long)]
    pub duration: Option<String>,

    /// Stop after N detections, before the duration if reached first.
    #[arg(long)]
    pub limit: Option<u64>,

    /// Minimum severity: `informational`, `low`, `medium`, `high`, `critical`.
    #[arg(long)]
    pub level: Option<String>,

    /// Case-insensitive substring matched against the rule title or id.
    #[arg(long)]
    pub rule: Option<String>,
}

pub(crate) fn cmd_tail(args: TailArgs, ctx: OutputCtx) {
    let addr = config::resolve_daemon_addr(args.addr.clone(), args.config.as_deref());
    let url = build_url(&config::api_url(&addr, "/api/v1/detections/stream"), &args);

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();

    let resp = match agent.get(&url).call() {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("tail failed: could not reach {url}: {e}");
            eprintln!("(is the daemon running?)");
            process::exit(exit_code::CONFIG_ERROR);
        }
    };

    let status = resp.status().as_u16();
    if status != 200 {
        let body = resp.into_body().read_to_string().unwrap_or_default();
        eprintln!("tail failed: {url} returned HTTP {status}");
        if !body.trim().is_empty() {
            eprintln!("{}", body.trim());
        }
        process::exit(exit_code::CONFIG_ERROR);
    }

    let reader = BufReader::new(resp.into_body().into_reader());
    let mut renderer = TailRenderer::new(ctx);
    let mut summary: Option<serde_json::Value> = None;

    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("tail failed: error reading stream: {e}");
                process::exit(exit_code::CONFIG_ERROR);
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        // The final line is a summary record; drive the stats line, not output.
        if value.get("rsigma_tail_summary").is_some() {
            summary = Some(value);
            continue;
        }
        renderer.emit(&line, &value);
    }
    renderer.flush();

    if ctx.show_stats() {
        print_stats(summary.as_ref());
    }
}

/// Append the query string to the resolved endpoint URL, percent-encoding
/// values so a `--rule` substring with spaces or punctuation is safe.
fn build_url(base: &str, args: &TailArgs) -> String {
    let mut params: Vec<String> = Vec::new();
    if let Some(duration) = &args.duration {
        params.push(format!("duration={}", encode(duration)));
    }
    if let Some(limit) = args.limit {
        params.push(format!("limit={limit}"));
    }
    if let Some(level) = &args.level {
        params.push(format!("level={}", encode(level)));
    }
    if let Some(rule) = &args.rule {
        params.push(format!("rule={}", encode(rule)));
    }
    if params.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", params.join("&"))
    }
}

/// Percent-encode a query-parameter value (RFC 3986 unreserved set passes
/// through; everything else is `%XX`).
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Print the tail summary (streamed / dropped) to stderr, gated by the global
/// `--quiet` / `--no-stats` flags.
fn print_stats(summary: Option<&serde_json::Value>) {
    let (streamed, dropped) = match summary.map(|v| &v["rsigma_tail_summary"]) {
        Some(s) => (
            s["streamed"].as_u64().unwrap_or(0),
            s["dropped"].as_u64().unwrap_or(0),
        ),
        None => (0, 0),
    };
    eprintln!("tail: streamed {streamed}, dropped {dropped}");
    if dropped > 0 {
        eprintln!("warning: {dropped} detection(s) dropped under load");
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Per-line renderer over the global output formats. `json`/`ndjson` stream
/// the result verbatim; `csv`/`tsv` stream a projected row; `table` buffers
/// rows and renders on stream end (so it suits a bounded `--duration`/`--limit`
/// tail rather than an open-ended one).
struct TailRenderer {
    state: RenderState,
}

enum RenderState {
    Json { pretty: bool },
    Ndjson,
    Delimited(DelimitedWriter),
    Table(Vec<TailRow>),
}

impl TailRenderer {
    fn new(ctx: OutputCtx) -> Self {
        let state = match ctx.format {
            OutputFormat::Json => RenderState::Json {
                pretty: ctx.pretty_json(),
            },
            OutputFormat::Ndjson => RenderState::Ndjson,
            OutputFormat::Csv => RenderState::Delimited(DelimitedWriter::new(',', TAIL_HEADERS)),
            OutputFormat::Tsv => RenderState::Delimited(DelimitedWriter::new('\t', TAIL_HEADERS)),
            OutputFormat::Table => RenderState::Table(Vec::new()),
        };
        Self { state }
    }

    fn emit(&mut self, raw_line: &str, value: &serde_json::Value) {
        match &mut self.state {
            RenderState::Json { pretty } => output::render_json(value, *pretty),
            RenderState::Ndjson => println!("{raw_line}"),
            RenderState::Delimited(writer) => writer.push(&TailRow::from_json(value).row()),
            RenderState::Table(rows) => rows.push(TailRow::from_json(value)),
        }
    }

    fn flush(&mut self) {
        if let RenderState::Table(rows) = &self.state {
            output::render_table(rows);
        }
    }
}

const TAIL_HEADERS: &[&str] = &["LEVEL", "RULE", "TYPE", "DETAIL"];
const DETAIL_MAX: usize = 200;

/// A four-column projection of a streamed result for the human / spreadsheet
/// views, mirroring `engine eval`'s table columns. Built from the JSON line
/// because the client never reconstructs the typed `EvaluationResult`.
#[derive(Clone)]
struct TailRow {
    level: String,
    rule: String,
    kind: String,
    detail: String,
}

impl TailRow {
    fn from_json(value: &serde_json::Value) -> Self {
        let level = value
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let rule = value
            .get("rule_title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let (kind, detail) = if let Some(ct) =
            value.get("correlation_type").and_then(|v| v.as_str())
        {
            let group = value
                .get("group_key")
                .and_then(|v| v.as_array())
                .map(|pairs| {
                    pairs
                        .iter()
                        .filter_map(|pair| {
                            let p = pair.as_array()?;
                            let k = p.first()?.as_str()?;
                            let v = p.get(1)?.as_str()?;
                            Some(format!("{k}={v}"))
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let agg = value
                .get("aggregated_value")
                .map(summarize_value)
                .unwrap_or_default();
            let detail = if group.is_empty() {
                format!("agg={agg}")
            } else {
                format!("{group} | agg={agg}")
            };
            (ct.to_string(), truncate(detail))
        } else {
            let detail = value
                .get("matched_fields")
                .and_then(|v| v.as_array())
                .map(|fields| {
                    fields
                        .iter()
                        .filter_map(|fm| {
                            let field = fm.get("field")?.as_str()?;
                            let value = fm.get("value").map(summarize_value).unwrap_or_default();
                            Some(format!("{field}={value}"))
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            ("detection".to_string(), truncate(detail))
        };

        Self {
            level,
            rule,
            kind,
            detail,
        }
    }
}

impl Tabular for TailRow {
    fn headers() -> &'static [&'static str] {
        TAIL_HEADERS
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.level.clone(),
            self.rule.clone(),
            self.kind.clone(),
            self.detail.clone(),
        ]
    }
}

/// Render a JSON value as a compact one-line cell.
fn summarize_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Cap a detail cell so one wide field cannot derail the table layout.
fn truncate(mut s: String) -> String {
    if s.chars().count() <= DETAIL_MAX {
        return s;
    }
    let truncated: String = s.chars().take(DETAIL_MAX - 1).collect();
    s.clear();
    s.push_str(&truncated);
    s.push('…');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detection_row_projects_matched_fields() {
        let v = json!({
            "rule_title": "Whoami",
            "level": "high",
            "matched_selections": ["sel"],
            "matched_fields": [{"field": "CommandLine", "value": "whoami"}],
        });
        let row = TailRow::from_json(&v).row();
        assert_eq!(
            row,
            vec!["high", "Whoami", "detection", "CommandLine=whoami"]
        );
    }

    #[test]
    fn correlation_row_projects_group_and_agg() {
        let v = json!({
            "rule_title": "Brute Force",
            "level": "critical",
            "correlation_type": "event_count",
            "group_key": [["src_ip", "10.0.0.1"]],
            "aggregated_value": 5.0,
        });
        let row = TailRow::from_json(&v).row();
        assert_eq!(row[0], "critical");
        assert_eq!(row[2], "event_count");
        assert!(row[3].contains("src_ip=10.0.0.1"));
        assert!(row[3].contains("agg=5"));
    }

    #[test]
    fn missing_level_renders_dash() {
        let v = json!({"rule_title": "X", "matched_fields": []});
        assert_eq!(TailRow::from_json(&v).level, "-");
    }

    #[test]
    fn build_url_encodes_rule_and_omits_unset() {
        let url = build_url(
            "http://h:9090/api/v1/detections/stream",
            &TailArgs {
                addr: None,
                config: None,
                duration: None,
                limit: Some(10),
                level: Some("high".into()),
                rule: Some("net cat".into()),
            },
        );
        assert!(url.contains("limit=10"));
        assert!(url.contains("level=high"));
        assert!(url.contains("rule=net%20cat"));
        assert!(!url.contains("duration="));
    }
}
