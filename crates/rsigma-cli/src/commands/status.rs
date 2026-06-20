//! `rsigma engine status`: query a running daemon's `/api/v1/status` endpoint
//! and render the snapshot through the shared TTY-aware output layer.
//!
//! This is the read-only client counterpart to `engine daemon`. It copies the
//! `config reload` client conventions (`--addr` resolves from
//! `daemon.api.addr`, wildcard binds map to loopback) and uses the same
//! synchronous `ureq` transport, so it builds without the `daemon` feature and
//! a lightweight build can still inspect a remote daemon.

use std::path::PathBuf;
use std::process;
use std::time::Duration;

use clap::Args;
use serde::Deserialize;

use crate::config;
use crate::exit_code;
use crate::output::{self, DelimitedWriter, OutputCtx, OutputFormat, Tabular};

#[derive(Args, Debug)]
pub(crate) struct StatusArgs {
    /// Daemon API address as `host:port` or a full URL.
    /// Defaults to `daemon.api.addr` from the resolved config.
    #[arg(long)]
    pub addr: Option<String>,

    /// Explicit config file used to resolve the daemon address.
    #[arg(short, long)]
    pub config: Option<PathBuf>,
}

/// Typed mirror of the daemon's `/api/v1/status` response, used to build the
/// table / CSV / TSV views. Unknown fields are ignored so a newer daemon does
/// not break an older client; the `json` / `ndjson` views echo the raw body
/// and preserve every field.
#[derive(Debug, Deserialize)]
struct DaemonStatus {
    status: String,
    detection_rules: u64,
    correlation_rules: u64,
    correlation_state_entries: u64,
    events_processed: u64,
    detection_matches: u64,
    correlation_matches: u64,
    uptime_seconds: f64,
    #[serde(default)]
    dynamic_sources: Option<DynamicSources>,
}

#[derive(Debug, Deserialize)]
struct DynamicSources {
    total: u64,
    resolves_total: u64,
    errors_total: u64,
    cache_hits: u64,
}

/// One `METRIC | VALUE` row for the human-facing renderers.
struct StatusRow {
    metric: String,
    value: String,
}

impl StatusRow {
    fn new(metric: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            metric: metric.into(),
            value: value.into(),
        }
    }
}

impl Tabular for StatusRow {
    fn headers() -> &'static [&'static str] {
        &["METRIC", "VALUE"]
    }

    fn row(&self) -> Vec<String> {
        vec![self.metric.clone(), self.value.clone()]
    }
}

pub(crate) fn cmd_status(args: StatusArgs, ctx: OutputCtx) {
    let addr = config::resolve_daemon_addr(args.addr, args.config.as_deref());
    let url = config::api_url(&addr, "/api/v1/status");

    let resp = match ureq::get(&url).call() {
        Ok(resp) => resp,
        Err(ureq::Error::StatusCode(code)) => {
            eprintln!("status failed: {url} returned HTTP {code}");
            process::exit(exit_code::CONFIG_ERROR);
        }
        Err(e) => {
            eprintln!("status failed: could not reach {url}: {e}");
            eprintln!("(is the daemon running?)");
            process::exit(exit_code::CONFIG_ERROR);
        }
    };

    let body = match resp.into_body().read_to_string() {
        Ok(body) => body,
        Err(e) => {
            eprintln!("status failed: could not read response from {url}: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        }
    };

    let value: serde_json::Value = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("status failed: invalid JSON from {url}: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        }
    };

    match ctx.format {
        OutputFormat::Json => output::render_json(&value, ctx.pretty_json()),
        OutputFormat::Ndjson => output::render_ndjson(&value),
        OutputFormat::Table | OutputFormat::Csv | OutputFormat::Tsv => {
            let status: DaemonStatus = match serde_json::from_value(value) {
                Ok(status) => status,
                Err(e) => {
                    eprintln!("status failed: unexpected response shape from {url}: {e}");
                    process::exit(exit_code::CONFIG_ERROR);
                }
            };
            let rows = status_rows(&status);
            match ctx.format {
                OutputFormat::Csv => {
                    push_rows(DelimitedWriter::new(',', StatusRow::headers()), &rows)
                }
                OutputFormat::Tsv => {
                    push_rows(DelimitedWriter::new('\t', StatusRow::headers()), &rows)
                }
                _ => output::render_table(&rows),
            }
        }
    }
}

/// Stream every row through a `csv`/`tsv` writer.
fn push_rows(mut writer: DelimitedWriter, rows: &[StatusRow]) {
    for row in rows {
        writer.push(&row.row());
    }
}

/// Flatten a [`DaemonStatus`] into ordered `METRIC | VALUE` rows. The optional
/// dynamic-source block is appended with dotted metric names when present.
fn status_rows(status: &DaemonStatus) -> Vec<StatusRow> {
    let mut rows = vec![
        StatusRow::new("status", status.status.clone()),
        StatusRow::new("detection_rules", status.detection_rules.to_string()),
        StatusRow::new("correlation_rules", status.correlation_rules.to_string()),
        StatusRow::new(
            "correlation_state_entries",
            status.correlation_state_entries.to_string(),
        ),
        StatusRow::new("events_processed", status.events_processed.to_string()),
        StatusRow::new("detection_matches", status.detection_matches.to_string()),
        StatusRow::new(
            "correlation_matches",
            status.correlation_matches.to_string(),
        ),
        StatusRow::new("uptime", format_uptime(status.uptime_seconds)),
    ];
    if let Some(ds) = &status.dynamic_sources {
        rows.push(StatusRow::new(
            "dynamic_sources.total",
            ds.total.to_string(),
        ));
        rows.push(StatusRow::new(
            "dynamic_sources.resolves_total",
            ds.resolves_total.to_string(),
        ));
        rows.push(StatusRow::new(
            "dynamic_sources.errors_total",
            ds.errors_total.to_string(),
        ));
        rows.push(StatusRow::new(
            "dynamic_sources.cache_hits",
            ds.cache_hits.to_string(),
        ));
    }
    rows
}

/// Render `uptime_seconds` as a human-friendly duration for the table view
/// (e.g. `1h 2m 3s`). Sub-second uptimes collapse to `0s`.
fn format_uptime(seconds: f64) -> String {
    let secs = seconds.max(0.0) as u64;
    humantime::format_duration(Duration::from_secs(secs)).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "status": "running",
        "detection_rules": 3,
        "correlation_rules": 1,
        "correlation_state_entries": 2,
        "events_processed": 10,
        "detection_matches": 4,
        "correlation_matches": 1,
        "uptime_seconds": 63.5
    }"#;

    #[test]
    fn parses_status_without_dynamic_sources() {
        let status: DaemonStatus = serde_json::from_str(SAMPLE).unwrap();
        assert_eq!(status.status, "running");
        assert!(status.dynamic_sources.is_none());
        let rows = status_rows(&status);
        assert_eq!(rows.len(), 8);
        assert!(
            rows.iter()
                .all(|r| !r.metric.starts_with("dynamic_sources"))
        );
    }

    #[test]
    fn includes_dynamic_source_rows_when_present() {
        let json = r#"{
            "status": "running",
            "detection_rules": 1,
            "correlation_rules": 0,
            "correlation_state_entries": 0,
            "events_processed": 0,
            "detection_matches": 0,
            "correlation_matches": 0,
            "uptime_seconds": 1.0,
            "dynamic_sources": {"total": 2, "resolves_total": 4, "errors_total": 0, "cache_hits": 1}
        }"#;
        let status: DaemonStatus = serde_json::from_str(json).unwrap();
        let rows = status_rows(&status);
        assert_eq!(rows.len(), 12);
        assert!(
            rows.iter()
                .any(|r| r.metric == "dynamic_sources.total" && r.value == "2")
        );
    }

    #[test]
    fn unknown_fields_are_ignored() {
        // A newer daemon may add fields the client does not know about; the
        // typed view must not reject the response.
        let json = r#"{
            "status": "running",
            "detection_rules": 1,
            "correlation_rules": 0,
            "correlation_state_entries": 0,
            "events_processed": 0,
            "detection_matches": 0,
            "correlation_matches": 0,
            "uptime_seconds": 1.0,
            "some_future_field": true
        }"#;
        let status: DaemonStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.detection_rules, 1);
    }

    #[test]
    fn uptime_is_humanized() {
        assert_eq!(format_uptime(0.4), "0s");
        assert_eq!(format_uptime(63.0), "1m 3s");
    }
}
