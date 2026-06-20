//! `rsigma engine tap`: stream a bounded, optionally-redacted window of a
//! running daemon's live event stream into a replayable NDJSON fixture.
//!
//! This is a read-only client over `GET /api/v1/tap`. Like `engine status` it
//! reuses the shared `--addr` resolution (`daemon.api.addr`, wildcard binds
//! mapped to loopback) and the synchronous `ureq` transport, so it builds
//! without the `daemon` feature. The server performs redaction; the client
//! only forwards `--redact-fields` and writes the captured events, stripping
//! the trailing summary record (used for the stderr stats line) so the fixture
//! replays cleanly with `rsigma engine eval -e @fixture.ndjson`.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process;

use clap::Args;

use crate::config;
use crate::exit_code;
use crate::output::OutputCtx;

#[derive(Args, Debug)]
pub(crate) struct TapArgs {
    /// Daemon API address as `host:port` or a full URL.
    /// Defaults to `daemon.api.addr` from the resolved config.
    #[arg(long)]
    pub addr: Option<String>,

    /// Explicit config file used to resolve the daemon address.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Capture window (humantime, e.g. `30s`, `2m`).
    /// The server caps this at `daemon.tap.max_duration`.
    #[arg(long, default_value = "30s")]
    pub duration: String,

    /// Stop after N events, before the duration if reached first.
    #[arg(long)]
    pub limit: Option<u64>,

    /// Fixture destination. Defaults to stdout.
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Comma-separated dotted field paths to redact (server-side).
    #[arg(long = "redact-fields", value_name = "a,b,...")]
    pub redact_fields: Option<String>,

    /// Capture stage: `decoded` (post-parse, post-filter; the default) or
    /// `raw` (the input line as received).
    #[arg(long, value_parser = ["decoded", "raw"], default_value = "decoded")]
    pub stage: String,
}

pub(crate) fn cmd_tap(args: TapArgs, ctx: OutputCtx) {
    let addr = config::resolve_daemon_addr(args.addr.clone(), args.config.as_deref());
    let url = build_url(&config::api_url(&addr, "/api/v1/tap"), &args);

    // An agent that surfaces non-2xx as a normal response so the server's JSON
    // error hint (503 disabled, 409 cap, 400 bad params) can be shown.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();

    let resp = match agent.get(&url).call() {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("tap failed: could not reach {url}: {e}");
            eprintln!("(is the daemon running?)");
            process::exit(exit_code::CONFIG_ERROR);
        }
    };

    let status = resp.status().as_u16();
    if status != 200 {
        let body = resp.into_body().read_to_string().unwrap_or_default();
        eprintln!("tap failed: {url} returned HTTP {status}");
        if !body.trim().is_empty() {
            eprintln!("{}", body.trim());
        }
        process::exit(exit_code::CONFIG_ERROR);
    }

    let mut writer: Box<dyn Write> = match &args.output {
        Some(path) => match File::create(path) {
            Ok(f) => Box::new(BufWriter::new(f)),
            Err(e) => {
                eprintln!("tap failed: could not create {}: {e}", path.display());
                process::exit(exit_code::CONFIG_ERROR);
            }
        },
        None => Box::new(BufWriter::new(std::io::stdout().lock())),
    };

    let reader = BufReader::new(resp.into_body().into_reader());
    let mut summary: Option<serde_json::Value> = None;
    let mut written: u64 = 0;

    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("tap failed: error reading stream: {e}");
                process::exit(exit_code::CONFIG_ERROR);
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        // The final line is a summary record; keep it out of the fixture.
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line)
            && value.get("rsigma_tap_summary").is_some()
        {
            summary = Some(value);
            continue;
        }
        if let Err(e) = writeln!(writer, "{line}") {
            eprintln!("tap failed: error writing fixture: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        }
        written += 1;
    }

    if let Err(e) = writer.flush() {
        eprintln!("tap failed: error flushing fixture: {e}");
        process::exit(exit_code::CONFIG_ERROR);
    }

    if ctx.show_stats() {
        print_stats(&args, summary.as_ref(), written);
    }
}

/// Append the validated query string to the resolved endpoint URL.
fn build_url(base: &str, args: &TapArgs) -> String {
    let mut params = vec![
        format!("duration={}", args.duration),
        format!("stage={}", args.stage),
    ];
    if let Some(limit) = args.limit {
        params.push(format!("limit={limit}"));
    }
    if let Some(redact) = &args.redact_fields
        && !redact.is_empty()
    {
        params.push(format!("redact={redact}"));
    }
    format!("{base}?{}", params.join("&"))
}

/// Print the capture summary (captured / dropped counts, window, stage) and a
/// replay hint to stderr. Gated by the global `--quiet` / `--no-stats` flags.
fn print_stats(args: &TapArgs, summary: Option<&serde_json::Value>, written: u64) {
    let (captured, dropped, duration_ms) = match summary.map(|v| &v["rsigma_tap_summary"]) {
        Some(s) => (
            s["captured"].as_u64().unwrap_or(written),
            s["dropped"].as_u64().unwrap_or(0),
            s["duration_ms"].as_u64().unwrap_or(0),
        ),
        None => (written, 0, 0),
    };

    eprintln!(
        "tap: captured {captured}, dropped {dropped} ({duration_ms}ms, stage: {})",
        args.stage
    );
    if dropped > 0 {
        eprintln!("warning: {dropped} event(s) dropped under load; the fixture has gaps");
    }

    if let Some(path) = &args.output {
        let dest = path.display();
        if args.stage == "raw" {
            eprintln!(
                "replay: rsigma engine eval -r <rules> -e @{dest} (match the daemon's --input-format / --jq / --jsonpath)"
            );
        } else {
            eprintln!("replay: rsigma engine eval -r <rules> -e @{dest}");
        }
    }
}
