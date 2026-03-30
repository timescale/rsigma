use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rsigma_eval::{CorrelationConfig, Pipeline, ProcessResult};
use serde::Serialize;
use tokio::sync::mpsc;

use super::engine::{SharedEngine, process_line};
use super::health::HealthState;
use super::metrics::Metrics;
use super::reload;
use super::state::DaemonEngine;
use super::store::SqliteStateStore;
use super::streaming::{self, FileSink, Sink, StdinSource, StdoutSink};
use crate::EventFilter;

#[derive(Clone)]
struct AppState {
    engine: SharedEngine,
    metrics: Metrics,
    health: HealthState,
    reload_tx: mpsc::Sender<()>,
    start_time: Instant,
    /// Channel for HTTP event ingestion. Set when --input is http.
    event_tx: Option<mpsc::Sender<String>>,
}

#[derive(Clone)]
pub struct DaemonConfig {
    pub rules_path: PathBuf,
    pub pipelines: Vec<Pipeline>,
    pub corr_config: CorrelationConfig,
    pub include_event: bool,
    pub pretty: bool,
    pub api_addr: SocketAddr,
    pub event_filter: Arc<EventFilter>,
    pub state_db: Option<PathBuf>,
    pub state_save_interval: u64,
    pub input: String,
    pub output: Vec<String>,
}

pub async fn run_daemon(config: DaemonConfig) {
    let metrics = Metrics::new();
    let health = HealthState::new();

    // Open SQLite state store if configured
    let state_store = config.state_db.as_ref().map(|path| {
        let store = SqliteStateStore::open(path).unwrap_or_else(|e| {
            tracing::error!(error = %e, path = %path.display(), "Failed to open state database");
            std::process::exit(1);
        });
        tracing::info!(path = %path.display(), "State database opened");
        Arc::new(store)
    });

    let daemon_engine = DaemonEngine::new(
        config.rules_path.clone(),
        config.pipelines.clone(),
        config.corr_config.clone(),
        config.include_event,
    );
    let shared_engine: SharedEngine = Arc::new(std::sync::Mutex::new(daemon_engine));

    // Initial rule load
    {
        let mut engine = shared_engine.lock().unwrap();
        match engine.load_rules() {
            Ok(stats) => {
                tracing::info!(
                    detection_rules = stats.detection_rules,
                    correlation_rules = stats.correlation_rules,
                    path = %config.rules_path.display(),
                    "Rules loaded"
                );
                metrics
                    .detection_rules_loaded
                    .set(stats.detection_rules as i64);
                metrics
                    .correlation_rules_loaded
                    .set(stats.correlation_rules as i64);
                health.set_ready(true);
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to load initial rules");
                std::process::exit(1);
            }
        }
    }

    // Restore correlation state from SQLite (after rules are loaded, lock released)
    if let Some(ref store) = state_store {
        match store.load().await {
            Ok(Some(snapshot)) => {
                let mut engine = shared_engine.lock().unwrap();
                if engine.import_state(&snapshot) {
                    let entries = snapshot.windows.values().map(|g| g.len()).sum::<usize>();
                    tracing::info!(
                        state_entries = entries,
                        "Correlation state restored from database"
                    );
                } else {
                    tracing::warn!(
                        snapshot_version = snapshot.version,
                        "Incompatible snapshot version, starting with fresh state"
                    );
                }
            }
            Ok(None) => {
                tracing::info!("No previous correlation state found in database");
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to load state from database, starting fresh");
            }
        }
    }

    let (reload_tx, mut reload_rx) = mpsc::channel::<()>(4);

    // File watcher for hot-reload
    let _watcher = if config.rules_path.is_dir() {
        reload::spawn_file_watcher(&config.rules_path, reload_tx.clone())
    } else {
        reload::spawn_file_watcher(
            config.rules_path.parent().unwrap_or(&config.rules_path),
            reload_tx.clone(),
        )
    };

    let start_time = Instant::now();

    // Create event channel early so both source and HTTP handler can use it
    let (event_tx, mut event_rx) = mpsc::channel::<String>(10_000);

    let http_event_tx = if config.input == "http" {
        Some(event_tx.clone())
    } else {
        None
    };

    let app_state = AppState {
        engine: shared_engine.clone(),
        metrics: metrics.clone(),
        health: health.clone(),
        reload_tx: reload_tx.clone(),
        start_time,
        event_tx: http_event_tx,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .route("/api/v1/rules", get(list_rules))
        .route("/api/v1/status", get(status))
        .route("/api/v1/reload", post(trigger_reload))
        .route("/api/v1/events", post(ingest_events))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(config.api_addr)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(addr = %config.api_addr, error = %e, "Failed to bind API server");
            std::process::exit(1);
        });
    tracing::info!(addr = %config.api_addr, "API server listening");

    // Spawn SIGHUP listener
    let sighup_tx = reload_tx.clone();
    tokio::spawn(async move {
        reload::sighup_listener(sighup_tx).await;
    });

    // Spawn reload handler
    let reload_engine = shared_engine.clone();
    let reload_metrics = metrics.clone();
    let reload_health = health.clone();
    tokio::spawn(async move {
        while reload_rx.recv().await.is_some() {
            // Debounce: batch rapid file changes
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            while reload_rx.try_recv().is_ok() {}

            reload_metrics.reloads_total.inc();
            tracing::info!("Reloading rules...");

            let mut engine = reload_engine.lock().unwrap();
            match engine.load_rules() {
                Ok(stats) => {
                    tracing::info!(
                        detection_rules = stats.detection_rules,
                        correlation_rules = stats.correlation_rules,
                        path = %engine.rules_path().display(),
                        "Rules reloaded"
                    );
                    reload_metrics
                        .detection_rules_loaded
                        .set(stats.detection_rules as i64);
                    reload_metrics
                        .correlation_rules_loaded
                        .set(stats.correlation_rules as i64);
                    reload_health.set_ready(true);
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to reload rules");
                    reload_metrics.reloads_failed.inc();
                }
            }
        }
    });

    // Spawn periodic state saver
    if let Some(ref store) = state_store {
        let save_engine = shared_engine.clone();
        let save_store = store.clone();
        let save_interval_secs = config.state_save_interval;
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(save_interval_secs));
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                let snapshot = {
                    let engine = save_engine.lock().unwrap();
                    engine.export_state()
                };
                if let Some(snapshot) = snapshot {
                    if let Err(e) = save_store.save(&snapshot).await {
                        tracing::warn!(error = %e, "Failed to save periodic state snapshot");
                    } else {
                        tracing::debug!("Periodic state snapshot saved");
                    }
                }
            }
        });
    }

    // --- Streaming pipeline: source -> engine -> sink ---
    // event_tx / event_rx were created above (before AppState) so the HTTP
    // handler can share event_tx when --input is http.

    let (sink_tx, mut sink_rx) = mpsc::channel::<ProcessResult>(10_000);

    // Select source based on --input flag
    match config.input.as_str() {
        "stdin" | "stdin://" => {
            streaming::spawn_source(StdinSource::new(), event_tx);
            tracing::info!(input = "stdin", "Event source started");
        }
        "http" => {
            // Events arrive via POST /api/v1/events; event_tx is held by AppState.
            // Drop the local event_tx so the channel closes when AppState is dropped.
            drop(event_tx);
            tracing::info!(input = "http", "Event source started (POST /api/v1/events)");
        }
        #[cfg(feature = "daemon-nats")]
        input if input.starts_with("nats://") => {
            let (url, subject) = parse_nats_url(input);
            match streaming::NatsSource::connect(&url, &subject).await {
                Ok(source) => {
                    streaming::spawn_source(source, event_tx);
                    tracing::info!(url = url, subject = subject, "NATS source started");
                }
                Err(e) => {
                    tracing::error!(error = %e, url = url, "Failed to connect NATS source");
                    std::process::exit(1);
                }
            }
        }
        other => {
            tracing::error!(
                input = other,
                "Unsupported input source (supported: stdin, http, nats://)"
            );
            std::process::exit(1);
        }
    }

    // Engine task: reads events, evaluates rules, sends results to sink channel
    let engine_shared = shared_engine.clone();
    let engine_metrics = metrics.clone();
    let event_filter = config.event_filter.clone();
    let engine_handle = tokio::spawn(async move {
        while let Some(line) = event_rx.recv().await {
            let result = {
                let mut engine = engine_shared.lock().unwrap();
                let result = process_line(&mut engine, &line, &engine_metrics, &event_filter);
                let stats = engine.stats();
                engine_metrics
                    .correlation_state_entries
                    .set(stats.state_entries as i64);
                result
            };
            if result.detections.is_empty() && result.correlations.is_empty() {
                continue;
            }
            if sink_tx.send(result).await.is_err() {
                tracing::debug!("Sink channel closed, engine shutting down");
                break;
            }
        }
        tracing::info!("Event source exhausted, engine shutting down");
    });

    // Build sink(s) from --output flags. Multiple outputs produce a FanOut.
    let pretty = config.pretty;
    let output_specs = if config.output.is_empty() {
        vec!["stdout".to_string()]
    } else {
        config.output.clone()
    };
    let mut sinks = Vec::new();
    for spec in &output_specs {
        sinks.push(build_sink(spec, pretty).await);
    }
    let sink = if sinks.len() == 1 {
        sinks.pop().unwrap()
    } else {
        Sink::FanOut(sinks)
    };
    tracing::info!(output = ?output_specs, "Sink started");

    // Sink task: reads ProcessResult from channel, writes via Sink dispatch
    let sink_handle = tokio::spawn(async move {
        let mut sink = sink;
        while let Some(result) = sink_rx.recv().await {
            if let Err(e) = sink.send(&result).await {
                tracing::warn!(error = %e, "Error writing to sink");
            }
        }
    });

    tokio::select! {
        result = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HTTP server error");
            }
        }
        _ = engine_handle => {
            tracing::info!("Streaming pipeline complete");
        }
    }

    // Wait for the sink task to drain any remaining results before exiting.
    // The engine task owns sink_tx, so once it exits, sink_rx closes and the
    // sink task finishes after processing buffered items.
    let _ = sink_handle.await;

    // Save state on shutdown
    if let Some(ref store) = state_store {
        let snapshot = {
            let engine = shared_engine.lock().unwrap();
            engine.export_state()
        };
        if let Some(snapshot) = snapshot {
            match store.save(&snapshot).await {
                Ok(()) => tracing::info!("Correlation state saved to database on shutdown"),
                Err(e) => tracing::error!(error = %e, "Failed to save state on shutdown"),
            }
        }
    }
}

/// Build a single Sink from an output spec string.
async fn build_sink(spec: &str, pretty: bool) -> Sink {
    if spec == "stdout" || spec == "stdout://" {
        return Sink::Stdout(StdoutSink::new(pretty));
    }

    if let Some(path) = spec.strip_prefix("file://") {
        let path = std::path::Path::new(path);
        return match FileSink::open(path) {
            Ok(file_sink) => {
                tracing::info!(path = %path.display(), "File sink opened");
                Sink::File(file_sink)
            }
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "Failed to open file sink");
                std::process::exit(1);
            }
        };
    }

    #[cfg(feature = "daemon-nats")]
    if spec.starts_with("nats://") {
        let (url, subject) = parse_nats_url(spec);
        return match streaming::NatsSink::connect(&url, &subject).await {
            Ok(nats_sink) => {
                tracing::info!(url = url, subject = subject, "NATS sink started");
                Sink::Nats(nats_sink)
            }
            Err(e) => {
                tracing::error!(error = %e, url = url, "Failed to connect NATS sink");
                std::process::exit(1);
            }
        };
    }

    tracing::error!(
        output = spec,
        "Unsupported output sink (supported: stdout, file://<path>, nats://)"
    );
    std::process::exit(1);
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    tracing::info!("Shutdown signal received");
}

/// Parse a nats:// URL into (server_url, subject).
///
/// Input: "nats://host:port/subject.path.>"
/// Output: ("nats://host:port", "subject.path.>")
#[cfg(feature = "daemon-nats")]
fn parse_nats_url(url: &str) -> (String, String) {
    let without_scheme = url.strip_prefix("nats://").unwrap_or(url);
    match without_scheme.find('/') {
        Some(pos) => {
            let server = format!("nats://{}", &without_scheme[..pos]);
            let subject = without_scheme[pos + 1..].to_string();
            (server, subject)
        }
        None => (format!("nats://{without_scheme}"), ">".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn readyz(State(state): State<AppState>) -> Response {
    if state.health.is_ready() {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "ready", "rules_loaded": true })),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "not_ready", "rules_loaded": false })),
        )
            .into_response()
    }
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    state
        .metrics
        .uptime_seconds
        .set(state.start_time.elapsed().as_secs_f64());

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.encode(),
    )
}

async fn list_rules(State(state): State<AppState>) -> impl IntoResponse {
    let engine = state.engine.lock().unwrap();
    let stats = engine.stats();
    Json(serde_json::json!({
        "detection_rules": stats.detection_rules,
        "correlation_rules": stats.correlation_rules,
        "rules_path": engine.rules_path().display().to_string(),
    }))
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    detection_rules: usize,
    correlation_rules: usize,
    correlation_state_entries: usize,
    events_processed: u64,
    detection_matches: u64,
    correlation_matches: u64,
    uptime_seconds: f64,
}

async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let engine = state.engine.lock().unwrap();
    let stats = engine.stats();
    let resp = StatusResponse {
        status: if state.health.is_ready() {
            "running".to_string()
        } else {
            "loading".to_string()
        },
        detection_rules: stats.detection_rules,
        correlation_rules: stats.correlation_rules,
        correlation_state_entries: stats.state_entries,
        events_processed: state.metrics.events_processed.get(),
        detection_matches: state.metrics.detection_matches.get(),
        correlation_matches: state.metrics.correlation_matches.get(),
        uptime_seconds: state.start_time.elapsed().as_secs_f64(),
    };
    Json(resp)
}

async fn trigger_reload(State(state): State<AppState>) -> impl IntoResponse {
    match state.reload_tx.try_send(()) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "reload_triggered" })),
        ),
        Err(_) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "status": "reload_already_pending" })),
        ),
    }
}

/// Accept NDJSON events via HTTP POST for processing.
/// Each non-empty line in the request body is treated as a separate JSON event.
async fn ingest_events(State(state): State<AppState>, body: String) -> Response {
    let event_tx = match &state.event_tx {
        Some(tx) => tx,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "event ingestion not enabled (start with --input http)"
                })),
            )
                .into_response();
        }
    };

    let mut accepted = 0u64;
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if event_tx.send(line.to_string()).await.is_err() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "event channel closed",
                    "accepted": accepted,
                })),
            )
                .into_response();
        }
        accepted += 1;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "accepted": accepted })),
    )
        .into_response()
}
