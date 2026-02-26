use std::io::{self, BufRead};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rsigma_eval::{CorrelationConfig, Pipeline};
use serde::Serialize;
use tokio::sync::mpsc;

use super::engine::{SharedEngine, process_line};
use super::health::HealthState;
use super::metrics::Metrics;
use super::reload;
use super::state::DaemonEngine;
use crate::EventFilter;

#[derive(Clone)]
struct AppState {
    engine: SharedEngine,
    metrics: Metrics,
    health: HealthState,
    reload_tx: mpsc::Sender<()>,
    start_time: Instant,
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
}

pub async fn run_daemon(config: DaemonConfig) {
    let metrics = Metrics::new();
    let health = HealthState::new();

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

    let app_state = AppState {
        engine: shared_engine.clone(),
        metrics: metrics.clone(),
        health: health.clone(),
        reload_tx: reload_tx.clone(),
        start_time,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .route("/api/v1/rules", get(list_rules))
        .route("/api/v1/status", get(status))
        .route("/api/v1/reload", post(trigger_reload))
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

    // Spawn stdin reader in a blocking thread
    let stdin_engine = shared_engine.clone();
    let stdin_metrics = metrics.clone();
    let pretty = config.pretty;
    let event_filter = config.event_filter.clone();
    let stdin_handle = tokio::task::spawn_blocking(move || {
        let stdin = io::stdin();
        let reader = stdin.lock();
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let mut engine = stdin_engine.lock().unwrap();
                    process_line(&mut engine, &line, &stdin_metrics, pretty, &event_filter);

                    let stats = engine.stats();
                    stdin_metrics
                        .correlation_state_entries
                        .set(stats.state_entries as i64);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Error reading stdin");
                    break;
                }
            }
        }
        tracing::info!("stdin closed, shutting down");
    });

    tokio::select! {
        result = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HTTP server error");
            }
        }
        _ = stdin_handle => {
            tracing::info!("stdin processing complete");
        }
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    tracing::info!("Shutdown signal received");
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
