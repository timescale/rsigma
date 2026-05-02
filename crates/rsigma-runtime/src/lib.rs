//! # rsigma-runtime
//!
//! Streaming runtime for rsigma — event sources, sinks, and log processing pipeline.
//!
//! This crate extracts the streaming pipeline from the `rsigma` CLI daemon into
//! a reusable library. It provides:
//!
//! - **I/O adapters**: [`io::EventSource`] trait for inputs (stdin, NATS) and
//!   [`io::Sink`] enum for outputs (stdout, file, NATS).
//! - **Engine wrapper**: [`RuntimeEngine`] wraps `rsigma-eval`'s `Engine` and
//!   `CorrelationEngine` with rule loading and state management.
//! - **Log processor**: [`LogProcessor`] combines engine + metrics + event
//!   filtering into a batch processing pipeline with atomic hot-reload via
//!   `ArcSwap`.
//! - **Metrics abstraction**: [`MetricsHook`] trait lets consumers plug in
//!   Prometheus, OpenTelemetry, or any other metrics backend without the
//!   runtime depending on a specific implementation.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use rsigma_runtime::{LogProcessor, RuntimeEngine, NoopMetrics};
//! use rsigma_eval::CorrelationConfig;
//!
//! let mut engine = RuntimeEngine::new(
//!     "rules/".into(),
//!     vec![],
//!     CorrelationConfig::default(),
//!     false,
//! );
//! engine.load_rules().unwrap();
//!
//! let processor = LogProcessor::new(engine, Arc::new(NoopMetrics));
//!
//! let batch = vec![r#"{"EventID": 1}"#.to_string()];
//! let results = processor.process_batch_lines(&batch, &|v| vec![v.clone()]);
//! for result in &results {
//!     for det in &result.detections {
//!         println!("Detection: {}", det.rule_title);
//!     }
//! }
//! ```

pub mod engine;
pub mod error;
pub mod input;
pub mod io;
pub mod metrics;
pub mod parse;
pub mod processor;

pub use engine::{EngineStats, RuntimeEngine};
pub use error::RuntimeError;
pub use input::{EventInputDecoded, InputFormat, parse_line};
pub use io::{
    AckToken, EventSource, FileSink, RawEvent, Sink, StdinSource, StdoutSink, spawn_source,
};
pub use metrics::{MetricsHook, NoopMetrics};
pub use processor::{EventFilter, LogProcessor};

pub use rsigma_eval::ProcessResult;

#[cfg(feature = "nats")]
pub use io::{NatsConnectConfig, NatsSink, NatsSource, ReplayPolicy};

#[cfg(feature = "otlp")]
pub use io::otlp::{
    ExportLogsServiceRequest, ExportLogsServiceResponse, LogsService, LogsServiceServer,
    logs_request_to_raw_events,
};
