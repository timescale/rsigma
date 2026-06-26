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
//!     for r in result.iter().filter(|r| r.is_detection()) {
//!         println!("Detection: {}", r.header.rule_title);
//!     }
//! }
//! ```

pub mod alert_pipeline;
pub mod egress;
pub mod engine;
pub mod enrichment;
pub mod error;
pub mod input;
pub mod io;
pub mod metrics;
pub mod parse;
pub mod pipeline_deprecation;
pub mod processor;
pub mod scope;
pub mod sources;
pub mod tap;

pub use alert_pipeline::{
    AlertPipeline, AlertPipelineConfigError, AlertPipelineFile, DedupStore, Selector,
    SelectorParseError, build_alert_pipeline, load_alert_pipeline_file,
    parse_alert_pipeline_config,
};
pub use egress::{
    EgressDenial, EgressFilteredResolver, EgressPolicy, default_egress_policy,
    set_default_egress_policy,
};
pub use engine::{EngineStats, RoutingSpec, RuntimeEngine};
pub use enrichment::config::{
    EnricherConfig, EnrichersConfigError, EnrichersFile, build_enrichers, build_enrichers_full,
    load_enrichers_file,
};
pub use enrichment::{
    CacheKey, CacheOutcome, CommandEnricher, EnrichError, EnrichErrorKind, Enricher,
    EnricherFactory, EnricherKind, EnrichmentPipeline, HttpEnricher, HttpEnricherClient,
    HttpResponseCache, LookupEnricher, OnError, OutputFormat, Scope, TemplateEnricher,
    TemplateError, build_default_http_client, lookup_builtin, register_builtin,
    validate_template_namespace,
};
pub use error::RuntimeError;
pub use input::{EventInputDecoded, InputFormat, parse_line};
pub use io::webhook::{
    BuiltWebhook, WebhookConfig, WebhookConfigError, WebhookKind, WebhookSink, WebhooksFile,
    build_webhooks, load_webhooks_file,
};
pub use io::{
    AckToken, DeliveryConfig, DeliveryFailure, DeliverySink, Dispatcher, EventSource, FileSink,
    OnFull, RawEvent, Sink, StdinSource, StdoutSink, spawn_source,
};
pub use metrics::{MetricsHook, NoopMetrics};
pub use pipeline_deprecation::warn_pipeline_inline_sources;
pub use processor::{EventFilter, LogProcessor};
pub use tap::{TapPayload, TapRegistry, TapSessionHandle, TapStage};

pub use rsigma_eval::{
    FieldCoverage, FieldObservation, FieldObservationEntry, FieldObserver, ProcessResult,
    ProcessResultExt, SchemaClassifier, SchemaCountEntry, SchemaError, SchemaObservation,
    SchemaObserver, load_schema_signatures,
};
pub use sources::refresh::{RefreshResult, RefreshScheduler, RefreshTrigger};
pub use sources::{
    DefaultSourceResolver, ResolvedValue, SourceCache, SourceError, SourceErrorKind,
    SourceResolver, TemplateExpander,
};

#[cfg(feature = "nats")]
pub use io::{NatsConnectConfig, NatsSink, NatsSource, ReplayPolicy};

#[cfg(feature = "evtx")]
pub use input::evtx::{EvtxError, EvtxFileReader};

#[cfg(feature = "otlp")]
pub use io::otlp::{
    ExportLogsServiceRequest, ExportLogsServiceResponse, LogsService, LogsServiceServer,
    OtlpClientTls, OtlpProtocol, OtlpSink, evaluation_results_to_logs_request,
    logs_request_to_raw_events,
};
