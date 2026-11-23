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
pub mod capture;
pub mod capture_spool;
pub mod dispositions;
pub mod egress;
pub mod engine;
pub mod enrichment;
pub mod error;
pub mod finding_links;
pub mod input;
pub mod io;
mod log_throttle;
pub mod metrics;
pub mod ocsf;
pub mod parse;
pub mod processor;
pub mod risk;
pub mod ruleset;
pub mod scope;
pub mod selector;
pub mod sources;
pub mod tap;

pub use alert_pipeline::{
    AlertPipeline, AlertPipelineConfigError, AlertPipelineFile, AlertPipelineSnapshot,
    AlertPipelineState, AlertTenantQuotas, CapTrim, Caps, DEFAULT_MAX_DYNAMIC_SILENCES,
    DEFAULT_MAX_SILENCE_DURATION, DedupStore, GroupMode, IncidentRef, IncidentResult,
    IncidentStore, IncludeMode, MatchOp, Matcher, MatcherError, MatcherSet, MatcherSpec,
    SNAPSHOT_VERSION, Silence, SilenceError, SilenceLimits, SilenceOrigin, SilenceRejection,
    SilenceRemoval, SilenceSpec, SilenceState, SilenceStore, SilenceView, TickOutput,
    build_alert_pipeline, group_fingerprint, load_alert_pipeline_file, parse_alert_pipeline_config,
    strip_auto_retained_event, strip_event_payloads,
};
pub use capture::{
    AdmittedEvent, AdmittedMatch, CaptureConfig, CaptureConfigError, CaptureIncompatibility,
    CaptureReject, CaptureRing, CaptureRingSink, CaptureSink, CaptureSnapshot, CaptureStats,
    CapturedEvent, event_digest,
};
pub use capture_spool::{
    BUNDLE_FORMAT_VERSION, BundleKind, BundleManifest, BundleRule, ProvenanceLine, SpoolReadError,
    bundle_id, disposition_identity, parse_corpus_events, parse_manifest, parse_provenance,
};
pub use dispositions::{
    Disposition, DispositionConfig, DispositionError, DispositionScope, DispositionSnapshot,
    DispositionStore, IngestOutcome, Numerator, RawDisposition, RuleSummary, Verdict,
    parse_dispositions, triage_feed,
};
pub use egress::{
    EgressDenial, EgressFilteredResolver, EgressPolicy, default_egress_policy,
    set_default_egress_policy,
};
pub use engine::{EngineStats, RoutingSpec, RuntimeEngine, SourceFetch};
pub use enrichment::config::{
    EnricherConfig, EnricherResources, EnrichersConfigError, EnrichersFile, build_enrichers,
    build_enrichers_full, load_enrichers_file, parse_enrichers_config,
};
pub use enrichment::{
    CacheKey, CacheOutcome, CommandEnricher, EnrichError, EnrichErrorKind, Enricher,
    EnricherFactory, EnricherKind, EnrichmentPipeline, HttpEnricher, HttpEnricherClient,
    HttpResponseCache, LookupEnricher, OnError, OutputFormat, Scope, TemplateEnricher,
    TemplateError, build_default_http_client, env_references, lookup_builtin, register_builtin,
    render_webhook_body, validate_template_namespace, validate_url_tenant_position,
};
#[cfg(feature = "dns-enrich")]
pub use enrichment::{DnsEnricher, DnsRecordType, DnsResolverConfig, SUPPORTED_DNS_RECORD_TYPES};
#[cfg(feature = "mmdb-enrich")]
pub use enrichment::{MmdbDatabase, MmdbEnricher, MmdbFields, MmdbLookupError};
#[cfg(feature = "stix-enrich")]
pub use enrichment::{StixEnricher, StixEnricherQuery};
pub use error::RuntimeError;
pub use finding_links::FindingLinks;
pub use input::{EventInputDecoded, InputFormat, parse_line};
pub use io::webhook::{
    BuiltWebhook, WebhookConfig, WebhookConfigError, WebhookKind, WebhookSink, WebhooksFile,
    build_webhooks, load_webhooks_file,
};
pub use io::{
    AckToken, DeliveryConfig, DeliveryContext, DeliveryFailure, DeliverySink, Dispatcher,
    EventSource, FileSink, FormattedIncidentEnvelope, IncidentEnvelope, OnFull, RawEvent, Sink,
    SinkFormat, StdinReadStatus, StdinSource, StdoutSink, WithTenant, spawn_source,
    validate_nats_subject_template,
};
#[cfg(all(unix, feature = "uds"))]
pub use io::{
    UnixSocketGuard, UnixSocketSink, UnixSocketSource, bind_unix_listener, parse_unix_scheme,
};
pub use metrics::{MetricsHook, NoopMetrics};
pub use processor::{
    BatchProcessOutcome, EventFilter, LogProcessor, detection_threads, init_detection_pool,
};
pub use risk::{
    IncidentConfig as RiskIncidentConfig, RiskCaps, RiskConfigError, RiskEntityView, RiskEvent,
    RiskFile, RiskIncidentResult, RiskLayer, RiskObject, RiskOutput, RiskRef, RiskState,
    RiskStateSnapshot, SNAPSHOT_VERSION as RISK_SNAPSHOT_VERSION, build_risk_layer, load_risk_file,
    parse_risk_config,
};
pub use ruleset::{PipelineRef, RuleSource, RulesetBinding, load_pipelines, watch_paths};
pub use selector::{Selector, SelectorParseError};
pub use tap::{TapPayload, TapRegistry, TapSessionHandle, TapStage};

pub use rsigma_eval::{
    FieldCoverage, FieldObservation, FieldObservationEntry, FieldObserver, ProcessResult,
    ProcessResultExt, SchemaClassifier, SchemaCountEntry, SchemaError, SchemaObservation,
    SchemaObserver, SchemaPruning, TenantId, UnknownShapeEntry, load_schema_signatures,
};
pub use sources::refresh::{RefreshResult, RefreshScheduler, RefreshTrigger, SourceSubscription};
pub use sources::{
    AddSummary, DefaultSourceResolver, RemoveSummary, ReplaceSummary, ResolvedValue, SourceCache,
    SourceError, SourceErrorKind, SourceResolver, TemplateExpander, WatchlistError, WatchlistItem,
    WatchlistRegistry, WatchlistRestore,
};

#[cfg(feature = "nats")]
pub use io::{NatsConnectConfig, NatsSink, NatsSource, ReplayPolicy};

#[cfg(feature = "evtx")]
pub use input::evtx::{EvtxError, EvtxFileReader};

#[cfg(feature = "otlp")]
pub use io::otlp::{
    DEFAULT_OTLP_TIMEOUT, ExportLogsServiceRequest, ExportLogsServiceResponse, LogsService,
    LogsServiceServer, OtlpClientTls, OtlpProtocol, OtlpSink, evaluation_results_to_logs_request,
    logs_request_to_raw_events, logs_request_to_raw_events_for,
};
