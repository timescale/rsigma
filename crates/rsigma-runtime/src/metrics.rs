/// Abstraction for runtime metrics so the runtime crate does not depend on
/// `prometheus` directly. The CLI (or any other consumer) provides a concrete
/// implementation backed by Prometheus, OpenTelemetry, or whatever it prefers.
pub trait MetricsHook: Send + Sync {
    /// A JSON line failed to parse.
    fn on_parse_error(&self);
    /// `count` events were successfully evaluated.
    fn on_events_processed(&self, count: u64);
    /// `count` detection rule matches were produced.
    fn on_detection_matches(&self, count: u64);
    /// `count` correlation rule matches were produced.
    fn on_correlation_matches(&self, count: u64);
    /// Observe per-event processing latency in seconds.
    fn observe_processing_latency(&self, seconds: f64);
    /// The input queue depth changed by `delta` (positive = enqueue, negative = dequeue).
    fn on_input_queue_depth_change(&self, delta: i64);
    /// Back-pressure event: a source tried to send but the channel was full.
    fn on_back_pressure(&self);
    /// Observe the batch size used for a single engine lock acquisition.
    fn observe_batch_size(&self, size: u64);
    /// The output queue depth changed by `delta`.
    fn on_output_queue_depth_change(&self, delta: i64);
    /// Observe end-to-end pipeline latency (dequeue → sink) in seconds.
    fn observe_pipeline_latency(&self, seconds: f64);
    /// Report current correlation state entry count.
    fn set_correlation_state_entries(&self, count: u64);

    /// A single detection rule matched. Labels enable per-rule Prometheus counters.
    fn on_detection_match_detail(&self, _rule_title: &str, _level: &str) {}
    /// A single correlation rule matched. Labels enable per-rule Prometheus counters.
    fn on_correlation_match_detail(
        &self,
        _rule_title: &str,
        _level: &str,
        _correlation_type: &str,
    ) {
    }
}

/// No-op implementation for use when metrics are disabled (e.g., `rsigma run`).
pub struct NoopMetrics;

impl MetricsHook for NoopMetrics {
    fn on_parse_error(&self) {}
    fn on_events_processed(&self, _count: u64) {}
    fn on_detection_matches(&self, _count: u64) {}
    fn on_correlation_matches(&self, _count: u64) {}
    fn observe_processing_latency(&self, _seconds: f64) {}
    fn on_input_queue_depth_change(&self, _delta: i64) {}
    fn on_back_pressure(&self) {}
    fn observe_batch_size(&self, _size: u64) {}
    fn on_output_queue_depth_change(&self, _delta: i64) {}
    fn observe_pipeline_latency(&self, _seconds: f64) {}
    fn set_correlation_state_entries(&self, _count: u64) {}
}
