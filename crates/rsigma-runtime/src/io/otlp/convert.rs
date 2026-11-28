use opentelemetry_proto::tonic::{
    collector::logs::v1::ExportLogsServiceRequest,
    common::v1::{AnyValue, ArrayValue, InstrumentationScope, KeyValue, KeyValueList, any_value},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    resource::v1::Resource,
};
use rsigma_eval::EvaluationResult;
use rsigma_eval::TenantId;
use serde_json::{Map, Value};

use crate::io::{AckToken, RawEvent};

/// Limits on how much one OTLP logs request may expand into events.
///
/// Every log record is flattened into its own JSON event that carries a copy
/// of the resource attributes, so a request with large resource attributes
/// and many records would otherwise expand far beyond its own size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtlpLimits {
    /// Most log records one request may carry. A request with more is
    /// refused as a whole, before it is decoded.
    pub max_records: usize,
    /// Largest flattened event, in bytes. A larger record is rejected.
    pub max_record_bytes: usize,
    /// Most bytes of flattened events one request may produce. Once the next
    /// record would pass it, that record and every later one are rejected.
    pub max_request_bytes: usize,
}

impl Default for OtlpLimits {
    /// 10,000 records, 1 MiB per event, and 64 MiB per request.
    fn default() -> Self {
        Self {
            max_records: 10_000,
            max_record_bytes: crate::io::MAX_LINE_BYTES,
            max_request_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Log records a [`LogRecordConverter`] rejected, by reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RejectedRecords {
    /// Records whose flattened event was larger than
    /// [`OtlpLimits::max_record_bytes`].
    pub too_large: u64,
    /// Records past [`OtlpLimits::max_request_bytes`].
    pub over_budget: u64,
}

impl RejectedRecords {
    /// Every rejected record.
    pub fn total(&self) -> u64 {
        self.too_large + self.over_budget
    }
}

/// Count the log records in an encoded `ExportLogsServiceRequest` without
/// decoding it, so a request with too many can be refused before decoding
/// allocates them all.
///
/// Walks only the `resource_logs`, `scope_logs`, and `log_records` framing.
/// Returns `None` when that framing is malformed. For a request that decodes,
/// the count equals the number of decoded records.
pub fn count_log_records(request: &[u8]) -> Option<usize> {
    let mut count = 0usize;
    for_each_message(request, 1, &mut |resource_logs| {
        for_each_message(resource_logs, 2, &mut |scope_logs| {
            for_each_message(scope_logs, 2, &mut |_| {
                count += 1;
                Some(())
            })
        })
    })?;
    Some(count)
}

/// Call `f` with the payload of every length-delimited occurrence of field
/// `field` in one protobuf message, skipping every other field.
fn for_each_message(
    mut buf: &[u8],
    field: u64,
    f: &mut dyn FnMut(&[u8]) -> Option<()>,
) -> Option<()> {
    // Field numbers of the groups being skipped, innermost last.
    let mut groups: Vec<u64> = Vec::new();
    while !buf.is_empty() {
        let key = read_varint(&mut buf)?;
        let number = key >> 3;
        if number == 0 {
            return None;
        }
        match key & 7 {
            0 => {
                read_varint(&mut buf)?;
            }
            1 => buf = buf.get(8..)?,
            2 => {
                let len = usize::try_from(read_varint(&mut buf)?).ok()?;
                let payload = buf.get(..len)?;
                buf = &buf[len..];
                if groups.is_empty() && number == field {
                    f(payload)?;
                }
            }
            3 => groups.push(number),
            4 => {
                if groups.pop()? != number {
                    return None;
                }
            }
            5 => buf = buf.get(4..)?,
            _ => return None,
        }
    }
    groups.is_empty().then_some(())
}

fn read_varint(buf: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = buf.split_first()?;
        *buf = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// Count the log records in an OTLP/JSON `ExportLogsServiceRequest` without
/// decoding it into records.
///
/// Walks `resourceLogs[].scopeLogs[].logRecords[]` and skips everything else
/// without allocating. Returns `None` when the body is not valid JSON. For a
/// request that decodes, the count is at least the number of decoded records.
pub fn count_log_records_json(request: &[u8]) -> Option<usize> {
    use serde::de::DeserializeSeed;
    let mut de = serde_json::Deserializer::from_slice(request);
    let count = json_count::Level::Request.deserialize(&mut de).ok()?;
    de.end().ok()?;
    Some(count)
}

mod json_count {
    use std::fmt;

    use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

    /// The object a seed expects. Anything else at that place counts zero.
    #[derive(Clone, Copy)]
    pub(super) enum Level {
        Request,
        ResourceLogs,
        ScopeLogs,
    }

    impl Level {
        fn child(self) -> (&'static str, Option<Level>) {
            match self {
                Level::Request => ("resourceLogs", Some(Level::ResourceLogs)),
                Level::ResourceLogs => ("scopeLogs", Some(Level::ScopeLogs)),
                Level::ScopeLogs => ("logRecords", None),
            }
        }
    }

    impl<'de> DeserializeSeed<'de> for Level {
        type Value = usize;

        fn deserialize<D: de::Deserializer<'de>>(self, de: D) -> Result<usize, D::Error> {
            de.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for Level {
        type Value = usize;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an OTLP logs object")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<usize, A::Error> {
            let (name, child) = self.child();
            let mut count = 0usize;
            while let Some(matched) = map.next_key_seed(KeyIs(name))? {
                count = count.saturating_add(if matched {
                    map.next_value_seed(Elements(child))?
                } else {
                    map.next_value::<IgnoredAny>()?;
                    0
                });
            }
            Ok(count)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<usize, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(0)
        }

        fn visit_bool<E: de::Error>(self, _: bool) -> Result<usize, E> {
            Ok(0)
        }

        fn visit_i64<E: de::Error>(self, _: i64) -> Result<usize, E> {
            Ok(0)
        }

        fn visit_u64<E: de::Error>(self, _: u64) -> Result<usize, E> {
            Ok(0)
        }

        fn visit_f64<E: de::Error>(self, _: f64) -> Result<usize, E> {
            Ok(0)
        }

        fn visit_str<E: de::Error>(self, _: &str) -> Result<usize, E> {
            Ok(0)
        }

        fn visit_unit<E: de::Error>(self) -> Result<usize, E> {
            Ok(0)
        }
    }

    /// The elements of an array: each counted at the next level down, or
    /// counted as one record when there is no lower level.
    struct Elements(Option<Level>);

    impl<'de> DeserializeSeed<'de> for Elements {
        type Value = usize;

        fn deserialize<D: de::Deserializer<'de>>(self, de: D) -> Result<usize, D::Error> {
            de.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for Elements {
        type Value = usize;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an array")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<usize, A::Error> {
            let mut count = 0usize;
            match self.0 {
                Some(level) => {
                    while let Some(n) = seq.next_element_seed(level)? {
                        count = count.saturating_add(n);
                    }
                }
                None => {
                    while seq.next_element::<IgnoredAny>()?.is_some() {
                        count = count.saturating_add(1);
                    }
                }
            }
            Ok(count)
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<usize, A::Error> {
            IgnoredAny.visit_map(map).map(|_| 0)
        }

        fn visit_bool<E: de::Error>(self, _: bool) -> Result<usize, E> {
            Ok(0)
        }

        fn visit_i64<E: de::Error>(self, _: i64) -> Result<usize, E> {
            Ok(0)
        }

        fn visit_u64<E: de::Error>(self, _: u64) -> Result<usize, E> {
            Ok(0)
        }

        fn visit_f64<E: de::Error>(self, _: f64) -> Result<usize, E> {
            Ok(0)
        }

        fn visit_str<E: de::Error>(self, _: &str) -> Result<usize, E> {
            Ok(0)
        }

        fn visit_unit<E: de::Error>(self) -> Result<usize, E> {
            Ok(0)
        }
    }

    /// Whether an object key equals one name, compared without allocating
    /// when the key has no escapes.
    struct KeyIs(&'static str);

    impl<'de> DeserializeSeed<'de> for KeyIs {
        type Value = bool;

        fn deserialize<D: de::Deserializer<'de>>(self, de: D) -> Result<bool, D::Error> {
            de.deserialize_str(self)
        }
    }

    impl<'de> Visitor<'de> for KeyIs {
        type Value = bool;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object key")
        }

        fn visit_str<E: de::Error>(self, key: &str) -> Result<bool, E> {
            Ok(key == self.0)
        }
    }
}

/// Convert an OTLP `ExportLogsServiceRequest` into a vec of [`RawEvent`]s.
///
/// Each `LogRecord` is flattened into a JSON object following industry
/// conventions (Elastic, Datadog, Splunk OTel integrations):
///
/// - Resource attributes are prefixed with `resource.`
/// - Log attributes are unprefixed (primary detection target)
/// - Scope metadata goes to `scope.name` / `scope.version`
/// - Timestamps are ISO 8601, trace/span IDs are lowercase hex
///
/// Records past the [`OtlpLimits::default`] sizes are left out; use a
/// [`LogRecordConverter`] to learn how many.
pub fn logs_request_to_raw_events(request: &ExportLogsServiceRequest) -> Vec<RawEvent> {
    logs_request_to_raw_events_for(request, None)
}

/// Like [`logs_request_to_raw_events`] but stamps every event with `tenant`,
/// which comes from the authenticated ingest principal.
pub fn logs_request_to_raw_events_for(
    request: &ExportLogsServiceRequest,
    tenant: Option<&TenantId>,
) -> Vec<RawEvent> {
    LogRecordConverter::new(request, tenant, OtlpLimits::default()).collect()
}

/// The number of log records in a decoded request.
pub fn log_record_count(request: &ExportLogsServiceRequest) -> usize {
    request
        .resource_logs
        .iter()
        .flat_map(|resource| &resource.scope_logs)
        .map(|scope| scope.log_records.len())
        .sum()
}

/// Flattens the log records of one request into [`RawEvent`]s one at a time,
/// within [`OtlpLimits`].
///
/// The resource attributes of each `ResourceLogs` are converted once and
/// copied into its events. A record whose event would be larger than
/// [`OtlpLimits::max_record_bytes`] is rejected, mostly before its event is
/// built, and once the events produced so far plus the next one would pass
/// [`OtlpLimits::max_request_bytes`], every remaining record is rejected.
/// [`Self::rejected`] reports both after the iteration.
pub struct LogRecordConverter<'a> {
    request: &'a ExportLogsServiceRequest,
    tenant: Option<TenantId>,
    limits: OtlpLimits,
    resource: usize,
    scope: usize,
    record: usize,
    prepared: Option<PreparedResource>,
    total_records: usize,
    seen_records: usize,
    produced_bytes: usize,
    rejected: RejectedRecords,
}

/// The resource attributes of one `ResourceLogs`, converted once for all of
/// its records.
struct PreparedResource {
    /// `resource.`-prefixed attributes, or `None` when they alone exceed the
    /// per-record limit, so every record under them is rejected.
    attributes: Option<Vec<(String, Value)>>,
    /// A lower bound on the bytes the attributes add to an event.
    bytes: usize,
}

impl<'a> LogRecordConverter<'a> {
    /// A converter over `request` that stamps every event with `tenant`.
    pub fn new(
        request: &'a ExportLogsServiceRequest,
        tenant: Option<&TenantId>,
        limits: OtlpLimits,
    ) -> Self {
        Self {
            request,
            tenant: tenant.cloned(),
            limits,
            resource: 0,
            scope: 0,
            record: 0,
            prepared: None,
            total_records: log_record_count(request),
            seen_records: 0,
            produced_bytes: 0,
            rejected: RejectedRecords::default(),
        }
    }

    /// Records rejected so far.
    pub fn rejected(&self) -> RejectedRecords {
        self.rejected
    }

    fn prepare(&self, resource_logs: &ResourceLogs) -> PreparedResource {
        let attrs = resource_logs
            .resource
            .as_ref()
            .map(|r| &r.attributes[..])
            .unwrap_or_default();
        let bytes = attributes_len(attrs, "resource.".len());
        if bytes > self.limits.max_record_bytes {
            return PreparedResource {
                attributes: None,
                bytes,
            };
        }
        let mut attributes = Vec::with_capacity(attrs.len());
        for kv in attrs {
            if let Some(v) = &kv.value {
                attributes.push((format!("resource.{}", kv.key), any_value_to_json(v)));
            }
        }
        PreparedResource {
            attributes: Some(attributes),
            bytes,
        }
    }
}

impl Iterator for LogRecordConverter<'_> {
    type Item = RawEvent;

    fn next(&mut self) -> Option<RawEvent> {
        loop {
            let resource_logs = self.request.resource_logs.get(self.resource)?;
            let Some(scope_logs) = resource_logs.scope_logs.get(self.scope) else {
                self.resource += 1;
                self.scope = 0;
                self.prepared = None;
                continue;
            };
            let Some(record) = scope_logs.log_records.get(self.record) else {
                self.scope += 1;
                self.record = 0;
                continue;
            };
            self.record += 1;
            self.seen_records += 1;
            if self.prepared.is_none() {
                self.prepared = Some(self.prepare(resource_logs));
            }
            let prepared = self.prepared.as_ref()?;
            let scope = scope_logs.scope.as_ref();
            let estimate = prepared.bytes + record_len(record, scope);
            if estimate > self.limits.max_record_bytes {
                self.rejected.too_large += 1;
                continue;
            }
            if self.produced_bytes + estimate > self.limits.max_request_bytes {
                let remaining = self.total_records - self.seen_records + 1;
                self.rejected.over_budget += remaining as u64;
                self.resource = self.request.resource_logs.len();
                return None;
            }
            let resource = prepared.attributes.as_deref().unwrap_or_default();
            let json = log_record_to_json(record, resource, scope);
            let payload = serde_json::to_string(&json).unwrap_or_default();
            if payload.len() > self.limits.max_record_bytes {
                self.rejected.too_large += 1;
                continue;
            }
            self.produced_bytes += payload.len();
            return Some(RawEvent {
                payload,
                ack_token: AckToken::Noop,
                tenant: self.tenant.clone(),
            });
        }
    }
}

/// A lower bound on the bytes the record's own fields and its scope add to
/// its flattened event.
fn record_len(record: &LogRecord, scope: Option<&InstrumentationScope>) -> usize {
    // `"timestamp":"…"` with a nanosecond RFC 3339 value.
    const TIMESTAMP: usize = 45;
    let mut len = 2usize;
    if record.time_unix_nano != 0 {
        len += TIMESTAMP;
    }
    if record.observed_time_unix_nano != 0 {
        len += TIMESTAMP + "observed_".len();
    }
    if !record.severity_text.is_empty() {
        len += record.severity_text.len() + "\"severity_text\":\"\",".len();
    }
    if let Some(body) = &record.body {
        len = len.saturating_add(any_value_len(body) + "\"body\":,".len());
    }
    len += record.trace_id.len() * 2 + record.span_id.len() * 2;
    len = len.saturating_add(attributes_len(&record.attributes, 0));
    if let Some(scope) = scope {
        len += scope.name.len() + scope.version.len();
    }
    len
}

/// A lower bound on the bytes `"key":value,` pairs add to an event, with
/// `prefix` extra bytes on every key.
fn attributes_len(attrs: &[KeyValue], prefix: usize) -> usize {
    attrs.iter().fold(0usize, |len, kv| match &kv.value {
        Some(v) => len.saturating_add(prefix + kv.key.len() + 4 + any_value_len(v)),
        None => len,
    })
}

/// A lower bound on the length of a value serialized as JSON.
fn any_value_len(value: &AnyValue) -> usize {
    match &value.value {
        Some(any_value::Value::StringValue(s)) => s.len() + 2,
        Some(any_value::Value::BoolValue(_)) => 4,
        Some(any_value::Value::IntValue(_)) | Some(any_value::Value::DoubleValue(_)) => 1,
        Some(any_value::Value::ArrayValue(arr)) => arr
            .values
            .iter()
            .fold(2usize, |len, v| len.saturating_add(any_value_len(v) + 1)),
        Some(any_value::Value::KvlistValue(kvlist)) => {
            attributes_len(&kvlist.values, 0).saturating_add(2)
        }
        Some(any_value::Value::BytesValue(bytes)) => bytes.len() * 2 + 2,
        Some(any_value::Value::StringValueStrindex(_)) | None => 4,
    }
}

fn log_record_to_json(
    record: &LogRecord,
    resource_attrs: &[(String, Value)],
    scope: Option<&InstrumentationScope>,
) -> Value {
    let mut map = Map::new();

    if record.time_unix_nano != 0 {
        map.insert(
            "timestamp".to_string(),
            Value::String(nanos_to_iso8601(record.time_unix_nano)),
        );
    }

    if record.observed_time_unix_nano != 0 {
        map.insert(
            "observed_timestamp".to_string(),
            Value::String(nanos_to_iso8601(record.observed_time_unix_nano)),
        );
    }

    if record.severity_number != 0 {
        map.insert(
            "severity_number".to_string(),
            Value::Number(record.severity_number.into()),
        );
    }

    if !record.severity_text.is_empty() {
        map.insert(
            "severity_text".to_string(),
            Value::String(record.severity_text.clone()),
        );
    }

    if let Some(body) = &record.body {
        insert_body(&mut map, body);
    }

    if !record.trace_id.is_empty() {
        map.insert(
            "trace_id".to_string(),
            Value::String(hex::encode(&record.trace_id)),
        );
    }

    if !record.span_id.is_empty() {
        map.insert(
            "span_id".to_string(),
            Value::String(hex::encode(&record.span_id)),
        );
    }

    // Log attributes (unprefixed)
    flatten_attributes(&mut map, &record.attributes, "");

    // Resource attributes (prefixed with "resource.")
    for (key, value) in resource_attrs {
        map.insert(key.clone(), value.clone());
    }

    // Scope metadata
    if let Some(scope) = scope {
        if !scope.name.is_empty() {
            map.insert("scope.name".to_string(), Value::String(scope.name.clone()));
        }
        if !scope.version.is_empty() {
            map.insert(
                "scope.version".to_string(),
                Value::String(scope.version.clone()),
            );
        }
    }

    Value::Object(map)
}

fn insert_body(map: &mut Map<String, Value>, body: &AnyValue) {
    match &body.value {
        Some(any_value::Value::KvlistValue(kvlist)) => {
            for kv in &kvlist.values {
                if let Some(v) = &kv.value {
                    map.insert(kv.key.clone(), any_value_to_json(v));
                }
            }
        }
        Some(_) => {
            map.insert("body".to_string(), any_value_to_json(body));
        }
        None => {}
    }
}

fn flatten_attributes(map: &mut Map<String, Value>, attrs: &[KeyValue], prefix: &str) {
    for kv in attrs {
        if let Some(v) = &kv.value {
            let key = format!("{prefix}{}", kv.key);
            map.insert(key, any_value_to_json(v));
        }
    }
}

fn any_value_to_json(value: &AnyValue) -> Value {
    match &value.value {
        Some(any_value::Value::StringValue(s)) => Value::String(s.clone()),
        Some(any_value::Value::BoolValue(b)) => Value::Bool(*b),
        Some(any_value::Value::IntValue(i)) => Value::Number((*i).into()),
        Some(any_value::Value::DoubleValue(d)) => {
            serde_json::Number::from_f64(*d).map_or(Value::Null, Value::Number)
        }
        Some(any_value::Value::ArrayValue(arr)) => {
            Value::Array(arr.values.iter().map(any_value_to_json).collect())
        }
        Some(any_value::Value::KvlistValue(kvlist)) => {
            let mut m = Map::new();
            for kv in &kvlist.values {
                if let Some(v) = &kv.value {
                    m.insert(kv.key.clone(), any_value_to_json(v));
                }
            }
            Value::Object(m)
        }
        Some(any_value::Value::BytesValue(bytes)) => Value::String(hex::encode(bytes)),
        // StringValueStrindex references a string in ProfilesDictionary.string_table
        // and is exclusive to the Profiling signal. Per the OTLP spec, non-Profiling
        // receivers must treat its presence as if the value were absent.
        Some(any_value::Value::StringValueStrindex(_)) | None => Value::Null,
    }
}

fn nanos_to_iso8601(nanos: u64) -> String {
    let secs = (nanos / 1_000_000_000) as i64;
    let subsec_nanos = (nanos % 1_000_000_000) as u32;
    chrono::DateTime::from_timestamp(secs, subsec_nanos)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
        .unwrap_or_default()
}

/// Convert a batch of [`EvaluationResult`]s into one OTLP
/// `ExportLogsServiceRequest` for delivery to a collector.
///
/// Every result becomes one `LogRecord` under a single `rsigma` resource and
/// instrumentation scope: the Sigma `level` maps to the OTLP severity, the
/// rule title becomes the log body, and the full serialized result (rule
/// metadata, detection match detail or correlation fields, enrichments) is
/// attached as structured log attributes.
pub fn evaluation_results_to_logs_request(
    results: &[EvaluationResult],
) -> ExportLogsServiceRequest {
    logs_request(results.iter().map(result_to_log_record).collect())
}

/// Convert evaluation results into an `ExportLogsServiceRequest` whose log
/// bodies are OCSF findings.
///
/// `finding` returns the finding for the result at an index. Each record's
/// body is that finding as a JSON string, and its severity follows the
/// Sigma level as in [`evaluation_results_to_logs_request`]. The attribute
/// set is the same one a native record carries, so a collector can still
/// route on `rule_title`, `rule_id`, `level`, and `tags`.
pub(crate) fn ocsf_findings_to_logs_request(
    results: &[EvaluationResult],
    finding: impl Fn(usize, &EvaluationResult) -> Value,
) -> ExportLogsServiceRequest {
    logs_request(
        results
            .iter()
            .enumerate()
            .map(|(index, result)| ocsf_log_record(result, &finding(index, result)))
            .collect(),
    )
}

fn logs_request(log_records: Vec<LogRecord>) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![string_kv("service.name", "rsigma")],
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: "rsigma".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    ..Default::default()
                }),
                log_records,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

fn result_to_log_record(result: &EvaluationResult) -> LogRecord {
    let now = now_unix_nanos();
    let value = serde_json::to_value(result).unwrap_or(Value::Null);
    let (severity_number, severity_text) =
        severity_from_level(value.get("level").and_then(Value::as_str));
    let attributes = match &value {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| KeyValue {
                key: k.clone(),
                value: Some(json_to_any_value(v)),
                ..Default::default()
            })
            .collect(),
        _ => Vec::new(),
    };
    LogRecord {
        time_unix_nano: now,
        observed_time_unix_nano: now,
        severity_number,
        severity_text: severity_text.to_string(),
        body: Some(string_any_value(&result.header.rule_title)),
        attributes,
        ..Default::default()
    }
}

fn ocsf_log_record(result: &EvaluationResult, finding: &Value) -> LogRecord {
    let mut record = result_to_log_record(result);
    record.body = Some(string_any_value(
        &serde_json::to_string(finding).unwrap_or_else(|_| "{}".to_string()),
    ));
    record
}

/// Map a Sigma level to an OTLP severity `(number, text)`. Unknown or absent
/// levels map to `UNSPECIFIED` (0).
fn severity_from_level(level: Option<&str>) -> (i32, &'static str) {
    match level {
        Some("critical") => (21, "FATAL"),
        Some("high") => (17, "ERROR"),
        Some("medium") => (13, "WARN"),
        Some("low") => (9, "INFO"),
        Some("informational") => (5, "DEBUG"),
        _ => (0, ""),
    }
}

fn string_kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(string_any_value(value)),
        ..Default::default()
    }
}

fn string_any_value(s: &str) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::StringValue(s.to_string())),
    }
}

/// Inverse of [`any_value_to_json`]: lower a JSON value into an OTLP `AnyValue`.
fn json_to_any_value(value: &Value) -> AnyValue {
    let inner = match value {
        Value::Null => None,
        Value::Bool(b) => Some(any_value::Value::BoolValue(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(any_value::Value::IntValue(i))
            } else {
                n.as_f64().map(any_value::Value::DoubleValue)
            }
        }
        Value::String(s) => Some(any_value::Value::StringValue(s.clone())),
        Value::Array(arr) => Some(any_value::Value::ArrayValue(ArrayValue {
            values: arr.iter().map(json_to_any_value).collect(),
        })),
        Value::Object(map) => Some(any_value::Value::KvlistValue(KeyValueList {
            values: map
                .iter()
                .map(|(k, v)| KeyValue {
                    key: k.clone(),
                    value: Some(json_to_any_value(v)),
                    ..Default::default()
                })
                .collect(),
        })),
    };
    AnyValue { value: inner }
}

fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Encode bytes as lowercase hex without any prefix.
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::{
        common::v1::{AnyValue, ArrayValue, InstrumentationScope, KeyValue, KeyValueList},
        logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
        resource::v1::Resource,
    };

    fn kv(key: &str, value: AnyValue) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(value),
            ..Default::default()
        }
    }

    fn string_val(s: &str) -> AnyValue {
        AnyValue {
            value: Some(any_value::Value::StringValue(s.to_string())),
        }
    }

    fn int_val(i: i64) -> AnyValue {
        AnyValue {
            value: Some(any_value::Value::IntValue(i)),
        }
    }

    fn bool_val(b: bool) -> AnyValue {
        AnyValue {
            value: Some(any_value::Value::BoolValue(b)),
        }
    }

    fn make_request(
        resource_attrs: Vec<KeyValue>,
        scope: Option<InstrumentationScope>,
        log_records: Vec<LogRecord>,
    ) -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: resource_attrs,
                    ..Default::default()
                }),
                scope_logs: vec![ScopeLogs {
                    scope,
                    log_records,
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
    }

    #[test]
    fn basic_log_record() {
        let request = make_request(
            vec![kv("service.name", string_val("my-service"))],
            Some(InstrumentationScope {
                name: "my-lib".to_string(),
                version: "1.0.0".to_string(),
                ..Default::default()
            }),
            vec![LogRecord {
                time_unix_nano: 1_700_000_000_000_000_000,
                observed_time_unix_nano: 1_700_000_001_000_000_000,
                severity_number: 9,
                severity_text: "INFO".to_string(),
                body: Some(string_val("User logged in")),
                attributes: vec![
                    kv("user.id", string_val("alice")),
                    kv("request.method", string_val("POST")),
                ],
                trace_id: vec![
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
                    0xab, 0xcd, 0xef,
                ],
                span_id: vec![0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
                ..Default::default()
            }],
        );

        let events = logs_request_to_raw_events(&request);
        assert_eq!(events.len(), 1);

        let json: Value = serde_json::from_str(&events[0].payload).unwrap();
        assert_eq!(json["severity_text"], "INFO");
        assert_eq!(json["severity_number"], 9);
        assert_eq!(json["body"], "User logged in");
        assert_eq!(json["user.id"], "alice");
        assert_eq!(json["request.method"], "POST");
        assert_eq!(json["resource.service.name"], "my-service");
        assert_eq!(json["scope.name"], "my-lib");
        assert_eq!(json["scope.version"], "1.0.0");
        assert_eq!(json["trace_id"], "0123456789abcdef0123456789abcdef");
        assert_eq!(json["span_id"], "fedcba9876543210");
        assert!(
            json["timestamp"]
                .as_str()
                .unwrap()
                .starts_with("2023-11-14")
        );
    }

    #[test]
    fn map_body_flattened_to_top_level() {
        let body = AnyValue {
            value: Some(any_value::Value::KvlistValue(KeyValueList {
                values: vec![
                    kv("EventID", int_val(4625)),
                    kv("TargetUserName", string_val("admin")),
                ],
            })),
        };

        let request = make_request(
            vec![],
            None,
            vec![LogRecord {
                body: Some(body),
                severity_text: "WARN".to_string(),
                ..Default::default()
            }],
        );

        let events = logs_request_to_raw_events(&request);
        let json: Value = serde_json::from_str(&events[0].payload).unwrap();
        assert_eq!(json["EventID"], 4625);
        assert_eq!(json["TargetUserName"], "admin");
        assert!(json.get("body").is_none());
    }

    #[test]
    fn empty_request_yields_no_events() {
        let request = ExportLogsServiceRequest {
            resource_logs: vec![],
        };
        let events = logs_request_to_raw_events(&request);
        assert!(events.is_empty());
    }

    #[test]
    fn missing_optional_fields() {
        let request = make_request(vec![], None, vec![LogRecord::default()]);

        let events = logs_request_to_raw_events(&request);
        assert_eq!(events.len(), 1);

        let json: Value = serde_json::from_str(&events[0].payload).unwrap();
        assert!(json.get("timestamp").is_none());
        assert!(json.get("observed_timestamp").is_none());
        assert!(json.get("severity_text").is_none());
        assert!(json.get("severity_number").is_none());
        assert!(json.get("trace_id").is_none());
        assert!(json.get("span_id").is_none());
    }

    #[test]
    fn multiple_log_records_across_scopes() {
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![kv("host.name", string_val("server-1"))],
                    ..Default::default()
                }),
                scope_logs: vec![
                    ScopeLogs {
                        scope: Some(InstrumentationScope {
                            name: "scope-a".to_string(),
                            ..Default::default()
                        }),
                        log_records: vec![
                            LogRecord {
                                body: Some(string_val("event-1")),
                                ..Default::default()
                            },
                            LogRecord {
                                body: Some(string_val("event-2")),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    },
                    ScopeLogs {
                        scope: Some(InstrumentationScope {
                            name: "scope-b".to_string(),
                            ..Default::default()
                        }),
                        log_records: vec![LogRecord {
                            body: Some(string_val("event-3")),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
        };

        let events = logs_request_to_raw_events(&request);
        assert_eq!(events.len(), 3);

        let j1: Value = serde_json::from_str(&events[0].payload).unwrap();
        let j2: Value = serde_json::from_str(&events[1].payload).unwrap();
        let j3: Value = serde_json::from_str(&events[2].payload).unwrap();

        assert_eq!(j1["body"], "event-1");
        assert_eq!(j1["scope.name"], "scope-a");
        assert_eq!(j1["resource.host.name"], "server-1");

        assert_eq!(j2["body"], "event-2");
        assert_eq!(j2["scope.name"], "scope-a");

        assert_eq!(j3["body"], "event-3");
        assert_eq!(j3["scope.name"], "scope-b");
    }

    #[test]
    fn array_and_nested_attribute_values() {
        let nested = AnyValue {
            value: Some(any_value::Value::KvlistValue(KeyValueList {
                values: vec![kv("inner", string_val("value"))],
            })),
        };
        let arr = AnyValue {
            value: Some(any_value::Value::ArrayValue(ArrayValue {
                values: vec![int_val(1), int_val(2), int_val(3)],
            })),
        };

        let request = make_request(
            vec![],
            None,
            vec![LogRecord {
                attributes: vec![
                    kv("nested", nested),
                    kv("tags", arr),
                    kv("enabled", bool_val(true)),
                ],
                ..Default::default()
            }],
        );

        let events = logs_request_to_raw_events(&request);
        let json: Value = serde_json::from_str(&events[0].payload).unwrap();

        assert_eq!(json["nested"]["inner"], "value");
        assert_eq!(
            json["tags"],
            Value::Array(vec![
                Value::Number(1.into()),
                Value::Number(2.into()),
                Value::Number(3.into()),
            ])
        );
        assert_eq!(json["enabled"], true);
    }

    fn nested_array(depth: usize) -> AnyValue {
        let mut value = string_val("leaf");
        for _ in 0..depth {
            value = AnyValue {
                value: Some(any_value::Value::ArrayValue(ArrayValue {
                    values: vec![value],
                })),
            };
        }
        value
    }

    /// Conversion recurses once per `AnyValue` level, so it relies on prost's
    /// decode recursion limit to bound nesting in untrusted OTLP payloads. A
    /// dependency enabling prost's `no-recursion-limit` feature fails here.
    #[test]
    fn protobuf_decode_bounds_any_value_nesting() {
        use prost::Message;

        let encode = |depth| {
            make_request(
                vec![],
                None,
                vec![LogRecord {
                    attributes: vec![kv("deep", nested_array(depth))],
                    ..Default::default()
                }],
            )
            .encode_to_vec()
        };

        let request = ExportLogsServiceRequest::decode(encode(45).as_slice())
            .expect("45 nested values are within the limit");
        let events = logs_request_to_raw_events(&request);
        let json: Value = serde_json::from_str(&events[0].payload).unwrap();
        let leaf = (0..45).fold(&json["deep"], |v, _| &v[0]);
        assert_eq!(leaf, "leaf");

        let Err(err) = ExportLogsServiceRequest::decode(encode(200).as_slice()) else {
            panic!("200 nested values exceed the limit");
        };
        assert!(err.to_string().contains("recursion limit"), "{err}");
    }

    #[test]
    fn hex_encode_correctness() {
        assert_eq!(hex::encode(&[]), "");
        assert_eq!(hex::encode(&[0x00]), "00");
        assert_eq!(hex::encode(&[0xff]), "ff");
        assert_eq!(hex::encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn detection_result_lowers_to_otlp_log_record() {
        use rsigma_eval::result::{DetectionBody, FieldMatch, ResultBody, RuleHeader};
        use std::collections::HashMap;
        use std::sync::Arc;

        let result = EvaluationResult {
            header: RuleHeader {
                rule_title: "Suspicious PowerShell".to_string(),
                rule_id: Some("rule-1".to_string()),
                tenant_id: None,
                level: Some(rsigma_parser::Level::High),
                tags: vec!["attack.t1059".to_string()],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec!["selection".to_string()],
                matched_fields: vec![FieldMatch::new(
                    "CommandLine",
                    serde_json::json!("powershell -enc"),
                )],
                event: None,
            }),
        };

        let request = evaluation_results_to_logs_request(std::slice::from_ref(&result));
        let resource_logs = &request.resource_logs[0];
        assert!(
            resource_logs
                .resource
                .as_ref()
                .unwrap()
                .attributes
                .iter()
                .any(|kv| kv.key == "service.name"),
            "resource carries service.name",
        );

        let scope_logs = &resource_logs.scope_logs[0];
        assert_eq!(scope_logs.scope.as_ref().unwrap().name, "rsigma");

        let record = &scope_logs.log_records[0];
        assert_eq!(record.severity_number, 17, "high maps to ERROR(17)");
        assert_eq!(record.severity_text, "ERROR");
        match record.body.as_ref().and_then(|b| b.value.as_ref()) {
            Some(any_value::Value::StringValue(s)) => assert_eq!(s, "Suspicious PowerShell"),
            other => panic!("body should be the rule title string, got {other:?}"),
        }
        let keys: Vec<&str> = record.attributes.iter().map(|kv| kv.key.as_str()).collect();
        assert!(keys.contains(&"rule_title"));
        assert!(keys.contains(&"level"));
        assert!(keys.contains(&"matched_fields"));
        assert!(
            !keys.contains(&"correlation_type"),
            "a detection must not carry correlation_type",
        );
    }

    #[test]
    fn severity_mapping_covers_every_level() {
        assert_eq!(severity_from_level(Some("critical")), (21, "FATAL"));
        assert_eq!(severity_from_level(Some("high")), (17, "ERROR"));
        assert_eq!(severity_from_level(Some("medium")), (13, "WARN"));
        assert_eq!(severity_from_level(Some("low")), (9, "INFO"));
        assert_eq!(severity_from_level(Some("informational")), (5, "DEBUG"));
        assert_eq!(severity_from_level(None), (0, ""));
        assert_eq!(severity_from_level(Some("bogus")), (0, ""));
    }

    #[test]
    fn correlation_result_lowers_to_otlp_log_record() {
        use rsigma_eval::result::{CorrelationBody, ResultBody, RuleHeader};
        use rsigma_parser::CorrelationType;
        use std::collections::HashMap;
        use std::sync::Arc;

        let result = EvaluationResult {
            header: RuleHeader {
                rule_title: "SSH brute force".to_string(),
                rule_id: Some("corr-1".to_string()),
                tenant_id: None,
                level: Some(rsigma_parser::Level::Critical),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
            },
            body: ResultBody::Correlation(CorrelationBody {
                correlation_type: CorrelationType::EventCount,
                group_key: vec![("SourceIP".to_string(), "203.0.113.4".to_string())],
                aggregated_value: 73.0,
                timespan_secs: 300,
                events: None,
                event_refs: None,
                event_sources: None,
                absence: None,
            }),
        };

        let request = evaluation_results_to_logs_request(std::slice::from_ref(&result));
        let record = &request.resource_logs[0].scope_logs[0].log_records[0];
        assert_eq!(record.severity_number, 21, "critical maps to FATAL(21)");
        assert_eq!(record.severity_text, "FATAL");
        let keys: Vec<&str> = record.attributes.iter().map(|kv| kv.key.as_str()).collect();
        assert!(keys.contains(&"correlation_type"));
        assert!(keys.contains(&"group_key"));
        assert!(keys.contains(&"aggregated_value"));
        assert!(
            !keys.contains(&"matched_fields"),
            "a correlation must not carry matched_fields",
        );
    }

    #[test]
    fn ocsf_body_is_the_finding_as_json() {
        use rsigma_eval::result::{DetectionBody, ResultBody, RuleHeader};
        use std::collections::HashMap;
        use std::sync::Arc;

        let golden: Value = serde_json::from_str(include_str!(
            "../../../tests/golden/ocsf/1.1.0/detection.json"
        ))
        .unwrap();
        let result = EvaluationResult {
            header: RuleHeader {
                rule_title: "Suspicious PowerShell".to_string(),
                rule_id: Some("rule-1".to_string()),
                tenant_id: None,
                level: Some(rsigma_parser::Level::Medium),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![],
                event: None,
            }),
        };

        let request =
            ocsf_findings_to_logs_request(std::slice::from_ref(&result), |_, _| golden.clone());
        let record = &request.resource_logs[0].scope_logs[0].log_records[0];
        assert_eq!(
            record.severity_number, 13,
            "severity still follows the level"
        );
        assert_eq!(record.severity_text, "WARN");
        assert!(
            record.attributes.iter().any(|kv| kv.key == "rule_title"),
            "native attributes stay on the record: {:?}",
            record.attributes,
        );
        let body = record.body.as_ref().unwrap();
        let serde_json::Value::String(raw) = any_value_to_json(body) else {
            panic!("the body must be a JSON string: {body:?}");
        };
        let parsed: Value = serde_json::from_str(&raw).expect("finding JSON");
        assert_eq!(parsed, golden, "the string body is the finding");
    }

    fn records(n: usize) -> Vec<LogRecord> {
        (0..n)
            .map(|i| LogRecord {
                body: Some(string_val(&format!("event-{i}"))),
                ..Default::default()
            })
            .collect()
    }

    #[test]
    fn record_counts_match_the_decoded_request() {
        use prost::Message;

        let request = ExportLogsServiceRequest {
            resource_logs: vec![
                ResourceLogs {
                    resource: Some(Resource {
                        attributes: vec![kv("host.name", string_val("a"))],
                        ..Default::default()
                    }),
                    scope_logs: vec![
                        ScopeLogs {
                            log_records: records(3),
                            schema_url: "https://example.test".to_string(),
                            ..Default::default()
                        },
                        ScopeLogs::default(),
                        ScopeLogs {
                            log_records: records(2),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
                ResourceLogs {
                    scope_logs: vec![ScopeLogs {
                        log_records: records(4),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
        };
        assert_eq!(log_record_count(&request), 9);

        let encoded = request.encode_to_vec();
        assert_eq!(count_log_records(&encoded), Some(9));
        let json = serde_json::to_vec(&request).unwrap();
        assert_eq!(count_log_records_json(&json), Some(9));

        assert_eq!(count_log_records(&[]), Some(0));
        assert_eq!(count_log_records_json(b"{}"), Some(0));
        assert_eq!(count_log_records(&encoded[..encoded.len() - 1]), None);
        assert_eq!(count_log_records_json(b"{\"resourceLogs\":["), None);
    }

    #[test]
    fn the_protobuf_count_skips_unknown_fields_and_groups() {
        use prost::Message;

        let mut encoded = Vec::new();
        // Field 9 as a varint, a fixed64, a fixed32, and a group.
        encoded.extend_from_slice(&[0x48, 0x96, 0x01]);
        encoded.extend_from_slice(&[0x49, 1, 2, 3, 4, 5, 6, 7, 8]);
        encoded.extend_from_slice(&[0x4d, 1, 2, 3, 4]);
        encoded.extend_from_slice(&[0x4b, 0x08, 0x01, 0x4c]);
        make_request(vec![], None, records(5))
            .encode(&mut encoded)
            .unwrap();

        let decoded = ExportLogsServiceRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(log_record_count(&decoded), 5);
        assert_eq!(count_log_records(&encoded), Some(5));

        // An unterminated group.
        assert_eq!(count_log_records(&[0x4b, 0x08, 0x01]), None);
    }

    #[test]
    fn the_json_count_ignores_other_fields_and_shapes() {
        let body = br#"{
            "resourceLogs": [
                {"resource": {"attributes": [{"key": "logRecords", "value": {"arrayValue": {"values": [1, 2]}}}]},
                 "scopeLogs": [{"scope": {"name": "s"}, "logRecords": [{}, {"body": {"stringValue": "x"}}]},
                               {"logRecords": null}]},
                {"scopeLogs": "not an array"}
            ],
            "extra": {"resourceLogs": [{"scopeLogs": [{"logRecords": [{}]}]}]}
        }"#;
        assert_eq!(count_log_records_json(body), Some(2));
    }

    #[test]
    fn a_large_resource_over_many_records_stays_within_the_request_budget() {
        let big = "r".repeat(512 * 1024);
        let request = make_request(
            vec![kv("service.blob", string_val(&big))],
            None,
            records(10_000),
        );
        let limits = OtlpLimits::default();
        let mut converter = LogRecordConverter::new(&request, None, limits);
        let mut produced = 0usize;
        let mut accepted = 0u64;
        for event in converter.by_ref() {
            assert!(event.payload.len() <= limits.max_record_bytes);
            produced += event.payload.len();
            accepted += 1;
        }
        let rejected = converter.rejected();
        assert!(produced <= limits.max_request_bytes);
        assert!(accepted > 0);
        assert_eq!(rejected.too_large, 0);
        assert_eq!(accepted + rejected.over_budget, 10_000);
    }

    #[test]
    fn a_resource_over_the_record_limit_rejects_every_record_under_it() {
        let huge = "r".repeat(2 * 1024 * 1024);
        let request = ExportLogsServiceRequest {
            resource_logs: vec![
                ResourceLogs {
                    resource: Some(Resource {
                        attributes: vec![kv("service.blob", string_val(&huge))],
                        ..Default::default()
                    }),
                    scope_logs: vec![ScopeLogs {
                        log_records: records(1000),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                ResourceLogs {
                    scope_logs: vec![ScopeLogs {
                        log_records: records(2),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
        };
        let mut converter = LogRecordConverter::new(&request, None, OtlpLimits::default());
        let events: Vec<RawEvent> = converter.by_ref().collect();
        assert_eq!(
            events.len(),
            2,
            "the records under the small resource remain"
        );
        assert_eq!(converter.rejected().too_large, 1000);
        assert_eq!(converter.rejected().over_budget, 0);
    }

    #[test]
    fn an_over_large_record_is_rejected_and_its_neighbours_kept() {
        let mut log_records = records(3);
        log_records[1].attributes = vec![kv("blob", string_val(&"x".repeat(2 * 1024 * 1024)))];
        let request = make_request(vec![], None, log_records);
        let mut converter = LogRecordConverter::new(&request, None, OtlpLimits::default());
        let bodies: Vec<String> = converter
            .by_ref()
            .map(|e| serde_json::from_str::<Value>(&e.payload).unwrap()["body"].to_string())
            .collect();
        assert_eq!(bodies, ["\"event-0\"", "\"event-2\""]);
        assert_eq!(converter.rejected().too_large, 1);
    }

    #[test]
    fn a_record_whose_estimate_fits_but_whose_event_does_not_is_rejected() {
        // Every byte here is escaped in JSON, so the event is six times the
        // size the estimate assumes.
        let control = "\u{1}".repeat(400 * 1024);
        let request = make_request(
            vec![],
            None,
            vec![LogRecord {
                body: Some(string_val(&control)),
                ..Default::default()
            }],
        );
        let mut converter = LogRecordConverter::new(&request, None, OtlpLimits::default());
        assert_eq!(converter.by_ref().count(), 0);
        assert_eq!(converter.rejected().too_large, 1);
    }

    #[test]
    fn logs_request_stamps_the_tenant() {
        let tenant = TenantId::new("tenant-a").unwrap();
        let request = make_request(vec![], None, vec![LogRecord::default()]);
        let events = logs_request_to_raw_events_for(&request, Some(&tenant));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tenant.as_ref(), Some(&tenant));

        let events = logs_request_to_raw_events(&request);
        assert!(events[0].tenant.is_none());
    }
}

#[cfg(test)]
mod tenant_tests {
    use super::*;
    use rsigma_eval::result::{DetectionBody, ResultBody, RuleHeader};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn tenant_id_becomes_a_log_attribute() {
        let result = EvaluationResult {
            header: RuleHeader {
                rule_title: "Tenanted".to_string(),
                rule_id: Some("rule-1".to_string()),
                tenant_id: Some(TenantId::new("tenant-a").unwrap()),
                level: None,
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![],
                event: None,
            }),
        };
        let request = evaluation_results_to_logs_request(&[result]);
        let records = &request.resource_logs[0].scope_logs[0].log_records;
        let attr = records[0]
            .attributes
            .iter()
            .find(|kv| kv.key == "tenant_id")
            .expect("tenant_id attribute");
        let value = attr.value.as_ref().and_then(|value| value.value.as_ref());
        assert!(matches!(value, Some(any_value::Value::StringValue(s)) if s == "tenant-a"));
    }
}
