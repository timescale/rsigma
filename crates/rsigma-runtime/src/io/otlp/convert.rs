use opentelemetry_proto::tonic::{
    collector::logs::v1::ExportLogsServiceRequest,
    common::v1::{AnyValue, ArrayValue, InstrumentationScope, KeyValue, KeyValueList, any_value},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    resource::v1::Resource,
};
use rsigma_eval::EvaluationResult;
use serde_json::{Map, Value};

use crate::io::{AckToken, RawEvent};

/// Convert an OTLP `ExportLogsServiceRequest` into a vec of [`RawEvent`]s.
///
/// Each `LogRecord` is flattened into a JSON object following industry
/// conventions (Elastic, Datadog, Splunk OTel integrations):
///
/// - Resource attributes are prefixed with `resource.`
/// - Log attributes are unprefixed (primary detection target)
/// - Scope metadata goes to `scope.name` / `scope.version`
/// - Timestamps are ISO 8601, trace/span IDs are lowercase hex
pub fn logs_request_to_raw_events(request: &ExportLogsServiceRequest) -> Vec<RawEvent> {
    let mut events = Vec::new();

    for resource_logs in &request.resource_logs {
        let resource_attrs = resource_logs
            .resource
            .as_ref()
            .map(|r| &r.attributes[..])
            .unwrap_or_default();

        for scope_logs in &resource_logs.scope_logs {
            let scope = scope_logs.scope.as_ref();

            for log_record in &scope_logs.log_records {
                let json = log_record_to_json(log_record, resource_attrs, scope);
                let payload = serde_json::to_string(&json).unwrap_or_default();
                events.push(RawEvent {
                    payload,
                    ack_token: AckToken::Noop,
                });
            }
        }
    }

    events
}

fn log_record_to_json(
    record: &opentelemetry_proto::tonic::logs::v1::LogRecord,
    resource_attrs: &[KeyValue],
    scope: Option<&opentelemetry_proto::tonic::common::v1::InstrumentationScope>,
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
    flatten_attributes(&mut map, resource_attrs, "resource.");

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
    let log_records = results.iter().map(result_to_log_record).collect();
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
                level: Some(rsigma_parser::Level::High),
                tags: vec!["attack.t1059".to_string()],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
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
                level: Some(rsigma_parser::Level::Critical),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Correlation(CorrelationBody {
                correlation_type: CorrelationType::EventCount,
                group_key: vec![("SourceIP".to_string(), "203.0.113.4".to_string())],
                aggregated_value: 73.0,
                timespan_secs: 300,
                events: None,
                event_refs: None,
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
}
