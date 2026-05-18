# Input Formats

RSigma can read events in seven formats, with auto-detection as the default. This page covers when to choose each format, the parser specifics, the timestamps extracted, and the format-specific flags.

The same set of formats works in both `engine eval` and `engine daemon`. The `--input-format` flag selects one; without it, auto-detect tries JSON, then syslog, then plain text on every line.

## Format summary

| Format | Flag value | Feature flag | Typical source |
|--------|-----------|--------------|----------------|
| JSON/NDJSON | `json` | default | Application logs, Sysmon-as-JSON, OTLP stripped of envelope, anything via Helr |
| Syslog (RFC 3164/5424) | `syslog` | default | Network appliances, traditional Unix logs |
| logfmt | `logfmt` | `logfmt` | Go services (HashiCorp, Grafana, kubelet logs) |
| CEF | `cef` | `cef` | ArcSight, McAfee, vendor SIEM-friendly format |
| EVTX | (auto-detected by `.evtx` extension) | `evtx` | Windows Event Log binary files |
| OTLP | (separate `/v1/logs` endpoint) | `daemon-otlp` | OpenTelemetry-compatible agents (Alloy, Vector, Fluent Bit, OTel Collector) |
| Plain text | `plain` | default | Unstructured lines, fallback for keyword-only rules |
| Auto-detect | `auto` (default) | default | When you do not know what you will get |

Default features include JSON, syslog, EVTX, and plain text. logfmt, CEF, and OTLP are feature-gated to keep the dependency surface small.

## JSON/NDJSON

JSON is the universal default. Each line is parsed as a single JSON object and evaluated as one event.

```bash
cat events.ndjson | rsigma engine eval -r rules/ --input-format json
hel run | rsigma engine daemon -r rules/ --input-format json
```

Fields are accessed both as flat keys (`"process.command_line"`) and as dot-notation paths (`process.command_line` -> `process.command_line` literal, then fallback to nested `{"process": {"command_line": "..."}}`). The flat key takes priority when both are present.

Use `--jq` or `--jsonpath` to extract events from inside an envelope:

```bash
rsigma engine eval -r rules/ --jq '.records[]' < envelope.ndjson
rsigma engine eval -r rules/ --jsonpath '$.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'
```

For full event extraction details and array-unwrap semantics, see [Evaluating Rules](evaluating-rules.md#event-extraction-with-jq-and-jsonpath).

## Syslog

Both RFC 3164 (BSD) and RFC 5424 are supported. The parser produces a flat key/value map with fields like `facility`, `severity`, `hostname`, `appname`, `procid`, `msgid`, `message`. Custom structured-data elements from RFC 5424 become keys with their identifier as prefix.

```bash
tail -f /var/log/syslog | rsigma engine eval -r rules/ --input-format syslog
```

### Timezone handling

RFC 3164 syslog does not carry a timezone. RSigma assumes UTC by default. Override with `--syslog-tz`:

```bash
tail -f /var/log/syslog | rsigma engine eval -r rules/ --input-format syslog --syslog-tz +05:30
```

The value is a fixed offset (`+0530`, `-0800`). For ambiguity-free parsing, prefer RFC 5424 sources that carry the offset inline.

### Auto-detect validation

When `--input-format auto`, RSigma's syslog detection requires the line to parse cleanly with a facility, severity, and hostname before accepting. Random text that happens to begin with a number does not get misparsed.

## logfmt (feature-gated)

`logfmt` is the `key=value key="quoted value"` format used by Go services. Hand-rolled parser, zero external dependencies, supports escaped quotes and bare keys.

```bash
rsigma engine eval -r rules/ --input-format logfmt < app.log
```

Build with the `logfmt` feature:

```bash
cargo install --locked rsigma --features logfmt
```

Auto-detect does not consider logfmt because the format is ambiguous against plain text. Pass `--input-format logfmt` explicitly.

## CEF/ArcSight (feature-gated)

[Common Event Format](https://en.wikipedia.org/wiki/Common_Event_Format) is the ArcSight-style pipe-delimited header plus key/value extensions. Hand-rolled parser handles the full spec including `\=`, `\n`, `\\` escapes, and CEF wrapped in syslog (the parser locates the `CEF:0|` start automatically).

```bash
rsigma engine eval -r rules/ --input-format cef < arcsight.log
```

The parser produces:

- `cef.version`, `cef.device_vendor`, `cef.device_product`, `cef.device_version`, `cef.signature_id`, `cef.name`, `cef.severity` (the seven header fields).
- Every extension key/value pair as a top-level field.

Build with the `cef` feature:

```bash
cargo install --locked rsigma --features cef
```

## EVTX (Windows Event Log, feature-gated)

EVTX files are the binary Windows Event Log format. RSigma parses them directly without converting to XML first.

```bash
rsigma engine eval -r rules/ -e @security.evtx
rsigma engine eval -r rules/ -e @C:\Windows\System32\winevt\Logs\Security.evtx
```

Detection happens automatically by file extension. Any `@file` argument ending in `.evtx` (case-insensitive) is routed through the EVTX reader. Records are yielded as JSON in the **nested shape** produced by the `evtx` crate (which mirrors the original Windows XML structure):

```json
{
  "Event": {
    "System": {
      "Provider": { "#attributes": { "Name": "Microsoft-Windows-Security-Auditing", "Guid": "..." } },
      "EventID": 4624,
      "Channel": "Security",
      "Computer": "WIN-HOST-01",
      "TimeCreated": { "#attributes": { "SystemTime": "2016-07-08T18:12:51.681640Z" } }
    },
    "EventData": {
      "SubjectUserName": "SYSTEM",
      "TargetUserName": "Administrator",
      "LogonType": 3
    }
  }
}
```

Sigma rules must reference fields by their full dotted path, not by the flat Sigma-Windows-convention names:

```yaml
detection:
    sel:
        Event.System.EventID: 4624
        Event.EventData.TargetUserName: 'Administrator'
    condition: sel
```

If you would rather write rules against the conventional flat names (`EventID`, `Channel`, `TargetUserName`, etc.), supply a pipeline that maps the nested paths to the flat ones with `field_name_mapping`. The builtin `sysmon` and `ecs_windows` pipelines do **not** do this flattening; they map the flat schema to either Sysmon's `EventID` routing or to Elastic Common Schema. They are useful once you have already-flat events (for example, when an agent ingests EVTX and emits ECS), not for raw `.evtx` files.

Build with the `evtx` feature (on by default):

```bash
cargo install --locked rsigma --features evtx
```

EVTX is read in streaming mode, so the file can be larger than memory. Records are evaluated one at a time and a `Processed N EVTX records, M matches.` summary lands on stderr at the end.

EVTX is only supported through the `@file` syntax. There is no `--input-format evtx` for stdin, since the format is binary and stdin streaming would not interact well with the chunked record layout.

## OTLP (daemon only, feature-gated)

OpenTelemetry Protocol log ingestion is wired into the daemon's API server, not the `--input` flag. Agents POST to `/v1/logs` over HTTP (protobuf or JSON, optionally gzipped) or call the gRPC `LogsService/Export` on the same port.

```bash
rsigma engine daemon -r rules/ --input http --api-addr 0.0.0.0:9090
```

When the daemon is built with `daemon-otlp`, the OTLP endpoints are always active regardless of `--input`. You can pair OTLP ingestion with NATS or stdin input on the same daemon.

```bash
curl -X POST http://localhost:9090/v1/logs \
    -H 'Content-Type: application/x-protobuf' \
    --data-binary @export_logs_request.pb

curl -X POST http://localhost:9090/v1/logs \
    -H 'Content-Type: application/json' \
    -d '{"resourceLogs":[...]}'
```

LogRecord fields are flattened into a JSON event:

- `timestamp` from `time_unix_nano`, ISO 8601.
- `observed_timestamp` from `observed_time_unix_nano`.
- `severity_text`, `severity_number` preserved as-is.
- `body` from the LogRecord body (string, map, or array).
- `trace_id`, `span_id` as hex strings.
- `attributes.*` dot-flattened from `LogRecord.attributes`.
- `resource.*` dot-flattened from `Resource.attributes`.
- `scope.name`, `scope.version` from `InstrumentationScope`.

Key-value map bodies are flattened to top-level fields so a Sigma rule against `EventID` works against an OTLP log whose `body` is `{"EventID": 4625, ...}`.

Build with `daemon-otlp`:

```bash
cargo install --locked rsigma --features daemon-otlp
```

For agent configurations (Alloy, Vector, Fluent Bit, OpenTelemetry Collector), see [OTLP Integration](otlp-integration.md).

## Plain text

The fallback. Each line wraps as a `PlainEvent` that supports keyword-only matching. Use this when your inputs are unstructured log lines and rules use field-less `keywords:` blocks.

```bash
rsigma engine eval -r rules/ --input-format plain < unstructured.log
```

Plain text is the fastest format because there is no structured parsing. Lines are evaluated against rules that use keyword detection only; rules with field-based selections never match plain text events because there are no fields to match against.

## Auto-detect

The default. Each line is tried as JSON, then as syslog, then falls back to plain text:

```bash
rsigma engine eval -r rules/ < mixed.log
rsigma engine daemon -r rules/ --input-format auto
```

Auto-detect adds roughly 1 microsecond of overhead per line for the format probe. For homogeneous high-volume streams, explicitly specifying `--input-format json` (or whatever your source produces) avoids that overhead and prevents ambiguous lines from being misclassified.

logfmt and CEF are not part of the auto-detect chain because they overlap too much with arbitrary plain text. Pass them explicitly.

## Timestamp extraction

Correlation windows need a timestamp. RSigma tries a configurable list of fields in order, taking the first non-empty value that parses. The default list:

1. `@timestamp` (ECS, Elastic-style)
2. `timestamp`
3. `EventTime` (Sysmon)
4. `TimeCreated` (Windows Event Log)
5. `eventTime` (Okta, AWS CloudTrail)

Prepend your own with `--timestamp-field` (repeatable):

```bash
rsigma engine daemon -r rules/ --timestamp-field time --timestamp-field _ts
```

Or set the engine-level default in a pipeline with `set_custom_attribute`:

```yaml
transformations:
  - id: my_timestamp
    type: set_custom_attribute
    attribute: rsigma.timestamp_field
    value: time
```

### Accepted formats

| Format | Example |
|--------|---------|
| RFC 3339 | `2026-05-15T14:30:00Z`, `2026-05-15T14:30:00+02:00` |
| ISO 8601 without zone | `2026-05-15T14:30:00`, `2026-05-15T14:30:00.123` |
| Space-separated | `2026-05-15 14:30:00` |
| Epoch seconds | `1747315800` |
| Epoch milliseconds | `1747315800000` (auto-detected when value > 10^12) |

When an event has no parseable timestamp, the correlation engine falls back to the wall clock by default. Pass `--timestamp-fallback skip` to instead drop the event from correlation state updates (detections still fire). The `skip` mode is the right choice for forensic replay of historical data, where wall-clock substitution would corrupt the temporal windows.

## When to use which format

| Situation | Pick |
|-----------|------|
| Modern application logs | JSON, with `--jq '.event'` if wrapped |
| Sysmon, Winlogbeat, ECS-shaped events | JSON, often paired with the `ecs_windows` builtin pipeline |
| Offline forensics on an EVTX file | `@file.evtx` |
| Cisco / Palo Alto / network appliance | syslog |
| ArcSight, McAfee export | CEF (`--features cef`) |
| Go service writing `key=value` logs | logfmt (`--features logfmt`) |
| OTel-instrumented service | OTLP via `/v1/logs` |
| Don't know yet | `auto` |
| Highest throughput, fields are guaranteed | `json` explicitly (no auto-detect overhead) |
| Keyword search on free-form text | `plain` |

## See also

- [Evaluating Rules](evaluating-rules.md) for event extraction with `--jq`/`--jsonpath`.
- [Streaming Detection](streaming-detection.md) for daemon input modes and back-pressure tuning.
- [OTLP Integration](otlp-integration.md) for the agent configurations on the producer side.
- [Feature Flags reference](../reference/feature-flags.md) for the `logfmt`, `cef`, `evtx`, `daemon-otlp` feature gates.
- [Custom Attributes reference](../reference/custom-attributes.md) for the timestamp-field override.
