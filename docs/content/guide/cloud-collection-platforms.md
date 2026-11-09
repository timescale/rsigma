# Cloud Platform Recipes

{{ added "0.20.0" }}

Collection recipes for AWS CloudTrail, Azure, and GCP Cloud Audit Logs. Each recipe gives Vector, OpenTelemetry Collector, and Grafana Alloy configs for delivering the source's native JSON to `rsigma engine daemon` with `--schema-routing`. Vector posts to `/api/v1/events` (`--input http`); the OTel Collector and Alloy use OTLP HTTP (`/v1/logs`), which needs the `daemon-otlp` feature (release archives include it). The [overview](cloud-collection-recipes.md) has the schema table and a combined daemon config.

## AWS CloudTrail

CloudTrail delivers JSON events with `eventVersion`, `eventSource`, `userIdentity`, and `eventID`, the four marker fields. Shippers just need to deliver the native JSON form.

::: tabs

== tab "Vector"
```toml
[sources.cloudtrail]
type = aws_s3
acknowledgements.enabled = false
bucket.name = "cloudtrail-bucket"
bucket.region = "us-east-1"
format = {type = "ndjson", parse_from = "s3_key"}

[sinks.rsigma]
inputs = ["cloudtrail"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
No native CloudTrail OTel collector; ship via the generic `file` input reading from the S3-retrieved JSON:

```yaml
receivers:
  filelog:
    include: [/var/log/cloudtrail/*.json]
    operators:
      - type: json_parser
        parse_to: body
processors:
  batch: {}
exporters:
  otlphttp/rsigma:
    endpoint: "http://localhost:8952"
    compression: none
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [batch]
      exporters: [otlphttp/rsigma]
```

== tab "Alloy"
```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "cloudtrail" {
    include  = ["/var/log/cloudtrail/*.json"]
    start_at = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

Start Alloy with `--stability.level=public-preview` when using `otelcol.receiver.filelog`.

:::

## Azure Event Hubs / Management Activity API

Azure emits JSON with a `category` field that determines the service (`activitylogs`, `signinlogs`, `auditlogs`). Shippers need only deliver each category as-is; the built-in schema classifier picks the right service from the `category` value.

::: tabs

== tab "Vector"
```toml
[sources.azure_signin]
type = azure_event_hubs
connection_string = "<connection-string>"
topic = "insights-operationallogs"
partition_endpoint = "2021-04-01"

[sinks.rsigma]
inputs = ["azure_signin"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  azureeventhub:
    connection_string: "<connection-string>"
    storage: file_storage
processors:
  batch: {}
exporters:
  otlphttp/rsigma:
    endpoint: "http://localhost:8952"
    compression: none
service:
  pipelines:
    logs:
      receivers: [azureeventhub]
      processors: [batch]
      exporters: [otlphttp/rsigma]
```

== tab "Alloy"
No native Azure Event Hubs to OTLP component; read Event Hub-exported JSON from disk (or a puller that writes NDJSON) and forward:

```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "azure" {
    include  = ["/var/log/azure/*.json"]
    start_at = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

:::

## GCP Cloud Audit Logs

GCP Cloud Audit logs are `LogEntry` objects whose `protoPayload.@type` equals `type.googleapis.com/google.cloud.audit.AuditLog`. The built-in signature matches on the `@type` value alone (specificity 95).

SigmaHQ's `gcp.audit` rules reference fields under a `data.` prefix (for example `data.protoPayload.serviceName`), while a native Cloud Logging event carries them without it (`protoPayload.serviceName`). Use the shipped [`gcp_audit.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/pipelines/gcp_audit.yml) pipeline (path-only, not a builtin name) to strip the `data.` prefix from rule field names so those rules match native events.

For a GCP-only feed, apply the pipeline globally (schema routing is optional):

```bash
rsigma engine daemon -r rules/ -p crates/rsigma-eval/pipelines/gcp_audit.yml --input http --api-addr 127.0.0.1:8952
```

On a mixed stream with `--schema-routing`, bind the pipeline to the `gcp_audit` schema in `--schema-config` instead of relying on `-p` alone (see [A combined example](cloud-collection-recipes.md#a-combined-example)). With schema routing enabled and no bindings, every event falls through to `default_pipelines`, and a bare `-p` is not applied per schema.

::: tabs

== tab "Vector"
```toml
[sources.gcp_audit]
type = http_server
address = "0.0.0.0:9001"
method = POST
allowed_sources = ["127.0.0.1"]

[sinks.rsigma]
inputs = ["gcp_audit"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/gcp-audit/*.json]
    operators:
      - type: json_parser
        parse_to: body
processors:
  batch: {}
exporters:
  otlphttp/rsigma:
    endpoint: "http://localhost:8952"
    compression: none
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [batch]
      exporters: [otlphttp/rsigma]
```

== tab "Alloy"
```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "gcp_audit" {
    include  = ["/var/log/gcp-audit/*.json"]
    start_at = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

:::

## See also

- [Cloud Collection Recipes](cloud-collection-recipes.md) for the built-in schema table and a combined daemon config.
- [Schema Routing](schema-routing.md) for bindings, aliases, and schema-derived logsource pruning.
- [Schema Signatures](../reference/schema-signatures.md) for the built-in catalog and signature grammar.
- [OTLP Integration](otlp-integration.md) for `/v1/logs`, LogRecord flattening, and agent recipes.
