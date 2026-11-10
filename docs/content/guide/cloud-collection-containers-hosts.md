---
description: "Ship Kubernetes audit logs, Docker events, and osquery results to RSigma with Vector, the OpenTelemetry Collector, or Grafana Alloy for Sigma detection."
---

# Container and Host Recipes

{{ added "0.20.0" }}

Collection recipes for Kubernetes audit logs, Docker events, and osquery results. Each recipe gives Vector, OpenTelemetry Collector, and Grafana Alloy configs for delivering the source's native JSON to `rsigma engine daemon` with `--schema-routing`. Vector posts to `/api/v1/events` (`--input http`); the OTel Collector and Alloy use OTLP HTTP (`/v1/logs`), which needs the `daemon-otlp` feature (release archives include it). The [overview](cloud-collection-recipes.md) has the schema table and a combined daemon config.

## Kubernetes Audit Log

Kubernetes audit events have `kind: Event`, `apiVersion: audit.k8s.io/`, `auditID`, `verb`, and `user.username`.

::: tabs

== tab "Vector"
### Option A: kube-apiserver sink

The kube-apiserver has a built-in audit webhook that forwards events in JSON. Forward to a Vector HTTP listener:

```toml
[sources.k8s]
type = http_server
address = "0.0.0.0:9006"

[sinks.rsigma]
inputs = ["k8s"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

### Option B: audit log file

Forward the audit log JSON file with a tailing file input:

```toml
[sources.k8s]
type = file
include = ["/var/log/kubernetes/audit.log"]
read_from = beginning
encoding = "ndjson"

[sinks.rsigma]
inputs = ["k8s"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/kubernetes/audit.log]
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

otelcol.receiver.filelog "k8s" {
    include  = ["/var/log/kubernetes/audit.log"]
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

## Docker Events

Docker events (`docker events --format json` or the API `events` endpoint) carry `Type`, `Action`, and `Actor`. The `docker_events` signature (specificity 70) uses these fields for recognition.

::: tabs

== tab "Vector"
```toml
[sources.docker]
type = docker_events
format = pretty

[sinks.rsigma]
inputs = ["docker"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

The native `docker` input (which taps into the Docker Engine API directly) may not capture all events the CLI `--format json` form does. Use the Docker Engine API's `/events` endpoint via `curl` or a dedicated library for full coverage.

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/docker/events.json]
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

Pipe `docker events --format json` into the file, or use a small sidecar that writes the Engine API `/events` stream as NDJSON.

== tab "Alloy"
```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "docker" {
    include  = ["/var/log/docker/events.json"]
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

## osquery

osquery sends result lines (one JSON per table query) to configured log destinations. Each result carries `name`, `action` (added/removed/snapshot), `hostIdentifier`, and `columns`.

::: tabs

== tab "Vector"
```toml
[sources.osquery]
type = file
include = ["/var/log/osquery/*.log"]
read_from = beginning

[sinks.rsigma]
inputs = ["osquery"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/osquery/*.log]
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

otelcol.receiver.filelog "osquery" {
    include  = ["/var/log/osquery/*.log"]
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
