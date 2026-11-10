---
description: "Ship Microsoft 365, Entra, GitHub, Okta, and OneLogin audit logs to RSigma with Vector, the OpenTelemetry Collector, or Grafana Alloy for Sigma detection."
---

# Identity and SaaS Recipes

{{ added "0.20.0" }}

Collection recipes for Microsoft 365 and Entra, GitHub, Okta, and OneLogin audit events. Each recipe gives Vector, OpenTelemetry Collector, and Grafana Alloy configs for delivering the source's native JSON to `rsigma engine daemon` with `--schema-routing`. Vector posts to `/api/v1/events` (`--input http`); the OTel Collector and Alloy use OTLP HTTP (`/v1/logs`), which needs the `daemon-otlp` feature (release archives include it). The [overview](cloud-collection-recipes.md) has the schema table and a combined daemon config.

## Microsoft 365 / Entra

The Office 365 Management Activity API emits unified audit log events with the common-schema fields `RecordType`, `Operation`, `CreationTime`, `Workload`, and `OrganizationId`. The classifier recognizes this raw shape (any `Workload`) as `m365_audit` and maps it to `product: m365, service: audit`, where SigmaHQ's native-field rules live.

SigmaHQ's `exchange`, `threat_detection`, and `threat_management` services are written against a separately normalized shape (`eventSource`, `eventName`, `status`), which are not Management Activity common-schema fields. RSigma does not ship a normalization pipeline for that shape, so raw Management Activity events are not classified into those services.

::: tabs

== tab "Vector"
```toml
[sources.m365]
type = http_server
address = "0.0.0.0:9002"

[sinks.rsigma]
inputs = ["m365"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/m365/*.json]
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

otelcol.receiver.filelog "m365" {
    include  = ["/var/log/m365/*.json"]
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

## GitHub Audit Log

The GitHub Audit Log API returns JSON with `action`, `actor`, `org`/`repo`, `created_at`, and `_document_id`.

::: tabs

== tab "Vector"
```toml
[sources.github]
type = http_server
address = "0.0.0.0:9003"

[sinks.rsigma]
inputs = ["github"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/github-audit/*.json]
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

otelcol.receiver.filelog "github" {
    include  = ["/var/log/github-audit/*.json"]
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

## Okta System Log

Okta System Log API events carry `eventType`, `actor`, `outcome.result`, and `published`.

::: tabs

== tab "Vector"
```toml
[sources.okta]
type = http_server
address = "0.0.0.0:9004"

[sinks.rsigma]
inputs = ["okta"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/okta/*.json]
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

otelcol.receiver.filelog "okta" {
    include  = ["/var/log/okta/*.json"]
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

## OneLogin Events API

OneLogin Events API records carry `event_type_id`, `account_id`, `created_at`, and `user_id`/`actor_user_id`.

::: tabs

== tab "Vector"
```toml
[sources.onelogin]
type = http_server
address = "0.0.0.0:9005"

[sinks.rsigma]
inputs = ["onelogin"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/onelogin/*.json]
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

otelcol.receiver.filelog "onelogin" {
    include  = ["/var/log/onelogin/*.json"]
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
