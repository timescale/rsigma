# Cloud Collection Recipes

This page shows how common log shippers, such as Vector, OpenTelemetry (OTel), and Fluent Bit, deliver CloudTrail, Azure, GCP, M365, GitHub, Okta, OneLogin, Kubernetes audit, Docker, and osquery events in a structured JSON shape that [schema classification](../reference/schema-signatures.md) recognizes automatically, and which routing binding to use.

All examples target `rsigma engine daemon` with `--schema-routing` and `--schema-config`. Each recipe maps to one of the built-in schemas defined in [Schema Signatures](../reference/schema-signatures.md); no user-defined `schemas:` block is needed because every source ships as a built-in.

## Built-in schemas (quick reference)

| Schema | Signature name | Implied logsource |
|--------|---------------|-------------------|
| AWS CloudTrail | `aws_cloudtrail` | `aws / cloudtrail` |
| AWS VPC Flow Logs (JSON) | `aws_vpcflow` | `aws` + custom `{source: vpcflow}` |
| Azure Activity Logs | `azure_activitylogs` | `azure / activitylogs` |
| Azure Audit Logs | `azure_auditlogs` | `azure / auditlogs` |
| Azure SignIn Logs | `azure_signinlogs` | `azure / signinlogs` |
| GCP Cloud Audit | `gcp_audit` | `gcp / gcp.audit` |
| Microsoft 365 unified audit log | `m365_audit` | `m365 / audit` |
| GitHub Audit | `github_audit` | `github / audit` |
| Okta System Log | `okta_system_log` | `okta / okta` |
| OneLogin | `onelogin_events` | `onelogin / onelogin.events` |
| Kubernetes Audit | `k8s_audit` | custom `{platform: kubernetes, source: k8s.audit}` |
| Docker Events | `docker_events` | custom `{platform: docker, source: docker.events}` |
| osquery Result | `osquery_result` | custom `{platform: osquery, source: osquery.result}` |

## AWS CloudTrail

CloudTrail delivers JSON events with `eventVersion`, `eventSource`, `userIdentity`, and `eventID` — the four marker fields. Shippers just need to deliver the native JSON form.

### Vector

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

### OpenTelemetry

No native CloudTrail OTel collector; ship via the generic `file` input reading from the S3-retrieved JSON:

```yaml
receivers:
  filelog:
    include: [/var/log/cloudtrail/*.json]
    operator: parser
    parsers:
      json: {}
processors:
  batch: {}
exporters:
  http:
    endpoint: "http://localhost:8952/api/v1/events"
    compression: none
```

## Azure Event Hubs / Management Activity API

Azure emits JSON with a `category` field that determines the service (`activitylogs`, `signinlogs`, `auditlogs`). Shippers need only deliver each category as-is; the built-in schema classifier picks the right service from the `category` value.

### Vector

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

### OpenTelemetry

```yaml
receivers:
  azure/eventhub:
    connection_string: "<connection-string>"
    eventHubConsumer:
      consumerGroup: "$Default"
      partitionCount: 16
      offset: "-1"
processors:
  batch: {}
exporters:
  http:
    endpoint: "http://localhost:8952/api/v1/events"
```

## GCP Cloud Audit Logs

GCP Cloud Audit logs are `LogEntry` objects whose `protoPayload.@type` equals `type.googleapis.com/google.cloud.audit.AuditLog`. The built-in signature matches on the `@type` value alone (specificity 95).

SigmaHQ's `gcp.audit` rules reference fields under a `data.` prefix (for example `data.protoPayload.serviceName`), while a native Cloud Logging event carries them without it (`protoPayload.serviceName`). Use the `gcp_audit` pipeline to strip the `data.` prefix from rule field names so those rules match native events:

```bash
rsigma engine daemon -r rules/ -p gcp_audit --input http --schema-routing
```

### Vector

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

## Microsoft 365 / Entra

The Office 365 Management Activity API emits unified audit log events with the common-schema fields `RecordType`, `Operation`, `CreationTime`, `Workload`, and `OrganizationId`. The classifier recognizes this raw shape (any `Workload`) as `m365_audit` and maps it to `product: m365, service: audit`, where SigmaHQ's native-field rules live.

SigmaHQ's `exchange`, `threat_detection`, and `threat_management` services are written against a separately normalized shape (`eventSource`, `eventName`, `status`), which are not Management Activity common-schema fields. Routing those services requires a normalization pipeline that rsigma does not yet ship, so raw Management Activity events are not classified into them.

### Vector

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

## GitHub Audit Log

The GitHub Audit Log API returns JSON with `action`, `actor`, `org`/`repo`, `created_at`, and `_document_id`.

### Vector

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

## Okta System Log

Okta System Log API events carry `eventType`, `actor`, `outcome.result`, and `published`.

### Vector

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

## OneLogin Events API

OneLogin Events API records carry `event_type_id`, `account_id`, `created_at`, and `user_id`/`actor_user_id`.

### Vector

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

## Kubernetes Audit Log

Kubernetes audit events have `kind: Event`, `apiVersion: audit.k8s.io/`, `auditID`, `verb`, and `user.username`.

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

### Option B: kube-babel / kubectl

Forward the audit log JSON file to a tailing file input:

```toml
[sources.k8s]
type = file
include = ["/var/log/kubernetes/audit.log"]
read_from = beginning
encoding = "ndjson"
```

## Docker Events

Docker events (`docker events --format json` or the API `events` endpoint) carry `Type`, `Action`, and `Actor`. The `docker_events` signature (specificity 70) uses these fields for recognition.

### Vector

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

> **Note**: The native `docker` input (which taps into the Docker Engine API directly) may not capture all events the CLI `--format json` form does. Use the Docker Engine API's `/events` endpoint via `curl` or a dedicated library for full coverage.

## osquery

osquery sends result lines (one JSON per table query) to configured log destinations. Each result carries `name`, `action` (added/removed/snapshot), `hostIdentifier`, and `columns`.

### Vector

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

## A combined example

One daemon that ingests from all sources:

```toml
[daemon]
address = "0.0.0.0:8952"

input = { type = "http" }

schema_routing = true
schema_config = "/etc/rsigma/schema-routing.yml"

[sinks]
# Or use a file-based output for further processing.
engine_rules = "/etc/rsigma/rules/"
engine_pipelines = ["gcp_audit"]
```

`schema-routing.yml`:

```yaml
schemas: []
routing:
  on_unknown: warn
  default_pipelines: []
  bindings:
    # GCP AuditLog needs the field-mapping pipeline.
    - schema: gcp_audit
      pipelines: [gcp_audit]
      logsource:
        product: gcp
        service: gcp.audit
```

No `schemas:` entries are needed — every Cloud, SaaS, and Container source in this guide ships as a built-in. The only binding required is the `gcp_audit` pipeline mapping (since Sigma rules expect `gcp.audit.*` fields, not native `protoPayload.*`).