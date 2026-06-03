# Kafka Streaming

rsigma supports [Apache Kafka](https://kafka.apache.org/) as both an input source and output sink, enabling streaming detection over Kafka topics with at-least-once delivery guarantees.

## Feature Gate

Kafka support requires the `daemon-kafka` feature:

```bash
cargo build --features daemon-kafka
```

## URL Scheme

Input and output use the `kafka://` URL scheme:

```
kafka://<bootstrap-servers>/<topics>
```

Examples:

```bash
# Single topic
--input kafka://localhost:9092/security-events

# Multiple topics (comma-separated)
--input kafka://broker1:9092,broker2:9092/events,alerts

# Regex pattern for multi-tenant fan-in
--input kafka://broker:9092/^tenant-.*

# Output to a single topic
--output kafka://broker:9092/detections
```

## Quick Start

```bash
rsigma engine daemon \
  --rules ./rules/ \
  --input kafka://localhost:9092/events \
  --output kafka://localhost:9092/detections \
  --kafka-group-id rsigma-prod
```

## Consumer Groups

Multiple daemon instances using the same `--kafka-group-id` automatically load-balance across topic partitions via Kafka's consumer group protocol:

```bash
# Instance 1
rsigma engine daemon --input kafka://brokers/events --kafka-group-id rsigma-cluster

# Instance 2 (same group = shared workload)
rsigma engine daemon --input kafka://brokers/events --kafka-group-id rsigma-cluster
```

## Authentication

### SASL/PLAIN over SSL (Confluent Cloud, MSK)

```bash
rsigma engine daemon \
  --input kafka://pkc-xxxxx.us-east-1.aws.confluent.cloud:9092/events \
  --kafka-security-protocol SASL_SSL \
  --kafka-sasl-mechanism PLAIN \
  --kafka-sasl-username "$KAFKA_SASL_USERNAME" \
  --kafka-sasl-password "$KAFKA_SASL_PASSWORD"
```

### SASL/SCRAM over SSL

```bash
rsigma engine daemon \
  --input kafka://broker:9092/events \
  --kafka-security-protocol SASL_SSL \
  --kafka-sasl-mechanism SCRAM-SHA-256 \
  --kafka-sasl-username "$KAFKA_SASL_USERNAME" \
  --kafka-sasl-password "$KAFKA_SASL_PASSWORD" \
  --kafka-ssl-ca-cert /etc/kafka/ca.pem
```

### Mutual TLS (mTLS)

```bash
rsigma engine daemon \
  --input kafka://broker:9092/events \
  --kafka-security-protocol SSL \
  --kafka-ssl-ca-cert /etc/kafka/ca.pem \
  --kafka-ssl-cert /etc/kafka/client.pem \
  --kafka-ssl-key /etc/kafka/client-key.pem
```

## At-Least-Once Delivery

Consumer offsets are committed only after successful processing and sink delivery. If the daemon crashes before committing, Kafka redelivers the message on next startup. This matches the same at-least-once guarantee provided by the NATS integration.

The consumer always uses manual commit (`enable.auto.commit=false`).

## Offset Reset

Control where the consumer starts when no committed offset exists:

```bash
--kafka-offset-reset earliest   # Process all available messages (default)
--kafka-offset-reset latest     # Skip history, only new messages
```

## Multi-Tenant Streaming

Combine Kafka regex subscriptions with rsigma's tenant-aware correlation:

```bash
rsigma engine daemon \
  --input "kafka://broker:9092/^tenant-.*" \
  --tenant-field tenant_id \
  --missing-tenant reject \
  --kafka-group-id rsigma-multi-tenant
```

Each topic matching `^tenant-.*` feeds events into the engine. The `--tenant-field` isolates correlation state per tenant, preventing cross-tenant window contamination.

## Configuration File

Non-secret Kafka settings can be placed in `rsigma.yaml`:

```yaml
daemon:
  kafka:
    consumer_group: rsigma-prod
    security_protocol: SASL_SSL
    sasl_mechanism: SCRAM-SHA-256
    ssl_ca_cert: /etc/kafka/ca.pem
    offset_reset: earliest
    session_timeout_ms: 30000
```

Secrets (SASL username/password) must use environment variables or CLI flags:

| Variable | Flag |
|----------|------|
| `KAFKA_BOOTSTRAP_SERVERS` | `--kafka-bootstrap-servers` |
| `KAFKA_GROUP_ID` | `--kafka-group-id` |
| `KAFKA_SECURITY_PROTOCOL` | `--kafka-security-protocol` |
| `KAFKA_SASL_MECHANISM` | `--kafka-sasl-mechanism` |
| `KAFKA_SASL_USERNAME` | `--kafka-sasl-username` |
| `KAFKA_SASL_PASSWORD` | `--kafka-sasl-password` |

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--kafka-bootstrap-servers` | — | Kafka broker addresses (comma-separated) |
| `--kafka-group-id` | `rsigma` | Consumer group ID |
| `--kafka-security-protocol` | — | `PLAINTEXT`, `SSL`, `SASL_PLAINTEXT`, `SASL_SSL` |
| `--kafka-sasl-mechanism` | — | `PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512` |
| `--kafka-sasl-username` | — | SASL username |
| `--kafka-sasl-password` | — | SASL password |
| `--kafka-ssl-ca-cert` | — | Path to CA certificate |
| `--kafka-ssl-cert` | — | Path to client certificate (mTLS) |
| `--kafka-ssl-key` | — | Path to client private key (mTLS) |
| `--kafka-offset-reset` | `earliest` | `earliest` or `latest` |

## Limitations

- **Multi-partition ordering**: Events from different partitions have no ordering guarantee. Correlation windows handle this correctly via timestamp-based windowing, but events arriving out-of-order may see slightly different aggregation boundaries.
- **Regex topic discovery**: New topics matching a regex pattern are discovered via metadata refresh (default: every 5 minutes via `topic.metadata.refresh.interval.ms`).
- **Sink single topic**: The output sink publishes to exactly one topic. Use fan-out (`--output kafka://a --output kafka://b`) for multiple output topics.
