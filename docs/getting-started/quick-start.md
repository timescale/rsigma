# Quick Start

This page gets you from a fresh install to a fired detection in five minutes. We will write one Sigma rule, evaluate it against a JSON event, then run RSigma as a streaming daemon that hot-reloads when the rule changes.

If you have not installed RSigma yet, follow [Installation](installation.md) first.

## 1. Write your first rule

Create a directory for rules and a single rule file:

```bash
mkdir -p rules
cat > rules/whoami.yml <<'EOF'
title: Suspicious whoami invocation
id: 8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a
status: experimental
description: Flags any process that runs the whoami binary.
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
tags:
    - attack.discovery
    - attack.t1033
EOF
```

This is the minimum useful Sigma rule. `selection` matches the `CommandLine` field with a case-insensitive substring; `condition: selection` activates that selection.

!!! tip "New to Sigma?"
    SigmaHQ maintains the canonical documentation for writing rules. Start with the [Getting Started guide](https://sigmahq.io/docs/guide/getting-started.html), then deep-dive into [rule structure](https://sigmahq.io/docs/basics/rules.html), [field modifiers](https://sigmahq.io/docs/basics/modifiers.html), [condition expressions](https://sigmahq.io/docs/basics/conditions.html), and [log sources](https://sigmahq.io/docs/basics/log-sources.html). The full [Sigma v2.1.0 specification](https://sigmahq.io/sigma-specification/) is the authoritative reference. Everything you write against the spec works in RSigma.

## 2. Evaluate a single event

RSigma writes detection matches to **stdout** as JSON, and progress messages to **stderr** as plain text. Run:

```bash
rsigma engine eval --pretty -r rules/ -e '{"CommandLine": "cmd /c whoami"}'
```

You should see a `MatchResult` like this on stdout:

```json
{
  "rule_title": "Suspicious whoami invocation",
  "rule_id": "8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a",
  "level": "medium",
  "tags": [
    "attack.discovery",
    "attack.t1033"
  ],
  "matched_selections": [
    "selection"
  ],
  "matched_fields": [
    {
      "field": "CommandLine",
      "value": "cmd /c whoami"
    }
  ]
}
```

Stderr is just `Loaded 1 rules from rules/`. The `event` field of `MatchResult` is only populated when `--include-event` is set; every other field is always present.

`--pretty` is great while you are exploring. Drop it to get the compact one-line form used in production:

```bash
rsigma engine eval -r rules/ -e '{"CommandLine": "cmd /c whoami"}'
```

```json
{"rule_title":"Suspicious whoami invocation","rule_id":"8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a","level":"medium","tags":["attack.discovery","attack.t1033"],"matched_selections":["selection"],"matched_fields":[{"field":"CommandLine","value":"cmd /c whoami"}]}
```

A non-matching event writes nothing to stdout, prints `No matches.` to stderr, and exits 0:

```bash
rsigma engine eval -r rules/ -e '{"CommandLine": "powershell.exe -enc ..."}'
```

## 3. Stream events from stdin

The same command reads NDJSON from stdin when `--event` is omitted. Each line is parsed as a JSON object and evaluated independently.

```bash
cat <<'EOF' | rsigma engine eval -r rules/
{"CommandLine": "cmd /c whoami"}
{"CommandLine": "dir C:\\Users"}
{"CommandLine": "whoami /all"}
EOF
```

Two of the three lines match. RSigma emits one JSON line per match on stdout, dropping the non-matching line silently so the output stays safe for direct piping into downstream tools:

```json
{"rule_title":"Suspicious whoami invocation","rule_id":"8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a","level":"medium","tags":["attack.discovery","attack.t1033"],"matched_selections":["selection"],"matched_fields":[{"field":"CommandLine","value":"cmd /c whoami"}]}
{"rule_title":"Suspicious whoami invocation","rule_id":"8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a","level":"medium","tags":["attack.discovery","attack.t1033"],"matched_selections":["selection"],"matched_fields":[{"field":"CommandLine","value":"whoami /all"}]}
```

Stderr closes with a `Processed 3 events, 2 matches.` summary.

## 4. Lint and validate the rule

`rule lint` checks the rule against 66 Sigma spec checks. By default, only a summary line is printed:

```bash
rsigma rule lint rules/
```

```text
────────────────────────────────────────────────────────────
Checked 1 file(s): 1 passed, 0 failed (0 error(s), 0 warning(s), 1 info(s))
```

`--verbose` shows each finding with its rule ID and location, useful when investigating informational findings or copy-pasting a path:

```bash
rsigma rule lint rules/ -v
```

```text
rules/whoami.yml
  info[missing_author]: missing recommended field 'author'
    --> /author

────────────────────────────────────────────────────────────
Checked 1 file(s): 1 passed, 0 failed (0 error(s), 0 warning(s), 1 info(s))
```

`rule validate` parses, compiles, and reports counts without running matchers, which is the safest gate for CI:

```bash
rsigma rule validate rules/ -v
```

```text
Parsed 1 documents from rules/
  Detection rules:   1
  Correlation rules: 0
  Filter rules:      0
  Parse errors:      0
  Compiled OK:       1
  Compile errors:    0
```

Both commands return [structured exit codes](../reference/exit-codes.md) so they slot into CI without parsing stdout. `lint --fix` will apply safe auto-fixes for 13 of the 68 rules.

## 5. Run as a streaming daemon

For continuous detection with hot-reload, metrics, and a management API, run RSigma as a daemon. With `--input http`, the daemon accepts NDJSON events over an HTTP endpoint instead of reading stdin:

```bash
rsigma engine daemon -r rules/ --input http --api-addr 127.0.0.1:9090 &
```

Loopback (`127.0.0.0/8`, `::1`) keeps plaintext for local development. When you move to a production bind such as `--api-addr 0.0.0.0:9090`, the daemon (built with the `daemon-tls` feature) refuses to start without either `--tls-cert`/`--tls-key` or an explicit `--allow-plaintext`. See [TLS termination](../reference/security.md#tls-termination-for-the-api-listener) for the full story.

The daemon logs structured JSON to stderr while it starts. Detections are written to stdout as they fire. In another terminal (or after `&` returns control), send an event:

```bash
curl -sS -X POST http://127.0.0.1:9090/api/v1/events \
  -H 'Content-Type: application/x-ndjson' \
  --data '{"CommandLine":"whoami /priv"}'
```

`curl` reports `{"accepted":1}`, and a matching detection appears on the daemon's stdout almost immediately:

```json
{"rule_title":"Suspicious whoami invocation","rule_id":"8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a","level":"medium","tags":["attack.discovery","attack.t1033"],"matched_selections":["selection"],"matched_fields":[{"field":"CommandLine","value":"whoami /priv"}]}
```

While the daemon is running, edit `rules/whoami.yml`. The file watcher reloads rules within 500 ms and re-emits detections against subsequent events. The management endpoints expose health, status, and Prometheus metrics:

```bash
curl -sS http://127.0.0.1:9090/healthz
```

```json
{"status":"ok"}
```

```bash
curl -sS http://127.0.0.1:9090/api/v1/status
```

```json
{"status":"running","detection_rules":1,"correlation_rules":0,"correlation_state_entries":0,"events_processed":1,"detection_matches":1,"correlation_matches":0,"uptime_seconds":0.57}
```

```bash
curl -sS http://127.0.0.1:9090/metrics | head -n 5
```

```text
# HELP rsigma_back_pressure_events_total Times a source was blocked on a full event channel
# TYPE rsigma_back_pressure_events_total counter
rsigma_back_pressure_events_total 0
# HELP rsigma_batch_size Number of events processed per batch
# TYPE rsigma_batch_size histogram
```

The metrics endpoint exposes 27 labeled counters, gauges, and histograms covering input, detection, correlation, and dynamic sources. Per-rule labels make Grafana alerting straightforward:

```text
rsigma_detection_matches_by_rule_total{level="medium",rule_title="Suspicious whoami invocation"} 1
```

See [Prometheus metrics](../reference/metrics.md) for the full catalog and the [streaming detection guide](../guide/streaming-detection.md) for hot-reload internals, state persistence, and the rest of the HTTP API.

When you are done, stop the backgrounded daemon with `kill %1` (or your shell's job-control equivalent). It catches `SIGINT` and `SIGTERM` and shuts down cleanly after draining the in-flight events.

## 6. Convert the rule to PostgreSQL

`rsigma backend convert` turns the same rule into a backend-native query for historical hunting:

```bash
rsigma backend convert rules/ -t postgres
```

```sql
SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'
```

Five PostgreSQL output formats are available (default, `view`, `timescaledb`, `continuous_aggregate`, `sliding_window`), and a `lynxdb` target is also shipped. Drop the SQL into psql, a view definition, or a TimescaleDB continuous aggregate without further translation. The [rule conversion guide](../guide/rule-conversion.md) walks through every format.

## What next

You have used RSigma in three modes:

- One-shot evaluation with `engine eval`.
- Continuous streaming detection with `engine daemon`.
- Query generation with `backend convert`.

From here, pick the path that matches your work:

- **Detection engineers**: [linting rules](../guide/linting-rules.md), [CI/CD](../guide/ci-cd.md), [processing pipelines](../guide/processing-pipelines.md).
- **Platform engineers**: [streaming detection](../guide/streaming-detection.md), [NATS](../guide/nats-streaming.md), [OTLP integration](../guide/otlp-integration.md).
- **Threat hunters**: [evaluating rules](../guide/evaluating-rules.md), [input formats](../guide/input-formats.md), [EVTX files](../guide/input-formats.md#evtx-windows-event-log-feature-gated).
- **Library users**: [embedding the crates](../library/index.md).

If anything in this quick start did not work, run the [quick-verification checklist](../guide/observability.md#quick-verification) (log filter targets, `/healthz` / `/readyz`, `/metrics` smoke check) or [open an issue](https://{{ rsigma.repo_url | replace("https://", "") }}/issues).
