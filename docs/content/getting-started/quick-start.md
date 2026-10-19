# Quick Start

This guide walks through writing one Sigma rule, evaluating it against a JSON event, and running RSigma as a streaming daemon that reloads when the rule changes.

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

::: callout tip "New to Sigma?"
See [Core Concepts](concepts.md) for an RSigma-oriented overview, and the [SigmaHQ docs](https://sigmahq.io/docs/guide/getting-started.html) for rule authoring. Everything you write against the [Sigma v2.1.0 specification](https://sigmahq.io/sigma-specification/) works in RSigma.
:::

## 2. Evaluate a single event

RSigma writes detection matches to **stdout** as JSON, and progress messages to **stderr** as plain text. Run:

```bash
rsigma engine eval --pretty -r rules/ -e '{"CommandLine": "cmd /c whoami"}'
```

You should see an `EvaluationResult` like this on stdout:

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

Stderr prints `Loaded 1 rules from rules/`. Omit `--pretty` for the compact one-line form used in production. The `event` field is only populated when `--include-event` is set; every other field is always present.

A non-matching event writes nothing to stdout, prints `No matches.` to stderr, and exits 0:

```bash
rsigma engine eval -r rules/ -e '{"CommandLine": "powershell.exe -enc ..."}'
```

## 3. Stream events from stdin

The same command reads NDJSON from stdin when `--event` is omitted. Each line is parsed as a JSON object and evaluated independently:

```bash
cat <<'EOF' | rsigma engine eval -r rules/
{"CommandLine": "cmd /c whoami"}
{"CommandLine": "dir C:\\Users"}
{"CommandLine": "whoami /all"}
EOF
```

Two of the three lines match. RSigma emits one compact JSON line per match on stdout and drops non-matching lines, so the output is safe to pipe downstream. Stderr closes with `Processed 3 events, 2 matches.`

## 4. Run as a streaming daemon

For continuous detection, start the daemon with HTTP input. Detections go to stdout; startup logs go to stderr:

```bash
rsigma engine daemon -r rules/ --input http --api-addr 127.0.0.1:9090 &
```

Loopback binds keep plaintext and need no token for local development. Non-loopback binds require TLS (or `--allow-plaintext`) and authentication (or `--allow-unauthenticated`); see [Daemon network exposure](../reference/security.md#daemon-network-exposure).

In another terminal, send an event:

```bash
curl -sS -X POST http://127.0.0.1:9090/api/v1/events \
  -H 'Content-Type: application/x-ndjson' \
  --data '{"CommandLine":"whoami /priv"}'
```

`curl` reports `{"accepted":1}`, and a matching detection appears on the daemon's stdout:

```json
{"rule_title":"Suspicious whoami invocation","rule_id":"8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a","level":"medium","tags":["attack.discovery","attack.t1033"],"matched_selections":["selection"],"matched_fields":[{"field":"CommandLine","value":"whoami /priv"}]}
```

Edit `rules/whoami.yml` while the daemon is running: the file watcher reloads rules within 500 ms and applies them to subsequent events. Check that the process is healthy with `curl -sS http://127.0.0.1:9090/healthz` (expect `{"status":"ok"}`).

See the [streaming detection guide](../guide/streaming-detection.md) for the management API, Prometheus metrics, hot-reload internals, and state persistence. Stop the backgrounded daemon with `kill %1` (or your shell's job-control equivalent); it drains in-flight events on `SIGINT`/`SIGTERM`.

## 5. Convert the rule to PostgreSQL

`rsigma backend convert` turns the same rule into a backend-native query for historical hunting:

```bash
rsigma backend convert rules/ -t postgres
```

The command prints JSON; the SQL is in `queries[].query`:

```json
{
  "format": "default",
  "queries": [
    {
      "query": "SELECT * FROM security_events WHERE \"CommandLine\" ILIKE '%whoami%'",
      "rule_id": "8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a",
      "rule_title": "Suspicious whoami invocation"
    }
  ],
  "target": "postgres"
}
```

Other PostgreSQL formats (`view`, `timescaledb`, `continuous_aggregate`, `sliding_window`) and the `lynxdb` and `fibratus` targets are also available. The [rule conversion guide](../guide/rule-conversion.md) covers each one.

## What next

You have used RSigma in three modes:

- One-shot evaluation with `engine eval`.
- Continuous streaming detection with `engine daemon`.
- Query generation with `backend convert`.

To take one rule through drafting, testing, deployment, triage, tuning, measurement, and hunting, follow [Tutorial: The Detection Loop](../guide/detection-loop.md). Otherwise, pick the path that matches your work:

- **Detection engineers**: [linting rules](../guide/linting-rules.md), [CI/CD](../guide/ci-cd.md), [processing pipelines](../guide/processing-pipelines.md).
- **Platform engineers**: [streaming detection](../guide/streaming-detection.md), [NATS](../guide/nats-streaming.md), [OTLP integration](../guide/otlp-integration.md).
- **Threat hunters**: [evaluating rules](../guide/evaluating-rules.md), [input formats](../guide/input-formats.md), [EVTX files](../guide/input-formats.md#evtx-windows-event-log-feature-gated).
- **Library users**: [embedding the crates](../library/index.md).

If anything in this quick start did not work, see [Troubleshooting](troubleshooting.md), run the [quick-verification checklist](../guide/observability.md#quick-verification), or [open an issue](https://{{ rsigma.repo_url | replace("https://", "") }}/issues).
