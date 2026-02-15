# rsigma-cli

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma-cli` is a command-line interface for parsing, validating, linting, and evaluating [Sigma](https://github.com/SigmaHQ/sigma) detection rules.

This binary is part of [rsigma].

## Installation

```bash
cargo install --path crates/rsigma-cli
```

## Quick Start

```bash
# Single event
rsigma eval -r path/to/rules/ -e '{"CommandLine": "cmd /c whoami"}'

# Stream NDJSON from stdin
cat events.ndjson | rsigma eval -r path/to/rules/

# With a processing pipeline for field mapping
rsigma eval -r rules/ -p pipelines/ecs.yml -e '{"process.command_line": "whoami"}'
```

## Subcommands

### `parse` — Parse a single rule

```bash
rsigma parse rule.yml            # print AST as JSON
rsigma parse rule.yml --pretty   # pretty-print (default)
```

### `validate` — Validate rules in a directory

```bash
rsigma validate path/to/rules/ -v              # verbose output
rsigma validate rules/ -p pipelines/ecs.yml    # validate with pipeline
```

### `lint` — Lint rules against the Sigma specification

```bash
rsigma lint path/to/rules/                     # lint all rules
rsigma lint path/to/rules/ -v                  # verbose (show passing files + info-only)
rsigma lint path/to/rules/ --schema default    # + JSON schema validation (downloads + caches)
rsigma lint rule.yml --schema my-schema.json   # local JSON schema
rsigma lint path/to/rules/ --color always      # force color (respects NO_COLOR)
rsigma lint rules/ --disable missing_description,missing_author  # suppress specific rules
rsigma lint rules/ --config my-lint.yml        # explicit config file
```

### `eval` — Evaluate events against rules

**Basic evaluation:**

```bash
# Single event
rsigma eval -r path/to/rules/ -e '{"CommandLine": "whoami"}'

# Stream NDJSON from stdin
cat events.ndjson | rsigma eval -r path/to/rules/

# With processing pipeline(s) — applied in priority order
rsigma eval -r rules/ -p sysmon.yml -p custom.yml -e '...'
```

**Event extraction (jq / JSONPath):**

```bash
# Unwrap nested payloads with jq syntax
rsigma eval -r rules/ --jq '.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'

# JSONPath (RFC 9535)
rsigma eval -r rules/ --jsonpath '$.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'

# Array unwrapping — yields one event per element
rsigma eval -r rules/ --jq '.records[]' -e '{"records":[{"CommandLine":"whoami"},{"CommandLine":"id"}]}'

# Stream with extraction
hel run | rsigma eval -r rules/ -p ecs.yml --jq '.event'
```

**Detection output:**

```bash
# Include the full matched event JSON in detection output
rsigma eval -r rules/ --include-event -e '{"CommandLine": "whoami"}'
```

**Correlation options:**

```bash
# Suppression — deduplicate correlation alerts within a time window
rsigma eval -r rules/ --suppress 5m -e @events.ndjson

# Action on fire — reset state after alert (default: alert)
rsigma eval -r rules/ --suppress 5m --action reset -e @events.ndjson

# Include full contributing events in correlation output (compressed in memory)
rsigma eval -r rules/ --correlation-event-mode full -e @events.ndjson

# Include lightweight event references (timestamp + ID) instead
rsigma eval -r rules/ --correlation-event-mode refs -e @events.ndjson

# Cap stored events per correlation window (default: 10)
rsigma eval -r rules/ --correlation-event-mode full --max-correlation-events 20 -e @events.ndjson

# Suppress detection output (only show correlation alerts)
rsigma eval -r rules/ --no-detections -e @events.ndjson

# Custom timestamp field for correlation windowing
rsigma eval -r rules/ --timestamp-field time -e @events.ndjson
```

### `condition` — Parse a condition expression

```bash
rsigma condition 'selection and not filter'
```

### `stdin` — Parse YAML from stdin

```bash
cat rule.yml | rsigma stdin
```

## License

MIT License.

[rsigma]: https://github.com/timescale/rsigma
