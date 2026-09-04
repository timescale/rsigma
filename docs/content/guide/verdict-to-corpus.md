# Verdict-Driven Corpora

When an analyst records a disposition, the admitted detection events behind that incident are useful regression evidence. True-positive and benign-true-positive verdicts become a corpus that [`rule backtest`](../cli/rule/backtest.md) can replay. False-positive verdicts become input for [`rule tune --from-dispositions`](../cli/rule/tune.md).

The daemon does not keep those payloads on the incident summary. Verdict-driven capture is an opt-in, byte-bounded ring for detection results admitted by a `group_by` alert pipeline. Accepted dispositions enqueue one asynchronous bundle per original verdict. The ring is not an event store, is not queryable, and is not written to the SQLite state database.

## Scope

Capture is detection-only and `group_by`-only.

- Correlation results are rejected and counted as `unsupported_result_kind`.
- `group.mode: entity_graph` is rejected at startup because its UUID identity can merge.
- If dedup is configured, every `group.by` selector must also appear in `dedup.fingerprint`.
- Capture runs after inhibition and silencing, and before dedup, so muted events never become evidence while repeated admitted firings do.

Changing any `daemon.capture.*` key requires a restart. The setting is not hot-reloadable.

## Enable

Capture is off by default. Enabling it also requires dispositions, a `group_by` alert pipeline, and `daemon.capture.spool_dir`.

```yaml
daemon:
  dispositions:
    enabled: true
  capture:
    enabled: true
    spool_dir: /var/lib/rsigma/capture
```

```bash
rsigma engine daemon -r rules/ --alert-pipeline pipeline.yml --config rsigma.yaml --enable-dispositions --enable-capture
```

`--enable-capture` turns the feature on for one run. Bounds and `spool_dir` stay config-file-only under `daemon.capture`.

When capture is enabled, the engine retains detection event payloads internally even if you did not pass `--include-event`. Those payloads are stripped before sink delivery unless you independently requested `--include-event`.

## Bounds

Every limit must be greater than zero, and `max_event_bytes <= max_bytes_per_incident <= max_capture_bytes`. Oversized events are dropped whole. They are never truncated.

| Key | Default | Role |
|-----|---------|------|
| `max_captured_incidents` | `1000` | Open incidents held in the ring |
| `max_events_per_incident` | `1000` | Events retained per incident |
| `max_event_bytes` | `1MiB` | Encoded size of one event |
| `max_bytes_per_incident` | `16MiB` | Encoded size of one incident |
| `max_capture_bytes` | `256MiB` | Encoded size of the whole ring |
| `ttl` | `24h` | How long a ring generation is kept after last admission |
| `max_spool_bytes` | `10GiB` | Completed-bundle disk budget |
| `spool_queue_capacity` | `128` | In-flight spool jobs |

A bundle larger than `max_spool_bytes` fails before commit. Completed bundles are evicted oldest-first when a new write would exceed the disk budget. Ring occupancy is independent of disk retention.

## Bundle layout

One directory per original normalized disposition. The directory name is the SHA-256 hex digest of that identity, so paths never contain raw incident or fingerprint strings.

- `spool_dir/tp/<bundle_id>/` for `true_positive` and `benign_true_positive`
- `spool_dir/fp/<bundle_id>/` for `false_positive`

Each bundle contains:

- `corpus/events.ndjson`: bare captured event objects only
- `provenance/events.ndjson`: one line per event with `event_digest`, `captured_at`, `matches`, and the event
- `manifest.json`: format version, bundle id, kind (`detection_group_by`), verdict, scope, rule ids, counts, and creation time
- `expectations.yml` on TP/BTP bundles only: a complete document with `at_least: 1` per contributing detection rule and `corpus: events.ndjson`

Do not pass `spool_dir` itself to `rule backtest`. Backtest walks every file under `--corpus` as an event source.

## Commands

Replay a true-positive bundle:

```bash
rsigma rule backtest -r rules/ --corpus /var/lib/rsigma/capture/tp/<bundle_id>/corpus --expectations /var/lib/rsigma/capture/tp/<bundle_id>/expectations.yml
```

Tune from every represented detection rule in the spool:

```bash
rsigma rule tune -r rules/ --from-dispositions /var/lib/rsigma/capture
```

`--from-dispositions` conflicts with `--fp` and `--tp`. It reads only versioned bundles, selects events whose provenance `matches` contain the target rule, and fails if a rule has false-positive evidence and no true-positive protection set. Malformed bundles fail with the file path; nothing is skipped.

The daemon never edits the rules directory. Converting a TP bundle into an embedded `rsigma.exemplars` block stays a human review step.

## Corrections, restarts, and queue loss

Successful spooling does not remove the ring entry. It stays until TTL or ring eviction so a later corrected verdict can write a separate TP or FP bundle. A same-verdict retry is a no-op when the destination already exists.

A restart empties the in-memory ring. Verdicts on pre-restart incidents increment `rsigma_capture_spool_jobs_total{result="miss"}`. That is expected; raw events are not persisted to SQLite.

`POST /api/v1/dispositions` and pull-source ingest stay accepted even when spooling reports `miss` or `queue_full`. The ingest summary includes a `capture` array with `queued`, `exists`, `miss`, or `queue_full` for each original disposition that reached the spool hook.

## Authorization and data at rest

Raw captured events may contain PII, secrets, tokens, or customer payloads. Treat `spool_dir` as sensitive data at rest. There is no built-in redaction.

On Unix, spool directories are created as `0700` and files as `0600`. Staging lives under `spool_dir/.staging/`, paths refuse symlinks, and abandoned staging directories are removed at startup. Unsupported permission hardening is warned and documented.

When API authentication is enabled and capture is on, `POST /api/v1/dispositions` requires both `dispositions:write` and `capture:write`. The built-in `operator` role includes `capture:write`. Configured pull sources are trusted operator input and do not present a bearer token.

There is no API to read or search the ring or the spool.

## See also

- [Triage Feedback Loop](triage-feedback.md)
- [Alert Pipeline](alert-pipeline.md)
- [Rule Tuning](rule-tuning.md)
- [CLI: `engine daemon`](../cli/engine/daemon.md)
- [HTTP API: Dispositions](../reference/http-api.md#dispositions)
- [Security](../reference/security.md#verdict-driven-capture)
