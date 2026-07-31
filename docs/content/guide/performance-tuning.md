# Performance Tuning

How fast RSigma evaluates depends on how much of your corpus the candidate index can prune. The index works from rule witnesses: necessary conditions, at least one of which must hold on any event the rule can match. Exact field values, substring needles, keywords, mandatory regex literals, and bare field presence all yield witnesses, so most of a real corpus is prunable and an event is only evaluated against the rules it could plausibly match. Rules whose conditions admit no witness, in practice the ones whose only required branch is negated, are evaluated against every event and cost time linear in their count. For each surviving rule, condition evaluation first computes only the boolean verdict, allowing `any` and threshold selectors to stop once decided; matched-selection details are collected only when the rule matches.

On the full SigmaHQ ruleset (~3,100 rules) expect roughly 19-66k events/s per core for offline `engine eval`, rising to 30-106k with `--logsource-routing`, and 88-287k end-to-end through the daemon (342-401k with routing) on a 12-core machine. Where a workload lands in those ranges depends on event shape: wide structured events are the slow end, narrowly tagged syslog the fast end. The [SigmaHQ corpus baseline](../benchmarks.md#sigmahq-corpus-baseline-representative) in Benchmarks documents the full matrix with before-and-after numbers. Small or exact-match-heavy rulesets are considerably faster still.

This page covers the cases where the defaults stop being optimal: very large rule sets, substring-heavy threat-intel feeds, high-throughput daemon ingestion, and memory-constrained deployments. For SigmaHQ-scale corpora the single biggest lever is `--logsource-routing`, which is also a correctness filter because it stops cross-product keyword false positives. `--cross-rule-ac` is no longer worth enabling alongside it: the candidate index already does that substring work over a smaller rule population, and layering the cross-rule automaton on top of routing costs 20-35% on every measured lane, offline and end-to-end. The daemon now batches up to 128 events by default, which gives `Engine::evaluate_batch` enough work to fan detection across rayon without requiring manual tuning. The bloom pre-filter (`--bloom-prefilter`) is off by default for a reason and should be benchmarked before flipping it on.

## Always-on: the matcher optimizer

Three rewrites run at rule-compile time, transparently. There is no flag to disable or configure them.

| Pass | What it does | Source |
|------|--------------|--------|
| `AhoCorasickSet` collapse | Any `AnyOf` group of 8+ `contains` matchers collapses into one Aho-Corasick automaton that scans the haystack in a single pass. Replaces O(N × haystack_len) sequential `str::contains` with O(haystack_len). | [`compiler/optimizer.rs`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/src/compiler/optimizer.rs) |
| `RegexSet` collapse | Any `AnyOf` group of 3+ `re` matchers collapses into a single `regex::RegexSet`. | same |
| `CaseInsensitiveGroup` wrapper | A group whose children are all case-insensitive lowers the haystack once via `ascii_lowercase_cow` and dispatches to the children via `matches_pre_lowered`. Removes the per-child `to_lowercase()` allocation. | same |

Threshold choices come from a Criterion sweep documented in the [Benchmarks](../benchmarks.md) page (8 patterns is where the sequential `str::contains` path with `memchr`/Two-Way SIMD acceleration loses to Aho-Corasick on typical haystacks). The compiler invariant is that these are pure rewrites: the optimized tree returns the same `bool` for the same event as the unoptimized tree.

Because the optimizer is part of compilation, a rule reload picks up any new pattern groupings automatically.

## Rule loading at scale

Loading a large rule corpus is no longer the bottleneck it was in v0.11.x. As of v0.12.0, `Engine::add_rule` and `Engine::add_compiled_rule` are amortized O(1) per call, and the bulk loaders (`Engine::add_rules`, `Engine::extend_compiled_rules`, `Engine::add_collection`) rebuild the candidate index and the per-field bloom filter exactly once per batch instead of once per rule.

| Loader | Single-rule cost | Batched cost | When you use it |
|--------|------------------|--------------|-----------------|
| `Engine::add_rule(rule)` | Amortized O(1) | n/a | Streaming rule ingestion (e.g. a control-plane that adds one rule at a time). |
| `Engine::add_compiled_rule(rule)` | Amortized O(1) | n/a | Same, but for pre-compiled rules. |
| `Engine::add_rules(iter)` | n/a | One index rebuild at the end | Library callers loading a batch with per-rule compile-error tolerance. |
| `Engine::add_collection(collection)` | n/a | One index rebuild at the end | `rsigma engine eval` and `rsigma engine daemon`'s rule load. |
| `Engine::extend_compiled_rules(iter)` | n/a | One index rebuild at the end | Hot-reload of a fully pre-compiled snapshot. |

Concrete numbers from the `rule_load` Criterion group on an Apple M4 Pro (release build):

| Rules   | `add_collection` | `add_rules` | `add_rule` loop |
|--------:|-----------------:|------------:|----------------:|
| 1,000   |          1.15 ms |     1.17 ms |         1.64 ms |
| 10,000  |         11.82 ms |    11.85 ms |        17.23 ms |
| 100,000 |        121.65 ms |   122.13 ms |       166.07 ms |

Reproduce with `cargo bench -p rsigma-eval --bench eval -- rule_load`. The full SigmaHQ corpus (~3,120 rules) loads in ~120 ms.

**How the bloom rebuild is amortized.** The per-field bloom uses a doubling watermark with a 64-rule floor. A full bloom rebuild only fires when the rule count has at least doubled past the last rebuild, capping false-positive-rate drift while keeping the amortized per-rule cost flat. Rules that introduce a brand-new indexed field get a fresh bloom on the fly. The differential test `append_rule_matches_build_verdicts` pins the property that incremental and batched indexes accept the same haystacks (with the documented MaybeMatch tolerance between rebuilds).

**Caveat: the cross-rule Aho-Corasick index falls back to a full rebuild on `add_rule`.** The daachorse automaton has no incremental update story, so if you enable `--cross-rule-ac` and then call `add_rule` in a loop, each call rebuilds the cross-rule AC. The batched loaders (`add_collection`, `add_rules`, `extend_compiled_rules`) keep the single-rebuild-at-end fast path. For very large rule sets with cross-rule AC on, always batch.

## Bloom pre-filter for substring-heavy rule sets

The bloom pre-filter is the right knob when:

- Most events do NOT match any rule.
- Your rules are dominated by positive substring needles (`|contains`, `|startswith`, `|endswith`, IOC lists).
- Per-event latency matters more than rule-load latency.

When enabled, the engine builds a per-field bloom filter at rule-load time over every positive substring needle. At eval time, `Engine::evaluate` short-circuits any positive substring detection item whose field value cannot possibly contain a needle trigram, skipping the matcher entirely.

```bash
rsigma engine eval -r rules/ --bloom-prefilter -e @events.ndjson
rsigma engine daemon -r rules/ --bloom-prefilter --bloom-max-bytes 2097152
```

| Flag | Default | When to change |
|------|---------|----------------|
| `--bloom-prefilter` | off | Substring-heavy IOC rule sets paired with mostly-non-matching telemetry. |
| `--bloom-max-bytes` | `1048576` (1 MiB) | Lower on memory-constrained deployments. Raise when the default starts evicting useful filters at very large rule counts. Has no effect unless `--bloom-prefilter` is also set. |

The trigram probe costs roughly 1 µs on a typical `CommandLine` field. On rule sets where most events overlap with at least one needle, that 1 µs is pure overhead and the bloom hurts throughput.

Always benchmark first. The `eval_bloom_rejection` Criterion group in `crates/rsigma-eval/benches/eval.rs` reports throughput with the bloom on and off on synthetic data; clone the corpus shape onto your own events before deciding.

## Cross-rule Aho-Corasick pre-filter

The cross-rule AC index is a feature-gated opt-in for very large rule sets (~5000+) dominated by shared substring patterns. Threat-intel feeds and IOC packs are the canonical case.

When enabled, the engine builds one per-field `DoubleArrayAhoCorasick` automaton ([daachorse](https://crates.io/crates/daachorse)) over every rule's positive substring needles. At eval time, the engine scans each indexed field once with that automaton and drops the AC-prunable rules from the candidate set when zero needles hit the event.

A rule is AC-prunable when:

1. It has at least one positive substring detection item.
2. Every detection consists exclusively of positive substring matchers (`Contains`, `StartsWith`, `EndsWith`, `AhoCorasickSet`, possibly nested under `AnyOf`/`AllOf`/`CaseInsensitiveGroup`).
3. The condition expression contains no `not`.

Rules with `Exact`, `Regex`, `Numeric`, or `Cidr` matchers, or with `not` selectors in their conditions, are kept in the candidate set unfiltered.

### Building with the feature

The flag is feature-gated. The default `cargo install rsigma` does NOT include it. Build or install with `daachorse-index`:

```bash
cargo install --locked rsigma --features daachorse-index
```

The released archives (`x86_64-unknown-linux-gnu.tar.gz` and friends) and the GHCR Docker image are built with `--all-features`, so they already include the flag. Run `rsigma engine eval --help | grep cross-rule-ac` to confirm.

```bash
rsigma engine eval -r rules/ --cross-rule-ac -e @events.ndjson
rsigma engine daemon -r rules/ --cross-rule-ac
```

### When it pays off

The published benchmark (`eval_cross_rule_ac` group, 200 non-matching events against pure-substring rules) shows the best-case win:

| Rules | Off (default) | On (`--cross-rule-ac`) | Speedup |
|-------|---------------|-------------------------|---------|
| 1,000 | 17.34 ms | 253 µs | ~68× |
| 5,000 | 85.51 ms | 883 µs | ~97× |
| 10,000 | 173.37 ms | 1.71 ms | ~101× |

Those numbers predate witness-based candidate indexing, which closed most of the gap the AC pass existed to close. On the measured SigmaHQ lanes, `--cross-rule-ac` now loses to `--logsource-routing` alone on every lane, and adding it on top of routing costs 27-35%. Treat it as a knob to benchmark on pure-substring corpora at 5,000+ rules rather than one to enable by default, and measure it against routing rather than against the bare default.

The pattern-count cap per field is 100,000; rules referencing fields above that cap are kept unfiltered.

## Daemon throughput knobs

These two only matter for the streaming daemon, not for `engine eval`.

| Flag | Default | Effect |
|------|---------|--------|
| `--buffer-size N` | `10000` | Bounded mpsc capacity for both source→engine and engine→sink queues. Higher values absorb burstier input; lower values apply back-pressure sooner. Watch `rsigma_back_pressure_events_total` to see whether the queues are filling. |
| `--batch-size N` | `128` | Maximum events per detection batch, capped at `--buffer-size`. The batch is the unit `Engine::evaluate_batch` fans across rayon. The published SigmaHQ baseline uses 512. |
| `RSIGMA_DETECT_INFLIGHT` | scales with rayon (1–5) | How many detection-only batches may evaluate at once when the rule set has no correlation rules. A sequence-numbered reducer restores sink/ack order. Correlation engines ignore this and stay at 1. Cap is 8. |

A typical high-throughput configuration:

```bash
rsigma engine daemon -r rules/ \
    --buffer-size 50000 \
    --batch-size 128
```

The daemon does not wait for a batch to fill: it blocks for the first event, then drains up to `--batch-size` events already waiting in the queue. A larger value therefore increases the maximum processing quantum rather than adding a batch-fill timer. Lower it when short bursts need the smallest tail latency, or raise it when sustained load and a large corpus justify more parallel work per lock acquisition. The effective value never exceeds `--buffer-size`; the published SigmaHQ baseline found 512 best on sustained load.

Formatted input parsing fans across the same rayon pool before engine evaluation. When there are no correlation rules, several batches may be in flight so one batch's serial merge can overlap another's rayon work; set `RSIGMA_DETECT_INFLIGHT=1` to force the older single-batch path. Correlation engines stay one batch at a time. Raising `RAYON_NUM_THREADS` beyond the physical performance-core count should not be expected to scale linearly. Use `rsigma_batch_phase_duration_seconds` (`parse`, `decode_merge`, `observe`, `evaluate`, `result_merge`, `dispatch`) to rank where batch time goes on your workload.

`--include-event` clones the complete input event into every detection result. Its cost scales with matches rather than inputs: the raw Windows baseline produces about 3 matches per event without routing and about 0.02 with routing, so measure this option on the actual match volume. The checked-in daemon matrix includes both forms, a match-heavy lane, and a handcrafted lane covering event-count, value-count, value-sum, and ordered-temporal correlations; the pinned SigmaHQ tree itself contains no correlation rules.

## Memory pressure and correlation state

Correlation state lives in memory unless `--state-db` writes periodic snapshots to SQLite. The hard cap is `max_state_entries`, default 100,000 `(correlation, group-key)` entries across all correlation rules, settable with `--max-state-entries` (or `daemon.correlation.max_state_entries` in the config file). When the cap is hit, the engine evicts the stalest 10% and emits a warning.

The cap bounds the number of groups, not the bytes within one. A single group's window state grows with `timespan` x event rate: 8 bytes per in-window event for `event_count`, 16 for the numeric aggregations (`value_sum`/`value_avg`/`value_percentile`/`value_median`), and roughly 32 bytes plus the value string for `value_count`. `--max-group-entries` (or the per-rule `rsigma.max_group_entries` custom attribute) caps that within-window growth; when a group exceeds it, the oldest entries are dropped, which can only under-count. Session windows always keep their oldest entry as the span anchor so truncation cannot silently extend the `timespan` cap. Unset means unbounded, the historical behavior. The measured shape (see [Benchmarks](../benchmarks.md#window-mode-memory-stress)): 1M unique session keys against the default cap peaked at 39.8 MiB, and a fully chatty `event_count` workload (100 groups sustaining 1 event/s through a 2h session cap) held 6.3 MiB. A live but quiet session group costs ~256 bytes, dominated by the group-key strings.

Window modes (`sliding`/`tumbling`/`session`) have identical per-event cost; they differ only in how long entries are retained. `tumbling` resets per-group state at each bucket boundary and is the cheapest under sustained load; `session` retains everything between the first event and the `timespan` cap, so it is the mode to watch on chatty groups.

Two workload shapes deserve attention:

- **`value_count` with high-cardinality values.** Every `(timestamp, value)` pair is retained for the window, and the distinct count is recomputed per event over the whole window — O(window size) per event. At 1,800 distinct values per window, measured throughput drops from ~1.1M to 63K events/s. CPU collapses before memory does. Prefer `event_count` where distinctness is not actually required, shorten the window, or set `--max-group-entries` to bound the retained pairs.
- **Group-key cardinality floods.** Under cap pressure the stalest groups are evicted first, so a burst of unique keys can push a slow-burning session out of state before it completes. The eviction warning in the log is the tripwire; raise `--max-state-entries` if the warning fires during legitimate traffic.

Watch:

- `rsigma_correlation_state_entries` (Prometheus gauge) — current size.
- `tracing` warnings tagged `rsigma_eval::correlation_engine` (the `correlation memory pressure` span) — eviction events.

Tune by:

- Lowering the per-correlation window (`timespan: 5m` instead of `1h`) so older state expires faster.
- Setting `--max-group-entries` (or `rsigma.max_group_entries` per-rule) to cap within-window growth on chatty groups, e.g. `value_count` rules over high-rate telemetry.
- Lowering `--max-state-entries` on memory-constrained deployments, or raising it when the eviction warning fires during legitimate high-cardinality traffic.
- Setting `--max-correlation-events 5` (or via `rsigma.max_correlation_events` per-rule) to cap the per-window event list.
- Setting `--correlation-event-mode refs` to store lightweight references instead of full event bodies. `refs` mode keeps timestamps and event IDs only; `full` retains the deflate-compressed event JSON. `none` (the default) keeps no events.

See [Evaluating Rules](evaluating-rules.md#correlation-in-eval-mode) for the matching `engine eval` flags and [Streaming Detection](streaming-detection.md#state-persistence) for the daemon's SQLite snapshot path.

## Benchmarking your own corpus

Criterion benchmarks live in [`crates/rsigma-eval/benches/eval.rs`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/benches/eval.rs) and [`crates/rsigma-runtime/benches/`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-runtime/benches). The full numbers ship in the [Benchmarks](../benchmarks.md) page.

Quick runs on a checkout:

```bash
# Pure eval throughput, single event
cargo bench -p rsigma-eval --bench eval -- eval_single_event

# Bloom on/off comparison
cargo bench -p rsigma-eval --bench eval -- eval_bloom_rejection

# Cross-rule AC on/off comparison
cargo bench -p rsigma-eval --features daachorse-index --bench eval -- eval_cross_rule_ac

# Streaming pipeline throughput
cargo bench -p rsigma-runtime --bench runtime_throughput

# Dynamic pipeline resolve cost (HTTP/file/command source + extract)
cargo bench -p rsigma-runtime --bench dynamic_pipelines
```

Replace the synthetic Criterion inputs with rules and events that mirror your own corpus. Both the bloom and cross-rule AC wins are workload-shaped: the published numbers above are the upper bound, not what you should expect on mixed data.

For an end-to-end measurement on a real corpus rather than synthetic inputs, `scripts/perf/fetch-fixtures.sh` pins the SigmaHQ ruleset and generates deterministic event lanes, and `scripts/perf/baseline-eval.sh` and `scripts/perf/daemon-matrix.sh` walk the flag matrix over them offline and through the daemon. Point them at your own rules and events to get the same table for your workload.

## Quick decision matrix

| Symptom | First thing to try |
|---------|--------------------|
| Eval latency too high on a SigmaHQ-scale corpus | `--logsource-routing`, provided your events carry `product`/`category`/`service` hints. |
| Eval latency still too high at 5k+ pure-substring rules | Benchmark `--cross-rule-ac` (needs the `daachorse-index` build) against routing alone; it usually loses. |
| Eval latency too high on substring-heavy rules with mostly-non-matching events | `--bloom-prefilter`. |
| Daemon queue depth (`rsigma_input_queue_depth`) climbing under load | Raise `--batch-size` to 64 or 128, then `--buffer-size` to absorb bursts. |
| `rsigma_correlation_state_entries` near 100k and growing | Shorter `timespan`, `--max-group-entries`, lower `max_correlation_events`, or `--correlation-event-mode refs`. Raise `--max-state-entries` if the traffic is legitimately high-cardinality. |
| `rsigma_back_pressure_events_total` increasing rapidly | Upstream input is faster than the engine. Raise `--batch-size`, scale horizontally with NATS consumer groups (see [NATS Streaming](nats-streaming.md#consumer-groups)), or shed load upstream. |
| Tail latency too high after raising `--batch-size` | Lower the batch size; the trade-off has reached the wrong side of the curve. |

## See also

- [Observability](observability.md) for the Prometheus metrics that surface every knob above (`rsigma_input_queue_depth`, `rsigma_back_pressure_events_total`, `rsigma_correlation_state_entries`, `rsigma_event_processing_seconds`).
- [Streaming Detection](streaming-detection.md) for daemon-level configuration around hot-reload, state, and back-pressure.
- [Evaluating Rules](evaluating-rules.md) for the corresponding `engine eval` flags.
- [Feature Flags reference](../reference/feature-flags.md) for `daachorse-index`, `evtx`, `logfmt`, `cef`, and `daemon-*` features.
- [Benchmarks](../benchmarks.md) for the full Criterion results across parser, evaluator, correlation engine, runtime, and dynamic pipelines.
- [`rsigma-eval/README.md`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/README.md) for the matcher optimizer, bloom, and cross-rule AC implementation notes.
