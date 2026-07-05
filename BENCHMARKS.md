# Benchmarks

Criterion benchmark results for the rsigma detection engine.

**Hardware**: Apple M4 Pro, macOS  
**Profile**: `bench` (optimized, release)  
**Date captured**: 2026-07-05  
**Captured on version**: 0.18.0 (main)

All suites below were rerun in full on the date above. To refresh for a specific release, check out the matching tag, run the commands in [Running](#running), and update the hardware/date/version block.

## Running

```bash
# All benchmarks across all crates
cargo bench

# Individual suites
cargo bench -p rsigma-parser --bench parse
cargo bench -p rsigma-eval --bench eval
cargo bench -p rsigma-eval --bench eval --features daachorse-index   # includes the cross-rule AC suite
cargo bench -p rsigma-eval --bench logsource
cargo bench -p rsigma-eval --bench schema
cargo bench -p rsigma-eval --bench routing
cargo bench -p rsigma-eval --bench array
cargo bench -p rsigma-eval --bench correlation
cargo bench -p rsigma-eval --bench correlation_memory   # peak-heap stress (not Criterion)
cargo bench -p rsigma-eval --bench result_serialize
cargo bench -p rsigma-runtime --bench runtime_throughput
cargo bench -p rsigma-runtime --bench input_formats --features logfmt,cef,evtx
cargo bench -p rsigma-runtime --bench otlp --features otlp
cargo bench -p rsigma-runtime --bench dynamic_pipelines
cargo bench -p rsigma-runtime --bench enrichment
cargo bench -p rsigma-runtime --bench alert_pipeline
cargo bench -p rsigma-runtime --bench risk

# Specific benchmark group
cargo bench -p rsigma-eval --bench eval -- eval_throughput

# Quick mode (fewer samples, useful for CI smoke tests)
cargo bench -- --quick
```

---

## Parser (`rsigma-parser`)

### Rule Parsing

| Benchmark | Time (median) | Throughput |
|-----------|---------------|------------|
| Single rule | 10.6 us | - |
| 10 rules | 110.0 us | - |
| 100 rules | 1.18 ms | 2.37 MiB/s |
| 500 rules | 5.81 ms | 5.09 MiB/s |
| 1000 rules | 11.9 ms | 12.4 MiB/s |
| Complex condition (single) | 23.8 us | - |

### Wildcard and Regex Rules (pre-compiled pattern cache)

| Benchmark | Time (median) |
|-----------|---------------|
| Wildcard rules (100) | 85.8 us |
| Wildcard rules (500) | 88.2 us |
| Wildcard rules (1000) | 85.1 us |
| Regex rules (100) | 51.5 us |
| Regex rules (500) | 50.2 us |
| Regex rules (1000) | 51.6 us |

Wildcard/regex rule parsing is O(1) due to pattern caching (only the first parse compiles the patterns).

---

## Evaluation Engine (`rsigma-eval`)

### Rule Compilation

| Rules | Time (median) |
|------:|---------------|
| 100 | 138.8 us |
| 500 | 620.9 us |
| 1,000 | 1.16 ms |
| 5,000 | 6.12 ms |

### Rule Load Paths

Compares the three engine entry points for loading rules at large N. `add_collection` and `add_rules` rebuild the inverted and bloom indexes once at the end of the batch; `add_rule` in a loop folds each rule incrementally with an amortized-doubling bloom rebuild (64-rule floor, 2x ratchet).

| Rules   | `add_collection`           | `add_rules`               | `add_rule` loop           |
|--------:|----------------------------|----------------------------|----------------------------|
| 1,000   | 1.21 ms (1.21 us/rule)     | 1.18 ms (1.18 us/rule)     | 1.63 ms (1.63 us/rule)     |
| 10,000  | 11.94 ms (1.19 us/rule)    | 12.04 ms (1.20 us/rule)    | 17.99 ms (1.80 us/rule)    |
| 100,000 | 131.44 ms (1.31 us/rule)   | 131.17 ms (1.31 us/rule)   | 176.26 ms (1.76 us/rule)   |

All three paths scale linearly in the rule count. Per-rule cost is essentially constant from 1K to 100K, confirming the O(N) total complexity:

- `add_collection` and `add_rules` cost roughly 1.2-1.3 us/rule. The fixed per-batch cost is dominated by the final inverted index + bloom build over the aggregate.
- `add_rule` in a loop costs roughly 1.6-1.8 us/rule, about 40% more than the batched paths. The overhead is the per-rule incremental insert plus the ~11 doubling-watermark rebuilds the bloom triggers between 1 and 100K rules. There is no quadratic blowup; the constant factor pays for the incremental contract.

The takeaway is that `add_rule` is not a foot-gun for bulk loads. Batched APIs are still slightly faster and remain the recommended path for cold-load scenarios; the single-rule path exists for cases where the caller wants per-rule error reporting (`rsigma rule validate`) or per-rule mutation semantics.

Run with `cargo bench -p rsigma-eval --bench eval -- rule_load`.

### Single Event Evaluation

Time to evaluate one event against N compiled rules.

| Rules | Time (median) | Per-rule |
|------:|---------------|----------|
| 100 | 2.55 us | 25.5 ns |
| 500 | 14.2 us | 28.4 ns |
| 1,000 | 31.8 us | 31.8 ns |
| 5,000 | 168.6 us | 33.7 ns |

### Detection Throughput (100 rules)

| Events | Time (median) | Throughput |
|-------:|---------------|------------|
| 1,000 | 2.71 ms | 370 Kelem/s |
| 10,000 | 27.4 ms | 364 Kelem/s |
| 100,000 | 276.4 ms | 362 Kelem/s |

### Batch Mode (Sequential vs Parallel)

| Configuration | Time (median) | Throughput |
|---------------|---------------|------------|
| 100 rules, sequential | 2.73 ms | 367 Kelem/s |
| 100 rules, batch | 2.73 ms | 366 Kelem/s |
| 1000 rules, sequential | 33.9 ms | 29.5 Kelem/s |
| 1000 rules, batch | 34.5 ms | 28.9 Kelem/s |
| 5000 rules, sequential | 182.1 ms | 5.49 Kelem/s |
| 5000 rules, batch | 244.8 ms | 4.09 Kelem/s |

### Wildcard and Regex Matching

| Benchmark | Time (median) |
|-----------|---------------|
| Wildcard (100 rules) | 21.0 us |
| Wildcard (500 rules) | 20.9 us |
| Wildcard (1000 rules) | 20.9 us |
| Regex (100 rules) | 5.50 us |
| Regex (500 rules) | 5.51 us |
| Regex (1000 rules) | 5.55 us |

Wildcard/regex matching scales O(1) with rule count thanks to compiled pattern sets.

### Aho-Corasick Threshold Sweep

Single rule with N `|contains` patterns evaluated against 50 randomly generated events at varying haystack lengths. Drove the choice of `AHO_CORASICK_THRESHOLD = 8` in `compiler/optimizer.rs`. Throughput is per event.

| Patterns | h=100 B | h=1 KB | h=8 KB | h=64 KB |
|---------:|---------|--------|--------|---------|
| 1  | 8.34 Melem/s (5.99 us / batch) | 4.99 Melem/s (10.0 us) | 1.11 Melem/s (45.1 us) | 67.8 Kelem/s (737.9 us) |
| 2  | 5.91 Melem/s (8.46 us) | 1.60 Melem/s (31.2 us) | 195 Kelem/s (256.1 us) | 18.0 Kelem/s (2.77 ms) |
| 4  | 4.10 Melem/s (12.2 us) | 1.09 Melem/s (45.9 us) | 93.9 Kelem/s (532.3 us) | 10.1 Kelem/s (4.96 ms) |
| **8**  | **5.44 Melem/s (9.19 us)** | **639 Kelem/s (78.2 us)** | **82.2 Kelem/s (608.2 us)** | **10.2 Kelem/s (4.90 ms)** |
| 16 | 5.32 Melem/s (9.39 us) | 641 Kelem/s (78.0 us) | 82.3 Kelem/s (607.9 us) | 10.1 Kelem/s (4.94 ms) |
| 32 | 5.19 Melem/s (9.64 us) | 638 Kelem/s (78.4 us) | 79.3 Kelem/s (630.6 us) | 9.27 Kelem/s (5.39 ms) |

Throughput flattens at p=8: p16 and p32 perform within ~3% of p8 because the AC automaton scans the haystack once regardless of pattern count. Below 8 patterns, the sequential `str::contains` path with SIMD acceleration (memchr / Two-Way) wins on longer haystacks; at p8 the automaton already beats the p4 sequential path on short haystacks. The crossover stands at 8.

Run with `cargo bench -p rsigma-eval --bench eval -- eval_ac_threshold_sweep`.

### Bloom Pre-Filter (`--bloom-prefilter`)

200 non-matching events evaluated against N substring-heavy rules with the bloom prefilter off vs on (`Engine::set_bloom_prefilter(true)`).

| Rules  | Off                      | On                       | Speedup |
|-------:|--------------------------|--------------------------|---------|
| 100    | 6.62 ms (151 Kelem/s)    | 6.65 ms (150 Kelem/s)    | ~1.0x   |
| 500    | 43.7 ms (22.9 Kelem/s)   | 38.6 ms (25.9 Kelem/s)   | ~1.13x  |
| 1,000  | 88.6 ms (11.3 Kelem/s)   | 74.4 ms (13.4 Kelem/s)   | ~1.19x  |
| 5,000  | 442.6 ms (2.26 Kelem/s)  | 365.7 ms (2.73 Kelem/s)  | ~1.21x  |

The bloom filter pays off from roughly 500 rules upward on non-matching traffic and is neutral below that. It never slows evaluation down in this workload, but it is opt-in because matching-heavy traffic pays the filter cost without the skip benefit.

Run with `cargo bench -p rsigma-eval --bench eval -- eval_bloom_rejection`.

### Cross-Rule Aho-Corasick Pre-Filter, `daachorse-index` feature

200 non-matching events evaluated against N pure-substring rules. Best-case workload for the cross-rule index: every rule is AC-prunable (every detection consists exclusively of positive substring matchers, no negation in conditions), and every event has zero pattern hits across all fields.

| Rules  | Off (default)            | On (`set_cross_rule_ac(true)`)   | Speedup     |
|-------:|--------------------------|----------------------------------|-------------|
| 1,000  | 17.50 ms (11.4 Kelem/s)  | 288.8 us (693 Kelem/s)           | **~61x**    |
| 5,000  | 87.63 ms (2.28 Kelem/s)  | 1.05 ms (191 Kelem/s)            | **~84x**    |
| 10,000 | 186.92 ms (1.07 Kelem/s) | 2.05 ms (97.6 Kelem/s)           | **~91x**    |

The cross-rule index turns O(rules × patterns) per event into O(haystack_length) for the AC scan, so throughput is essentially constant in rule count once the index is enabled.

For typical mixed workloads (substring + exact + regex rules, events that hit multiple fields, smaller rule sets) the index adds build-time and lookup overhead with smaller wins or none, and can even cause a slowdown. **Off by default.** Enable via `Engine::set_cross_rule_ac(true)` programmatically, or `--cross-rule-ac` on `rsigma engine daemon` / `rsigma engine eval` (requires the `daachorse-index` Cargo feature). Always benchmark against representative data before flipping it on.

Run with `cargo bench -p rsigma-eval --features daachorse-index --bench eval -- eval_cross_rule_ac`.

### Logsource Pruning (`--logsource-routing`)

Single-event evaluation over an always-evaluated (`contains`-only, never-matching) ruleset split 50/50 across `product: windows` and `product: linux`, with a windows-tagged event. With pruning on, the conflicting-product half is never iterated, so the win tracks the pruned fraction.

| Rules  | Off           | On            | Speedup |
|-------:|---------------|---------------|---------|
| 1,000  | 112.2 us      | 64.1 us       | ~1.75x  |
| 10,000 | 1.19 ms       | 678.1 us      | ~1.76x  |

Run with `cargo bench -p rsigma-eval --bench logsource`.

### Schema Classification (`engine classify`, `--schema-routing`, `--observe-schemas`)

Per-event cost of `SchemaClassifier::classify` against the built-in signature set. This is the hot-path overhead schema routing and schema observability add per event.

| Event | Time (median) |
|-------|---------------|
| ECS Windows (early match, highest specificity) | 289 ns |
| Sysmon flat (mid-list match) | 443 ns |
| OCSF | 216 ns |
| Unknown (full signature scan, worst case) | 548 ns |
| ECS Windows with ambiguity check | 296 ns |

Classification stays well under a microsecond per event even in the full-scan worst case, so `--observe-schemas` and `--schema-routing` cost a fraction of a percent at typical pipeline throughputs.

Run with `cargo bench -p rsigma-eval --bench schema`.

### Schema-Routed Dispatch (`--schema-routing`)

End-to-end routed evaluation over a mixed stream (one third ECS, one third flat Sysmon, one third unrecognized; 1,000 events, 100 non-matching rules), with `ecs` and `sysmon` bound to their builtin pipelines, against a single pipeline-less engine over the same stream.

| Configuration | Time (median) | Throughput |
|---------------|---------------|------------|
| Single engine, no pipelines | 5.07 ms | 197 Kelem/s |
| Routed, per-event `route()` | 9.34 ms | 107 Kelem/s |
| Routed, `process_batch` | 9.45 ms | 106 Kelem/s |

The ~4.3 us/event difference overstates the dispatch cost: classification itself is ~0.3 us (see above), and most of the rest is the routed engines doing real matching work, because their pipeline-mapped rules reference fields the events actually carry (`process.command_line`), while the unrouted baseline's unmapped rules miss ECS events on absent fields without ever scanning a value. That is the correctness gap routing exists to close: the baseline is faster partly because it silently cannot match two thirds of the stream.

Run with `cargo bench -p rsigma-eval --bench routing`.

### Array Matching (`sigma-version: 3`)

Per-event cost of the array evaluation paths. Events carry a `connections` array of objects; the flat baseline is the same engine evaluating a single scalar field (326 ns). Array-scope bodies are evaluated per member rather than through the batched flat-field matchers, so cost is linear in member count.

| Path | 10 members | 100 members | 1,000 members |
|------|-----------:|------------:|--------------:|
| Implicit any-member, hit at last element | 1.80 us | 12.4 us | 113.2 us |
| Implicit any-member, miss (full scan) | 564 ns | 3.78 us | 34.6 us |
| `[any]` scope, hit at first element | 2.47 us | 22.2 us | 220.2 us |
| `[any]` scope, hit at last element | 2.75 us | 24.9 us | 245.3 us |
| `[any]` scope, miss | 635 ns | 5.80 us | 57.8 us |
| `[all]` scope, every member satisfies | 2.68 us | 24.8 us | 247.1 us |
| `[all]` scope, first member fails | 391 ns | 3.08 us | 31.4 us |

Positional indexing is O(1) in the array length: `args[0]` costs 693 ns and `args[-1]` 671 ns against a 1,000-element array, about 2x the flat baseline for the index resolution.

Two properties fall out of the numbers. Non-firing evaluation costs ~35-60 ns per member (a 100-member `[any]` miss is 5.8 us, ~18x the flat baseline), and `[all]` exits early on the first failing member. But a **firing** rule pays ~110-250 ns per member regardless of where the matching element sits: `[any]` hit-first costs nearly the same as hit-last because the fan-out continues past the first hit to collect every matching member for match details. Budget array rules by array length times rule count on matching traffic, not by early-exit intuition.

Run with `cargo bench -p rsigma-eval --bench array`.

### Result Serialization

Serializing `EvaluationResult` to the flat NDJSON wire shape, comparing the derive-based baseline against a `#[serde(flatten)]` variant and a hand-written `Serialize` impl.

| Payload | v1 baseline | v2 flatten derive | v3 hand-written |
|---------|-------------|-------------------|-----------------|
| Small detection | 136 ns | 135 ns | 135 ns |
| Realistic detection | 481 ns | 477 ns | 479 ns |
| Small correlation | 177 ns | 182 ns | 180 ns |
| Realistic correlation | 1.72 us | 1.72 us | 1.73 us |

All three implementations are within noise of each other; a hand-written serializer buys nothing, so the derive stays. Even a realistic correlation result serializes in under 2 us, an order of magnitude below its evaluation cost.

Run with `cargo bench -p rsigma-eval --bench result_serialize`.

---

## Correlation Engine (`rsigma-eval`)

### Event Count Correlation

1000 events evaluated against N correlation rules.

| Corr rules | Time (median) | Throughput |
|-----------:|---------------|------------|
| 5 | 1.10 ms | 907 Kelem/s |
| 10 | 1.09 ms | 915 Kelem/s |
| 20 | 1.12 ms | 894 Kelem/s |

### Temporal Correlation

1000 events evaluated with temporal ordering constraints.

| Corr rules | Time (median) | Throughput |
|-----------:|---------------|------------|
| 3 | 567.4 us | 1.76 Melem/s |
| 5 | 569.4 us | 1.76 Melem/s |
| 10 | 569.6 us | 1.76 Melem/s |

### Correlation Throughput

| Events | Time (median) | Throughput |
|-------:|---------------|------------|
| 10,000 | 20.1 ms | 497 Kelem/s |
| 100,000 | 199.6 ms | 501 Kelem/s |

### Sequential vs Batch (10,000 events)

| Mode | Time (median) | Throughput |
|------|---------------|------------|
| Sequential | 20.0 ms | 499 Kelem/s |
| Batch | 21.7 ms | 462 Kelem/s |

### State Pressure (unique group-by keys)

| Unique keys | Time (median) | Throughput |
|------------:|---------------|------------|
| 1,000 | 795.2 us | 1.26 Melem/s |
| 10,000 | 8.15 ms | 1.23 Melem/s |
| 50,000 | 41.4 ms | 1.21 Melem/s |

### Window Modes: sliding vs tumbling vs session

Identical `event_count` workload for all three modes: 10,000 events across 1,000 group keys, one event per group per 10s tick, 1h window, 10m session gap. The window decision in `apply_window_open` is O(1) (deque front/back inspection), so the three modes cost the same per event.

| Window mode | Time (median) | Throughput |
|-------------|---------------|------------|
| `sliding` (default) | 8.12 ms | 1.23 Melem/s |
| `tumbling` | 7.77 ms | 1.29 Melem/s |
| `session` | 7.91 ms | 1.26 Melem/s |

Run with `cargo bench -p rsigma-eval --bench correlation -- correlation_window_modes`.

### Window-Mode Memory Stress

The `correlation_memory` bench is not a Criterion suite: it installs a counting global allocator and reports **peak** and **settled** heap deltas over the engine baseline, isolating window-state maintenance (alert thresholds are unreachable; event construction is excluded from the deltas). It reproduces the two scenarios from the [SEP #214](https://github.com/SigmaHQ/sigma-specification/issues/214) discussion on memory becoming the bottleneck in stateful window correlation.

**A. High-cardinality session windows** (one event per unique key, `event_count`, gap 5m, cap 2h), exercising the `max_state_entries` hard cap and stalest-first eviction:

| Configuration | Throughput | Peak heap | Settled | Live groups |
|---------------|-----------:|----------:|--------:|------------:|
| 100k keys, default cap (100k) | 756 Kelem/s | 20.5 MiB | 17.7 MiB | 100,000 |
| 1M keys, default cap (100k) | 841 Kelem/s | 39.8 MiB | 22.4 MiB | capped |
| 1M keys, cap raised to 2M | 742 Kelem/s | 327.4 MiB | 243.8 MiB | 1,000,000 |

A live session group costs ~256 B settled, dominated by the `GroupKey` heap strings rather than the timestamps. Throughput under active eviction is the highest of the three runs because the state map stays small; the eviction sort is amortized over the 10% headroom the cap reclaims.

**B. Long-lived chatty sessions** (groups emitting continuously inside an open session; gap never exceeded, so the per-group deque grows to timespan/interval entries):

| Workload | Throughput | Peak heap | Bytes/in-window event |
|----------|-----------:|----------:|----------------------:|
| `event_count` session, 1k groups @ 30s (240 ev/window) | 1.08 Melem/s | 2.2 MiB | ~10 B |
| `event_count` sliding, 1k groups @ 30s (240 ev/window) | 1.06 Melem/s | 2.2 MiB | ~10 B |
| `value_count` session, 1k groups @ 30s, distinct strings | 306 Kelem/s | 21.1 MiB | ~92 B |
| `event_count` session, 100 groups @ 1 ev/s (7,200 ev/window) | 1.10 Melem/s | 6.3 MiB | ~9 B |
| `value_count` session, 100 groups @ 1 ev/s, distinct (1,800 ev/window) | 57 Kelem/s | 16.0 MiB | ~93 B |

**C. Mode comparison** (10k groups, 1M events, 1h window): sliding 915 Kelem/s, tumbling 959 Kelem/s, session 997 Kelem/s, all at a 6.6 MiB peak. Memory differences between modes come only from how long entries are retained, not from per-event overhead.

Run with `cargo bench -p rsigma-eval --bench correlation_memory` (about half a minute total).

---

## Runtime (`rsigma-runtime`)

### LogProcessor Pipeline Throughput

End-to-end processing: format parsing, detection, and result collection (100 rules).

| Format | Events | Time (median) | Throughput |
|--------|-------:|---------------|------------|
| JSON | 1,000 | 1.14 ms | 880 Kelem/s |
| JSON | 10,000 | 8.94 ms | 1.12 Melem/s |
| Syslog | 1,000 | 744.3 us | 1.34 Melem/s |
| Syslog | 10,000 | 6.35 ms | 1.57 Melem/s |
| Plain | 1,000 | 184.4 us | 5.42 Melem/s |
| Plain | 10,000 | 1.05 ms | 9.52 Melem/s |
| Auto-detect | 1,000 | 1.07 ms | 939 Kelem/s |
| Auto-detect | 10,000 | 8.86 ms | 1.13 Melem/s |

### Feature-Gated Input Formats (100 rules)

logfmt and CEF run through the same `LogProcessor` pipeline as the table above; EVTX measures `EvtxFileReader` binary-record parsing over the checked-in 2 MiB `security.evtx` fixture (~2,260 records), the dominant cost of `engine eval -e @file.evtx`.

| Format | Events | Time (median) | Throughput |
|--------|-------:|---------------|------------|
| logfmt | 1,000 | 1.83 ms | 546 Kelem/s |
| logfmt | 10,000 | 15.8 ms | 631 Kelem/s |
| CEF | 1,000 | 2.11 ms | 473 Kelem/s |
| CEF | 10,000 | 19.0 ms | 527 Kelem/s |
| EVTX (parse only) | ~2,260 records | 11.6 ms | 195 Kelem/s |

Run with `cargo bench -p rsigma-runtime --bench input_formats --features logfmt,cef,evtx`.

### OTLP Log Decode (`otlp` feature)

`logs_request_to_raw_events`: flattening an OTLP `ExportLogsServiceRequest` (string body, eight log attributes, four resource attributes, scope metadata, trace context per record) into the JSON events the engine evaluates. This is the ingest-side cost of OTLP/HTTP and OTLP/gRPC downstream of transport and protobuf decoding.

| Records | Time (median) | Throughput |
|--------:|---------------|------------|
| 100 | 225.4 us | 444 Kelem/s |
| 1,000 | 2.27 ms | 441 Kelem/s |
| 10,000 | 22.8 ms | 439 Kelem/s |

Decode costs a flat ~2.3 us per record independent of batch size, comparable to the JSON-line parse-plus-detect cost, so OTLP ingestion roughly halves single-core throughput relative to NDJSON input.

Run with `cargo bench -p rsigma-runtime --bench otlp --features otlp`.

### Field Observability (`--observe-fields`)

The same 10,000-event JSON workload as above (seven fields per event, 100 rules) with the field observer off vs on.

| Mode | Time (median) | Throughput |
|------|---------------|------------|
| Off | 8.58 ms | 1.17 Melem/s |
| On | 11.5 ms | 867 Kelem/s |

The observer adds ~0.3 us per event on seven-key events (a mutex-guarded counter update per field key), about 25% of this workload's total pipeline cost. Cheap in absolute terms, but it is the most expensive of the opt-in per-event observability features and scales with the event's key count.

Run with `cargo bench -p rsigma-runtime --bench runtime_throughput -- runtime_observe_fields`.

### Raw Engine vs LogProcessor (10,000 events, 100 rules)

| Mode | Time (median) | Throughput |
|------|---------------|------------|
| Raw Engine (pre-parsed) | 11.3 ms | 884 Kelem/s |
| LogProcessor (JSON) | 8.70 ms | 1.15 Melem/s |
| LogProcessor (auto-detect) | 8.73 ms | 1.15 Melem/s |

### Rule Scaling (1,000 JSON events)

| Rules | Time (median) | Throughput |
|------:|---------------|------------|
| 100 | 1.04 ms | 959 Kelem/s |
| 500 | 1.04 ms | 957 Kelem/s |
| 1,000 | 1.04 ms | 961 Kelem/s |

Rule count has minimal impact on runtime throughput due to the engine's indexed matching.

---

## Post-Engine Layers (`rsigma-runtime`)

Sink-path stages that run after evaluation and before delivery. All figures are per 1,000-result batch; cardinality is the number of distinct entity/fingerprint values cycling through the batch.

### Enrichment (`template` primitive)

The CPU-only floor cost of the enrichment pipeline: template interpolation, kind/scope filtering, semaphore acquisition, and the enrichments-map injection. I/O-bound primitives (`http`, `command`, `lookup`) are dominated by their fetch latency and response cache, not the pipeline.

| Enrichers | Time (median) | Per result |
|----------:|---------------|------------|
| 1 | 857.0 us | ~0.86 us |
| 4 | 2.56 ms | ~0.64 us per enricher |

Run with `cargo bench -p rsigma-runtime --bench enrichment`.

### Alert Pipeline (dedup + incident grouping)

| Entity cardinality | Time (median) | Per result |
|-------------------:|---------------|------------|
| 1 | 435.2 us | ~0.44 us |
| 10 | 449.6 us | ~0.45 us |
| 100 | 564.2 us | ~0.56 us |

Dedup folding plus incident grouping cost roughly half a microsecond per result and grow gently with fingerprint cardinality (more open alerts and incidents to track).

Run with `cargo bench -p rsigma-runtime --bench alert_pipeline`.

### Risk Layer (annotation + per-entity accumulation)

| Entity cardinality | Time (median) | Per result |
|-------------------:|---------------|------------|
| 1 | 3.87 ms | ~3.9 us |
| 10 | 1.21 ms | ~1.2 us |
| 100 | 1.09 ms | ~1.1 us |

Single-entity is the worst case, inverted from the alert pipeline: every result accrues into one entity whose window deque keeps growing and whose accumulated risk repeatedly crosses the incident threshold. At realistic cardinalities the layer costs about a microsecond per result.

Run with `cargo bench -p rsigma-runtime --bench risk`.

---

## Dynamic Pipelines (`rsigma-runtime`)

### Source Resolution (File I/O + JSON Parse)

| Items | Time (median) |
|------:|---------------|
| 10 | 17.4 us |
| 100 | 20.5 us |
| 1,000 | 61.6 us |
| 10,000 | 441.8 us |

### Data Parsing (No I/O)

| Format | Items | Time (median) |
|--------|------:|---------------|
| JSON | 10 | 366 ns |
| JSON | 100 | 2.78 us |
| JSON | 1,000 | 24.3 us |
| JSON | 10,000 | 239.0 us |
| YAML | 10 | 3.46 us |
| Lines | 100 | 2.83 us |

### Extract Expressions

Expression evaluation on a 100-item dataset with nested objects.

| Language | Expression type | Time (median) |
|----------|----------------|---------------|
| JQ | Identity (`.items`) | 206.5 us |
| JQ | Filter (`select(.active)`) | 284.2 us |
| JQ | Nested path (`.a.b.c`) | 177.9 us |
| JSONPath | Simple (`$.items[*].name`) | 22.5 us |
| JSONPath | Filter (`[?@.active==true]`) | 23.6 us |
| CEL | Field access (`data.metadata.count`) | 54.1 us |
| CEL | List filter (`.filter(x, x.active)`) | 759.3 us |

JQ times rose roughly 3x against the 0.9.0 baseline following the jaq 1.x to 3.0 migration (0.13.0, Radically Open Security audit fixes); JSONPath is unaffected and now ~10x faster than JQ for comparable filters.

### Template Expansion

`TemplateExpander::expand` substituting `${source.*}` references in pipeline vars.

| Vars | Values/source | Time (median) |
|-----:|-------------:|---------------|
| 1 | 10 | 487 ns |
| 5 | 10 | 2.17 us |
| 10 | 10 | 4.24 us |
| 20 | 10 | 8.54 us |
| 5 | 100 | 10.1 us |
| 5 | 1,000 | 91.3 us |

### Resolve with Extract (File + Filter, 500 IOC entries)

| Language | Time (median) |
|----------|---------------|
| JQ (`.indicators[] \| select(.active) \| .value`) | 943.8 us |
| JSONPath (`$.indicators[?@.active==true].value`) | 253.4 us |
| CEL (`data.indicators.filter(x, x.active).map(x, x.value)`) | 39.7 ms |

### Dynamic Detection End-to-End

Full pipeline: resolve source, expand templates, apply value_placeholders, evaluate events.

| Scenario | Time (median) | Throughput |
|----------|---------------|------------|
| Detect 1000 events (50 IOCs) | 351.3 us | 2.85 Melem/s |
| Reload with resolve | 175.4 us | - |

Reload now includes the fail-closed dynamic-source re-resolution that `load_rules` performs since 0.14.0, which is why it costs more than the 0.9.0 baseline measured without it. In production, reload latency is dominated by source fetch time anyway.

---

## Key Observations

- **AC threshold is empirically 8**: substring-list throughput flattens at 8 patterns once Aho-Corasick takes over. p16/p32 perform within ~3% of p8; below 8, the sequential `str::contains` SIMD path (memchr / Two-Way) is faster on longer haystacks.
- **Cross-rule AC is order-of-magnitude on substring-only rule sets**: with the `daachorse-index` feature enabled, 200 non-matching events against 10K pure-substring rules dropped from 187 ms to 2.05 ms (~91x). Off by default; only worth enabling for substring-heavy rule sets where most events don't match (e.g., threat-intel feeds against high-volume telemetry).
- **The bloom prefilter pays off from ~500 rules**: ~20% faster on non-matching traffic at 1K-5K rules, neutral at 100. Opt-in because matching-heavy traffic pays the filter cost without the skip benefit.
- **Logsource pruning wins track the pruned fraction**: a 50/50 two-product split evaluates ~1.75x faster with `--logsource-routing` on, at both 1K and 10K rules.
- **Schema classification is sub-microsecond**: 216-548 ns per event against the full built-in signature set, so schema routing and observability are effectively free at pipeline throughputs.
- **Array matching is linear in member count, and hits cost more than misses**: non-firing paths cost ~35-60 ns per member while a firing rule pays ~110-250 ns per member independent of match position, because the fan-out collects every matching member for match details. Positional indexing (`args[N]`) stays O(1).
- **Detection is fast**: ~365K events/sec with 100 rules in pure evaluation mode, scaling linearly with event count; the full JSON runtime pipeline reaches 1.12M events/sec.
- **Runtime overhead is negative**: LogProcessor with JSON batching is faster than raw Engine evaluation due to batch-level optimizations and format-aware parsing.
- **Rule count scales well**: runtime throughput is flat from 100 to 1,000 rules thanks to indexed field matching.
- **Correlation is efficient**: temporal correlations (1.76M elem/s) are ~2x faster than event-count correlations (~900K elem/s), and both scale linearly with events; the mixed-workload pipeline sustains ~500K events/sec.
- **Window modes cost the same per event**: sliding, tumbling, and session all run at ~1.2-1.3 Melem/s on an identical workload. The window decision is O(1); choosing `session` over `sliding` is free at evaluation time.
- **Correlation memory is bounded by entry count, not bytes**: the `max_state_entries` cap (default 100k) held 1M unique session keys to a 39.8 MiB peak via stalest-first eviction. Within the cap, per-group deques grow with timespan x event rate: ~10 B per in-window event for `event_count`, ~92 B for `value_count` with distinct string values.
- **`value_count` distinct counting is the correlation bottleneck**: the distinct count is recomputed per event over the whole window (O(W) per event), so throughput drops from ~1.1 Melem/s to 57 Kelem/s at 1,800 distinct values per window; CPU collapses before memory does. Prefer shorter windows or `event_count` where distinctness is not required.
- **Every wire format lands within one order of magnitude**: JSON 1.1M, logfmt 631K, CEF 527K, and OTLP decode 440K events/sec per core, with EVTX binary parsing at 195K records/sec. Format choice moves single-core ingest capacity by at most ~2.5x.
- **`--observe-fields` is the priciest per-event observability opt-in**: ~0.3 us per event on seven-key events (~25% of the JSON pipeline cost on this workload), versus effectively free schema observation. It scales with event key count.
- **Routed evaluation costs less than it looks**: the ~2x gap versus an unrouted engine is mostly the routed engines doing real matching on pipeline-mapped fields the unmapped baseline can never match. Pure dispatch (classify + route) is sub-microsecond.
- **Post-engine layers cost about a microsecond per result**: template enrichment ~0.9 us, alert-pipeline dedup + grouping ~0.5 us, risk accumulation ~1.1 us at realistic entity cardinalities. At 10K detections/sec the full opt-in sink path consumes under 3% of a core.
- **Result serialization is not worth hand-optimizing**: the derive-based serializer matches a hand-written impl within noise; even realistic correlation results serialize in under 2 us.
- **Template expansion is negligible**: even with 20 vars, expansion adds < 10 us. Not a bottleneck.
- **JSONPath is the fastest extraction language**: ~10x faster than JQ for comparable filter operations since the jaq 3.0 migration, with none of CEL's interpretation overhead.
- **CEL has high overhead**: ~150x slower than JSONPath for list filtering. Best suited for simple field access or small datasets.
- **Dynamic pipelines add no per-event cost**: once the engine is built, detection throughput with dynamic pipelines (2.85M elem/s) is comparable to static pipeline performance.
