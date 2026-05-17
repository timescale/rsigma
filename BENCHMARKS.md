# Benchmarks

Criterion benchmark results for the rsigma detection engine.

**Hardware**: Apple M4 Pro, macOS  
**Profile**: `bench` (optimized, release)  
**Date**: 2026-05-07  
**Version**: 0.9.0

## Running

```bash
# All benchmarks across all crates
cargo bench

# Individual suites
cargo bench -p rsigma-parser --bench parse
cargo bench -p rsigma-eval --bench eval
cargo bench -p rsigma-eval --bench correlation
cargo bench -p rsigma-runtime --bench runtime_throughput
cargo bench -p rsigma-runtime --bench dynamic_pipelines

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
| Single rule | 10.7 us | - |
| 10 rules | 110.0 us | - |
| 100 rules | 1.15 ms | 2.42 MiB/s |
| 500 rules | 5.79 ms | 5.10 MiB/s |
| 1000 rules | 11.7 ms | 12.7 MiB/s |
| Complex condition (single) | 23.8 us | - |

### Wildcard and Regex Rules (pre-compiled pattern cache)

| Benchmark | Time (median) |
|-----------|---------------|
| Wildcard rules (100) | 84.1 us |
| Wildcard rules (500) | 84.0 us |
| Wildcard rules (1000) | 84.5 us |
| Regex rules (100) | 50.6 us |
| Regex rules (500) | 50.2 us |
| Regex rules (1000) | 50.6 us |

Wildcard/regex rule parsing is O(1) due to pattern caching (only the first parse compiles the patterns).

---

## Evaluation Engine (`rsigma-eval`)

### Rule Compilation

| Rules | Time (median) |
|------:|---------------|
| 100 | 98.9 us |
| 500 | 478.3 us |
| 1,000 | 961.9 us |
| 5,000 | 4.90 ms |

### Rule Load Paths (0.11.x)

Apple M4 Pro, macOS, release build, 2026-05-16. Compares the three engine entry points for loading rules at large N. `add_collection` and `add_rules` rebuild the inverted and bloom indexes once at the end of the batch; `add_rule` in a loop folds each rule incrementally with an amortized-doubling bloom rebuild (64-rule floor, 2x ratchet).

| Rules   | `add_collection`           | `add_rules`               | `add_rule` loop           |
|--------:|----------------------------|----------------------------|----------------------------|
| 1,000   | 1.15 ms (1.15 us/rule)     | 1.17 ms (1.17 us/rule)     | 1.64 ms (1.64 us/rule)     |
| 10,000  | 11.82 ms (1.18 us/rule)    | 11.85 ms (1.18 us/rule)    | 17.23 ms (1.72 us/rule)    |
| 100,000 | 121.65 ms (1.22 us/rule)   | 122.13 ms (1.22 us/rule)   | 166.07 ms (1.66 us/rule)   |

All three paths scale linearly in the rule count. Per-rule cost is essentially constant from 1K to 100K, confirming the O(N) total complexity:

- `add_collection` and `add_rules` cost roughly 1.2 us/rule. The fixed per-batch cost is dominated by the final inverted index + bloom build over the aggregate.
- `add_rule` in a loop costs roughly 1.65 us/rule, about 40% more than the batched paths. The overhead is the per-rule incremental insert plus the ~11 doubling-watermark rebuilds the bloom triggers between 1 and 100K rules. There is no quadratic blowup; the constant factor pays for the incremental contract.

The takeaway is that `add_rule` is no longer a foot-gun for bulk loads. Batched APIs are still slightly faster and remain the recommended path for cold-load scenarios; the single-rule path exists for cases where the caller wants per-rule error reporting (`rsigma rule validate`) or per-rule mutation semantics.

Run with `cargo bench -p rsigma-eval --bench eval -- rule_load`.

### Single Event Evaluation

Time to evaluate one event against N compiled rules.

| Rules | Time (median) | Per-rule |
|------:|---------------|----------|
| 100 | 2.25 us | 22.5 ns |
| 500 | 12.3 us | 24.5 ns |
| 1,000 | 30.9 us | 30.9 ns |
| 5,000 | 162.9 us | 32.6 ns |

### Detection Throughput (100 rules)

| Events | Time (median) | Throughput |
|-------:|---------------|------------|
| 1,000 | 2.50 ms | 401 Kelem/s |
| 10,000 | 24.8 ms | 403 Kelem/s |
| 100,000 | 248.1 ms | 403 Kelem/s |

### Batch Mode (Sequential vs Parallel)

| Configuration | Time (median) | Throughput |
|---------------|---------------|------------|
| 100 rules, sequential | 2.48 ms | 404 Kelem/s |
| 100 rules, batch | 2.52 ms | 397 Kelem/s |
| 1000 rules, sequential | 31.2 ms | 32.0 Kelem/s |
| 1000 rules, batch | 31.3 ms | 32.0 Kelem/s |
| 5000 rules, sequential | 162.0 ms | 6.17 Kelem/s |
| 5000 rules, batch | 162.3 ms | 6.16 Kelem/s |

### Wildcard and Regex Matching

| Benchmark | Time (median) |
|-----------|---------------|
| Wildcard (100 rules) | 19.1 us |
| Wildcard (500 rules) | 19.2 us |
| Wildcard (1000 rules) | 19.1 us |
| Regex (100 rules) | 5.17 us |
| Regex (500 rules) | 5.21 us |
| Regex (1000 rules) | 5.15 us |

Wildcard/regex matching scales O(1) with rule count thanks to compiled pattern sets.

### Aho-Corasick Threshold Sweep (0.10.0)

Single rule with N `|contains` patterns evaluated against 50 randomly generated events at varying haystack lengths. Drove the choice of `AHO_CORASICK_THRESHOLD = 8` in `compiler/optimizer.rs`. Throughput is per event.

| Patterns | h=100 B | h=1 KB | h=8 KB | h=64 KB |
|---------:|---------|--------|--------|---------|
| 1  | 13.0 Melem/s (3.84 us / batch) | 7.77 Melem/s (6.43 us) | 1.85 Melem/s (27.1 us) | 248 Kelem/s (201.4 us) |
| 2  | 10.5 Melem/s (4.77 us) | 2.33 Melem/s (21.5 us) | 345 Kelem/s (144.8 us) | 42.3 Kelem/s (1.18 ms) |
| 4  | 9.08 Melem/s (5.51 us) | 2.03 Melem/s (24.6 us) | 293 Kelem/s (170.8 us) | 35.6 Kelem/s (1.40 ms) |
| **8**  | **5.17 Melem/s (9.68 us)** | **620 Kelem/s (80.6 us)** | **79.0 Kelem/s (633.1 us)** | **9.76 Kelem/s (5.12 ms)** |
| 16 | 5.19 Melem/s (9.63 us) | 628 Kelem/s (79.6 us) | 78.6 Kelem/s (636.4 us) | 9.67 Kelem/s (5.17 ms) |
| 32 | 4.99 Melem/s (10.0 us) | 607 Kelem/s (82.3 us) | 76.4 Kelem/s (654.4 us) | 8.88 Kelem/s (5.63 ms) |

Throughput flattens at p=8: p16 and p32 perform within ~3% of p8 because the AC automaton scans the haystack once regardless of pattern count. Below 8 patterns, the sequential `str::contains` path with SIMD acceleration (memchr / Two-Way) wins. The crossover is clearly at 8.

Run with `cargo bench -p rsigma-eval --bench eval -- eval_ac_threshold_sweep`.

### Cross-Rule Aho-Corasick Pre-Filter, `daachorse-index` feature (0.10.0)

200 non-matching events evaluated against N pure-substring rules. Best-case workload for the cross-rule index: every rule is AC-prunable (every detection consists exclusively of positive substring matchers, no negation in conditions), and every event has zero pattern hits across all fields.

| Rules  | Off (default)            | On (`set_cross_rule_ac(true)`)   | Speedup     |
|-------:|--------------------------|----------------------------------|-------------|
| 1,000  | 17.34 ms (11.5 Kelem/s)  | 253.0 us (790 Kelem/s)           | **~68x**    |
| 5,000  | 85.51 ms (2.34 Kelem/s)  | 883.0 us (226 Kelem/s)           | **~97x**    |
| 10,000 | 173.37 ms (1.15 Kelem/s) | 1.71 ms (117 Kelem/s)            | **~101x**   |

The cross-rule index turns O(rules × patterns) per event into O(haystack_length) for the AC scan, so throughput is essentially constant in rule count once the index is enabled.

For typical mixed workloads (substring + exact + regex rules, events that hit multiple fields, smaller rule sets) the index adds build-time and lookup overhead with smaller wins or none, and can even cause a slowdown. **Off by default.** Enable via `Engine::set_cross_rule_ac(true)` programmatically, or `--cross-rule-ac` on `rsigma engine daemon` / `rsigma engine eval` (requires the `daachorse-index` Cargo feature). Always benchmark against representative data before flipping it on.

Run with `cargo bench -p rsigma-eval --features daachorse-index --bench eval -- eval_cross_rule_ac`.

---

## Correlation Engine (`rsigma-eval`)

### Event Count Correlation

1000 events evaluated against N correlation rules.

| Corr rules | Time (median) | Throughput |
|-----------:|---------------|------------|
| 5 | 944.9 us | 1.06 Melem/s |
| 10 | 953.7 us | 1.05 Melem/s |
| 20 | 974.7 us | 1.03 Melem/s |

### Temporal Correlation

1000 events evaluated with temporal ordering constraints.

| Corr rules | Time (median) | Throughput |
|-----------:|---------------|------------|
| 3 | 475.6 us | 2.10 Melem/s |
| 5 | 478.5 us | 2.09 Melem/s |
| 10 | 483.5 us | 2.07 Melem/s |

### Correlation Throughput

| Events | Time (median) | Throughput |
|-------:|---------------|------------|
| 10,000 | 17.6 ms | 568 Kelem/s |
| 100,000 | 175.7 ms | 569 Kelem/s |

### Sequential vs Batch (10,000 events)

| Mode | Time (median) | Throughput |
|------|---------------|------------|
| Sequential | 17.7 ms | 565 Kelem/s |
| Batch | 18.7 ms | 534 Kelem/s |

### State Pressure (unique group-by keys)

| Unique keys | Time (median) | Throughput |
|------------:|---------------|------------|
| 1,000 | 764.0 us | 1.31 Melem/s |
| 10,000 | 7.97 ms | 1.25 Melem/s |
| 50,000 | 41.5 ms | 1.20 Melem/s |

---

## Runtime (`rsigma-runtime`)

### LogProcessor Pipeline Throughput

End-to-end processing: format parsing, detection, and result collection (100 rules).

| Format | Events | Time (median) | Throughput |
|--------|-------:|---------------|------------|
| JSON | 1,000 | 1.15 ms | 868 Kelem/s |
| JSON | 10,000 | 9.45 ms | 1.06 Melem/s |
| Syslog | 1,000 | 849.4 us | 1.18 Melem/s |
| Syslog | 10,000 | 7.20 ms | 1.39 Melem/s |
| Plain | 1,000 | 192.4 us | 5.20 Melem/s |
| Plain | 10,000 | 1.06 ms | 9.40 Melem/s |
| Auto-detect | 1,000 | 1.11 ms | 903 Kelem/s |
| Auto-detect | 10,000 | 9.38 ms | 1.07 Melem/s |

### Raw Engine vs LogProcessor (10,000 events, 100 rules)

| Mode | Time (median) | Throughput |
|------|---------------|------------|
| Raw Engine (pre-parsed) | 11.6 ms | 865 Kelem/s |
| LogProcessor (JSON) | 9.24 ms | 1.08 Melem/s |
| LogProcessor (auto-detect) | 9.14 ms | 1.09 Melem/s |

### Rule Scaling (1,000 JSON events)

| Rules | Time (median) | Throughput |
|------:|---------------|------------|
| 100 | 1.11 ms | 904 Kelem/s |
| 500 | 1.11 ms | 903 Kelem/s |
| 1,000 | 1.10 ms | 909 Kelem/s |

Rule count has minimal impact on runtime throughput due to the engine's indexed matching.

---

## Dynamic Pipelines (`rsigma-runtime`)

### Source Resolution (File I/O + JSON Parse)

| Items | Time (median) |
|------:|---------------|
| 10 | 18.9 us |
| 100 | 20.9 us |
| 1,000 | 64.3 us |
| 10,000 | 467.1 us |

### Data Parsing (No I/O)

| Format | Items | Time (median) |
|--------|------:|---------------|
| JSON | 10 | 388 ns |
| JSON | 100 | 2.89 us |
| JSON | 1,000 | 25.4 us |
| JSON | 10,000 | 255.4 us |
| YAML | 10 | 3.38 us |
| Lines | 100 | 3.05 us |

### Extract Expressions

Expression evaluation on a 100-item dataset with nested objects.

| Language | Expression type | Time (median) |
|----------|----------------|---------------|
| JQ | Identity (`.items`) | 60.8 us |
| JQ | Filter (`select(.active)`) | 96.2 us |
| JQ | Nested path (`.a.b.c`) | 34.8 us |
| JSONPath | Simple (`$.items[*].name`) | 25.2 us |
| JSONPath | Filter (`[?@.active==true]`) | 27.1 us |
| CEL | Field access (`data.metadata.count`) | 59.8 us |
| CEL | List filter (`.filter(x, x.active)`) | 827.6 us |

### Template Expansion

`TemplateExpander::expand` substituting `${source.*}` references in pipeline vars.

| Vars | Values/source | Time (median) |
|-----:|-------------:|---------------|
| 1 | 10 | 500 ns |
| 5 | 10 | 2.24 us |
| 10 | 10 | 4.37 us |
| 20 | 10 | 9.00 us |
| 5 | 100 | 11.3 us |
| 5 | 1,000 | 101.6 us |

### Resolve with Extract (File + Filter, 500 IOC entries)

| Language | Time (median) |
|----------|---------------|
| JQ (`.indicators[] \| select(.active) \| .value`) | 527.8 us |
| JSONPath (`$.indicators[?@.active==true].value`) | 272.0 us |
| CEL (`data.indicators.filter(x, x.active).map(x, x.value)`) | 43.2 ms |

### Dynamic Detection End-to-End

Full pipeline: resolve source, expand templates, apply value_placeholders, evaluate events.

| Scenario | Time (median) | Throughput |
|----------|---------------|------------|
| Detect 1000 events (50 IOCs) | 369.5 us | 2.71 Melem/s |
| Reload with resolve | 42.4 us | 23.6 Melem/s |

---

## Key Observations

- **AC threshold is empirically 8**: substring-list throughput flattens at 8 patterns once Aho-Corasick takes over. p16/p32 perform within ~3% of p8; below 8, the sequential `str::contains` SIMD path (memchr / Two-Way) is faster.
- **Cross-rule AC is order-of-magnitude on substring-only rule sets**: with the `daachorse-index` feature enabled, 200 non-matching events against 10K pure-substring rules dropped from 173 ms to 1.71 ms (~101x). Off by default; only worth enabling for substring-heavy rule sets where most events don't match (e.g., threat-intel feeds against high-volume telemetry).
- **Detection is fast**: ~400K events/sec with 100 rules in pure evaluation mode, scaling linearly with event count.
- **Runtime overhead is negative**: LogProcessor with JSON batching is actually faster than raw Engine evaluation due to batch-level optimizations and format-aware parsing.
- **Rule count scales well**: Increasing from 100 to 1000 rules has minimal per-event cost increase (~50%) thanks to indexed field matching.
- **Correlation is efficient**: Temporal correlations (2.1M elem/s) are 2x faster than event-count correlations (1.05M elem/s), and both scale linearly with events.
- **Template expansion is negligible**: Even with 20 vars, expansion adds < 10 us. Not a bottleneck.
- **JSONPath is the fastest extraction language**: Roughly 2x faster than JQ for comparable filter operations on dynamic source data.
- **CEL has high overhead**: ~160x slower than JSONPath for list filtering due to interpretation overhead. Best suited for simple field access or small datasets.
- **Dynamic pipelines add no per-event cost**: Once the engine is built, detection throughput with dynamic pipelines (2.71M elem/s) is comparable to static pipeline performance.
- **Reload is cheap**: Engine rebuild with source re-resolution takes ~42 us (excluding network/file I/O). In production, reload latency is dominated by source fetch time.
