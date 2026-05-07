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

- **Detection is fast**: ~400K events/sec with 100 rules in pure evaluation mode, scaling linearly with event count.
- **Runtime overhead is negative**: LogProcessor with JSON batching is actually faster than raw Engine evaluation due to batch-level optimizations and format-aware parsing.
- **Rule count scales well**: Increasing from 100 to 1000 rules has minimal per-event cost increase (~50%) thanks to indexed field matching.
- **Correlation is efficient**: Temporal correlations (2.1M elem/s) are 2x faster than event-count correlations (1.05M elem/s), and both scale linearly with events.
- **Template expansion is negligible**: Even with 20 vars, expansion adds < 10 us. Not a bottleneck.
- **JSONPath is the fastest extraction language**: Roughly 2x faster than JQ for comparable filter operations on dynamic source data.
- **CEL has high overhead**: ~160x slower than JSONPath for list filtering due to interpretation overhead. Best suited for simple field access or small datasets.
- **Dynamic pipelines add no per-event cost**: Once the engine is built, detection throughput with dynamic pipelines (2.71M elem/s) is comparable to static pipeline performance.
- **Reload is cheap**: Engine rebuild with source re-resolution takes ~42 us (excluding network/file I/O). In production, reload latency is dominated by source fetch time.
