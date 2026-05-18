{%
   include-markdown "../BENCHMARKS.md"
%}

---

For operator-facing performance guidance (when to enable `--bloom-prefilter` and `--cross-rule-ac`, how to tune `--batch-size` and `--buffer-size`), see [Performance Tuning](guide/performance-tuning.md). For the metrics that surface throughput and back-pressure at runtime, see [Prometheus metrics](reference/metrics.md) and [Observability](guide/observability.md).
