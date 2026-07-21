# rsigma-ir

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma-ir` is the intermediate representation for [Sigma](https://github.com/SigmaHQ/sigma) rules shared by evaluation and conversion.

This library is part of [rsigma].

## Role

```text
YAML → parser(AST) → static pipelines → lower(HIR) → compile(CompiledRule)
                                           │
                                       convert(backends)
```

The HIR is modifier-resolved. Quantified selectors keep their quantifier and name pattern so evaluation stays count-based. Compiled artifacts (`Regex`, `IpNet`, Aho-Corasick automata) are materialised later in `rsigma-eval`.

Because the matcher model is faithful and lossless, lowering is reversible: [`raise_rule`] turns an `IrRule` back into a parser `SigmaRule` (reconstructing the `field|modifier` surface each `IrMatcher` implies), the inverse of [`lower_rule`]. This is the pivot the `rsigma-convert` reverse conversion uses to raise a query into Sigma YAML.

## Public API

| Item | Description |
|------|-------------|
| [`IrRule`] / [`IrDetection`] / [`IrMatcher`] / [`IrCondition`] | Detection-rule HIR |
| [`IrCorrelation`] / [`IrFilter`] | Correlation and filter HIR shapes |
| [`lower_rule`] / [`lower_detection`] / [`lower_condition`] | AST → HIR |
| [`lower_correlation`] / [`lower_filter`] | Parallel walkers for those shapes |
| [`raise_rule`] / [`RaiseOptions`] / [`ir_pattern_to_sigma`] | HIR → AST, the inverse of `lower_rule` (used by reverse conversion) |
| [`LowerOptions`] | Strict vs placeholder-preserving lowering |
| [`optimize_rule`] / [`flatten_condition`] / [`eliminate_dead_detections`] | Opt-in, semantics-preserving HIR passes |
| [`common_subexpressions`] | Non-mutating analysis of repeated detection items |
| [`encode_rules`] / [`decode_rules`] / [`HirCacheHeader`] | Versioned HIR cache (CBOR) with schema-version check |

## HIR cache

`cache::*` serializes a slice of lowered rules to a versioned, self-describing blob for an on-disk cache (e.g. a daemon restart cache that skips parse, pipeline, and lowering). The blob is a [`HirCacheHeader`] (schema version + producing crate version) followed by the rules; `decode_rules` reads and version-checks the header before decoding the rules, rejecting an incompatible [`HIR_SCHEMA_VERSION`]. CBOR is the wire format because the HIR embeds `LogSource`, whose `#[serde(flatten)]` map has an unknown length that fixed-layout encoders reject. `cache::to_json` gives a human-readable debug export.

## Optimization passes

`optimize::*` are opt-in, total functions on the HIR for offline tooling. They are not run by the default eval or convert paths, so compiled-matcher behavior and byte-identical backend output are unchanged. `flatten_condition` normalizes boolean groups, `eliminate_dead_detections` prunes detections no condition can reference (honoring `them`/glob patterns), and `common_subexpressions` reports repeated detection items. Each pass preserves the match decision and the set of matched selections and fields.

## Constraints

- Sync-only: no tokio, reqwest, or other async runtime dependencies.
- Default lowering rejects unresolved `${source.*}` placeholders.
- All HIR types derive `serde::{Serialize, Deserialize}` for the cache and JSON export.

## License

MIT. See the repository root.

[rsigma]: https://github.com/timescale/rsigma
[`IrRule`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/struct.IrRule.html
[`IrDetection`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/enum.IrDetection.html
[`IrMatcher`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/enum.IrMatcher.html
[`IrCondition`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/enum.IrCondition.html
[`IrCorrelation`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/struct.IrCorrelation.html
[`IrFilter`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/struct.IrFilter.html
[`lower_rule`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/fn.lower_rule.html
[`lower_detection`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/lower/fn.lower_detection.html
[`lower_condition`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/lower/fn.lower_condition.html
[`lower_correlation`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/lower/fn.lower_correlation.html
[`lower_filter`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/lower/fn.lower_filter.html
[`raise_rule`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/fn.raise_rule.html
[`RaiseOptions`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/struct.RaiseOptions.html
[`ir_pattern_to_sigma`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/fn.ir_pattern_to_sigma.html
[`LowerOptions`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/struct.LowerOptions.html
[`optimize_rule`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/optimize/fn.optimize_rule.html
[`flatten_condition`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/optimize/fn.flatten_condition.html
[`eliminate_dead_detections`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/optimize/fn.eliminate_dead_detections.html
[`common_subexpressions`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/optimize/fn.common_subexpressions.html
[`encode_rules`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/cache/fn.encode_rules.html
[`decode_rules`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/cache/fn.decode_rules.html
[`HirCacheHeader`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/cache/struct.HirCacheHeader.html
[`HIR_SCHEMA_VERSION`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/cache/constant.HIR_SCHEMA_VERSION.html
