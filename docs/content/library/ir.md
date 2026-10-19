# `rsigma-ir`

{{ added "0.20.0" }}

Shared intermediate representation (HIR) for Sigma rules. Sits between the parser AST and the eval/convert consumers so modifier resolution happens once.

- [docs.rs/rsigma-ir](https://docs.rs/rsigma-ir)
- [README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-ir/README.md)
- [crates.io/crates/rsigma-ir](https://crates.io/crates/rsigma-ir)

## When to use

- Lower a parsed `SigmaRule` into a modifier-resolved form before custom analysis.
- Share one canonical rule shape between evaluation and query conversion.
- Inspect detections, conditions, correlation, or filter shapes without compiling regex/`IpNet` matchers.

Most embedders never depend on `rsigma-ir` directly: [`rsigma-eval`](eval.md) routes `compile_rule` through `lower_rule` → `compile_to_compiled` already.

## Install

```toml
[dependencies]
rsigma-parser = "{{ rsigma.version }}"
rsigma-ir = "{{ rsigma.version }}"
```

The crate is sync-only (no tokio/reqwest).

## Public surface

| Type / function | Purpose |
|-----------------|---------|
| `IrRule` / `IrDetection` / `IrMatcher` / `IrCondition` | Detection-rule HIR. `IrCondition::Selector` keeps the quantifier and name pattern. |
| `IrMatcher::Str` + `IrPattern` | Faithful, wildcard-aware, original-case string match. |
| `IrMatcher::Encoded` + `IrEncoding` | Explicit encoding transforms (`base64`, `wide`, `windash`, …) over a wildcard-aware `pattern`. {{ added "0.24.0" }} |
| `encoding::expand_encoded` / `encoding::expand_encoded_detections` / `encoding::expand_encoded_matcher` | Replay an `Encoded` matcher into the plain string matches its encodings produce (windash variants, UTF-16, base64 and base64offset), for one value, a whole detection map, or one matcher. Eval compiles them and conversion renders them, so both agree on the variants. `encoding::MAX_WINDASH_DASHES` caps windash expansion. {{ added "0.24.0" }} |
| `IrMatcher::Expand` | A `\|expand` value with placeholders left for match time, with the string operator in `op`. {{ added "0.24.0" }} |
| `IrNumber` / `NumericLiteral` | A numeric matcher value. `NumericLiteral` keeps a rule integer as an exact `i64` and a fractional value as an `f64`, and its `Display` renders integers digit for digit. {{ added "0.25.0" }} |
| `IrCorrelation` / `IrFilter` | Correlation and filter HIR. |
| `IrRuleMetadata` | Metadata superset used when projecting eval `RuleHeader`. |
| `lower_rule` / `lower_detection` / `lower_condition` | AST → HIR. |
| `lower_correlation` / `lower_filter` | Parallel walkers for those shapes. |
| `LowerOptions` | Strict (default) vs placeholder-preserving lowering. |
| `optimize_rule` / `flatten_condition` / `eliminate_dead_detections` | Opt-in, semantics-preserving HIR passes. |
| `common_subexpressions` / `CseReport` | Non-mutating analysis of repeated detection items. |
| `encode_rules` / `decode_rules` / `HirCacheHeader` | Versioned HIR cache (CBOR) with a schema-version check. |

## HIR cache

`cache::*` serializes lowered rules to a versioned, self-describing blob, the on-disk HIR cache. It is what [`rsigma-eval`](eval.md)'s `Engine::save_hir` / `load_hir` use for a restart cache that skips parse, pipeline, and lowering; the engine keeps the HIR to save only after `Engine::set_retain_hir(true)`.

- The blob is a `HirCacheHeader` (schema version + producing crate version) followed by the rules. `decode_rules` reads and version-checks the header before decoding the rules, rejecting a blob written under an incompatible `HIR_SCHEMA_VERSION`.
- CBOR is the binary format: the HIR embeds `LogSource`, whose `#[serde(flatten)]` custom-key map serializes with an unknown length that fixed-layout encoders reject.
- `cache::to_json` gives a human-readable debug export of the same header-plus-rules shape.
- All HIR types derive `serde::{Serialize, Deserialize}`; the embedded `rsigma-parser` types gained `Deserialize` so the HIR round-trips.

## Optimization passes

`optimize::*` provides opt-in, total functions on the HIR for offline tooling (pack building, analysis). They are **not** run by the default eval or convert paths, so compiled-matcher behavior and byte-identical backend output are unchanged.

- `flatten_condition` merges nested same-kind boolean groups, collapses `Not(Not(x))`, unwraps single-child `And`/`Or`, and drops idempotent duplicate siblings.
- `eliminate_dead_detections` removes detections no condition can reference (honoring `them`/glob selector patterns) and recurses into `Conditional` bodies.
- `common_subexpressions` reports detection items that occur more than once, the candidates a consumer could evaluate once and share.
- `optimize_rule` applies the two structural passes in order.

Each pass preserves the match decision and the set of matched selections and fields. Reported order and multiplicity of matched selections are not part of the contract: dropping a duplicate reference reports a selection once, and pruning changes a selector's `HashMap`-ordered reporting.

## Lowering notes

- Lowering is **purely structural**: it resolves *which* comparison applies but never lowercases, compiles regexes, or expands encodings. Eval does that at compile time; convert expands encodings with `encoding::expand_encoded_detections` and renders wildcards to backend tokens. This keeps the HIR lossless.
- Selectors such as `1 of selection_*` and `all of them` are preserved as `IrCondition::Selector`, so evaluation stays count-based and reports every matching detection. `them` and every pattern that does not start with `_` skip `_`-prefixed detection names; a pattern that starts with `_`, such as `1 of _filter*`, selects them. A selector that matches no detection name fails lowering with `IrError::NoSelectorMatches`, so evaluation and conversion reject the rule alike. {{ added "0.24.0" }}
- Modifier contradictions (`|cidr|contains`, `|base64|base64offset`, …) fail at lower time with the same error kinds eval previously surfaced from `compile_rule`. So do values an encoding cannot represent: a wildcard under `|base64` or `|base64offset`, and a non-ASCII value under a UTF-16 encoding with no base64 step. {{ added "0.24.0" }}
- An `|expand` value whose placeholders are all resolved by the pipeline lowers to an ordinary string matcher; only values with placeholders left become `IrMatcher::Expand`. {{ added "0.24.0" }}
- An empty value list (`Field: []`) lowers to `IrMatcher::Null`, or `Not(Null)` under `|neq`. {{ added "0.24.0" }}

## Related

- [`rsigma-eval`](eval.md): `compile_rule` (IR path) and `Engine::save_hir` / `load_hir` (HIR restart cache).
- [`rsigma-parser`](parser.md): source AST.
