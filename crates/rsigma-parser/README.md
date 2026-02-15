# rsigma-parser

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma-parser` is a parser for [Sigma](https://github.com/SigmaHQ/sigma) detection rules, correlations, and filters. It parses Sigma YAML into a strongly-typed AST covering the full Sigma 2.0 specification.

This library is part of [rsigma].

## Parsing

- **Multi-document YAML**: `---` separators, `action: global/reset/repeat` for rule templates
- **Condition expressions**: PEG grammar (pest) with Pratt parsing and correct operator precedence (`NOT` > `AND` > `OR`). Supports `and`, `or`, `not`, `1 of`, `all of`, `any of`, `N of`, parenthesized groups, wildcard patterns — `them` excludes `_`-prefixed identifiers per spec
- **Value types**: strings with wildcards (`*`, `?`), escape sequences (`\*`, `\?`, `\\`), integers, floats, booleans, null
- **Timespan parsing**: `15s`, `30m`, `1h`, `7d`, `1w`, `1M`, `1y`
- **Logsource**: `category`, `product`, `service`, `definition`, custom fields

## Field Modifiers (27)

| Category | Modifiers |
|----------|-----------|
| String matching | `contains`, `startswith`, `endswith` |
| Value linking | `all` |
| Encoding | `base64`, `base64offset`, `wide` / `utf16le`, `utf16be`, `utf16`, `windash` |
| Pattern | `re`, `cidr` |
| Case | `cased` |
| Existence | `exists` |
| Placeholder | `expand` |
| Field reference | `fieldref` |
| Numeric comparison | `gt`, `gte`, `lt`, `lte`, `neq` |
| Regex flags | `i` (ignore case), `m` (multiline), `s` (dotall) |
| Timestamp parts | `minute`, `hour`, `day`, `week`, `month`, `year` |

## Correlation Rules (8 types)

| Type | Description |
|------|-------------|
| `event_count` | Count matching events per group key |
| `value_count` | Count distinct field values per group key |
| `temporal` | Require multiple rules to fire in the same window |
| `temporal_ordered` | Same as temporal, but rules must fire in order |
| `value_sum` | Sum a numeric field across events |
| `value_avg` | Average a numeric field across events |
| `value_percentile` | Compute a percentile of a numeric field |
| `value_median` | Compute the median of a numeric field |

Supports threshold conditions with range predicates (e.g. `gt: 10, lte: 100`), extended boolean conditions for temporal types (e.g. `rule_a and rule_b`), field aliases for cross-rule group-by fields, and correlation chaining.

## Filter Rules

Filter rules inject `AND NOT` conditions into referenced detection rules — enables centralized exclusion management without modifying original rule files. References by rule ID or title, with optional logsource compatibility checks.

## Linter (64 rules)

64 built-in lint rules derived from the Sigma v2.1.0 specification, organized by scope:

| Scope | Count | Examples |
|-------|-------|---------|
| Infrastructure | 4 | YAML parse errors, non-mapping documents, schema violations |
| Shared metadata | 16 | Missing/empty title, missing description/author (Info), invalid UUID, invalid status/level/dates, non-lowercase keys |
| Detection rules | 17 | Missing logsource/detection/condition, invalid tags, unknown condition references |
| Correlation rules | 13 | Missing type/rules/timespan, invalid operators, non-numeric condition values |
| Filter rules | 8 | Missing filter section, filters with level/status, missing logsource |
| Detection logic | 6 | Null in value lists, single-value `\|all`, `\|all`+`\|re` conflict, wildcard-only values |

Four severity levels: **Error** (spec violation), **Warning** (best-practice issue), **Info** (soft suggestion), **Hint** (stylistic). Info/Hint findings don't cause lint failure.

Operates on raw YAML values to catch issues the parser silently ignores. Optionally validates against the official Sigma JSON schema (downloaded and cached for 7 days, with offline fallback to stale cache).

### Rule Suppression

Three-tier system to disable or override lint rules:

- **CLI**: `--disable rule1,rule2` suppresses specific rules globally
- **Config file**: `.rsigma-lint.yml` with `disabled_rules` and `severity_overrides`, auto-discovered by walking ancestor directories
- **Inline comments**: `# rsigma-disable`, `# rsigma-disable rule1, rule2`, `# rsigma-disable-next-line`

```yaml
# .rsigma-lint.yml
disabled_rules:
  - missing_description
  - missing_author
severity_overrides:
  title_too_long: info
```

## Compatibility

Tested against the [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) rule repository:

| Corpus | Rules Parsed | Errors |
|--------|-------------|--------|
| `rules/` | 3,110 | 0 |
| `rules-emerging-threats/` | 436 | 0 |
| `rules-threat-hunting/` | 133 | 0 |
| `rules-compliance/` | 3 | 0 |
| `rules-placeholder/` | 14 | 0 |
| `unsupported/` | 31 | 58 (deprecated pipe syntax) |
| `deprecated/` | 165 | 1 (deprecated pipe syntax) |
| **Total** | **3,892** | **0 real errors** |

The deprecated pipe aggregation syntax (`selection | count(field) by field > N`) is intentionally rejected, matching [pySigma](https://github.com/SigmaHQ/pySigma) behavior.

## Usage

```rust
use rsigma_parser::{parse_sigma_yaml, parse_condition};

let collection = parse_sigma_yaml(yaml).unwrap();
assert_eq!(collection.rules[0].title, "Detect Whoami");

// Parse a condition expression directly
let expr = parse_condition("selection1 and not filter").unwrap();
```

## Benchmarks

Criterion.rs benchmarks with synthetic rules (Apple M-series, single-threaded):

| Scenario | Time |
|----------|------|
| 1 rule | 11.7 us |
| 100 rules | 1.1 ms |
| 1,000 rules | 11.1 ms |
| Complex condition (8 selections, nested booleans) | 23.2 us |

```bash
cargo bench --bench parse
```

## License

MIT License.

[rsigma]: https://github.com/timescale/rsigma
