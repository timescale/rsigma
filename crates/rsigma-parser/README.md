# rsigma-parser

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma-parser` is a parser for [Sigma](https://github.com/SigmaHQ/sigma) detection rules, correlations, and filters. It parses Sigma YAML into a strongly-typed AST covering the full Sigma 2.0 specification, and includes a 64-rule linter derived from the Sigma v2.1.0 spec.

This library is part of [rsigma].

## Public API

### Parsing

| Function | Description |
|----------|-------------|
| `parse_sigma_yaml(yaml: &str)` | Parse a multi-document YAML string into a `SigmaCollection` |
| `parse_sigma_file(path: &Path)` | Parse a single YAML file |
| `parse_sigma_directory(dir: &Path)` | Recursively parse all `.yml`/`.yaml` files in a directory |
| `parse_condition(input: &str)` | Parse a condition expression string into a `ConditionExpr` |
| `parse_field_spec(key: &str)` | Parse a field specification like `"CommandLine\|contains\|all"` into a `FieldSpec` |

### Linting

| Function | Description |
|----------|-------------|
| `lint_yaml_value(value: &Value)` | Lint a single YAML document value (auto-detects document type) |
| `lint_yaml_str(text: &str)` | Lint raw YAML string with source span resolution |
| `lint_yaml_str_with_config(text: &str, config: &LintConfig)` | Lint with config-based suppression |
| `lint_yaml_file(path: &Path)` | Lint all documents in a file |
| `lint_yaml_file_with_config(path: &Path, config: &LintConfig)` | Lint a file with config |
| `lint_yaml_directory(dir: &Path)` | Recursively lint all `.yml`/`.yaml` in a directory |
| `lint_yaml_directory_with_config(dir: &Path, config: &LintConfig)` | Lint a directory with config |
| `parse_inline_suppressions(text: &str)` | Parse `# rsigma-disable` comments from YAML text |
| `apply_suppressions(warnings, config, inline)` | Filter and override warnings using config and inline suppressions |

### Value Types

| Type/Function | Description |
|---------------|-------------|
| `SigmaString::new(s: &str)` | Parse a string with wildcard interpretation (`*`, `?`, `\` escape) |
| `SigmaString::from_raw(s: &str)` | Create from raw string (no wildcard parsing; used for `\|re` modifier) |
| `SigmaString::is_plain()` | Returns `true` if no wildcards |
| `SigmaString::contains_wildcards()` | Returns `true` if any wildcard present |
| `SigmaString::as_plain()` | Get plain string; `None` if wildcards present |
| `SigmaValue::from_yaml(v: &Value)` | Create from a YAML value |
| `Timespan::parse(s: &str)` | Parse timespan like `1h`, `15s`, `7d` |

## Parsing

- **Multi-document YAML**: `---` separators, `action: global/reset/repeat` for rule templates
- **Condition expressions**: PEG grammar (pest) with Pratt parsing and correct operator precedence (`NOT` > `AND` > `OR`). Supports `and`, `or`, `not`, `1 of`, `all of`, `any of`, `N of`, parenthesized groups, wildcard patterns — `them` excludes `_`-prefixed identifiers per spec
- **Value types**: strings with wildcards (`*`, `?`), escape sequences (`\*`, `\?`, `\\`), integers, floats, booleans, null
- **Timespan parsing**: `15s`, `30m`, `1h`, `7d`, `1w`, `1M`, `1y`
- **Logsource**: `category`, `product`, `service`, `definition`, custom fields

### Multi-Document Behavior

1. `serde_yaml::Deserializer` yields documents separated by `---`.
2. Non-mapping documents are skipped; errors are accumulated in `collection.errors`.
3. YAML parse errors stop iteration (the deserializer may not recover from malformed input).
4. **Collection actions:**
   - `action: global` — store document as a template; remove `action` key; do not produce a rule.
   - `action: reset` — clear the global template.
   - `action: repeat` — merge current document onto the previous document; apply global template if present; parse the merged result. Error if no previous document exists.
5. **Merge order:** For normal documents: `merged = deep_merge(global, value)`. For repeat: `merged = deep_merge(global, deep_merge(previous, repeat_doc))`.
6. **`deep_merge`:** Recursive. Source mappings override destination keys; non-mapping source replaces destination entirely.
7. **Previous tracking:** Updated after each non-action document and after each repeat. Repeat chains from the *last* document, not the original.

### SigmaString Escape Semantics

| Input | Parsed as |
|-------|-----------|
| `\*` | literal `*` (not a wildcard) |
| `\?` | literal `?` (not a wildcard) |
| `\\` | literal `\` |
| `\W` (non-special) | literal `\W` (both characters kept) |

Backslash only consumes itself when followed by `*`, `?`, or `\`. This preserves Windows paths like `\Windows\System32`.

### Condition Expression Grammar (PEG)

The full PEG grammar is defined in [`src/sigma.pest`](src/sigma.pest). It implements the [Sigma condition expression syntax](https://sigmahq.io/docs/basics/conditions.html) using a Pratt parser with `not` > `and` > `or` precedence.

**Parsing quirks:**

- `!ident_char` lookahead ensures `and_filter` parses as a single identifier, not `and` + `filter`.
- `1 of` and `any of` both map to `Quantifier::Any`.
- Nested same-type binary ops are flattened: `a and b and c` becomes `And([a, b, c])`, not `And(a, And(b, c))`.

### Operator Precedence

| Precedence (highest first) | Operator | Associativity |
|---------------------------|----------|---------------|
| 1 | `not` (prefix) | — |
| 2 | `and` (infix) | Left |
| 3 | `or` (infix) | Left |

`a or not b and c` parses as `a or ((not b) and c)`.

## AST Types

### Core Types

| Type | Description |
|------|-------------|
| `SigmaCollection` | Collection of rules, correlations, filters, and errors |
| `SigmaRule` | A parsed detection rule with metadata, logsource, and detections |
| `CorrelationRule` | A correlation rule with type, referenced rules, timespan, and conditions |
| `FilterRule` | A filter rule that injects `AND NOT` conditions into referenced rules |
| `Detections` | Named detections, condition expressions, and optional timeframe |
| `Detection` | `AllOf` (AND-linked items), `AnyOf` (OR-linked), or `Keywords` (plain values) |
| `FieldSpec` | Field name + modifier chain; `name` is `None` for keyword detections |
| `ConditionExpr` | `And`, `Or`, `Not`, `Identifier`, or `Selector` with quantifier and pattern |
| `SigmaValue` | `String`, `Integer`, `Float`, `Bool`, or `Null` |
| `SigmaString` | String with wildcard parts (`Plain` text + `WildcardMulti`/`WildcardSingle`) |

### Enums

| Enum | Variants |
|------|----------|
| `Status` | `Stable`, `Test`, `Experimental`, `Deprecated`, `Unsupported` |
| `Level` | `Informational`, `Low`, `Medium`, `High`, `Critical` |
| `RelationType` | `Derived`, `Obsolete`, `Merged`, `Renamed`, `Similar` |
| `Quantifier` | `Any`, `All`, `Count(u64)` |
| `SelectorPattern` | `Them`, `Pattern(String)` |
| `CorrelationType` | `EventCount`, `ValueCount`, `Temporal`, `TemporalOrdered`, `ValueSum`, `ValueAvg`, `ValuePercentile`, `ValueMedian` |

### Detection Parsing

- **YAML mapping** → `Detection::AllOf` (AND-linked items)
- **YAML list of mappings** → `Detection::AnyOf` (OR-linked)
- **YAML list of plain values** → `Detection::Keywords` (keyword search across all fields)
- **Condition as list** (`condition: [s1, s2]`) → multiple `ConditionExpr` parsed independently
- **Empty field name** (`parse_field_spec("")`) → `FieldSpec { name: None, modifiers: [] }` (keyword)

## Field Modifiers (30)

The parser recognizes 30 modifier variants, some with aliases:

| Category | Modifiers | Aliases |
|----------|-----------|---------|
| String matching | `contains`, `startswith`, `endswith` | — |
| Value linking | `all` | — |
| Encoding | `base64`, `base64offset`, `wide`, `utf16be`, `utf16`, `windash` | `utf16le` → `wide` |
| Pattern | `re`, `cidr` | — |
| Case | `cased` | — |
| Existence | `exists` | — |
| Placeholder | `expand` | — |
| Field reference | `fieldref` | — |
| Numeric comparison | `gt`, `gte`, `lt`, `lte`, `neq` | — |
| Regex flags | `i`, `m`, `s` | `ignorecase` → `i`, `multiline` → `m`, `dotall` → `s` |
| Timestamp parts | `minute`, `hour`, `day`, `week`, `month`, `year` | — |

When the `re` modifier is present, string values are parsed with `SigmaValue::from_raw_string` (no wildcard interpretation).

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

### Correlation Conditions

- **Threshold (mapping):** `{ gte: 100 }` or `{ gt: 10, lte: 100, field: "TargetUser" }`. Operators: `lt`, `lte`, `gt`, `gte`, `eq`, `neq`. Values must be numeric.
- **Extended (string):** `"rule_a and rule_b"` for temporal types — parsed as a boolean expression over rule references.
- **Default (temporal, no condition):** `Threshold { predicates: [(Gte, 1)], field: None }`.
- **Timeframe/timespan:** The parser accepts both `timeframe` and `timespan` keys.
- **Custom attributes:** Correlation rules support a `custom_attributes` mapping (string-to-string) for `rsigma.*` engine extensions.

## Filter Rules

Filter rules inject exclusion conditions into referenced detection rules — enables centralized tuning without modifying original rule files. See the [Sigma Filters Specification](https://sigmahq.io/sigma-specification/specification/sigma-filters-specification.html) for the full standard.

Per the spec, `selection`, `condition`, and `rules` all live inside the `filter` section:

```yaml
title: Exclude Admin Users
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - <rule-id>
    selection:
        User|startswith: 'adm_'
    condition: selection
```

## Timespan Parsing

| Unit | Suffix | Multiplier (seconds) |
|------|--------|----------------------|
| Second | `s` | 1 |
| Minute | `m` | 60 |
| Hour | `h` | 3,600 |
| Day | `d` | 86,400 |
| Week | `w` | 604,800 |
| Month | `M` (uppercase) | 2,629,746 (~30.44 days) |
| Year | `y` | 31,556,952 (~365.25 days) |

The string must be at least 2 characters (e.g. `1h`). The last character is the unit; the prefix must be a positive integer.

## Linter (64 rules)

64 built-in lint rules derived from the Sigma v2.1.0 specification. Four severity levels: **Error** (spec violation), **Warning** (best-practice issue), **Info** (soft suggestion), **Hint** (stylistic). Info/Hint findings don't cause lint failure.

The linter operates on raw YAML values to catch issues the parser silently ignores.

### Infrastructure (4)

| Rule | Severity | Trigger |
|------|----------|---------|
| `yaml_parse_error` | Error | YAML parse failure |
| `not_a_mapping` | Error | Document is not a YAML mapping |
| `file_read_error` | Error | Cannot read file |
| `schema_violation` | Error | JSON schema validation failure (optional) |

### Shared Metadata (16)

| Rule | Severity | Trigger |
|------|----------|---------|
| `missing_title` | Error | No `title` field |
| `empty_title` | Error | `title` is empty or whitespace |
| `title_too_long` | Warning | `title` exceeds 256 characters |
| `missing_description` | Info | No `description` |
| `missing_author` | Info | No `author` |
| `invalid_id` | Warning | `id` not a valid UUID (8-4-4-4-12 hex) |
| `invalid_status` | Error | `status` not in `stable`/`test`/`experimental`/`deprecated`/`unsupported` |
| `missing_level` | Warning | No `level` (detection rules) |
| `invalid_level` | Error | `level` not in `informational`/`low`/`medium`/`high`/`critical` |
| `invalid_date` | Error | `date` not `YYYY-MM-DD` with valid day-of-month |
| `invalid_modified` | Error | `modified` not `YYYY-MM-DD` |
| `modified_before_date` | Warning | `modified` is earlier than `date` |
| `description_too_long` | Warning | `description` exceeds 65,535 characters |
| `name_too_long` | Warning | `name` exceeds 256 characters |
| `taxonomy_too_long` | Warning | `taxonomy` exceeds 256 characters |
| `non_lowercase_key` | Warning | Top-level key is not lowercase |

### Detection Rules (17)

| Rule | Severity | Trigger |
|------|----------|---------|
| `missing_logsource` | Error | No `logsource` |
| `missing_detection` | Error | No `detection` |
| `missing_condition` | Error | No `condition` in detection |
| `empty_detection` | Warning | No named search identifiers |
| `invalid_related_type` | Error | `related[].type` not in `derived`/`obsolete`/`merged`/`renamed`/`similar` |
| `invalid_related_id` | Warning | `related[].id` not a valid UUID |
| `related_missing_required` | Error | `related[]` missing `id` or `type` |
| `deprecated_without_related` | Warning | `status: deprecated` but no `related` |
| `invalid_tag` | Warning | Tag doesn't match `^[a-z0-9_-]+\.[a-z0-9._-]+$` |
| `unknown_tag_namespace` | Warning | Tag namespace not in `attack`/`car`/`cve`/`d3fend`/`detection`/`stp`/`tlp` |
| `duplicate_tags` | Warning | Duplicate tag |
| `duplicate_references` | Warning | Duplicate reference URL |
| `duplicate_fields` | Warning | Duplicate field name |
| `falsepositive_too_short` | Warning | `falsepositives` entry under 2 characters |
| `scope_too_short` | Warning | `scope` entry under 2 characters |
| `logsource_value_not_lowercase` | Warning | Logsource `category`/`product`/`service` not lowercase |
| `condition_references_unknown` | Error | Condition references non-existent detection identifier |

### Correlation Rules (13)

| Rule | Severity | Trigger |
|------|----------|---------|
| `missing_correlation` | Error | No `correlation` or not a mapping |
| `missing_correlation_type` | Error | No `correlation.type` |
| `invalid_correlation_type` | Error | Type not a recognized correlation type |
| `missing_correlation_rules` | Error | No `correlation.rules` |
| `empty_correlation_rules` | Warning | `correlation.rules` is empty |
| `missing_correlation_timespan` | Error | No `correlation.timespan` or `correlation.timeframe` |
| `invalid_timespan_format` | Error | Timespan format invalid |
| `missing_group_by` | Error | No `correlation.group-by` |
| `missing_correlation_condition` | Error | Non-temporal type without condition |
| `missing_condition_field` | Error | `value_count`/`value_sum`/`value_avg`/`value_percentile` without `condition.field` |
| `invalid_condition_operator` | Error | Operator not in `gt`/`gte`/`lt`/`lte`/`eq`/`neq` |
| `condition_value_not_numeric` | Error | Condition value not numeric |
| `generate_not_boolean` | Error | `generate` is not a boolean |

### Filter Rules (8)

| Rule | Severity | Trigger |
|------|----------|---------|
| `missing_filter` | Error | No `filter` or not a mapping |
| `missing_filter_rules` | Error | No `filter.rules` |
| `empty_filter_rules` | Warning | `filter.rules` is empty |
| `missing_filter_selection` | Error | No `filter.selection` |
| `missing_filter_condition` | Error | No `filter.condition` |
| `filter_has_level` | Warning | Filter has `level` (not applicable) |
| `filter_has_status` | Warning | Filter has `status` (not applicable) |
| `missing_filter_logsource` | Warning | No `logsource` |

### Detection Logic (6)

| Rule | Severity | Trigger |
|------|----------|---------|
| `null_in_value_list` | Warning | `null` mixed with other values in a list |
| `single_value_all_modifier` | Warning | `\|all` with a single value |
| `all_with_re` | Warning | `\|all` and `\|re` combined |
| `empty_value_list` | Warning | Empty value list |
| `wildcard_only_value` | Warning | Lone `*` value (suggests `\|exists: true` instead) |
| `unknown_key` | Warning | Unrecognized top-level key |

### Rule Suppression

Three-tier system to disable or override lint rules:

- **CLI**: `--disable rule1,rule2` suppresses specific rules globally
- **Config file**: `.rsigma-lint.yml` (or `.rsigma-lint.yaml`) with `disabled_rules` and `severity_overrides`, auto-discovered by walking ancestor directories from the target path upward
- **Inline comments**: `# rsigma-disable`, `# rsigma-disable rule1, rule2`, `# rsigma-disable-next-line`, `# rsigma-disable-next-line rule1, rule2`

```yaml
# .rsigma-lint.yml
disabled_rules:
  - missing_description
  - missing_author
severity_overrides:
  title_too_long: info
```

**Suppression order:** Warnings are first filtered by `disabled_rules`, then by inline suppressions, then `severity_overrides` are applied to remaining warnings.

Inline `#` inside quoted YAML strings is not treated as a comment.

### Optional Schema Validation

The `schema_violation` lint rule optionally validates rules against a JSON schema. The schema can be the official Sigma schema (downloaded and cached for 7 days, with offline fallback to stale cache) or a local file.

## Directory Parsing and Linting

- **`parse_sigma_directory`:** Recursively walks directories; only processes `.yml`/`.yaml` files. File-level parse errors are accumulated in `collection.errors` (not fatal). Sub-collections (rules, correlations, filters) are merged.
- **`lint_yaml_directory`:** Skips hidden directories (`.` prefix). Canonicalizes paths to detect symlink cycles. Sorts entries by path for deterministic output.

## Error Types

| Error | When |
|-------|------|
| `Yaml` | serde_yaml parse failure |
| `Condition` | Condition expression parse failure (PEG/Pratt) |
| `UnknownModifier` | Unknown modifier in field spec |
| `InvalidFieldSpec` | Invalid field specification |
| `InvalidRule` | Document not a mapping, or invalid structure |
| `MissingField` | Required field missing (e.g. `title`, `detection`) |
| `InvalidDetection` | Detection section invalid |
| `InvalidCorrelation` | Correlation rule invalid |
| `InvalidTimespan` | Timespan string invalid (wrong format, unknown unit) |
| `InvalidValue` | Invalid value in detection |
| `InvalidAction` | Unknown collection action |
| `Io` | File read error |

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
