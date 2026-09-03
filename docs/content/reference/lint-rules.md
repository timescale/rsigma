# Lint Rules

`rsigma rule lint` runs {{ rsigma.lint.rules }} built-in checks derived from the Sigma v2.1.0 specification, plus {{ rsigma.lint.reserved }} reserved enum value (`empty_filter_rules`) that no production code currently emits. This page is the canonical catalog: every rule's ID, default severity, what it flags, and whether `--fix` can auto-correct it.

For the workflow and CLI surface see [Linting Rules](../guide/linting-rules.md) and the [`rule lint` CLI reference](../cli/rule/lint.md). For the source of truth see [`crates/rsigma-parser/src/lint`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-parser/src/lint).

## Severities

| Severity | Meaning | Default `--fail-level` exit |
|----------|---------|------------------------------|
| `error` | Spec violation. The rule cannot parse, compile, or run correctly. | Exits 1 by default (`--fail-level error`). |
| `warning` | Best-practice issue. The rule runs but should be cleaned up. | Does not fail by default. |
| `info` | Soft suggestion. Cosmetic or documentation. | Does not fail by default. |
| `hint` | Stylistic suggestion below `info`. Never triggers a non-zero exit, even with `--fail-level info`. | Never fails. |

Override the threshold with `--fail-level warning` or `--fail-level info`. See [Linting Rules: severity gate](../guide/linting-rules.md#severities-and-the-fail-level-gate).

## Counts at a glance

| Severity | Rules |
|----------|------:|
| `error` | 38 |
| `warning` | 43 |
| `info` | 6 |
| `hint` | 0 |
| Reserved (no production emission) | {{ rsigma.lint.reserved }} |
| **Total** | **{{ rsigma.lint.total }}** ({{ rsigma.lint.autofix }} of which have safe auto-fixes via `--fix`) |

The `hint` severity is defined but not used by any of the shipped rules.

### The {{ rsigma.lint.autofix }} safe-fix rules

| Rule | Severity | What the fix does |
|------|----------|-------------------|
| `invalid_status` | `error` | Replace the bad status value with the closest valid one (`stable`, `test`, `experimental`, `deprecated`, `unsupported`). |
| `invalid_level` | `error` | Replace the bad level with the closest valid one (`informational`, `low`, `medium`, `high`, `critical`). |
| `non_lowercase_key` | `warning` | Lowercase the offending key. |
| `logsource_value_not_lowercase` | `warning` | Lowercase the offending `category`/`product`/`service` value. |
| `duplicate_tags` | `warning` | Remove the duplicate tag entry. |
| `duplicate_references` | `warning` | Remove the duplicate URL. |
| `duplicate_fields` | `warning` | Remove the duplicate entry from the top-level `fields:` list. |
| `single_value_all_modifier` | `warning` | Remove the redundant `all` modifier on a single-value item. |
| `all_with_re` | `warning` | Remove the redundant `all` modifier when used alongside `re`. |
| `wildcard_only_value` | `warning` | Replace the lone `*` value with `exists: true`. |
| `filter_has_level` | `warning` | Remove the inapplicable `level:` from the filter rule. |
| `filter_has_status` | `warning` | Remove the inapplicable `status:` from the filter rule. |
| `unknown_key` | `info` | Replace a typo'd key with the closest known key (when the edit distance is small). |
| `ads_unknown_section` | `info` | Rename an unrecognized `rsigma.ads.*` key to the closest known ADS section (when the edit distance is small). |

## Infrastructure rules (4)

Fired by the linter's loader and runner before per-rule checks even start. Cannot be suppressed with inline comments because the rule never gets parsed.

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `yaml_parse_error` | `error` | none | The file contains malformed YAML that the parser cannot recover. |
| `not_a_mapping` | `error` | none | The top-level YAML document is a sequence or scalar instead of a mapping. |
| `file_read_error` | `error` | none | The lint path could not be opened (IO error, permission denied). |
| `schema_violation` | `error` | none | When `--schema` is set, the rule fails the JSON schema. Schema violations attach the JSON schema error message verbatim. |

## Shared metadata rules (17)

Apply to detection, correlation, and filter rules alike.

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `missing_title` | `error` | none | Rule has no `title:` field. |
| `empty_title` | `error` | none | `title:` is present but empty. |
| `title_too_long` | `warning` | none | `title:` exceeds 256 characters. |
| `name_too_long` | `warning` | none | A `name:` field (e.g. on a correlation reference) exceeds 256 characters. |
| `missing_author` | `info` | none | The rule has no `author:` field. |
| `missing_description` | `info` | none | The rule has no `description:` field. |
| `description_too_long` | `warning` | none | `description:` exceeds 65535 characters. |
| `invalid_status` | `error` | yes | `status:` is not one of `stable`, `test`, `experimental`, `deprecated`, `unsupported`. The fix replaces it with the closest match. |
| `invalid_level` | `error` | yes | `level:` is not one of `informational`, `low`, `medium`, `high`, `critical`. The fix replaces it with the closest match. |
| `missing_level` | `warning` | none | The rule has no `level:` field. |
| `invalid_date` | `error` | none | `date:` is not `YYYY-MM-DD`. |
| `invalid_modified` | `error` | none | `modified:` is not `YYYY-MM-DD`. |
| `modified_before_date` | `warning` | none | `modified:` is earlier than `date:`. |
| `invalid_id` | `warning` | none | `id:` is not a valid UUID. Replace it with a freshly generated UUIDv4 manually. |
| `taxonomy_too_long` | `warning` | none | Top-level `taxonomy:` exceeds 256 characters. |
| `non_lowercase_key` | `warning` | yes | A top-level key uses non-lowercase characters (e.g. `Title:` instead of `title:`). The fix lowercases the key. |
| `unknown_key` | `info` | yes | An unrecognized top-level key. The fix suggests the closest known key when the edit distance is small (e.g. `descirption` → `description`). |

## Detection rules (18)

Apply to detection rules (`detection:` block + `condition:`).

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `missing_detection` | `error` | none | The rule has no `detection:` block. |
| `empty_detection` | `warning` | none | `detection:` is present but empty. |
| `missing_condition` | `error` | none | `detection:` has no `condition:` key. |
| `missing_logsource` | `error` | none | The rule has no `logsource:` block. |
| `logsource_value_not_lowercase` | `warning` | yes | A `logsource.category/product/service` value uses non-lowercase characters. The fix lowercases the value. |
| `duplicate_fields` | `warning` | yes | The top-level `fields:` list contains the same name twice. The fix removes the duplicate entry. |
| `duplicate_references` | `warning` | yes | `references:` contains the same URL twice. The fix dedupes. |
| `duplicate_tags` | `warning` | yes | `tags:` contains the same tag twice. The fix dedupes. |
| `invalid_tag` | `warning` | none | A tag value does not match the Sigma tag spec (`namespace.value`). |
| `unknown_tag_namespace` | `warning` | none | A tag uses a namespace outside the recognized set (`attack`, `cve`, `detection`, `tlp`, `stp`, `informational`). |
| `falsepositive_too_short` | `warning` | none | A `falsepositives:` entry is shorter than 2 characters. |
| `scope_too_short` | `warning` | none | A top-level `scope:` list entry is shorter than 2 characters. |
| `wildcard_only_value` | `warning` | yes | A detection value is just `*`. The fix replaces it with `exists: true`, which is what the author almost certainly meant. |
| `null_in_value_list` | `warning` | none | A `null` literal appears inside a list of values. Sigma's semantics around `null` in lists are spec-ambiguous; this flags the case so the author can be explicit. |
| `empty_value_list` | `warning` | none | A detection item with a list value is empty. |
| `condition_references_unknown` | `error` | none | The `condition:` expression references a selection name that is not in `detection:`. |
| `deprecated_aggregation_syntax` | `warning` | none | The condition uses the deprecated aggregation pipe syntax (`condition: selection \| count() > 5`). Use the modern `correlation:` block instead. |
| `flattened_array_correlation` | `warning` | none | Two or more sibling keys share a quantified array prefix (e.g. `connections[any].protocol` and `connections[any].ip`). Each opens an independent scope, so they do **not** correlate on the same array element. Use an object-scope block (`connections[any]:` with the fields nested) to require one element to satisfy all of them. See [Array Matching](../guide/array-matching.md). |

## Correlation rules (17)

Apply to correlation rules (`correlation:` block).

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `missing_correlation` | `error` | none | A `kind: correlation` rule has no `correlation:` block. |
| `missing_correlation_type` | `error` | none | `correlation:` has no `type:`. |
| `invalid_correlation_type` | `error` | none | `correlation.type:` is not one of `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`, `value_median`. |
| `missing_correlation_rules` | `error` | none | `correlation:` has no `rules:` list. |
| `empty_correlation_rules` | `warning` | none | `correlation.rules:` is present but empty. |
| `missing_correlation_timespan` | `error` | none | `correlation:` has no `timespan:`. |
| `invalid_timespan_format` | `error` | none | `timespan:` is not a valid duration (`5m`, `1h`, `30s`). |
| `invalid_window_mode` | `error` | none | `correlation.window:` is not one of `sliding`, `tumbling`, `session`. |
| `missing_session_gap` | `error` | none | `window: session` without a `gap:`. A session window needs an inactivity timeout. |
| `gap_without_session` | `error` | none | `gap:` is set without `window: session`. The gap only applies to session windows. |
| `invalid_gap_format` | `error` | none | `gap:` is not a valid duration (`5m`, `1h`, `30s`). |
| `missing_correlation_condition` | `error` | none | `correlation:` has no `condition:` block. |
| `missing_condition_field` | `error` | none | `correlation.condition` is missing `field:` for types that require it (`value_count`, `value_sum`, `value_avg`, `value_percentile`). |
| `condition_value_not_numeric` | `error` | none | The numeric threshold in `correlation.condition` is not a number. |
| `missing_group_by` | `error` | none | `correlation:` has no `group-by:` (required once `type:` is set). |
| `generate_not_boolean` | `error` | none | The `generate:` field is not a boolean. |
| `invalid_condition_operator` | `error` | none | A key in `correlation.condition` is not one of `gt`, `gte`, `lt`, `lte`, `eq`, `neq` (the `field` key is exempt). |

## Filter rules (8 IDs, 7 emitted)

Apply to filter rules (`kind: filter` with a `filter:` block). The eighth row (`empty_filter_rules`) is reserved: the variant exists in the lint-rule enum and is asserted in a regression test, but no production code path emits it today.

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `missing_filter` | `error` | none | A `kind: filter` rule has no `filter:` block. |
| `missing_filter_logsource` | `error` | none | Filter rule has no `logsource:`. |
| `missing_filter_rules` | `error` | none | `filter.rules` is present but not a list of rule IDs, a single rule ID string, or `any`. Absence of `rules` is allowed. |
| `missing_filter_selection` | `error` | none | `filter:` has no `selection:` block. |
| `missing_filter_condition` | `error` | none | `filter:` has no `condition:`. |
| `filter_has_level` | `warning` | yes | Filter rules should not carry `level:`. The fix removes the field. |
| `filter_has_status` | `warning` | yes | Filter rules should not carry `status:`. The fix removes the field. |
| `empty_filter_rules` | reserved | none | Variant declared in the enum and asserted in a regression test, but no production code emits it today. |

## Modifier and `related:` hygiene (7)

These also apply to detection rules but sit apart from the core detection-block checks above: modifier-misuse checks on a single detection item (`single_value_all_modifier`, `all_with_re`, `incompatible_modifiers`) and validation of the `related:` cross-reference block.

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `single_value_all_modifier` | `warning` | yes | A single-value detection item carries the `\|all` modifier, which is a no-op. The fix removes the redundant modifier. |
| `all_with_re` | `warning` | yes | The `\|all` modifier is combined with `\|re`, which is not meaningful (regex matching is inherently set-style). The fix removes `\|all`. |
| `incompatible_modifiers` | `warning` | none | Two modifiers on the same field are mutually exclusive (e.g. `\|contains\|startswith`). |
| `invalid_related_id` | `warning` | none | `related[].id` is not a valid UUID. |
| `invalid_related_type` | `error` | none | `related[].type` is not one of `derived`, `obsolete`, `merged`, `renamed`, `similar`. |
| `related_missing_required` | `error` | none | `related[]` entry is missing the required `id:` or `type:` field. |
| `deprecated_without_related` | `warning` | none | A rule with `status: deprecated` should declare `related:` pointing at the replacement. |

## Specification version and rule references (4)

The first two apply to any document type, based on the top-level `sigma-version` attribute (the Sigma specification major the document targets); see [Array Matching: requires `sigma-version: 3`](../guide/array-matching.md#requires-sigma-version-3). The last two resolve cross-document references (a correlation rule and the rules it aggregates, a filter and the rules it targets) by `id` or `name`. Reference resolution spans the whole directory when linting a directory; for a single file or string, only references to rules in the same input are resolved, and `unknown_rule_reference` is suppressed (the target may live in a file outside the linted scope).

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `unsupported_sigma_version` | `error` | none | `sigma-version` declares a specification major newer than this build implements, so the document cannot be interpreted correctly. Upgrade RSigma or target a supported major. |
| `array_matching_without_version` | `warning` | none | The document uses array-matching selector syntax (`field[any]`, `args[0]`, ...) but resolves below the major that enables it (absent or `sigma-version: 2`), so the brackets are read as literal field-name characters. Add `sigma-version: 3` to read them as array selectors, or escape the brackets (`\[` / `\]`) to keep them literal. |
| `sigma_version_mismatch` | `warning` | none | A correlation or filter and a rule it references declare different `sigma-version` majors. Cross-referencing rules must share a specification major, since the referencing rule's semantics depend on a consistent reading of the referenced ones. |
| `unknown_rule_reference` | `warning` | none | A correlation's `rules:` or a filter's `rules:` entry references a rule (by `id` or `name`) that does not exist among the linted rules. Only emitted when linting a directory, where the rule index is complete. |

## ADS detection-strategy metadata (11)

Optional [Alerting and Detection Strategy](https://github.com/palantir/alerting-detection-strategy-framework) checks. They are opt-in: nothing fires until an `ads:` block is present in the layered `.rsigma-lint.yml`. When enabled, they fire only on detection rules whose `status` is in the configured `enforce_status` set (default `[stable]`) and skip any rule carrying `rsigma.ads.exempt: true`. Four ADS sections reuse standard fields (`description`, `attack.*` `tags`, `falsepositives`, `level`); the rest live under a `rsigma.ads.*` custom-attribute namespace. See [Detection Strategy](../guide/detection-strategy.md) and [Custom Attributes](custom-attributes.md#ads-detection-strategy-attributes-rsigmaads).

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `ads_missing_goal` | `warning` | none | An enforced rule has no goal (`description`). |
| `ads_missing_categorization` | `warning` | none | An enforced rule has no ATT&CK categorization (no `attack.*` tag, nor a tag in a configured `tag_namespaces` namespace). |
| `ads_missing_strategy` | `warning` | none | No `rsigma.ads.strategy` abstract. |
| `ads_missing_technical_context` | `warning` | none | No `rsigma.ads.technical_context`. |
| `ads_missing_blind_spots` | `warning` | none | No `rsigma.ads.blind_spots` list. |
| `ads_missing_false_positives` | `warning` | none | An enforced rule has no false-positive notes (`falsepositives`). |
| `ads_missing_validation` | `warning` | none | No `rsigma.ads.validation` recipe and no structurally valid `expect: match` exemplar. |
| `ads_missing_priority` | `info` | none | No `rsigma.ads.priority` rationale (the `level` field still covers severity). |
| `ads_missing_response` | `warning` | none | No `rsigma.ads.response` plan. |
| `ads_empty_section` | `info` | none | A present `rsigma.ads.*` section is blank or too short. |
| `ads_unknown_section` | `info` | yes | An unrecognized `rsigma.ads.*` key (likely a typo). The fix renames it to the closest known section. |

## Embedded exemplars (2)

Static shape checks for [`rsigma.exemplars`](custom-attributes.md#rsigmaexemplars). Lint never executes events. Presence of a valid `expect: match` exemplar also satisfies ADS validation (see above); only `rsigma rule test` proves the current rule still matches.

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `exemplar_shape` | `warning` | none | The attribute is not a sequence, an entry is not a mapping, a key is unknown, a name is blank or duplicated, `expect` is missing or invalid, `event`/`events` is missing or both are set, an event is not a mapping, an offset is invalid or decreasing, or the list is empty. |
| `exemplar_wrong_rule_kind` | `warning` | none | A detection rule uses `events`, a correlation rule uses `event`, or a filter rule carries any exemplars. |

Configure the bar with an `ads:` block in `.rsigma-lint.yml`:

```yaml
ads:
  enforce_status: [stable]   # statuses that require ADS sections
  required:                  # mandatory sections (defaults to all nine)
    - goal
    - categorization
    - strategy
    - technical_context
    - blind_spots
    - false_positives
    - validation
    - priority
    - response
  severity: warning          # one severity for every ADS finding (optional)
```

## Selected findings, with worked examples

Most lint rules are self-evident from their description. The ones below tend to surprise rule authors when they hit them for the first time. Each section shows the Sigma fragment that triggers the rule and the cleanup the linter (or you with `--fix`) would apply.

### `wildcard_only_value`

Trigger:

```yaml
detection:
    selection:
        Image: '*'
    condition: selection
```

A lone `*` value matches **any** value of `Image`, including null. That's almost never what the author meant; what they actually wanted is "the field is present" or "match any non-null value", which Sigma expresses as `|exists: true`.

Fixed by `--fix`:

```yaml
detection:
    selection:
        Image|exists: true
    condition: selection
```

### `single_value_all_modifier`

Trigger:

```yaml
detection:
    selection:
        CommandLine|contains|all: 'whoami'
    condition: selection
```

The `|all` modifier is meaningful only with multiple values (it ANDs the per-value matches). On a single-value item it is a no-op and confuses readers. The fix removes `|all`.

```yaml
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
```

### `all_with_re`

Trigger:

```yaml
detection:
    selection:
        CommandLine|re|all:
            - '^cmd'
            - 'whoami'
    condition: selection
```

`|all` says every value in the list must match the field. `|re` says match a single regex. Combining the two on a single field can't be both at once: a regex is by definition the only matcher, so `|all` adds nothing. The fix removes `|all` and the rule keeps its OR semantics across the patterns; if you actually needed AND, use two separate selections joined with `and` in `condition:`.

### `non_lowercase_key`

Trigger:

```yaml
Title: Suspicious whoami invocation
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
```

Sigma's top-level keys (`title:`, `id:`, `logsource:`, `detection:`, `level:` …) are case-sensitive. `Title:` is **not** recognized by the parser; the rule silently has no title. The fix lowercases the offending key.

### `condition_references_unknown`

Trigger:

```yaml
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection_keywords
```

The `condition:` expression references `selection_keywords`, but the only selection defined in the `detection:` block is `selection`. The rule will fail to compile; this lint catches it before runtime. No auto-fix because the linter cannot tell which selection name was intended.

### `deprecated_aggregation_syntax`

Trigger:

```yaml
detection:
    selection:
        EventID: 4625
    condition: selection | count() by User > 5
```

The pipe-aggregation form in `condition:` is the pre-v2 way to express a correlation. Sigma v2.1.0 makes correlations first-class via a dedicated `correlation:` block, which RSigma evaluates and converts more accurately:

```yaml
title: Failed logon (base)
id: 9d2e7c48-4a3b-4f99-93c9-1c5f7c8b1a2b
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Brute force logon
id: aaaa1111-2222-3333-4444-555555555555
correlation:
    type: event_count
    rules: [9d2e7c48-4a3b-4f99-93c9-1c5f7c8b1a2b]
    group-by: [User]
    timespan: 5m
    condition:
        gte: 5
```

No auto-fix because the migration is structural (split into a base detection plus a correlation document).

### `duplicate_fields`

Trigger:

```yaml
fields:
    - CommandLine
    - User
    - CommandLine
```

The top-level `fields:` list names fields to surface in matches. A duplicate entry is redundant and the fix removes it. This rule does not detect duplicate YAML keys inside a detection selection (YAML keeps only the last key); use a single key with a value list when you need multiple values on one field.

```yaml
fields:
    - CommandLine
    - User
```

### `unknown_tag_namespace`

Trigger:

```yaml
tags:
    - attack.t1059
    - mittre.t1059       # typo: should be attack.t1059
```

The recognized tag namespaces are `attack.*`, `cve.*`, `detection.*`, `tlp.*`, `stp.*`, and `informational.*`. The fix is to manually replace the unknown namespace with the closest valid one (the linter doesn't auto-correct; tag namespaces are ambiguous enough that silent rewrites would be unsafe).

To allow organization-specific namespaces, pass `--tag-namespace <name>` on the CLI (repeatable) or add a `tag_namespaces` list to `.rsigma-lint.yml`:

```yaml
tag_namespaces:
  - myorg
  - internal
```

### `null_in_value_list`

Trigger:

```yaml
detection:
    selection:
        ParentImage:
            - C:\Windows\System32\cmd.exe
            - null
    condition: selection
```

A `null` literal inside a values list is spec-ambiguous. Does it mean "the field is null" or "an absent value" or "the literal string `null`"? The lint flags it so the author can be explicit. To express "field is null", use `|exists: false`. To match the literal string, quote it (`'null'`).

### `invalid_status` and `invalid_level`

Trigger:

```yaml
status: experimnetal      # typo
level: criticla           # typo
```

The valid `status:` values are `stable`, `test`, `experimental`, `deprecated`, `unsupported`. The valid `level:` values are `informational`, `low`, `medium`, `high`, `critical`. The fix replaces the bad value with the closest valid one (edit-distance ≤ 3).

## How to read the source for any rule

Every lint rule's emission lives under [`crates/rsigma-parser/src/lint/rules/`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-parser/src/lint/rules), with a few loader/CLI exceptions noted below:

| File | Rules |
|------|-------|
| `metadata.rs` | Shared metadata (title, id, level, status, date, author, description, name, taxonomy, non-lowercase keys). |
| `detection.rs` | Detection-block rules (condition references, logsource, tags, references, fields, scope, falsepositives, modifiers, value-list hygiene, flattened array correlation, `related:`). |
| `correlation.rs` | Correlation-block rules. |
| `filter.rs` | Filter-block rules. |
| `version.rs` | `unsupported_sigma_version`, `array_matching_without_version`. |
| `ads.rs` | ADS detection-strategy presence checks (`ads_missing_*`, `ads_empty_section`, `ads_unknown_section`). |
| `exemplar.rs` | Embedded exemplar shape checks (`exemplar_shape`, `exemplar_wrong_rule_kind`). |
| `shared.rs` | `unknown_key`. |
| `mod.rs` | Module wiring for the rule packages above. |

Infrastructure findings (`yaml_parse_error`, `not_a_mapping`, `file_read_error`) and cross-document reference checks (`sigma_version_mismatch`, `unknown_rule_reference`) are produced by the lint loader/runner in [`crates/rsigma-parser/src/lint/mod.rs`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-parser/src/lint/mod.rs). `schema_violation` is attached by the CLI when `--schema` fails. Each emission is a call to `error(LintRule::X, ...)`, `warning(LintRule::X, ...)`, `info(LintRule::X, ...)`, or `hint(LintRule::X, ...)`. The full enum and the programmatic catalog live in that same module and in [`catalogue.rs`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-parser/src/lint/catalogue.rs).

## See also

- [Linting Rules](../guide/linting-rules.md) for the workflow walkthrough, suppression tiers, auto-fix patterns, and CI integration.
- [`rule lint` CLI reference](../cli/rule/lint.md) for every flag.
- [Sigma specification (v2.1.0)](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md) for the underlying constraints these rules enforce.
- [`crates/rsigma-parser/src/lint`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-parser/src/lint) for the implementation.
