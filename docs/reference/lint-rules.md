# Lint Rules

`rsigma rule lint` runs {{ rsigma.lint.rules }} built-in checks derived from the Sigma v2.1.0 specification, plus {{ rsigma.lint.reserved }} reserved enum value (`empty_filter_rules`) that no production code currently emits. This page is the canonical catalogue: every rule's ID, default severity, what it flags, and whether `--fix` can auto-correct it.

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
| `warning` | 33 |
| `info` | 3 |
| `hint` | 0 |
| Reserved (no production emission yet) | {{ rsigma.lint.reserved }} |
| **Total** | **{{ rsigma.lint.total }}** ({{ rsigma.lint.autofix }} of which have safe auto-fixes via `--fix`) |

The `hint` severity is defined but not yet used by any of the shipped rules. Future rules may use it.

### The 13 safe-fix rules

| Rule | Severity | What the fix does |
|------|----------|-------------------|
| `invalid_status` | `error` | Replace the bad status value with the closest valid one (`stable`, `test`, `experimental`, `deprecated`, `unsupported`). |
| `invalid_level` | `error` | Replace the bad level with the closest valid one (`informational`, `low`, `medium`, `high`, `critical`). |
| `non_lowercase_key` | `warning` | Lowercase the offending key. |
| `logsource_value_not_lowercase` | `warning` | Lowercase the offending `category`/`product`/`service` value. |
| `duplicate_tags` | `warning` | Remove the duplicate tag entry. |
| `duplicate_references` | `warning` | Remove the duplicate URL. |
| `duplicate_fields` | `warning` | Remove the duplicate field declaration. |
| `single_value_all_modifier` | `warning` | Remove the redundant `all` modifier on a single-value item. |
| `all_with_re` | `warning` | Remove the redundant `all` modifier when used alongside `re`. |
| `wildcard_only_value` | `warning` | Replace the lone `*` value with `exists: true`. |
| `filter_has_level` | `warning` | Remove the inapplicable `level:` from the filter rule. |
| `filter_has_status` | `warning` | Remove the inapplicable `status:` from the filter rule. |
| `unknown_key` | `info` | Replace a typo'd key with the closest known key (when the edit distance is small). |

## Infrastructure rules (4)

Fired by the linter's loader and runner before per-rule checks even start. Cannot be suppressed with inline comments because the rule never gets parsed.

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `yaml_parse_error` | `error` | — | The file contains malformed YAML that the parser cannot recover. |
| `not_a_mapping` | `error` | — | The top-level YAML document is a sequence or scalar instead of a mapping. |
| `file_read_error` | `error` | — | The lint path could not be opened (IO error, permission denied). |
| `schema_violation` | `error` | — | When `--schema` is set, the rule fails the JSON schema. Schema violations attach the JSON schema error message verbatim. |

## Shared metadata rules (16)

Apply to detection, correlation, and filter rules alike.

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `missing_title` | `error` | — | Rule has no `title:` field. |
| `empty_title` | `error` | — | `title:` is present but empty. |
| `title_too_long` | `warning` | — | `title:` exceeds the recommended length. |
| `name_too_long` | `warning` | — | A `name:` field (e.g. on a correlation reference) exceeds the recommended length. |
| `missing_author` | `info` | — | The rule has no `author:` field. |
| `missing_description` | `info` | — | The rule has no `description:` field. |
| `description_too_long` | `warning` | — | `description:` exceeds the recommended length. |
| `invalid_status` | `error` | yes | `status:` is not one of `stable`, `test`, `experimental`, `deprecated`, `unsupported`. The fix replaces it with the closest match. |
| `invalid_level` | `error` | yes | `level:` is not one of `informational`, `low`, `medium`, `high`, `critical`. The fix replaces it with the closest match. |
| `missing_level` | `warning` | — | The rule has no `level:` field. |
| `invalid_date` | `error` | — | `date:` is not ISO 8601 (`YYYY-MM-DD` or `YYYY/MM/DD`). |
| `invalid_modified` | `error` | — | `modified:` is not a valid date. |
| `modified_before_date` | `warning` | — | `modified:` is earlier than `date:`. |
| `invalid_id` | `warning` | — | `id:` is not a valid UUID. Replace it with a freshly generated UUIDv4 manually. |
| `non_lowercase_key` | `warning` | yes | A top-level key uses non-lowercase characters (e.g. `Title:` instead of `title:`). The fix lowercases the key. |
| `unknown_key` | `info` | yes | An unrecognised top-level key. The fix suggests the closest known key when the edit distance is small (e.g. `descirption` → `description`). |

## Detection rules (19)

Apply to detection rules (`detection:` block + `condition:`).

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `missing_detection` | `error` | — | The rule has no `detection:` block. |
| `empty_detection` | `warning` | — | `detection:` is present but empty. |
| `missing_condition` | `error` | — | `detection:` has no `condition:` key. |
| `missing_logsource` | `error` | — | The rule has no `logsource:` block. |
| `logsource_value_not_lowercase` | `warning` | yes | A `logsource.category/product/service` value uses non-lowercase characters. The fix lowercases the value. |
| `duplicate_fields` | `warning` | yes | A detection item lists the same field name twice. The fix removes the duplicate. |
| `duplicate_references` | `warning` | yes | `references:` contains the same URL twice. The fix dedupes. |
| `duplicate_tags` | `warning` | yes | `tags:` contains the same tag twice. The fix dedupes. |
| `invalid_tag` | `warning` | — | A tag value does not match the Sigma tag spec (`namespace.value`). |
| `unknown_tag_namespace` | `warning` | — | A tag uses a namespace outside the recognised set (`attack`, `cve`, `detection`, `tlp`, `stp`, `informational`). |
| `falsepositive_too_short` | `warning` | — | `falsepositives:` entries are below the recommended minimum length. |
| `scope_too_short` | `warning` | — | A scope token (in `tags:` or `name:` namespaces) is below the minimum length. |
| `taxonomy_too_long` | `warning` | — | A namespace component (in `tags:` or `name:`) is above the maximum length. |
| `wildcard_only_value` | `warning` | yes | A detection value is just `*`. The fix replaces it with `exists: true`, which is what the author almost certainly meant. |
| `null_in_value_list` | `warning` | — | A `null` literal appears inside a list of values. Sigma's semantics around `null` in lists are spec-ambiguous; this flags the case so the author can be explicit. |
| `empty_value_list` | `warning` | — | A detection item with a list value is empty. |
| `condition_references_unknown` | `error` | — | The `condition:` expression references a selection name that is not in `detection:`. |
| `deprecated_aggregation_syntax` | `warning` | — | The condition uses the deprecated aggregation pipe syntax (`condition: selection \| count() > 5`). Use the modern `correlation:` block instead. |
| `flattened_array_correlation` | `warning` | — | Two or more sibling keys share a quantified array prefix (e.g. `connections[any].protocol` and `connections[any].ip`). Each opens an independent scope, so they do **not** correlate on the same array element. Use an object-scope block (`connections[any]:` with the fields nested) to require one element to satisfy all of them. See [Array Matching](../guide/array-matching.md). |

## Correlation rules (17)

Apply to correlation rules (`correlation:` block).

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `missing_correlation` | `error` | — | A `kind: correlation` rule has no `correlation:` block. |
| `missing_correlation_type` | `error` | — | `correlation:` has no `type:`. |
| `invalid_correlation_type` | `error` | — | `correlation.type:` is not one of `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`, `value_median`. |
| `missing_correlation_rules` | `error` | — | `correlation:` has no `rules:` list. |
| `empty_correlation_rules` | `warning` | — | `correlation.rules:` is present but empty. |
| `missing_correlation_timespan` | `error` | — | `correlation:` has no `timespan:`. |
| `invalid_timespan_format` | `error` | — | `timespan:` is not a valid duration (`5m`, `1h`, `30s`). |
| `invalid_window_mode` | `error` | — | `correlation.window:` is not one of `sliding`, `tumbling`, `session`. |
| `missing_session_gap` | `error` | — | `window: session` without a `gap:`. A session window needs an inactivity timeout. |
| `gap_without_session` | `error` | — | `gap:` is set without `window: session`. The gap only applies to session windows. |
| `invalid_gap_format` | `error` | — | `gap:` is not a valid duration (`5m`, `1h`, `30s`). |
| `missing_correlation_condition` | `error` | — | `correlation:` has no `condition:` block. |
| `missing_condition_field` | `error` | — | `correlation.condition` is missing the required field for the chosen correlation type (e.g. `gte` for `event_count`, `field` for `value_sum`). |
| `condition_value_not_numeric` | `error` | — | The numeric threshold in `correlation.condition` is not a number. |
| `missing_group_by` | `error` | — | `value_*` and grouping-based correlations need a `group-by:`. |
| `generate_not_boolean` | `error` | — | The `generate:` field is not a boolean. |
| `invalid_condition_operator` | `error` | — | The condition uses an operator not valid for the correlation type (e.g. `lt` is not valid for `event_count`). |

## Filter rules (8 IDs, 7 emitted)

Apply to filter rules (`kind: filter` with a `filter:` block). The eighth row (`empty_filter_rules`) is reserved: the variant exists in the lint-rule enum and is asserted in a regression test, but no production code path emits it today.

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `missing_filter` | `error` | — | A `kind: filter` rule has no `filter:` block. |
| `missing_filter_logsource` | `error` | — | Filter rule has no `logsource:`. |
| `missing_filter_rules` | `error` | — | `filter:` has no `rules:` list. |
| `missing_filter_selection` | `error` | — | `filter:` has no `selection:` block. |
| `missing_filter_condition` | `error` | — | `filter:` has no `condition:`. |
| `filter_has_level` | `warning` | yes | Filter rules should not carry `level:`. The fix removes the field. |
| `filter_has_status` | `warning` | yes | Filter rules should not carry `status:`. The fix removes the field. |
| `empty_filter_rules` | reserved | — | Variant declared in the enum and asserted in a regression test, but no production code emits it today. May be repurposed in a future release. |

## Modifier and `related:` hygiene (7)

These also apply to detection rules but sit apart from the core detection-block checks above: modifier-misuse checks on a single detection item (`single_value_all_modifier`, `all_with_re`, `incompatible_modifiers`) and validation of the `related:` cross-reference block.

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `single_value_all_modifier` | `warning` | yes | A single-value detection item carries the `\|all` modifier, which is a no-op. The fix removes the redundant modifier. |
| `all_with_re` | `warning` | yes | The `\|all` modifier is combined with `\|re`, which is not meaningful (regex matching is inherently set-style). The fix removes `\|all`. |
| `incompatible_modifiers` | `warning` | — | Two modifiers on the same field are mutually exclusive (e.g. `\|contains\|startswith`). |
| `invalid_related_id` | `warning` | — | `related[].id` is not a valid UUID. |
| `invalid_related_type` | `error` | — | `related[].type` is not one of `derived`, `obsolete`, `merged`, `renamed`, `similar`. |
| `related_missing_required` | `error` | — | `related[]` entry is missing the required `id:` or `type:` field. |
| `deprecated_without_related` | `warning` | — | A rule with `status: deprecated` should declare `related:` pointing at the replacement. |

## Specification version and rule references (4)

The first two apply to any document type, based on the top-level `sigma-version` attribute (the Sigma specification major the document targets); see [Array Matching: requires `sigma-version: 3`](../guide/array-matching.md#requires-sigma-version-3). The last two resolve cross-document references (a correlation rule and the rules it aggregates, a filter and the rules it targets) by `id` or `name`. Reference resolution spans the whole directory when linting a directory; for a single file or string, only references to rules in the same input are resolved, and `unknown_rule_reference` is suppressed (the target may live in a file outside the linted scope).

| Rule | Severity | Fix | Description |
|------|----------|-----|-------------|
| `unsupported_sigma_version` | `error` | — | `sigma-version` declares a specification major newer than this build implements, so the document cannot be interpreted correctly. Upgrade rsigma or target a supported major. |
| `array_matching_without_version` | `warning` | — | The document uses array-matching selector syntax (`field[any]`, `args[0]`, ...) but resolves below the major that enables it (absent or `sigma-version: 2`), so the brackets are read as literal field-name characters. Add `sigma-version: 3` to read them as array selectors, or escape the brackets (`\[` / `\]`) to keep them literal. |
| `sigma_version_mismatch` | `warning` | — | A correlation or filter and a rule it references declare different `sigma-version` majors. Cross-referencing rules must share a specification major, since the referencing rule's semantics depend on a consistent reading of the referenced ones. |
| `unknown_rule_reference` | `warning` | — | A correlation's `rules:` or a filter's `rules:` entry references a rule (by `id` or `name`) that does not exist among the linted rules. Only emitted when linting a directory, where the rule index is complete. |

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

Sigma's top-level keys (`title:`, `id:`, `logsource:`, `detection:`, `level:` …) are case-sensitive. `Title:` is **not** recognised by the parser; the rule silently has no title. The fix lowercases the offending key.

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

The pipe-aggregation form in `condition:` is the pre-v2 way to express a correlation. Sigma v2.1.0 makes correlations first-class via a dedicated `correlation:` block, which rsigma evaluates and converts more accurately:

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
detection:
    selection:
        CommandLine|contains: whoami
        CommandLine|contains: net.exe
    condition: selection
```

YAML preserves duplicate keys silently; the parser keeps only the last one, so the `whoami` match is dropped. The fix removes the earlier duplicate. If you wanted both, use a single key with a list of values, or split the selections.

```yaml
detection:
    selection:
        CommandLine|contains:
            - whoami
            - net.exe
    condition: selection
```

### `unknown_tag_namespace`

Trigger:

```yaml
tags:
    - attack.t1059
    - mittre.t1059       # typo: should be attack.t1059
```

The recognised tag namespaces are `attack.*`, `cve.*`, `detection.*`, `tlp.*`, `stp.*`, and `informational.*`. The fix is to manually replace the unknown namespace with the closest valid one (the linter doesn't auto-correct; tag namespaces are ambiguous enough that silent rewrites would be unsafe).

To allow organisation-specific namespaces, pass `--tag-namespace <name>` on the CLI (repeatable) or add a `tag_namespaces` list to `.rsigma-lint.yml`:

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

Every lint rule's emission lives in a single file under [`crates/rsigma-parser/src/lint/rules/`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-parser/src/lint/rules):

| File | Rules |
|------|-------|
| `metadata.rs` | Shared metadata rules (title, id, level, status, date, author, description). |
| `detection.rs` | Detection-block rules (condition references, logsource, tags, references, modifiers). |
| `correlation.rs` | Correlation-block rules. |
| `filter.rs` | Filter-block rules. |
| `shared.rs` | Cross-kind helpers (unknown_key, non_lowercase_key). |
| `mod.rs` | Infrastructure (`yaml_parse_error`, `not_a_mapping`, `file_read_error`, `missing_title`, `missing_description`, `missing_author`, `title_too_long`, `missing_condition`). |

Each emission is a call to `error(LintRule::X, ...)`, `warning(LintRule::X, ...)`, `info(LintRule::X, ...)`, or `hint(LintRule::X, ...)`. The full enum lives at [`crates/rsigma-parser/src/lint/mod.rs`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-parser/src/lint/mod.rs).

## See also

- [Linting Rules](../guide/linting-rules.md) for the workflow walkthrough, suppression tiers, auto-fix patterns, and CI integration.
- [`rule lint` CLI reference](../cli/rule/lint.md) for every flag.
- [Sigma specification (v2.1.0)](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md) for the underlying constraints these rules enforce.
- [`crates/rsigma-parser/src/lint`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-parser/src/lint) for the implementation.
