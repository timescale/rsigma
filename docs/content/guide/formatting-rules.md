---
description: "Format Sigma rules consistently with rsigma rule fmt: the canonical style, key order, quoting, comment handling, and editor and CI integration."
---

# Formatting Rules

{{ added "0.27.0" }}

`rsigma rule fmt` rewrites Sigma rules into one canonical layout so that diffs stay small and reviews focus on behavior. The formatter keeps comments, anchors, aliases, tags, and directives, and it refuses any rewrite that would change what a rule means.

This page covers the canonical style, the key order for each document kind, quoting, comment placement, action chains, the constructs the formatter refuses, and editor and CI integration.

## Quick start

```bash
rsigma rule fmt rules/
rsigma rule fmt --write rules/
rsigma rule fmt --check rules/
```

The first command reports files that are not canonical. The second rewrites them atomically. The third exits `1` when any file would change, which is the gate for pull requests.

## The canonical style

The formatter writes four-space indentation, block collections, and one canonical key order per document kind. It removes blank lines, trailing whitespace, and tabs used for indentation, writes LF line endings, drops a leading BOM, and ends the file with exactly one newline.

Sequence items use a dash and a space. A mapping item starts on the dash line and its remaining keys align two spaces past the dash:

```yaml
title: Test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\cmd.exe'
          CommandLine|contains: '/c'
    condition: selection
```

Flow collections become block collections, except empty collections, which stay `{}` and `[]`:

```yaml
title: Test
logsource:
    category: process_creation
detection:
    selection:
        Image: cmd.exe
        CommandLine: []
    condition: selection
```

### Key order

Each document kind has a fixed root order. `action` comes first, then the keys named in the table, then recognized `rsigma.*` attributes, then any other keys in source order.

| Document kind | Key order |
|---------------|-----------|
| Detection rule | `title`, `id`, `name`, `status`, `description`, `references`, `author`, `date`, `modified`, `related`, `tags`, `sigma-version`, `logsource`, `detection`, `fields`, `falsepositives`, `level`, `scope`, `license`, `taxonomy` |
| Correlation rule | `title`, `id`, `name`, `status`, `description`, `references`, `author`, `date`, `modified`, `related`, `tags`, `sigma-version`, `correlation`, `generate`, `fields`, `falsepositives`, `level`, `scope`, `license`, `taxonomy` |
| Filter rule | `title`, `id`, `name`, `status`, `description`, `references`, `author`, `date`, `modified`, `related`, `tags`, `sigma-version`, `logsource`, `filter`, `fields`, `falsepositives`, `level`, `scope`, `license`, `taxonomy` |
| Common or `action: reset` document | `title`, `id`, `name`, `status`, `description`, `references`, `author`, `date`, `modified`, `related`, `tags`, `sigma-version`, `fields`, `falsepositives`, `level`, `scope`, `license`, `taxonomy` |

The formatter keeps the source order of detection selections and of keys inside a selection. It moves `timeframe` ahead of `condition` and puts `condition` last:

| Section | Key order |
|---------|-----------|
| `logsource` | `category`, `product`, `service`, `definition`, then other keys in source order |
| `detection` | selections in source order, then `timeframe`, then `condition` |
| `correlation` | `type`, `rules`, `aliases`, `group-by`, `timespan`, `timeframe`, `window`, `gap`, `condition`, `generate`, then other keys in source order |
| `filter` | `rules`, then other keys in source order, then `condition` |
| `related` item | `id`, `type` |

Recognized `rsigma.*` attributes come before other custom attributes, in this order:

| `rsigma.*` order |
|------------------|
| `rsigma.window`, `rsigma.gap`, `rsigma.timestamp_field`, `rsigma.suppress`, `rsigma.action`, `rsigma.correlation_event_mode`, `rsigma.max_correlation_events`, `rsigma.max_group_entries`, `rsigma.include_event`, `rsigma.risk_score`, `rsigma.exemplars`, `rsigma.ads.strategy`, `rsigma.ads.technical_context`, `rsigma.ads.blind_spots`, `rsigma.ads.validation`, `rsigma.ads.priority`, `rsigma.ads.response`, `rsigma.ads.exempt` |

### Quoting

Strings that YAML 1.1 would read as another type are quoted, including `true`, `false`, `null`, `yes`, `no`, `on`, `off`, `~`, `=`, `<<`, decimal and scientific numbers, `.inf`, `.nan`, hex, octal, binary, underscored numbers, sexagesimal numbers, and timestamps such as `2024-01-01`. A value that YAML 1.2 reads as a string but YAML 1.1 reads as a number or timestamp keeps its source style: an unquoted `date: 2024-01-01` or `Count: 1_000` stays unquoted and a quoted one stays quoted, so neither PyYAML (which pySigma uses) nor rsigma sees a different type after formatting. A `<<` key stays plain only when it was a plain merge key in the source.

The formatter also quotes strings that begin with a YAML indicator or contain `: ` or ` #`, and it uses double quotes when a value contains control characters that single quotes cannot carry or a multi-line value has a line that ends in a space or tab, since editors that trim trailing whitespace would change a literal block.

Values in detection selections stay plain only when every character is alphanumeric or one of `_`, `-`, `.`, `/`. Prose fields such as `title`, `description`, `author`, `license`, `logsource.definition`, and items of `references`, `tags`, `falsepositives`, `fields`, and `scope` stay plain when they start with an alphanumeric character and contain no indicator. Condition expressions stay plain unless a YAML rule forces quoting. Mapping keys use the same rules; detection field keys may also contain `/`, `[`, `]`, `@`, and `|`.

```yaml
title: Test
references:
    - https://example.com/rule
logsource:
    category: process_creation
detection:
    selection:
        CommandLine: 'true'
        Image|endswith:
            - '\cmd.exe'
    condition: selection
```

Multi-line strings become literal blocks with an explicit chomping indicator. The formatter uses `|-` when the string has no trailing newline, `|` for one trailing newline, and `|+` for more, and adds an indentation indicator when the first non-empty line starts with a space.

```yaml
title: Test
description: |-
    First line.
    Second line.
logsource:
    category: process_creation
detection:
    selection:
        Image: cmd.exe
    condition: selection
```

### Documents and directives

The formatter keeps YAML directives such as `%YAML 1.2` above the `---` marker and keeps one `---` between documents. A document marker comment stays on the marker line.

## Comments

The formatter keeps comment text and attaches each comment to the same entry or item as the source:

- A trailing comment on a key or item line stays on that entry or item.
- An own-line comment above an entry or item becomes a leading comment for it.
- A comment after the last entry of a mapping or sequence becomes a dangling comment at that collection.
- A comment above the first root entry moves into the document header, except a `rsigma-disable-next-line` comment, which stays directly above the entry it disables.
- A comment on a `---` marker stays on the marker.
- A comment between documents follows the previous document.

Place `# rsigma-disable-next-line <rule>` directly above the entry that the lint rule should ignore. The formatter keeps that position so the suppression still applies after formatting.

The formatter refuses a comment that sits alone between a key and a value when the value is a scalar, alias, or flow collection, because there is no canonical line for it. A trailing comment on a properties line, such as `&anchor # note` followed by the value on the next line, attaches to the entry.

## Action chains

Sigma collections can share metadata across documents with `action: global`, inherit the previous document with `action: repeat`, and clear inherited metadata with `action: reset`. The formatter classifies every document before it writes the file, puts `action` first, and orders the remaining keys by the effective document kind. Global keys are inherited by later documents for classification, `repeat` merges the previous document's keys, and `reset` clears the global keys.

```yaml
action: global
title: Global
logsource:
    product: windows
---
action: reset
detection:
    selection:
        Image: cmd.exe
    condition: selection
```

## What the formatter refuses

The formatter returns an error instead of guessing. The CLI reports the error on stderr and exits `2`; the LSP leaves the document unchanged.

| Error | Meaning | Example |
|-------|---------|---------|
| `Yaml` | The input is not valid YAML. The message includes a one-based line and column. | `title: [unclosed` |
| `NotSigma` | A document is empty, not a mapping, or has none of `detection`, `logsource`, `correlation`, or `filter`. The CLI skips these files with a `skipped:` line. | `name: pipeline` |
| `InvalidSigma` | The YAML parses but the Sigma parser reports an error, for example a missing `condition`. | A rule with `detection: {selection: {Image: cmd.exe}}` and no `condition` |
| `Unsupported` | Valid YAML that the formatter cannot lay out safely, such as a comment between a key and its scalar value, an explicit complex key, a comment inside a flow sequence, more than 64 levels of nesting, or output larger than 16 times the input. | `Field:` followed by a comment line and then `value` |
| `Guard` | The formatted text would change the rule's values, parsed rules, diagnostics, comments, anchors, aliases, tags, directives, or `action` values. | A rewrite that drops a comment or rebinds an alias |

Range formatting, used by the LSP for a selection, can also return `Range` when the selected lines cannot be formatted on their own. The CLI does not use range formatting.

## Editors

The rsigma language server advertises document and range formatting. See [VS Code](../editors/vscode.md) and [Neovim](../editors/neovim.md) for the client setup.

## CI

Run `rsigma rule fmt --check rules/` next to the lint step so pull requests fail when a rule is not canonical. See [CI/CD](ci-cd.md) for a complete workflow.
