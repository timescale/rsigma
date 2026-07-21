# `rsigma rule from-lucene`

Convert an Elastic Lucene query into a draft Sigma rule.

## Synopsis

```text
rsigma rule from-lucene [QUERY] [OPTIONS]
```

## Description

Reverse conversion: parse a Lucene / Elasticsearch `query_string`, build the intermediate representation the forward converter also uses, raise a Sigma rule, and print it as YAML. It is the query sibling of [`rsigma rule draft`](/cli/rule/draft) (events to Sigma) and the inverse of [`rsigma backend convert`](/cli/backend/convert) (Sigma to queries).

The query is read from the positional argument, from `--file`, or from stdin. Field predicates map to idiomatic Sigma: surrounding `*` wildcards become `|contains`/`|startswith`/`|endswith`, `field:/regex/` becomes `|re`, `field:[a TO b]` and `{a TO b}` ranges become `|gte`/`|lte` (or `|gt`/`|lt`) pairs, `field:>=N` shorthand becomes a numeric comparison, `field:(a OR b)` becomes a value list, `_exists_:field` becomes `|exists`, and bare terms become a `keywords` block. `AND`/`OR`/`NOT` (with `&&`/`||`/`!` and `+`/`-`) and parentheses become the condition; adjacent terms with no operator are ANDed. An `AND` of field predicates is merged into one `selection`, a negated branch becomes a `filter`, and a same-field `OR` collapses into one value list.

A query carries no rule metadata, so the title, id, level, status, and logsource come from flags; the result is a best-effort skeleton to review, not a finished rule. Constructs with no Sigma equivalent are rejected with a clear error rather than emitted as silently-wrong Sigma: term boosting (`^`), fuzzy and proximity (`~`), and non-numeric ranges. The emitted rule is parsed back before it is printed, so a rule that would not round-trip never reaches you.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `[QUERY]` | stdin | The Lucene query. Omit to read from `--file` or stdin. |
| `-f, --file <FILE>` | unset | Read the query from a file instead of the argument. |
| `--title <TITLE>` | `Converted query` | Rule title (recommended). |
| `--id <UUID>` | unset | Rule id. |
| `--level <LEVEL>` | unset | Rule level: `informational`, `low`, `medium`, `high`, or `critical`. |
| `--status <STATUS>` | unset | Rule status: `stable`, `test`, `experimental`, `deprecated`, or `unsupported`. |
| `--logsource-product <P>` | unset | Logsource product (e.g. `windows`). |
| `--logsource-category <C>` | unset | Logsource category (e.g. `process_creation`). |
| `--logsource-service <S>` | unset | Logsource service (e.g. `sysmon`). |
| `-o, --output <FILE>` | stdout | Write the rule to a file instead of stdout. |

## Examples

### Convert a query with a filter

```bash
rsigma rule from-lucene 'Image:*\\cmd.exe AND CommandLine:*whoami* AND NOT User:SYSTEM' \
  --title "Whoami via cmd" --logsource-product windows --logsource-category process_creation --level medium
```

```yaml
title: Whoami via cmd
logsource:
    category: process_creation
    product: windows
detection:
    filter:
        User: SYSTEM
    selection:
        Image|endswith: '\cmd.exe'
        CommandLine|contains: whoami
    condition: selection and not filter
level: medium
```

### Convert a range and a value group from stdin

```bash
echo 'DestinationPort:[1024 TO 65535] AND Image:("a.exe" OR "b.exe")' | rsigma rule from-lucene --title "Range and group"
```

## See also

- [`rsigma rule draft`](/cli/rule/draft) drafts a rule from exemplar events.
- [`rsigma backend convert`](/cli/backend/convert) is the forward direction (Sigma to backend queries).
