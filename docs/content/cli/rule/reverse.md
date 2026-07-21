# `rsigma rule reverse`

Convert a SIEM query into a draft Sigma rule (reverse conversion).

## Synopsis

```text
rsigma rule reverse [QUERY] --from <DIALECT> [OPTIONS]
```

## Description

The mirror of [`rsigma backend convert`](/cli/backend/convert): parse a query in the dialect chosen by `--from`, build the intermediate representation the forward converter also uses, raise a Sigma rule, and print it as YAML. It is also the query sibling of [`rsigma rule draft`](/cli/rule/draft) (events to Sigma).

The query comes from the positional argument, from `--file` (repeatable, files or directories), or from stdin. Each file is one query, and a directory contributes every query file it holds (recursively, filtered to `.lucene`/`.txt`/`.query`; an explicitly named file is read regardless of extension). Converting a directory yields one rule per query, titled from each file name; the results print as a multi-document YAML stream (or, with `-o` pointing at an existing directory, one `<name>.yml` per query). A query that cannot be converted is reported on stderr and the run exits non-zero, but the rules that did convert are still written.

Field predicates map to idiomatic Sigma: surrounding `*` wildcards become `|contains`/`|startswith`/`|endswith`, `field:/regex/` becomes `|re`, `field:[a TO b]` and `{a TO b}` ranges become `|gte`/`|lte` (or `|gt`/`|lt`) pairs, `field:>=N` shorthand becomes a numeric comparison, `field:(a OR b)` becomes a value list, `_exists_:field` becomes `|exists`, and bare terms become a `keywords` block. `AND`/`OR`/`NOT` (with `&&`/`||`/`!` and `+`/`-`) and parentheses become the condition; adjacent terms with no operator are ANDed. An `AND` of field predicates is merged into one `selection`, a negated branch becomes a `filter`, and a same-field `OR` collapses into one value list.

A query carries no rule metadata, so the title, id, level, status, and logsource come from flags; the result is a best-effort skeleton to review, not a finished rule. Constructs with no Sigma equivalent are rejected with a clear error rather than emitted as silently-wrong Sigma: term boosting (`^`), fuzzy and proximity (`~`), and non-numeric ranges. The emitted rule is parsed back before it is printed, so a rule that would not round-trip never reaches you.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `[QUERY]` | stdin | An inline query. Omit to read from `--file` or stdin. |
| `--from <DIALECT>` | `lucene` | Source query dialect. `lucene` (Elastic Lucene / Elasticsearch `query_string`) is the only dialect today. |
| `-f, --file <PATH>` | unset | Read queries from files or directories (repeatable). Each file is one query; a directory contributes every query file it holds. |
| `--title <TITLE>` | file name | Rule title. Single query only; multi-query runs title each rule from its file name. |
| `--id <UUID>` | unset | Rule id. Single query only. |
| `--level <LEVEL>` | unset | Rule level: `informational`, `low`, `medium`, `high`, or `critical`. |
| `--status <STATUS>` | unset | Rule status: `stable`, `test`, `experimental`, `deprecated`, or `unsupported`. |
| `--logsource-product <P>` | unset | Logsource product (e.g. `windows`). |
| `--logsource-category <C>` | unset | Logsource category (e.g. `process_creation`). |
| `--logsource-service <S>` | unset | Logsource service (e.g. `sysmon`). |
| `-o, --output <PATH>` | stdout | Write output instead of stdout. With multiple rules, an existing directory receives one `<name>.yml` per query; any other path receives a single multi-document bundle. |

## Examples

### Convert a Lucene query with a filter

```bash
rsigma rule reverse --from lucene 'Image:*\\cmd.exe AND CommandLine:*whoami* AND NOT User:SYSTEM' \
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
echo 'DestinationPort:[1024 TO 65535] AND Image:("a.exe" OR "b.exe")' | rsigma rule reverse --title "Range and group"
```

### Batch-convert a directory of queries into a directory of rules

```bash
rsigma rule reverse --file queries/ --logsource-product windows -o rules/
```

Each query file (for example `queries/whoami.lucene`) becomes `rules/whoami.yml`, titled from the file name.

## See also

- [`rsigma rule draft`](/cli/rule/draft) drafts a rule from exemplar events.
- [`rsigma backend convert`](/cli/backend/convert) is the forward direction (Sigma to backend queries).
