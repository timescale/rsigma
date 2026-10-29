# LynxDB Backend

The `lynxdb` backend converts Sigma rules into [SPL2](https://docs.lynxdb.org/docs/sigma/spl2-mapping/)-compatible queries for LynxDB. A rule renders as a native `search` expression when LynxDB's search matches every one of its values exactly, and as a `where` expression otherwise.

For the workflow walkthrough see [Rule Conversion](../../guide/rule-conversion.md#lynxdb). For LynxDB-side operational topics (REST API, saved queries, scheduled detection, drift runbook) see [Sigma rules on LynxDB](https://docs.lynxdb.org/docs/sigma/).

## How it differs from PostgreSQL

LynxDB is a log analytics engine with its own search language (SPL2 syntax). The translation strategy is therefore different:

- No table or schema concept; the target is an **index** (default `main`).
- The `search` command matches through an inverted index, which is fast but only exact for a subset of values. Rules outside that subset render as a `where` expression that evaluates the actual field values.
- Boolean precedence in `search` is non-standard (`NOT > OR > AND`), so the backend parenthesizes wherever that precedence would change a condition's meaning. `where` uses standard precedence.

## Backend options

LynxDB has no CLI options today. The single configurable knob is the target index, controlled exclusively via pipeline `set_state`:

```yaml
transformations:
  - type: set_state
    key: index
    value: security_logs
```

Defaults:

| Knob | Default |
|------|---------|
| Index | `main` |

The state key `index` is validated identically to PostgreSQL identifiers (`^[A-Za-z_][A-Za-z0-9_$]*$`). A custom index gets baked into the `FROM <index>` prefix of every generated query.

## Search or where

{{ added "0.24.0" }}

LynxDB's `search` matches tokens case-insensitively and only knows the `*` wildcard. Each rule condition renders as `FROM <index> | search ...` when every value in it is one `search` matches exactly:

- a string of letters, digits, spaces, and `. - _ : \`, matched case-insensitively, with `*` only at its start or end
- a number or boolean compared for equality
- `exists: true`/`false`

Anything else renders the whole condition as `FROM <index> | where ...`: regexes, CIDR, `null`, empty strings, `cased`, numeric comparisons, `?`, a literal `*`, a `*` between literals, and strings with other characters such as `/`, `>`, quotes, or brackets. Search alone would miss or over-match those values, and mixing a `search` term with a `where` stage cannot express a regex nested under an `OR` or `NOT`.

## Modifier mapping

Verified against the LynxDB backend's golden tests at [`crates/rsigma-convert/src/backends/lynxdb`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-convert/src/backends/lynxdb) and against a LynxDB server in the engine tests.

| Sigma feature | `search` | `where` |
|---------------|----------|---------|
| Field equality | `field="value"` | `match(field, "(?i)^value$")` |
| `contains`, `startswith`, `endswith` | `field=*"value"*`, `field="value"*`, `field=*"value"` | `match(field, "(?i)value")`, anchored with `^` or `$` |
| Wildcards `*` and `?` | `field="pre"*`, with the literal quoted and the wildcards outside the quotes | `.*` and `.` in the `match()` regex |
| Case-sensitive (`cased` modifier) | | `match(field, "^Value$")` (no `(?i)`) |
| Regex (`re` modifier) | | `match(field, "pattern")`; the `i`, `m`, and `s` flags are prepended as an inline group, such as `(?i)pattern`. |
| CIDR (`cidr` modifier) | | `cidrmatch("cidr", field)` |
| Numeric equality | `field=4688` | `coalesce(tonumber(field)=4688, false)` |
| `lt`, `lte`, `gt`, `gte` | | `coalesce(tonumber(field)>1000, false)` |
| Boolean | `field=true` | `match(field, "(?i)^true$")` |
| `null` value | | `isnull(json_extract(_raw, "field"))` |
| Empty string | | `coalesce(json_extract(_raw, "field")="", false)` |
| `exists: true`/`false` | `field=*`/`NOT field=*` | `isnotnull(json_extract(_raw, "field"))`/`isnull(...)` |
| Value list (`field` with multiple values) | `field="val1" OR field="val2"` | `match(field, "(?i)^val1$") OR match(field, "(?i)^val2$")` |
| Keywords | `"keyword"`, without outer wildcards, since a keyword already matches a substring | `match(_raw, "(?i)keyword")`, with the keyword escaped as serde_json writes it in the raw JSON; a wildcard matches within one JSON string |
| Boolean `AND`, `OR`, `NOT` | Parenthesized where the non-standard precedence (`NOT > OR > AND`) requires it: an `AND` under an `OR`, and a compound operand of `NOT`. | Standard precedence. |

`match()` returns false for a missing field, so a negated detection is true for an event that lacks the field, as in `engine eval`. The `coalesce(..., false)` wrappers do the same for comparisons. Null checks and empty strings read the event's raw JSON because LynxDB's columns store an empty string as null.

## Output formats

Pick with `-f <format>`. Two formats:

### `default`

Full query including the index prefix and the `search` or `where` command:

```text
FROM main | search CommandLine=*"whoami"*
FROM main | search EventID=4625
FROM security_logs | where match(CommandLine, "(?i) /c ")
```

### `minimal`

Just the search expression, no index prefix or `search` keyword. Useful when feeding the expression into LynxDB's REST API as a `q=` parameter:

```text
CommandLine=*"whoami"*
EventID=4625
* | where match(CommandLine, "(?i) /c ")
```

`minimal` output strips the leading `FROM <index> | search ` from the corresponding `default` query. A `where` query becomes `* | where ...`, which searches every event and filters it. {{ added "0.24.0" }} Use it as the value of LynxDB's saved-query `q` field or any context that expects only the search expression.

## Boolean precedence

LynxDB's `search` evaluates Boolean operators in the order `NOT > OR > AND`, which is the reverse of standard SQL (and most programming languages) for `AND` and `OR`. The backend groups by that precedence, so the same Sigma `condition:` produces the same set of matches as `engine eval`:

- An `AND` nested under an `OR` is parenthesized: `(A and B) or C` becomes `(A AND B) OR C`.
- An `OR` nested under an `AND` stays bare, because it already binds tighter: `(A or B) and C` becomes `A OR B AND C`.
- A compound operand of `NOT` is always parenthesized: `A and not 1 of filter_*` becomes `A AND NOT (filter_1 OR filter_2)`. {{ added "0.24.0" }}

`where` expressions use standard precedence (`NOT > AND > OR`) and are grouped accordingly. {{ added "0.24.0" }}

## Examples

### Plain string match

```yaml
title: Whoami
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
```

```text
FROM main | search CommandLine=*"whoami"*
```

### Integer field

```yaml
detection:
    sel:
        EventID: 4688
    condition: sel
```

```text
FROM main | search EventID=4688
```

### Custom index via pipeline

```yaml
# pipeline.yml
transformations:
  - type: set_state
    key: index
    value: security_logs
```

```bash
rsigma backend convert rules/ -t lynxdb -p pipeline.yml
```

```text
FROM security_logs | search CommandLine=*"whoami"*
```

### Regex

{{ added "0.24.0" }}

```yaml
detection:
    sel:
        CommandLine|re: '^cmd.*whoami'
    condition: sel
```

```text
FROM main | where match(CommandLine, "^cmd.*whoami")
```

A `where` query reads every event in the index rather than using the inverted index, so rules that render as `where` are slower than rules that stay in `search`.

### CIDR with combination

{{ added "0.24.0" }}

```yaml
detection:
    sel:
        Action: 'allow'
        DestinationIp|cidr: '10.0.0.0/8'
    condition: sel
```

```text
FROM main | where match(Action, "(?i)^allow$") AND cidrmatch("10.0.0.0/8", DestinationIp)
```

The CIDR check puts the whole condition in `where`, so the `Action` equality renders as an anchored case-insensitive `match()`.

## Limitations

| Feature | Status |
|---------|--------|
| Correlation rules | Not supported. Each correlation fails with `UnsupportedCorrelation`; the detection rules it references still convert. {{ added "0.24.0" }} |
| Field-to-field comparison (`fieldref`) | Not supported. |
| Fields with mixed value types | LynxDB stores each column with a single type, so a field holding numbers in some events and strings or booleans in others loses values once events are flushed to segments. For example, a boolean in a numeric field turns every value into 0 or 1. {{ added "0.24.0" }} |
| Keywords that are part of a word | LynxDB skips a segment whose bloom filter lacks the tokens of a keyword, so a keyword such as `hoami` misses `whoami` in events flushed to segments, in both `search` and `where` queries. {{ added "0.24.0" }} |
| Keywords in a `where` query | The regex runs on the event's raw JSON and assumes serde_json's escaping: `"`, `\`, and control characters escaped, other characters verbatim. A producer that escapes non-ASCII characters or `/` writes text the keyword does not match. {{ added "0.24.0" }} |
| `exists` in a `where` query | A field that is present with a null value counts as missing, while `engine eval` counts it as present. In a `search` query, `field=*` counts it as present. {{ added "0.24.0" }} |
| Continuous aggregates | LynxDB-equivalent (scheduled saved queries) lives on the LynxDB side. RSigma emits the SPL2; LynxDB schedules it. |

## See also

- [Rule Conversion](../../guide/rule-conversion.md#lynxdb) for the workflow walkthrough.
- [LynxDB's own Sigma guide](https://docs.lynxdb.org/docs/sigma/) for the operator-facing tutorials, the SPL2 mapping reference, scheduled detection, and the drift runbook.
- [`backend convert`](../../cli/backend/convert.md) for the CLI flag table.
- [PostgreSQL backend reference](postgres.md) for the alternate target.
- [`crates/rsigma-convert/src/backends/lynxdb`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-convert/src/backends/lynxdb) for the implementation.
