# Keywords and Conditions

{{ added "0.24.0" }}

This page describes how the evaluator and the converters interpret keyword detections and condition selectors where the specification leaves room for interpretation. The behavior follows the [Sigma specification](https://github.com/SigmaHQ/sigma-specification) and matches pySigma unless a section says otherwise. For value modifiers, see [Value Modifiers](modifiers.md).

## Keywords

A keyword detection is a list of values without a field name. It matches when any value occurs, case-insensitively, as a substring of any value in the event, at any nesting depth.

```yaml
detection:
    keywords:
        - 'mimikatz'
        - 4624
    condition: keywords
```

Keyword values are strings in the specification, so a number matches its decimal text: `4624` matches the numeric value `4624` and the string `logon 4624 succeeded`. The evaluator searches numeric event values as their JSON text, so `4624` also matches `46240`.

A YAML boolean keyword is the word: `true` matches `"true"` and `flag is TRUE now`, and converts as the term `true`. {{ added "0.25.0" }} Keyword search covers string and numeric event values, not JSON booleans, so neither `true` nor `'true'` matches the boolean value `{"a": true}`; match a boolean field with `a: true` instead.

## Field-less values with modifiers

A detection key made only of modifiers, such as `'|all':`, applies its values to the whole event like a keyword. A value without a string operator matches as a substring, and the modifiers combine as they do for a field:

| Key | Matches when |
|---|---|
| `'|all': [a, b]` | every value occurs somewhere in the event, in one event value or in several |
| `'|neq': [a, b]` | no event value contains any of the values |
| `'|startswith': a` | some event value starts with `a` |
| `'|re': 'a.*b'` | some event value matches the regular expression |

```yaml
detection:
    keywords:
        '|all':
            - 'bash -c'
            - '/dev/tcp/'
    condition: keywords
```

Inside an array body, such as `tags[any]: 'admin'`, a field-less value matches the array member itself rather than any value in the event. See [Array Matching](../guide/array-matching.md).

## Converting keywords

Backends render each keyword value as one full-text term. A field-less `|all` list becomes the terms joined with `AND`, and `|neq` negates them. A field-less value with `startswith` or `endswith` has no full-text equivalent and fails conversion with `UnsupportedKeyword`.

Full-text engines may match keywords differently from the evaluator: PostgreSQL matches whole tokens rather than substrings (see [PostgreSQL keywords](backends/postgres.md)), and Fibratus has no full-text search, so keyword rules fail to convert.

## Selectors

`1 of them` and `all of them` cover every detection whose name does not start with an underscore. A pattern selector such as `1 of selection_*` or `all of *` also skips names that start with an underscore, unless the pattern itself starts with one: `1 of _filter*` selects `_filter_a` and `_filter_b`.

A selector that matches no detection name, such as `all of zzz*`, or `1 of *` when every detection name starts with an underscore, is a compile error. Evaluation and conversion reject the rule alike, instead of treating `all of` over nothing as true.

`any of` is accepted as a synonym of `1 of`, as in pySigma. A count above one, such as `2 of selection_*`, is an extension beyond the specification: the evaluator matches when at least that many of the selected detections match. Backends cannot express a count, so conversion rejects the rule with `'2 of' quantifier not supported in conversion`.

`0 of` is a parse error, because it would match every event. Write `not 1 of selection_*` to require that none of the selected detections match. {{ added "0.25.0" }}
