---
description: "Reference for rsigma rule condition: parse a Sigma condition expression such as selection and not filter, and print its abstract syntax tree."
---

# `rsigma rule condition`

{{ added "0.12.0" }}

Parse a Sigma condition expression and print the AST.

## Synopsis

```text
rsigma rule condition [OPTIONS] <EXPR>
```

## Description

Takes a Sigma condition string (the right-hand side of `condition:` in a rule) and prints its parsed AST as JSON. Useful for tooling that reasons about condition trees, for sanity-checking a complicated expression before pasting it into a rule, and for understanding precedence on expressions with mixed `and`, `or`, `not`, and `1 of`/`all of` quantifiers.

## Flags

| Flag | Description |
|------|-------------|
| `<EXPR>` | The condition expression to parse. Quote the argument so the shell does not eat the `*` or `(` characters. |

## Examples

### Simple selection

```bash
rsigma rule condition 'selection'
```

### Combined selections

```bash
rsigma rule condition '(selection_a or selection_b) and not filter'
```

### Quantified expressions

```bash
rsigma rule condition '1 of selection_* and not filter_*'
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Expression parsed cleanly. |
| `2` | Parse error. |

## See also

- [Sigma specification: condition expressions](https://sigmahq.io/docs/basics/conditions.html) for the official condition grammar.
- [`rule parse`](parse.md) for parsing a full rule (including its condition).
- [Concepts](../../getting-started/concepts.md) for the Sigma primer.
