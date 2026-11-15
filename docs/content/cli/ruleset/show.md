---
description: "Show the documents a ruleset resolves to, including decisions, origins, reasons, and applied overlays."
---

# `rsigma ruleset show`

{{ added "unreleased" }}

Show every document a ruleset resolves to, with the decision that admitted or rejected it and the overlays that touched it.

## Synopsis

```text
rsigma ruleset show <NAME> [--config <PATH>] [--all] [--id <ID> [--yaml]]
```

## Description

`ruleset show` resolves one named ruleset and prints its candidates. By default it shows only kept documents: included detection rules and correlations, pulled-in dependencies, and retained filters. `--all` also shows not-selected, excluded, and dropped candidates with the reason.

Each row carries the kind, decision, id, title, origin, reason, and applied overlay origins. Origins use the form `s<source>:<file>#<ordinal>`.

`--id <ID>` prints one document's full detail, including every applied overlay with the keys it set or appended. Adding `--yaml` prints the canonical emitted YAML of the resolved document. `--yaml` requires `--id`.

Output uses the global `--output-format` layer. The list JSON envelope is `{ ruleset, counts: { detection, correlation, filter, candidates }, entries: [...] }`; `--id` returns `{ ruleset, document: { ... } }` with the document detail and applied overlays.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | discovery | Configuration file to read rulesets from. |
| `--all` | off | Show every candidate, including excluded and dropped documents. |
| `--id` | none | Show one document by id. |
| `--yaml` | off | Print the canonical emitted YAML of the document selected by `--id`. Requires `--id`. |

## Examples

### Show kept documents

```bash
rsigma ruleset show vendor
```

### Show every candidate

```bash
rsigma ruleset show vendor --all
```

### Inspect one document and its overlays

```bash
rsigma ruleset show vendor --id aaaaaaaa-0000-4000-8000-000000000001
```

### Print the resolved YAML

```bash
rsigma ruleset show vendor --id aaaaaaaa-0000-4000-8000-000000000001 --yaml
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The ruleset resolved and the requested document was printed. |
| `3` | Unknown ruleset name, resolution error, unknown id, or unreadable configuration. |

## See also

- [`rsigma ruleset list`](list.md)
- [`rsigma ruleset build`](build.md)
- [Rulesets guide](../../guide/rulesets.md)
