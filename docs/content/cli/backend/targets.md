---
description: "Reference for rsigma backend targets: list the Sigma conversion backends compiled into the binary, plus any sigma-cli targets available through delegation."
---

# `rsigma backend targets`

{{ added "0.12.0" }}

List the conversion backends compiled into this binary.

## Synopsis

```text
rsigma backend targets [OPTIONS]
```

## Description

Prints every native backend that [`backend convert`](convert.md) can target, plus a one-line description. Backend names are case-insensitive and accept short aliases (`pg` for PostgreSQL).

When an external [sigma-cli](https://github.com/SigmaHQ/sigma-cli) is discoverable, its targets are appended too (marked "via sigma-cli"), since `backend convert` delegates any non-native target to it. When sigma-cli is not installed, the command prints a short hint on how to add it. See [sigma-cli delegation](../../reference/backends/sigma-cli.md).

## Flags

This command takes no command-specific flags. The global `--output-format` selector is honored: the human listing is the default, and `json`/`ndjson`/`table`/`csv`/`tsv` emit `PROVIDER,NAME,DESCRIPTION` rows (`provider` is `native` or `sigma-cli`). JSON also includes a `sigma_cli` field naming the discovered program when delegation is available. See [Output Formats](../../reference/output.md).

## Examples

```bash
rsigma backend targets
```

```text
Available conversion targets:
  postgres  - PostgreSQL/TimescaleDB (aliases: postgresql, pg)
  lynxdb    - LynxDB log analytics engine
  fibratus  - Fibratus kernel-event detection engine
  test      - Backend-neutral test backend
```

The `test` backend produces backend-neutral text and is mainly used by the test suite, but it is occasionally useful for seeing how a rule lowers to a generic boolean expression before picking a real backend.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Always (the command is a pure read). |

## See also

- [`backend convert`](convert.md) to actually convert rules.
- [`backend formats <TARGET>`](formats.md) to list the per-backend output formats.
- [PostgreSQL backend reference](../../reference/backends/postgres.md), [LynxDB backend reference](../../reference/backends/lynxdb.md), [Fibratus backend reference](../../reference/backends/fibratus.md).
