# `rsigma rule lint`

Lint Sigma rules against the v2.1.0 specification with 66 built-in checks.

## Synopsis

```text
rsigma rule lint [OPTIONS] <PATH>
```

## Description

Reads one rule file or every `*.yml`/`*.yaml` in a directory, runs each rule through the linter's check pipeline, and reports findings on stdout. Each finding has a severity (`error`, `warning`, `info`, `hint`), a rule ID, a message, and a JSON-pointer location.

Thirteen of the 66 rules carry safe auto-fixes; pass `--fix` to apply them in place. Optional JSON schema validation, three suppression tiers (CLI, config file, inline comments), and a tiered `--fail-level` for CI gating.

For the narrative version with the full lint-rule catalog and CI patterns see [Linting Rules](../../guide/linting-rules.md).

## Flags

### Input

| Flag | Description |
|------|-------------|
| `<PATH>` | Path to a Sigma rule file or a directory of rules (recursive). |
| `--exclude <GLOB>` | Exclude paths matching a glob (relative to `<PATH>`). Repeatable: `--exclude "config/**" --exclude "**/unsupported/**"`. |

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `-v, --verbose` | off | Show details for all files, including those with zero findings. |
| `--color <MODE>` | `auto` | `auto`, `always`, `never`. `NO_COLOR=1` also disables color. |

### Severity gate

| Flag | Default | Description |
|------|---------|-------------|
| `--fail-level <LEVEL>` | `error` | Minimum severity that causes exit `1`. `error` fails on errors only; `warning` fails on warnings or errors; `info` fails on any finding (info, warning, error). Hint never fails. |

### Suppression

| Flag | Description |
|------|-------------|
| `--disable <IDS>` | Disable specific lint rules. Comma-separated: `--disable missing_author,missing_description`. |
| `--config <PATH>` | Path to a `.rsigma-lint.yml`. If unset, ancestors of `<PATH>` are searched. |
| `--tag-namespace <NS>` | Allow an additional tag namespace (repeatable). Tags using the given namespace no longer trigger `unknown_tag_namespace`. Example: `--tag-namespace myorg --tag-namespace internal`. |

Inline `# rsigma-disable` and `# rsigma-disable-next-line` comments also work; see [Linting Rules: suppression](../../guide/linting-rules.md#suppression-three-tiers).

### Auto-fix

| Flag | Description |
|------|-------------|
| `--fix` | Apply safe auto-fixes in place. Uses `yamlpath`/`yamlpatch` to preserve formatting and comments. |

### JSON schema validation

| Flag | Description |
|------|-------------|
| `-s, --schema <SCHEMA>` | Validate each rule against a JSON schema. `default` downloads the official SigmaHQ schema (cached for 7 days), or pass a path to a local schema file. Findings appear as the `schema_violation` lint rule and respect the suppression mechanisms. |

## Examples

### Run the default `error`-level gate

```bash
rsigma rule lint rules/
```

```text
Checked 1 file(s): 1 passed, 0 failed (0 error(s), 0 warning(s), 1 info(s))
```

### Stricter gate for shared repos

```bash
rsigma rule lint rules/ --fail-level warning
```

### Apply safe fixes in place, then commit

```bash
rsigma rule lint rules/ --fix
git diff
```

### Validate against the official Sigma schema

```bash
rsigma rule lint rules/ --schema default
```

### Suppress specific rules in CI

```bash
rsigma rule lint rules/ --disable missing_author,missing_description --fail-level info
```

### Verbose per-file output

```bash
rsigma rule lint rules/whoami.yml -v
```

```text
rules/whoami.yml
  info[missing_description]: missing recommended field 'description'
    --> /description
  info[missing_author]: missing recommended field 'author'
    --> /author

────────────────────────────────────────────────────────────
Checked 1 file(s): 1 passed, 0 failed (0 error(s), 0 warning(s), 2 info(s))
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `--fail-level`. |
| `1` | At least one finding at or above `--fail-level`. |
| `2` | The rules path or a schema file could not be read. |
| `3` | Bad `--schema` argument or other CLI configuration error. |

## See also

- [Linting Rules](../../guide/linting-rules.md) for the full rule catalog, suppression tiers, and CI patterns.
- [`rule validate`](validate.md) for the cheaper parse-and-compile gate.
- [Lint Rules reference](../../reference/lint-rules.md) for the complete 66-rule catalog.
- [CI/CD](../../guide/ci-cd.md#-fail-level-for-rule-lint) for pre-commit hooks and pipeline patterns.
