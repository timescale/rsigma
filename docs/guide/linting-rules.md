# Linting Rules

`rsigma rule lint` runs {{ rsigma.lint.rules }} built-in lint rules derived from the Sigma v2.1.0 specification against your rule files. The linter reads each YAML rule, runs it through a pipeline of checks, and reports findings with severity, location, and an optional auto-fix. Use the linter both locally (before commit) and in CI (as a gate on PRs).

This page covers the four severity levels, the suppression system, auto-fix behaviour, JSON schema validation, and the CI integration patterns we recommend.

## Quick start

```bash
rsigma rule lint rules/
```

```text
────────────────────────────────────────────────────────────
Checked 1 file(s): 1 passed, 0 failed (0 error(s), 0 warning(s), 1 info(s))
```

By default the linter prints a one-line summary. Pass `-v` to see each finding:

```bash
rsigma rule lint rules/ -v
```

```text
rules/whoami.yml
  info[missing_author]: missing recommended field 'author'
    --> /author

────────────────────────────────────────────────────────────
Checked 1 file(s): 1 passed, 0 failed (0 error(s), 0 warning(s), 1 info(s))
```

The path after `-->` is a JSON pointer into the rule YAML, useful for editors and scripts.

## Severities and the `--fail-level` gate

Every lint rule has one of four severities:

| Severity | Meaning | Default in CI |
|----------|---------|---------------|
| `error` | A spec violation. The rule will not parse, compile, or run correctly. | Fails the build. |
| `warning` | A best-practice issue. The rule still runs but should be cleaned up. | Does not fail. |
| `info` | A soft suggestion. Cosmetic or documentation. | Does not fail. |
| `hint` | Stylistic. Even softer than info. | Does not fail. |

The default exit code policy is to fail only on errors. Override with `--fail-level`:

```bash
rsigma rule lint rules/                       # exit 1 only on errors
rsigma rule lint rules/ --fail-level warning  # exit 1 on errors or warnings
rsigma rule lint rules/ --fail-level info     # exit 1 on any finding
```

In CI we recommend `--fail-level warning` for shared rule repositories and `--fail-level info` for SigmaHQ-style contributions where stricter hygiene matters.

## The {{ rsigma.lint.rules }} rules at a glance

The lint rules are grouped by what part of a rule they inspect:

| Category | Count | Examples |
|----------|------:|----------|
| Infrastructure | 4 | `yaml_parse_error`, `not_a_mapping`, `file_read_error`, `schema_violation` |
| Shared metadata | 16 | `missing_title`, `invalid_status`, `invalid_level`, `invalid_date`, `non_lowercase_key` |
| Detection rules | 19 | `missing_detection`, `missing_condition`, `invalid_tag`, `duplicate_fields`, `deprecated_aggregation_syntax`, `flattened_array_correlation` |
| Correlation rules | 13 | `missing_correlation_type`, `missing_correlation_timespan`, `invalid_correlation_type`, `missing_condition_field` |
| Filter rules | 7 | `missing_filter_rules`, `missing_filter_selection`, `filter_has_level` |
| Detection logic | 7 | `single_value_all_modifier`, `incompatible_modifiers`, `wildcard_only_value` |

See the full catalog in [Lint Rules reference](../reference/lint-rules.md), with each rule documented with severity, description, example bad/good YAML, and auto-fix availability. The reference is the canonical place to look up a finding code.

## Auto-fix with `--fix`

{{ rsigma.lint.autofix }} of the {{ rsigma.lint.rules }} rules carry safe auto-fixes (no semantic change). Apply them in place with `--fix`:

```bash
rsigma rule lint rules/ --fix
```

The fixable rules:

| Rule | What gets fixed |
|------|-----------------|
| `invalid_status` | Replace with the closest valid `status` value. |
| `invalid_level` | Replace with the closest valid `level` value. |
| `non_lowercase_key` | Lowercase the key in place. |
| `logsource_value_not_lowercase` | Lowercase the `category`/`product`/`service` value. |
| `unknown_key` | Replace with the closest known key (typo correction). |
| `duplicate_tags` | Remove the duplicate tag entry. |
| `duplicate_references` | Remove the duplicate reference URL. |
| `duplicate_fields` | Remove the duplicate field name. |
| `single_value_all_modifier` | Remove the redundant `all` modifier. |
| `all_with_re` | Remove the redundant `all` modifier. |
| `wildcard_only_value` | Replace lone `*` with `exists: true`. |
| `filter_has_level` | Remove the inapplicable `level` field from a filter rule. |
| `filter_has_status` | Remove the inapplicable `status` field. |

Fixes preserve formatting and comments via `yamlpath`/`yamlpatch`. Always commit your rule files first, then run `--fix`, then diff the result.

## Suppression: three tiers

You can disable lint rules at three different levels. They compose: an excluded path is skipped entirely; remaining files are filtered through global `--disable` and config-file `disabled_rules`; then inline `# rsigma-disable` comments win finest-grained.

### 1. CLI: `--disable` and `--exclude`

```bash
rsigma rule lint rules/ --disable missing_author,missing_description
rsigma rule lint rules/ --exclude "config/**"
rsigma rule lint rules/ --exclude "config/**" --exclude "**/unsupported/**"
```

`--disable` is a comma-separated list of rule IDs. `--exclude` is a glob pattern (repeatable). Both apply for the duration of the lint run only.

### 2. Config file `.rsigma-lint.yml`

For team-wide policies, commit a `.rsigma-lint.yml` (or `.yaml`) into your rules repository. The linter walks ancestor directories upward from the target path to find it:

```yaml
disabled_rules:
  - missing_author
  - missing_description
severity_overrides:
  title_too_long: info
exclude:
  - "config/**"
  - "**/unsupported/**"
tag_namespaces:
  - myorg
  - internal
```

`severity_overrides` lets you keep a rule active but change how loud it is. Setting `title_too_long: info` keeps the check but stops it from failing `--fail-level warning` builds.

The `--config` flag overrides discovery and points at an explicit file:

```bash
rsigma rule lint rules/ --config /etc/rsigma/lint.yml
```

### 3. Inline comments

For one-off cases inside a single rule, use comments. These work both as full-line and trailing comments:

```yaml
# rsigma-disable
title: A rule we know breaks one check
detection:
    selection:
        # rsigma-disable-next-line wildcard_only_value
        WeirdField: "*"
    condition: selection
```

The variants:

| Comment | Effect |
|---------|--------|
| `# rsigma-disable` | Disable all lint rules from this line to the end of the file. |
| `# rsigma-disable rule1, rule2` | Disable only the listed rules. |
| `# rsigma-disable-next-line` | Disable all rules on the next line. |
| `# rsigma-disable-next-line rule1` | Disable a specific rule on the next line. |

Inline `#` inside quoted YAML strings is not treated as a comment, so `EventID: "1234 # comment"` keeps the literal value.

## JSON schema validation

The linter can optionally validate each rule against a JSON schema, surfacing structural issues that the spec-derived rules miss. Two modes:

```bash
# Download and cache the official SigmaHQ schema for 7 days
rsigma rule lint rules/ --schema default

# Validate against your own local schema
rsigma rule lint rules/ --schema ./my-schema.json
```

Schema validation skips documents with `action: global`, `action: reset`, or `action: repeat` (those are fragments, not standalone rules). Findings surface as the `schema_violation` lint rule, which respects the same suppression mechanisms as everything else.

## Auto-fix in editors via the LSP

`rsigma-lsp` exposes the same auto-fixes as code actions. When the cursor sits on a diagnostic, the editor offers a one-click fix. See [VS Code](../editors/vscode.md), [Neovim/Helix/Zed](../editors/neovim.md), and the LSP reference for setup.

## Output format and color

By default, the linter colours output for TTY and skips colour when piped. Three flags control this:

```bash
rsigma rule lint rules/ --color auto
rsigma rule lint rules/ --color always
rsigma rule lint rules/ --color never
```

The `NO_COLOR=1` environment variable also disables colour, matching the [NO_COLOR convention](https://no-color.org/).

## CI patterns

### GitHub Actions

```yaml
name: lint
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install --locked rsigma
      - run: rsigma rule lint rules/ --fail-level warning
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: rsigma-lint
        name: rsigma rule lint
        entry: rsigma rule lint --fail-level error
        language: system
        files: '^rules/.*\.ya?ml$'
```

### Catching regressions on auto-fix

If your CI runs `--fix` it should also check for diffs to avoid silent rewrites:

```bash
rsigma rule lint rules/ --fix
git diff --exit-code rules/
```

Exit code 1 means a fix was applied that you have not yet committed.

## See also

- [Lint Rules reference](../reference/lint-rules.md) for the full {{ rsigma.lint.rules }}-rule catalog.
- [CLI reference: `rule lint`](../cli/rule/lint.md) for every flag.
- [CI/CD](ci-cd.md) for full pipeline examples.
- [Editor integration](../editors/vscode.md) for the LSP-driven workflow.
