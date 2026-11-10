---
description: "Lint Sigma rules with rsigma rule lint: severity levels, suppressions, auto-fix, JSON schema validation, and CI integration patterns for rule repositories."
---

# Linting Rules

`rsigma rule lint` runs {{ rsigma.lint.rules }} built-in lint rules derived from the Sigma v2.1.0 specification against your rule files. The linter reads each YAML rule, runs it through a pipeline of checks, and reports findings with severity, location, and an optional auto-fix. Use the linter both locally (before commit) and in CI (as a gate on PRs).

This page covers the four severity levels, the suppression system, auto-fix behavior, JSON schema validation, and CI integration patterns. The full per-rule catalog lives in [Lint Rules reference](../reference/lint-rules.md).

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
| `hint` | Stylistic. Even softer than info. Never fails the build, even with `--fail-level info`. | Does not fail. |

The default exit code policy is to fail only on errors. Override with `--fail-level`:

```bash
rsigma rule lint rules/                       # exit 1 only on errors
rsigma rule lint rules/ --fail-level warning  # exit 1 on errors or warnings
rsigma rule lint rules/ --fail-level info     # exit 1 on any finding (except hint)
```

In CI we recommend `--fail-level warning` for shared rule repositories and `--fail-level info` for SigmaHQ-style contributions where stricter hygiene matters.

## The {{ rsigma.lint.rules }} rules at a glance

The lint rules are grouped by what part of a rule they inspect (counts match the [Lint Rules reference](../reference/lint-rules.md)):

| Category | Count | Examples |
|----------|------:|----------|
| Infrastructure | 4 | `yaml_parse_error`, `not_a_mapping`, `file_read_error`, `schema_violation` |
| Shared metadata | 17 | `missing_title`, `invalid_status`, `invalid_level`, `taxonomy_too_long`, `non_lowercase_key` |
| Detection rules | 20 | `missing_detection`, `missing_condition`, `invalid_tag`, `duplicate_fields`, `flattened_array_correlation` |
| Correlation rules | 17 | `missing_correlation_type`, `missing_correlation_timespan`, `invalid_correlation_type`, `missing_condition_field` |
| Filter rules | 8 emitted (9 IDs) | `missing_filter_rules`, `missing_filter_selection`, `filter_has_level`, `filter_reference_by_title` |
| Modifier and `related:` hygiene | 7 | `single_value_all_modifier`, `incompatible_modifiers`, `deprecated_without_related` |
| Spec version and rule references | 4 | `unsupported_sigma_version`, `array_matching_without_version`, `unknown_rule_reference` |
| ADS detection-strategy metadata | 11 | `ads_missing_goal`, `ads_unknown_section` (opt-in via `.rsigma-lint.yml`) |

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
| `duplicate_fields` | Remove the duplicate entry from the top-level `fields:` list. |
| `single_value_all_modifier` | Remove the redundant `all` modifier. |
| `all_with_re` | Remove the redundant `all` modifier. |
| `wildcard_only_value` | Replace lone `*` with `exists: true`. |
| `filter_has_level` | Remove the inapplicable `level` field from a filter rule. |
| `filter_has_status` | Remove the inapplicable `status` field. |
| `ads_unknown_section` | Rename an unrecognized `rsigma.ads.*` key to the closest known ADS section. |

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

The same `.rsigma-lint.yml` carries the opt-in `ads:` block that turns on the [detection-strategy checks](detection-strategy.md) (`enforce_status`, `required`, `severity`); without it, the `ads_missing_*` rules never fire. See [Lint Rules: ADS detection-strategy metadata](../reference/lint-rules.md#ads-detection-strategy-metadata-11).

The `--config` flag overrides discovery and points at an explicit file:

```bash
rsigma rule lint rules/ --config /etc/rsigma/lint.yml
```

### 3. Inline comments

For one-off cases inside a single rule, use comments. These work both as full-line and trailing comments:

```yaml
# rsigma-disable
title: A rule we know breaks one check
logsource:
    category: process_creation
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

Findings follow the global `--output-format` and `--color` flags (see [CLI overview](../cli/index.md#global-flags) and [Output Formats](../reference/output.md)). Human table output is the default on a TTY; use `json` or `ndjson` in CI when you want to pipe findings into other tools.

```bash
rsigma rule lint rules/ --output-format ndjson
rsigma rule lint rules/ --color never
```

`NO_COLOR=1` also disables color, matching the [NO_COLOR convention](https://no-color.org/).

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
      - name: Install RSigma
        run: |
          # Prefer a release binary; see Installation for Docker and Cargo.
          curl -fsSL -o rsigma.tar.gz \
            https://github.com/timescale/rsigma/releases/download/v{{ rsigma.version }}/rsigma-x86_64-unknown-linux-gnu.tar.gz
          tar -xzf rsigma.tar.gz
          sudo install -m 0755 rsigma /usr/local/bin/rsigma
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
- [Installation](../getting-started/installation.md) for binaries, Docker, and Cargo.
- [CI/CD](ci-cd.md) for full pipeline examples.
- [Editor integration](../editors/vscode.md) for the LSP-driven workflow.
