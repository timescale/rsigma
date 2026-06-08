# CI/CD

RSigma is designed to drop into a detection-as-code workflow. The four CLI surfaces that matter for CI are `rule lint`, `rule validate`, `engine eval`, and `backend convert`. Each exits with a structured code that lets CI runners distinguish "no findings, clean exit" from "the tool ran but reported findings" from "the tool could not run because of a configuration or rule error."

This page covers the exit-code model, the failure-controlling flags (`--fail-on-detection`, `--fail-level`), and copy-paste pipelines for GitHub Actions, GitLab CI, pre-commit, and a generic shell runner.

## Exit codes

Every `rsigma` command uses the same four-code scheme. The split is the conventional CI one shared by tools like `pylint` and `zizmor`: distinguish a tool failure from a finding, so the lint/validate steps in a pipeline can be required while the detection-match step can be advisory.

| Code | Meaning | Triggered by |
|------|---------|--------------|
| `0` | Success. The tool ran cleanly. With `--fail-on-detection`, no detection or correlation fired. | Default happy path. Also returned when `rule lint` produces findings below the `--fail-level` threshold. |
| `1` | Findings. The tool ran cleanly but found something noteworthy. | `eval --fail-on-detection` with at least one match; `rule lint --fail-level <X>` with at least one finding at or above `X`. |
| `2` | Rule error. The input rules could not be parsed, compiled, or converted. | `rule validate` with parse or compile errors; `backend convert` when conversion fails or every rule fails; `engine eval` and `rule lint` when the rules path itself cannot be read. |
| `3` | Configuration error. A pipeline file could not be loaded, a CLI argument was invalid, or the tool was misconfigured. | Bad `-p` path, unknown `-t backend`, malformed `--suppress` duration, unreadable schema file. |

The exact source of truth is the [`exit_code` module](https://github.com/timescale/rsigma/blob/main/crates/rsigma-cli/src/exit_code.rs).

A few non-obvious behaviours worth pinning down:

- `engine eval` exits `0` when a rule file contains a Sigma parse error (it logs a warning to stderr and continues with the rules that did load). Use `rule validate` if you want a parse error to fail the build.
- `engine eval` exits `0` by default even when matches fire. Pass `--fail-on-detection` if you want detections to fail the build.
- `rule lint` exits `0` for findings below `--fail-level`. The default threshold is `error`, so a clean lint with only info/warning findings still returns `0`.

## `--fail-on-detection` for `engine eval`

`engine eval` is the right tool for CI tests against fixtures: gold-standard "this event should match" / "this event should not match" pairs that catch detection regressions before they ship.

```bash
rsigma engine eval -r rules/ --fail-on-detection -e @ci/should-not-match.ndjson
```

In a "should match" fixture, you actually want exit `1`:

```bash
if rsigma engine eval -r rules/ --fail-on-detection -e @ci/should-match.ndjson; then
    echo "ERROR: rule did not fire on the positive fixture"
    exit 1
fi
```

The same pattern works for fingerprinting suppression and correlation behaviour. Pair `--fail-on-detection` with `--no-detections` if you only care whether correlations fire:

```bash
rsigma engine eval -r rules/ --fail-on-detection --no-detections \
    --correlation-event-mode none < events.ndjson
```

## `--fail-level` for `rule lint`

`rule lint` uses a tier system. The default threshold is `error`, meaning info, warning, and hint findings never fail the build:

```bash
rsigma rule lint rules/                        # exit 1 only on error findings
rsigma rule lint rules/ --fail-level warning   # exit 1 on warning or error
rsigma rule lint rules/ --fail-level info      # exit 1 on info, warning, or error
```

For shared repositories, `--fail-level warning` strikes the right balance: spec violations break the build, missing-author or missing-description findings don't. For SigmaHQ-style strict contributions, `--fail-level info` is reasonable.

## `rule validate` in CI

`rule validate` is the cheapest gate: it just parses and compiles every rule, no events involved. Wire it as the first step of any detection-as-code pipeline:

```bash
rsigma rule validate rules/
```

Exit `2` means a parse or compile error somewhere; the stdout summary shows the counts:

```text
Parsed 0 documents from rules/
  Detection rules:   0
  Correlation rules: 0
  Filter rules:      0
  Parse errors:      1
  Compiled OK:       0
  Compile errors:    0
```

Add `-p <pipeline.yml>` to validate that your processing pipelines apply cleanly too:

```bash
rsigma rule validate rules/ -p pipelines/ecs.yml
```

For dynamic pipelines, add `--resolve-sources` so CI also exercises the HTTP/file/command sources at validation time. The job fails with exit `3` if any source is unreachable:

```bash
rsigma rule validate rules/ -p pipelines/dynamic.yml --resolve-sources
```

See [Linting Rules](linting-rules.md) and [Processing Pipelines](processing-pipelines.md) for the deeper context on each gate.

## GitHub Actions

A four-job workflow that mirrors a typical detection-engineering loop: lint, validate, fixture eval, then convert and publish.

```yaml
name: detections

on:
  push:
    branches: [main]
  pull_request:

# Least-privilege default; jobs that need more (e.g. uploading artifacts) opt in.
permissions: {}

env:
  RSIGMA_VERSION: "{{ rsigma.version }}"

jobs:
  lint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false
      - run: cargo install --locked rsigma --version "${RSIGMA_VERSION}"
      - run: rsigma rule lint rules/ --fail-level warning

  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false
      - run: cargo install --locked rsigma --version "${RSIGMA_VERSION}"
      - run: rsigma rule validate rules/ -p pipelines/ecs.yml

  eval-fixtures:
    runs-on: ubuntu-latest
    needs: [lint, validate]
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false
      - run: cargo install --locked rsigma --version "${RSIGMA_VERSION}"
      - name: Negative fixtures must not match
        run: rsigma engine eval -r rules/ --fail-on-detection -e @ci/negative.ndjson
      - name: Positive fixtures must match
        run: |
          if rsigma engine eval -r rules/ --fail-on-detection -e @ci/positive.ndjson; then
              echo "::error::positive fixture produced no detection"
              exit 1
          fi

  convert:
    runs-on: ubuntu-latest
    needs: [validate]
    if: github.ref == 'refs/heads/main'
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false
      - run: cargo install --locked rsigma --version "${RSIGMA_VERSION}"
      - run: rsigma backend convert rules/ -t postgres -f view -p pipelines/ecs.yml -o views.sql
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: postgres-views
          path: views.sql
```

For a faster CI loop, install from the precompiled archives instead of `cargo install`. The release page publishes one archive per supported Rust target (see [Installation](../getting-started/installation.md#prebuilt-binaries) for the full list):

```yaml
      - name: Install rsigma
        run: |
          curl -fsSL -o rsigma.tar.gz \
            "https://github.com/timescale/rsigma/releases/download/v${RSIGMA_VERSION}/rsigma-x86_64-unknown-linux-gnu.tar.gz"
          tar -xzf rsigma.tar.gz
          sudo install -m 0755 rsigma /usr/local/bin/rsigma
          rsigma --version
```

`RSIGMA_VERSION` is taken from the workflow-level `env:` shown above; pin it to a released tag so a silent rsigma upgrade cannot change CI behaviour between runs.

!!! tip "Audit your detection workflow with zizmor"
    Detection-as-code repositories should hold themselves to the same supply-chain hygiene they expect from the rest of the org. Run [zizmor](https://github.com/zizmorcore/zizmor) against `.github/workflows/` to catch missing `permissions:`, unpinned actions, script-injection-prone GitHub-context interpolations, and other GHA pitfalls. RSigma's own workflows pass `zizmor --pedantic` with zero findings; the [`zizmor.yml`](https://github.com/timescale/rsigma/blob/main/.github/workflows/zizmor.yml) workflow is a small reference to copy.

## GitLab CI

```yaml
stages: [check, eval, build]

variables:
  RSIGMA_VERSION: "{{ rsigma.version }}"

default:
  image: debian:bookworm-slim

.install-rsigma: &install-rsigma
  before_script:
    - apt-get update && apt-get install -y --no-install-recommends curl ca-certificates
    - curl -fsSL -o rsigma.tar.gz "https://github.com/timescale/rsigma/releases/download/v${RSIGMA_VERSION}/rsigma-x86_64-unknown-linux-gnu.tar.gz"
    - tar -xzf rsigma.tar.gz
    - install -m 0755 rsigma /usr/local/bin/rsigma

lint:
  stage: check
  <<: *install-rsigma
  script:
    - rsigma rule lint rules/ --fail-level warning

validate:
  stage: check
  <<: *install-rsigma
  script:
    - rsigma rule validate rules/ -p pipelines/ecs.yml

negative-fixtures:
  stage: eval
  <<: *install-rsigma
  script:
    - rsigma engine eval -r rules/ --fail-on-detection -e @ci/negative.ndjson

convert-postgres:
  stage: build
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  <<: *install-rsigma
  script:
    - rsigma backend convert rules/ -t postgres -f view -p pipelines/ecs.yml -o views.sql
  artifacts:
    paths: [views.sql]
```

The `only: [main]` keyword is [deprecated in modern GitLab CI](https://docs.gitlab.com/ci/yaml/#only--except); the `rules:` form above is the supported replacement and works on both gitlab.com and self-managed instances at 15.x+.

## Pre-commit hook

A `.pre-commit-config.yaml` that runs the linter and validator on staged `.yml` rules:

```yaml
repos:
  - repo: local
    hooks:
      - id: rsigma-lint
        name: rsigma rule lint
        entry: rsigma rule lint rules/
        language: system
        pass_filenames: false
        files: '^rules/.*\.ya?ml$'

      - id: rsigma-validate
        name: rsigma rule validate
        entry: rsigma rule validate rules/ -p pipelines/ecs.yml
        language: system
        pass_filenames: false
        files: '^(rules|pipelines)/.*\.ya?ml$'
```

`rsigma rule lint` and `rsigma rule validate` take a single `<PATH>` argument (a file or a directory), so `pass_filenames: false` is required on both hooks. The `files:` glob still scopes pre-commit's trigger to the rule and pipeline directories, while the hook itself lints or validates the whole tree.

For auto-fix on commit, run `--fix` then check for diffs:

```bash
rsigma rule lint rules/ --fix
git diff --exit-code rules/
```

Exit code `1` from `git diff --exit-code` means an auto-fix changed a file that has not been committed yet; the commit hook should fail and ask the developer to re-stage.

## Generic shell pipeline

For environments without a managed CI system (cron jobs, scheduled detection regression checks, Concourse, Drone, Argo Workflows):

```bash
#!/usr/bin/env bash
set -euo pipefail

RSIGMA_BIN="${RSIGMA_BIN:-rsigma}"
RULES_DIR="${RULES_DIR:-rules/}"
PIPELINE="${PIPELINE:-pipelines/ecs.yml}"

$RSIGMA_BIN rule lint    "$RULES_DIR" --fail-level warning
$RSIGMA_BIN rule validate "$RULES_DIR" -p "$PIPELINE"

for fixture in ci/negative/*.ndjson; do
    $RSIGMA_BIN engine eval -r "$RULES_DIR" -p "$PIPELINE" \
        --fail-on-detection -e "@$fixture"
done

for fixture in ci/positive/*.ndjson; do
    if $RSIGMA_BIN engine eval -r "$RULES_DIR" -p "$PIPELINE" \
        --fail-on-detection -e "@$fixture"; then
        echo "positive fixture $fixture produced no detection" >&2
        exit 1
    fi
done
```

`set -e` plus `set -o pipefail` makes any non-zero exit fail the script, so the structured exit codes work without explicit `if` branches except for the positive-fixture inversion.

## Tips and gotchas

- **Cache the rsigma binary** between CI runs. The `cargo install` form compiles rsigma from source and typically takes several minutes on a GitHub-hosted runner; the precompiled archive download completes in under 5 seconds. The release page ships archives for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, and `aarch64-pc-windows-msvc`.
- **Pin the rsigma version** in CI. Detection-as-code repos test specific behaviour; a silent rsigma upgrade can flip a previously-fixed bug. Use `cargo install --locked rsigma --version {{ rsigma.version }}` or pin the precompiled archive URL.
- **Separate lint and validate jobs**. They fail for different reasons. A combined job hides which check broke.
- **Avoid `set +e` around rsigma**. Structured exit codes are the API. Wrapping commands in `|| true` or `set +e` defeats the whole model.
- **JSON output for diagnostic logs**. Pass `--log-format json` so CI log aggregators (Datadog CI Visibility, Buildkite test analytics) can parse run metadata without regex. Stdout/stderr are unchanged; only structured diagnostic logs flip to JSON. See [Observability](observability.md).

## See also

- [Evaluating Rules](evaluating-rules.md) for the full `engine eval` flag table and event extraction.
- [Linting Rules](linting-rules.md) for the 68 lint rules, suppression, and `--fix`.
- [Rule Conversion](rule-conversion.md) for the `backend convert` workflow that feeds `views.sql` into Grafana or alerting.
- [Processing Pipelines](processing-pipelines.md) for dynamic-source validation via `--resolve-sources`.
- [Exit Codes reference](../reference/exit-codes.md) for the canonical table and source-code link.
- [CLI reference: `engine eval`](../cli/engine/eval.md), [`rule lint`](../cli/rule/lint.md), [`rule validate`](../cli/rule/validate.md), [`backend convert`](../cli/backend/convert.md).
