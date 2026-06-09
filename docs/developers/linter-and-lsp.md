# Linter and LSP

The {{ rsigma.lint.rules }} lint rules are the single source of authority for "is this Sigma file well-formed"; the language server reuses them so an in-editor squiggle and a CI `rsigma rule lint` failure are byte-identical.

This page explains how the two pieces fit together, how to add a new lint rule, and how to extend the LSP (`rsigma-lsp`).

## Architecture at a glance

```
                   ┌────────────────────────────────────────────┐
                   │  rsigma-parser::lint                       │
                   │                                            │
                   │  pub enum LintRule { ... 66 variants }     │
                   │  pub enum Severity { Error|Warning|... }   │
                   │  pub struct LintWarning {                  │
                   │    rule, severity, message, path,          │
                   │    span: Option<Span>, fix: Option<Fix>    │
                   │  }                                         │
                   │  pub fn lint_yaml_str_with_config(...)     │
                   │  pub fn lint_yaml_directory(...)           │
                   └─────────┬──────────────────────┬───────────┘
                             │                      │
              ┌──────────────▼─────┐    ┌───────────▼────────────┐
              │  rsigma-cli        │    │  rsigma-lsp            │
              │  `rule lint`       │    │  diagnostics.rs        │
              │  CI output, exit   │    │  code_action.rs        │
              │  codes, --fix      │    │  → Diagnostic / Code-  │
              │                    │    │     Action over LSP    │
              └────────────────────┘    └────────────────────────┘
```

The CLI and the LSP share the same `lint_yaml_str_with_config` function; their only differences are output shape and timing (the LSP re-lints on every keystroke and overlays a Span -> LSP `Range` translation).

## LintRule, Severity, and LintWarning

| Type | Defined in | What it does |
|------|------------|--------------|
| `LintRule` | `crates/rsigma-parser/src/lint/mod.rs` | Enum with one variant per check (67 today, one of them the reserved `empty_filter_rules`). `Display` gives the snake_case ID used in CLI output, in YAML `# rsigma-disable:` suppressions, and in CI grep filters. |
| `Severity` | same file | `Error`, `Warning`, `Info`, `Hint`. Severity is configurable per rule via `LintConfig.severity_overrides`; `--fail-level` decides which severity gates the exit code. |
| `LintWarning` | same file | One finding. Carries the rule, severity, human message, JSON pointer `path`, optional source `Span` (line/col), and optional `Fix`. |
| `Fix` + `FixPatch` + `FixDisposition` | same file | An auto-fix proposal. `FixDisposition` is `Safe` or `Unsafe`; only `Safe` fixes are applied by `rsigma rule lint --fix` and by LSP code actions. `FixPatch` is `ReplaceValue`, `ReplaceKey`, or `Remove`. |
| `LintConfig` | same file | Per-rule severity overrides, suppression patterns, and the `--fail-level` resolver. |

The full catalogue with severities and fix availability is the [Lint Rules reference](../reference/lint-rules.md). Every rule has a string ID (e.g. `missing_title`) produced by the `Display` impl on `LintRule`.

## Adding a new lint rule

Step 1: classify it. The four buckets and the file each lives in:

| Bucket | File |
|--------|------|
| Infrastructure / shared metadata (title, id, description, status, level, dates, tags). | `crates/rsigma-parser/src/lint/rules/metadata.rs` |
| Detection rules (logsource, detection block, condition references, falsepositives, scope, …). | `crates/rsigma-parser/src/lint/rules/detection.rs` |
| Correlation rules. | `crates/rsigma-parser/src/lint/rules/correlation.rs` |
| Filter rules. | `crates/rsigma-parser/src/lint/rules/filter.rs` |
| Detection-logic / modifier hygiene (cross-cuts detection and correlation). | `crates/rsigma-parser/src/lint/rules/shared.rs` |

Pick one. If your rule genuinely crosses more than one, prefer the bucket where the bulk of the check happens; do not split.

Step 2: add the `LintRule` variant.

```rust
// crates/rsigma-parser/src/lint/mod.rs

pub enum LintRule {
    // ... existing variants ...
    AuthorMissingEmail,    // ← new
}
```

Step 3: register the `Display` string.

```rust
impl fmt::Display for LintRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            // ... existing arms ...
            LintRule::AuthorMissingEmail => "author_missing_email",
        };
        write!(f, "{s}")
    }
}
```

The string ID must be `lower_snake_case` and stable; never rename it once shipped (users put it in `# noqa: <id>` comments).

Step 4: pick a default severity and (if you intend to support `--fix`) write a `Fix`.

```rust
// crates/rsigma-parser/src/lint/rules/metadata.rs
use super::super::{warning, /* err, info, safe_fix, key, ... */};

pub(super) fn check_author_has_email(rule: &Mapping, path: &str, out: &mut Vec<LintWarning>) {
    let Some(author) = rule.get("author").and_then(|v| v.as_str()) else {
        return;
    };
    if !author.contains('@') {
        out.push(warning(
            LintRule::AuthorMissingEmail,
            "author field should include an email contact",
            format!("{path}/author"),
            /* span = */ None,
            /* fix = */ None,
        ));
    }
}
```

`err`, `warning`, and `info` are the severity-shorthand constructors; `safe_fix` builds an `Option<Fix>` with `FixDisposition::Safe`. They live in the parent `mod.rs`. Construct an `Unsafe` fix as a literal `Some(Fix { disposition: FixDisposition::Unsafe, ... })`. There is no `hint` constructor; emit `Severity::Hint` warnings by building a `LintWarning` directly.

Step 5: call your check from the file's top-level `check_<bucket>` function so the lint driver invokes it.

Step 6: cover it with tests in the same file's `#[cfg(test)] mod tests` block. The existing tests in `metadata.rs` are the reference shape: each test loads a small YAML fragment, runs the lint driver, and asserts on the variants in `Vec<LintWarning>`.

Step 7: update the [Lint Rules reference](../reference/lint-rules.md) catalogue (the source-of-truth table for severities and fix availability lives there).

## Writing a `Fix`

A `Fix` is a sequence of `FixPatch` operations. The patches operate at JSON-pointer paths inside the YAML document:

```rust
use crate::lint::{Fix, FixDisposition, FixPatch};

let fix = Fix {
    title: "Lowercase logsource.product".to_string(),
    disposition: FixDisposition::Safe,
    patches: vec![
        FixPatch::ReplaceValue {
            path: "/logsource/product".to_string(),
            new_value: "windows".to_string(),
        },
    ],
};
```

Three operations:

- `ReplaceValue { path, new_value }`. Most common; rewrite a scalar.
- `ReplaceKey { path, new_key }`. Rename a mapping key (e.g. fix a typo).
- `Remove { path }`. Drop a key or array element.

`Safe` fixes are applied by `rsigma rule lint --fix` (without prompting) and offered as one-click code actions in the LSP. `Unsafe` fixes are visible in CLI output (a hint that a fix exists) but only the LSP exposes them, and only via an explicit code-action invocation. Reserve `Safe` for changes that cannot break any rule that previously parsed and matched events.

## Suppressions

Two layers, both already implemented:

- **YAML comments.** A line comment `# rsigma-disable-next-line: missing_title, invalid_status` suppresses those rules for the immediately following line; `# rsigma-disable-next-line` (no list) suppresses all rules on the next line. A file-level `# rsigma-disable: missing_title` suppresses those rules across the whole document, and `# rsigma-disable` (no list) suppresses every rule in the document. The parser is in `parse_inline_suppressions`.
- **`LintConfig`.** Programmatic; CLI flags map as `--disable <id1,id2>` -> `LintConfig.disabled_rules`, `--exclude '<glob>'` -> `LintConfig.exclude_patterns`, `--tag-namespace <ns>` -> `LintConfig.tag_namespaces`, and a YAML config file (`rsigma-lint.yml` or `--lint-config`) feeds all four fields plus `severity_overrides`.

`apply_suppressions(warnings, &LintConfig, &InlineSuppressions) -> Vec<LintWarning>` filters out suppressed warnings and applies the severity overrides. Both the CLI and the LSP call it after linting.

## Connecting to the LSP

`rsigma-lsp` re-lints on every text-document `did_change` / `did_open` event:

```rust
// crates/rsigma-lsp/src/diagnostics.rs
pub fn diagnose_with_config(text: &str, config: &LintConfig) -> Vec<Diagnostic> {
    let warnings = lint_yaml_str_with_config(text, config);
    warnings.iter().map(|w| lint_warning_to_diagnostic(w, text, &index)).collect()
}
```

Adding a new lint rule does not require any LSP code change: the diagnostic generator iterates whatever the linter returns. Severities, source ranges, and `noqa:` suppressions all flow through unchanged.

Code actions (one-click fixes) likewise inherit the new rule automatically as long as your `Fix` is `Safe`:

```rust
// crates/rsigma-lsp/src/code_action.rs
for w in &warnings {
    let Some(fix) = &w.fix else { continue };
    if fix.disposition != FixDisposition::Safe { continue; }
    // ... convert FixPatch sequence into LSP TextEdits ...
}
```

The translation layer that turns a `FixPatch::ReplaceValue { path }` into an LSP `TextEdit { range, new_text }` lives in `code_action.rs`. If your patch type is one of the three existing ones, no change required. If you need a new patch shape (e.g. `InsertBefore`), open an issue first; this affects both the linter and the LSP.

## Extending the LSP itself

The other LSP modules are smaller and orthogonal to lints:

| Module | Purpose | Add a feature by... |
|--------|---------|---------------------|
| `completion.rs` | Field name and keyword completions. | Adding entries to the static completion table, or wiring a context-sensitive resolver. |
| `position.rs` | UTF-16 / UTF-8 / byte-offset conversion. | Rarely; touch only if you spot a multi-byte off-by-one. |
| `data.rs` | Static reference data (modifier list, well-known tags, severity colours). | Adding entries to the constant arrays. |
| `server.rs` | The LSP server-loop wiring (`tower_lsp_server`). | Adding new LSP methods (e.g. hover, goto-definition). |

The LSP has no integration tests of its own today; manual testing through the [VS Code extension](https://marketplace.visualstudio.com/items?itemName=timescale.rsigma) is the current verification path.

## Checklist for a new lint rule

- [ ] `LintRule::<Name>` variant added in `crates/rsigma-parser/src/lint/mod.rs`.
- [ ] String ID added to the `Display` impl (`lower_snake_case`, stable).
- [ ] Default severity chosen; `err`/`warning`/`info` constructor used.
- [ ] Detection function in the right `lint/rules/<bucket>.rs` file.
- [ ] Driver call added in that bucket's top-level `check_*` function.
- [ ] (Optional) `Fix` with `FixDisposition::Safe` + a covering `FixPatch` sequence.
- [ ] Unit tests in the `tests` module of the same file.
- [ ] Entry in [`docs/reference/lint-rules.md`](../reference/lint-rules.md) catalogue (and "selected examples" section if the rule is non-obvious).
- [ ] Mention in the next release-notes entry under `### Linter`.

## See also

- [Lint Rules reference](../reference/lint-rules.md) for the user-facing catalogue.
- [`rsigma rule lint`](../cli/rule/lint.md) CLI reference.
- [`rsigma-parser` lint module](https://github.com/timescale/rsigma/blob/main/crates/rsigma-parser/src/lint/mod.rs) for the full types.
- [`rsigma-lsp` README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-lsp/README.md).
