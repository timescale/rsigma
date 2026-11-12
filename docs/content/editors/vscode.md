---
description: "Install the RSigma extension for VS Code and Cursor: live Sigma rule linting, parse and compile errors, code actions, completions, hover, and formatting."
---

# VS Code and Cursor

The `rsigma` VS Code extension wraps [`rsigma-lsp`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-lsp) and lights up `.yml` files with the same {{ rsigma.lint.rules }} lint rules, parse errors, and compile errors that `rsigma rule lint` and `rsigma rule validate` produce. Because it is a thin client over the language server, anything that lints in CI also lights up in the editor, and vice versa.

The extension also runs as-is in [Cursor](https://cursor.sh/) and any other VS Code-compatible editor that supports VSIX installation.

## What you get

| Capability | Detail |
|------------|--------|
| Diagnostics | All {{ rsigma.lint.rules }} lint rules, plus YAML and condition-expression parse errors, plus per-rule compile errors. Three layers run on every save and after a 150 ms debounce on every change. |
| Code actions | One-click quick-fixes for the {{ rsigma.lint.autofix }} lint rules with a `Safe` fix. Cursor over a squiggle, press `Cmd+.`/`Ctrl+.`, pick the suggestion. |
| Completions | Modifier names after `|`, MITRE ATT&CK tags inside `tags:`, valid `status`, `level`, `product`, `category`, and `service` values, top-level keys, selection names referenced from `condition:`. |
| Hover | Modifier documentation, MITRE ATT&CK tactic and technique descriptions (with link-out to attack.mitre.org). |
| Document symbols | Hierarchical outline of `title`, `logsource`, `detection`, `correlation`, used by VS Code's Outline view and breadcrumb. |
| Formatting | Whole-document and selection formatting with rsigma's canonical layout. Comments, anchors, tags, and directives are kept, and the semantic guard refuses any change to what a rule means. |

All capabilities target Sigma detection, correlation, and filter rules. Processing pipeline YAML is not a first-class LSP document type; open pipelines may produce generic YAML/Sigma parse noise rather than pipeline-aware diagnostics.

## Install

The extension is distributed from the repository under `editors/vscode/`. Install it from a local VSIX:

### Prerequisites

1. Install the language server. Either `cargo install --locked rsigma-lsp` or unpack `rsigma-lsp` from the [release archive](../getting-started/installation.md) (it ships alongside `rsigma`). Confirm it is on your `$PATH`:

    ```bash
    rsigma-lsp --version
    ```

2. Have a recent VS Code or Cursor (the extension requires VS Code 1.75+).

### Build and install the VSIX

```bash
git clone https://github.com/timescale/rsigma
cd rsigma/editors/vscode

npm install
npm run package                                # produces rsigma-0.1.0.vsix

code --install-extension rsigma-0.1.0.vsix     # VS Code
cursor --install-extension rsigma-0.1.0.vsix   # Cursor
```

The extension activates on any `.yml` or `.yaml` workspace; you do not have to mark a file as a Sigma rule manually.

## Settings

| Setting | Default | What it does |
|---------|---------|--------------|
| `rsigma.serverPath` | `rsigma-lsp` | Path to the `rsigma-lsp` binary. Resolved against `$PATH` if not absolute. Override this if you keep `rsigma-lsp` in a non-standard location. Set it in user settings, or remote settings for a remote window; VS Code ignores it in a workspace or folder `.vscode/settings.json`, so a cloned repository cannot choose which program the extension runs. The value is not carried by Settings Sync. {{ added "0.27.0" }} |
| `rsigma.trace.server` | `off` | LSP wire-trace level: `off`, `messages`, or `verbose`. Set to `verbose` only when filing a bug; it prints every JSON-RPC frame to the `rsigma` output channel. |

The extension respects the same `.rsigma-lint.yml` files and `# rsigma-disable` inline suppressions that the CLI uses. Drop one in your workspace root or any ancestor directory of your rules.

## Recommended workspace settings

For a folder of Sigma rules, this is a sensible `.vscode/settings.json`:

```json
{
  "files.associations": {
    "*.sigma.yml": "yaml",
    "**/rules/**/*.yml": "yaml"
  },
  "yaml.validate": false,
  "yaml.format.enable": false,
  "[yaml]": {
    "editor.defaultFormatter": "rsigma.rsigma",
    "editor.formatOnSave": true
  }
}
```

The first two lines make sure VS Code treats your rules as YAML (and thus activates the rsigma extension). Disabling `yaml.validate` avoids double-squiggles from the generic YAML language server. Disabling `yaml.format.enable` prevents the generic YAML formatter from rewriting wildcard patterns and reflowing condition expressions, while the `[yaml]` block routes formatting to rsigma and formats on save. Choose rsigma as the default formatter for Sigma rules; the generic YAML formatter does not know the canonical key order or the semantic guard.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| No squiggles, even on obviously broken YAML. | Extension did not start. | Open the `rsigma` output channel: `View -> Output`, pick `rsigma` from the dropdown. Look for language-client startup errors or a `Failed to start rsigma language server` toast. |
| `rsigma-lsp: command not found` in the output channel. | Server binary not on `$PATH`. | `which rsigma-lsp` from your shell; if empty, install it (see prerequisites). If it is on `$PATH` only inside your shell init, set `rsigma.serverPath` to the absolute path. |
| Diagnostics work, but quick-fixes do nothing. | The lint rule does not have a `Safe` auto-fix. | See the [fixable-rules list](../reference/lint-rules.md). The {{ rsigma.lint.autofix }} rules with a `Yes` in the Fix column are the ones the extension can act on. |
| Stale diagnostics after changing `.rsigma-lint.yml`. | The server caches config per document. | Close and reopen the file, or run `Developer: Reload Window`. |
| The server panics or hangs. | A bug, or a malformed rule that exercises a known path. | Open the `rsigma` output channel, capture the log, and file an issue with the snippet that triggered it. Setting `rsigma.trace.server` to `verbose` first gives the maintainers the full wire log. |

## Debugging

To collect a server-side log instead of (or in addition to) the LSP wire trace:

```bash
RUST_LOG=rsigma_lsp=debug rsigma-lsp
```

Then in VS Code, set `rsigma.serverPath` to a wrapper script that spawns the server with that env var, and reload the window. The log lands wherever stderr goes (usually the `rsigma` output channel).

## See also

- [Linting rules](../guide/linting-rules.md) for the operator-facing CLI workflow.
- [Lint Rules reference](../reference/lint-rules.md) for the full {{ rsigma.lint.rules }}-rule catalog and which {{ rsigma.lint.autofix }} have safe auto-fixes.
- [Linter and LSP](../developers/linter-and-lsp.md) for the contributor walkthrough.
- [Neovim, Helix, Zed](neovim.md) for other LSP-aware editors.
- [`rsigma-lsp` README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-lsp/README.md) for the full capability matrix and protocol details.
